using System.Diagnostics;
using System.Reflection;
using System.Text.Json;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.ViewModels;

internal static class SessionStoreVersionTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("account state cleared before first login rejects the pending missing revision", MissingClear),
        ("account state stale clear cannot erase a replacement login", StaleClear),
        ("account state rotation keeps login identity and explicit relogin replaces it", LoginContinuity),
        ("account state migrates schema-one credentials only after live verification", LegacyMigration),
        ("account state preserves corrupt and unknown records on startup", BadRecords),
        ("account state rejects an oversized record without allocating its contents", Capacity),
        ("account state pre-commit clear failure retains the original protected record", FailedClear),
        ("account state ambiguous save failure never permits an old owner to clear the committed login", () => AmbiguousCommit(false)),
        ("account state ambiguous clear failure never permits stale restoration", () => AmbiguousCommit(true)),
        ("account state pending sign-in cannot overtake completed sign-out", PendingSignIn),
        ("account state pending hydration cannot replace another login", PendingHydration),
        ("account state stale coordinator logout revokes only its local publication", CoordinatorLogout),
        ("account state read failure cannot discard ownership and let a stale logout clear another login", ReadFailureKeepsOwnership),
        ("account state separate writer process cannot revive a cleared login", () => ProcessStale("save")),
        ("account state separate clearer process cannot erase a new login", () => ProcessStale("clear")),
        ("account state lease excludes another process and releases after termination", ProcessLease)
    ];

    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(20);
    private static readonly SessionAuthority Authority = SessionAuthority.ForSupabaseProject("https://session-storage-test.supabase.co");
    private static ISessionProtector Protector() => OperatingSystem.IsWindows() ? new DpapiSessionProtector() : new PlainSessionProtector();
    private static SessionStore Store(string path) => new(path, Protector());
    private static PersistedSession Credentials(string name = "Original", string subject = "storage-user", int minutes = 60)
    {
        static string Encode(object value) => Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(value)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        string token = Encode(new { alg = "EdDSA", typ = "JWT" }) + "." + Encode(new
        {
            iss = Authority.Issuer, sub = subject, aud = "authenticated", role = "authenticated",
            exp = DateTimeOffset.UtcNow.AddMinutes(minutes).ToUnixTimeSeconds(), app_metadata = new { tenant_id = "storage-tenant" }
        }) + ".dGVzdA";
        return new() { SchemaVersion = PersistedSession.CurrentSchemaVersion, Authority = Authority,
            Subject = subject, AccessToken = token, RefreshToken = "synthetic-refresh", DisplayName = name,
            IssuedAtUnix = DateTimeOffset.UtcNow.ToUnixTimeSeconds() };
    }
    private static AuthToken Token(PersistedSession value) => new()
    { AccessToken = value.AccessToken, RefreshToken = value.RefreshToken, User = User(value.DisplayName) };
    private static AuthUser User(string? name = "Verified") => new()
    { Id = "storage-user", UserMetadata = new AuthUserMetadata { DisplayName = name } };
    private static FakeAuthClient Auth() => new()
    { SessionAuthority = Authority, GetUserResult = AuthClientResult<AuthUser>.Success(User()) };
    private static SessionStoreWriteResult Create(SessionStore store, string name = "Original") =>
        store.Save(Credentials(name), store.Load().Version ?? throw new InvalidDataException("Missing fixture revision."), SessionStoreSaveMode.NewLogin);
    private static void Require(bool value, string message) { if (!value) throw new InvalidOperationException(message); }

    private static Task MissingClear()
    {
        using var directory = TempDir.Create(); var store = Store(directory.Path);
        var missing = store.Load(); Require(missing.Status == SessionStoreLoadStatus.Missing, "Expected a genuinely missing record.");
        var clear = store.Clear(missing.Version!); Require(clear.Succeeded, "Clear must commit an authoritative state even before first login.");
        Require(File.Exists(Path.Combine(directory.Path, "session.bin")) && store.Load().Status == SessionStoreLoadStatus.Cleared,
            "Completed clear reverted to absence.");
        Require(store.Save(Credentials(), missing.Version!, SessionStoreSaveMode.NewLogin).Status == SessionStoreWriteStatus.Conflict,
            "The old missing revision survived a completed clear.");
        Require(store.Clear(clear.Version!).Version == clear.Version, "Repeated clear should preserve the existing authoritative tombstone.");
        return Task.CompletedTask;
    }
    private static Task StaleClear()
    {
        using var directory = TempDir.Create(); var store = Store(directory.Path);
        Require(Create(store).Succeeded, "Initial save failed."); var old = store.Load();
        var replacement = Create(Store(directory.Path), "Replacement");
        Require(replacement.Succeeded && replacement.LoginId != old.LoginId, "A new login reused its predecessor's identity.");
        Require(store.Clear(old.Version!).Status == SessionStoreWriteStatus.Conflict, "A stale clear erased its replacement.");
        Require(store.Load().Version == replacement.Version && store.Load().Session?.DisplayName == "Replacement", "Replacement changed.");
        return Task.CompletedTask;
    }
    private static async Task LoginContinuity()
    {
        using var directory = TempDir.Create(); var store = Store(directory.Path);
        var first = Create(store); var captured = store.Load();
        var rotated = store.Save(captured.Session! with { RefreshToken = "synthetic-rotated" }, captured.Version!, SessionStoreSaveMode.ContinueLogin);
        Require(rotated.Succeeded && rotated.Version != first.Version && rotated.LoginId == first.LoginId, "Rotation lost the durable login or reused its revision.");
        var restarted = new AccountSessionCoordinator(Auth(), Store(directory.Path));
        Require((await restarted.HydrateFromStoreAsync()).Success && restarted.DurableLoginId == first.LoginId,
            "Verified process restart changed the durable login.");
        Require((await restarted.ApplyAuthAsync(Token(Credentials()))).Success && restarted.DurableLoginId != first.LoginId,
            "An explicit new login inherited the previous login identity.");
        var current = store.Load();
        Require(store.Save(Credentials(subject: "foreign"), current.Version!, SessionStoreSaveMode.ContinueLogin).Status == SessionStoreWriteStatus.SubjectMismatch,
            "Continuation admitted a different account.");
    }
    private static async Task LegacyMigration()
    {
        using var directory = TempDir.Create(); var store = Store(directory.Path); var value = Credentials();
        byte[] legacy = Protector().Protect(JsonSerializer.SerializeToUtf8Bytes(value));
        string path = Path.Combine(directory.Path, "session.bin"); File.WriteAllBytes(path, legacy);
        Require(store.Load() is { Succeeded: true, LoginId: null }, "Schema-one credentials became a durable grant on read.");
        var auth = Auth(); auth.GetUserResult = AuthClientResult<AuthUser>.Failed(AuthFailureKind.Network, "offline");
        var offline = new AccountSessionCoordinator(auth, store);
        Require(!(await offline.HydrateFromStoreAsync()).Success && offline.ReadAudioAuthorization() is null && File.ReadAllBytes(path).SequenceEqual(legacy),
            "Offline legacy startup created authority or rewrote the old credentials.");
        auth.GetUserResult = AuthClientResult<AuthUser>.Success(User());
        var verified = new AccountSessionCoordinator(auth, store);
        Require((await verified.HydrateFromStoreAsync()).Success, "Verified legacy migration failed.");
        var migrated = Store(directory.Path).Load();
        Require(migrated.LoginId is { } login && login != Guid.Empty && migrated.Session?.RefreshToken == value.RefreshToken,
            "Migration lost the credential or did not bind a durable login.");
    }
    private static async Task BadRecords()
    {
        foreach (string raw in new[] { "{bad-json", "{\"schemaVersion\":99}", "{\"schemaVersion\":\"2\"}",
            "{\"schemaVersion\":2,\"revision\":\"00000000-0000-0000-0000-000000000001\",\"state\":\"active\"}",
            "{\"schemaVersion\":2,\"schemaVersion\":1}" })
        {
            using var directory = TempDir.Create(); string path = Path.Combine(directory.Path, "session.bin");
            byte[] bytes = Protector().Protect(System.Text.Encoding.UTF8.GetBytes(raw)); File.WriteAllBytes(path, bytes);
            var store = Store(directory.Path); var load = store.Load();
            Require(!load.Succeeded && !load.IsQuietSignedOut && load.Version is not null, "Invalid state became absence or lost its captured identity.");
            var auth = Auth(); var coordinator = new AccountSessionCoordinator(auth, store);
            Require(!(await coordinator.HydrateFromStoreAsync()).Success && auth.GetUserCalls == 0 && File.ReadAllBytes(path).SequenceEqual(bytes),
                "Startup deleted invalid/newer state or authenticated through it.");
            Require(store.Save(Credentials(), load.Version!, SessionStoreSaveMode.NewLogin).Status == SessionStoreWriteStatus.InvalidRecord,
                "A new save silently replaced an invalid record.");
            Require(store.Clear(load.Version!).Succeeded && store.Load().Status == SessionStoreLoadStatus.Cleared,
                "An explicit clear of the exact invalid record failed.");
        }
    }
    private static Task Capacity()
    {
        using var directory = TempDir.Create(); var path = Path.Combine(directory.Path, "session.bin");
        using (var file = File.Create(path)) file.SetLength(1_048_577);
        var store = Store(directory.Path); var load = store.Load();
        Require(load.Status == SessionStoreLoadStatus.InvalidSession && load.Version is null, "Oversized state was read as a valid or missing record.");
        Require(store.Save(Credentials(), SessionStoreVersion.Missing, SessionStoreSaveMode.NewLogin).Status == SessionStoreWriteStatus.InvalidRecord,
            "Oversized state was replaced under an invented missing revision.");
        Require(new FileInfo(path).Length == 1_048_577, "Rejected oversized input changed.");
        return Task.CompletedTask;
    }
    private static Task FailedClear()
    {
        using var directory = TempDir.Create(); var store = Store(directory.Path); Require(Create(store).Succeeded, "Initial save failed.");
        var old = store.Load(); var bytes = File.ReadAllBytes(Path.Combine(directory.Path, "session.bin"));
        var failing = new SessionStore(directory.Path, Protector(), new ThrowingSessionFileCommitter());
        Require(failing.Clear(old.Version!).Status == SessionStoreWriteStatus.IoFailure, "Failed tombstone commit claimed logout success.");
        Require(File.ReadAllBytes(Path.Combine(directory.Path, "session.bin")).SequenceEqual(bytes), "Failed clear lost the prior record.");
        Require(!Directory.EnumerateFiles(directory.Path, ".session.bin.*.tmp").Any(), "Failed clear left a temporary credential record.");
        return Task.CompletedTask;
    }
    private static async Task PendingSignIn()
    {
        using var directory = TempDir.Create(); var store = Store(directory.Path); var auth = Auth();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        auth.GetUserHandler = async (_, _) => { entered.SetResult(); await release.Task.WaitAsync(Limit); return AuthClientResult<AuthUser>.Success(User()); };
        var coordinator = new AccountSessionCoordinator(auth, store); var pending = coordinator.ApplyAuthAsync(Token(Credentials()));
        await entered.Task.WaitAsync(Limit);
        var other = Store(directory.Path); var cleared = other.Clear(other.Load().Version!); release.SetResult();
        var result = await pending.WaitAsync(Limit);
        Require(cleared.Succeeded && !result.Success && result.ErrorCode == nameof(SessionStoreWriteStatus.Conflict) && !coordinator.IsSignedIn,
            "The delayed sign-in overtook completed logout.");
        Require(other.Load().Version == cleared.Version && auth.SignOutCalls == 0 && coordinator.ReadAudioAuthorization() is null,
            "Conflict cleanup changed a different owner or published audio authority.");
    }
    private static Task AmbiguousCommit(bool clear)
    {
        using var directory = TempDir.Create(); var store = Store(directory.Path); Require(Create(store).Succeeded, "Initial save failed.");
        var before = store.Load(); var failing = new SessionStore(directory.Path, Protector(), new FailAfterCommit());
        var result = clear ? failing.Clear(before.Version!) : failing.Save(Credentials("Committed"), before.Version!, SessionStoreSaveMode.NewLogin);
        Require(result.Status == SessionStoreWriteStatus.IoFailure && result.Failure?.Operation == "ReplaceRecord",
            "Ambiguous completion was reported as confirmed success or lost its failing boundary.");
        var after = Store(directory.Path).Load();
        Require(after.Version != before.Version && (clear ? after.Status == SessionStoreLoadStatus.Cleared : after.Succeeded),
            "The failure was incorrectly treated as proof that no commit occurred.");
        var stale = clear ? store.Save(before.Session!, before.Version!, SessionStoreSaveMode.ContinueLogin) : store.Clear(before.Version!);
        Require(stale.Status == SessionStoreWriteStatus.Conflict && store.Load().Version == after.Version,
            "An old owner overwrote the committed state after ambiguous completion.");
        return Task.CompletedTask;
    }
    private sealed class FailAfterCommit : ISessionFileCommitter
    {
        public void Commit(string temporaryPath, string destinationPath)
        {
            AtomicSessionFileCommitter.Instance.Commit(temporaryPath, destinationPath);
            throw new IOException("Synthetic failure after the real record replacement.");
        }
    }
    private static async Task PendingHydration()
    {
        using var directory = TempDir.Create(); var store = Store(directory.Path); Require(Create(store).Succeeded, "Initial save failed.");
        var auth = Auth(); var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        auth.GetUserHandler = async (_, _) => { entered.SetResult(); await release.Task.WaitAsync(Limit); return AuthClientResult<AuthUser>.Success(User()); };
        var coordinator = new AccountSessionCoordinator(auth, store); var pending = coordinator.HydrateFromStoreAsync();
        await entered.Task.WaitAsync(Limit); var replacement = Create(Store(directory.Path), "Replacement"); release.SetResult();
        var result = await pending.WaitAsync(Limit);
        Require(replacement.Succeeded && !result.Success && !coordinator.IsSignedIn && store.Load().Version == replacement.Version && auth.SignOutCalls == 0,
            "Delayed hydration changed/revoked the replacement or published its own stale account.");
    }
    private static async Task CoordinatorLogout()
    {
        using var directory = TempDir.Create(); var store = Store(directory.Path); var auth = Auth();
        var old = new AccountSessionCoordinator(auth, store); Require((await old.ApplyAuthAsync(Token(Credentials()))).Success, "Initial login failed.");
        var epoch = old.RequireAudioAuthorization(); var replacement = Create(Store(directory.Path), "New login");
        Require(replacement.Succeeded, "Replacement save failed.");
        var result = await old.SignOutAsync();
        Require(!result.Success && result.ErrorCode == nameof(SessionStoreWriteStatus.Conflict) && !old.IsSignedIn && !epoch.IsCurrent,
            "Stale sign-out retained its local authority or claimed it cleared the newer account.");
        Require(auth.SignOutCalls == 0 && store.Load().Version == replacement.Version, "Stale sign-out affected the new owner.");
    }
    private static async Task ReadFailureKeepsOwnership()
    {
        using var directory = TempDir.Create(); var store = Store(directory.Path); var wrapper = new FailingRead(store); var auth = Auth();
        var old = new AccountSessionCoordinator(auth, wrapper);
        Require((await old.ApplyAuthAsync(Token(Credentials(minutes: 4)))).Success, "Initial login failed.");
        wrapper.Fail = true;
        try
        {
            await old.GetDeviceAuthenticationAsync(default);
            throw new InvalidOperationException("A storage read failure was reported as successful account authentication.");
        }
        catch (AccountDeviceAuthenticationException error)
        { Require(error.Kind == AccountSessionFailureKind.SessionPersistenceFailed, "A read failure was misclassified as an account replacement."); }
        wrapper.Fail = false;
        var replacement = Create(Store(directory.Path), "New owner"); Require(replacement.Succeeded, "Replacement login failed.");
        var result = await old.SignOutAsync();
        Require(!result.Success && result.ErrorCode == nameof(SessionStoreWriteStatus.Conflict) && store.Load().Version == replacement.Version,
            "Read failure discarded the old owner revision and allowed it to clear a replacement login.");
    }
    private sealed class FailingRead(ISessionStore inner) : ISessionStore
    {
        internal bool Fail;
        public SessionStoreLoadResult Load() => Fail ? SessionStoreLoadResult.IoFailure() : inner.Load();
        public SessionStoreWriteResult Save(PersistedSession value, SessionStoreVersion expected, SessionStoreSaveMode mode) => inner.Save(value, expected, mode);
        public SessionStoreWriteResult Clear(SessionStoreVersion expected) => inner.Clear(expected);
    }

    internal static async Task ChildAsync(string directory, string action)
    {
        var store = Store(directory); var captured = store.Load();
        if (!captured.Succeeded) throw new InvalidDataException("Child did not read its synthetic account.");
        using var lease = action == "lease"
            ? new FileStream(Path.Combine(directory, ".session.lock"), FileMode.Open, FileAccess.ReadWrite, FileShare.None) : null;
        Console.WriteLine("READY"); await Console.Out.FlushAsync();
        if (await Console.In.ReadLineAsync().WaitAsync(Limit) != "commit") throw new InvalidDataException("Missing child release.");
        var result = action switch
        {
            "save" => store.Save(captured.Session! with { DisplayName = "Late child" }, captured.Version!, SessionStoreSaveMode.ContinueLogin),
            "clear" => store.Clear(captured.Version!),
            _ => throw new InvalidDataException("Unexpected child mutation.")
        };
        Console.WriteLine(result.Status);
    }
    private static async Task ProcessStale(string action)
    {
        using var directory = TempDir.Create(); var store = Store(directory.Path); Require(Create(store).Succeeded, "Parent fixture save failed.");
        await using var child = await Child.Start(directory.Path, action);
        var current = store.Load();
        var mutation = action == "save" ? store.Clear(current.Version!) : Create(store, "Parent replacement");
        Require(mutation.Succeeded, "Parent mutation failed.");
        await child.Process.StandardInput.WriteLineAsync("commit"); await child.Process.StandardInput.FlushAsync();
        Require(await child.Process.StandardOutput.ReadLineAsync().WaitAsync(Limit) == nameof(SessionStoreWriteStatus.Conflict),
            "A separate stale process changed a newer account record.");
        await child.Process.WaitForExitAsync().WaitAsync(Limit);
        ProcessTerminationBarrier.Require(child.Process, Limit);
        Require(child.Process.ExitCode == 0 && store.Load().Version == mutation.Version, "Separate process failed or changed the current record.");
        Console.WriteLine($"SESSION_PROCESS parent={Environment.ProcessId} child={child.Process.Id} action={action} protection={(OperatingSystem.IsWindows() ? "CurrentUser-DPAPI" : "host-fixture-only")}");
    }
    private static async Task ProcessLease()
    {
        using var directory = TempDir.Create(); var store = Store(directory.Path); Require(Create(store).Succeeded, "Parent fixture save failed.");
        var old = store.Load(); await using var child = await Child.Start(directory.Path, "lease");
        var blockedRead = store.Load();
        var blockedWrite = store.Save(old.Session!, old.Version!, SessionStoreSaveMode.ContinueLogin);
        Require(blockedRead.Status == SessionStoreLoadStatus.IoFailure && blockedRead.Failure?.Operation == "AcquireLease" &&
            blockedWrite.Status == SessionStoreWriteStatus.IoFailure && blockedWrite.Failure?.Operation == "AcquireLease",
            "A competing process read or mutated through an occupied lease.");
        child.Process.Kill(entireProcessTree: true); await child.Process.WaitForExitAsync().WaitAsync(Limit);
        ProcessTerminationBarrier.Require(child.Process, Limit);
        var resumed = store.Save(old.Session!, old.Version!, SessionStoreSaveMode.ContinueLogin);
        Console.WriteLine("SESSION_LEASE_CHECK " + JsonSerializer.Serialize(new
        {
            parent = Environment.ProcessId, child = child.Process.Id, childExit = child.Process.ExitCode,
            terminationBoundary = "signaled-process-handle",
            blockedRead = blockedRead.Failure, blockedWrite = blockedWrite.Failure,
            status = resumed.Status.ToString(), failure = resumed.Failure, cleanupFailure = resumed.CleanupFailure
        }));
        if (!resumed.Succeeded)
        {
            // Diagnostic readback/probe only: no retry of the failed commit, no lock-file deletion.
            var readback = store.Load(); SessionStoreFailure? probeFailure = null;
            try { using var probe = new FileStream(Path.Combine(directory.Path, ".session.lock"), FileMode.Open, FileAccess.ReadWrite, FileShare.None); }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            { probeFailure = SessionStoreFailure.From("ProbeLeaseAfterFailedCommit", error); }
            Console.WriteLine("SESSION_LEASE_READBACK " + JsonSerializer.Serialize(new
            { status = readback.Status.ToString(), sameRevision = readback.Version == old.Version, readbackFailure = readback.Failure, probeFailure }));
        }
        Require(resumed.Succeeded, $"Account write after lease-holder termination failed: {resumed.Status}; {resumed.Failure}; cleanup={resumed.CleanupFailure}.");
        Require(File.Exists(Path.Combine(directory.Path, ".session.lock")), "Reacquisition deleted the shared lease inode.");
    }
    private sealed class Child(Process process) : IAsyncDisposable
    {
        internal Process Process { get; } = process;
        private readonly Task<string> _error = process.StandardError.ReadToEndAsync();
        internal static async Task<Child> Start(string directory, string action)
        {
            var executable = Environment.ProcessPath ?? throw new InvalidOperationException("Missing process path.");
            var info = new ProcessStartInfo(executable)
            { UseShellExecute = false, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
            if (Path.GetFileNameWithoutExtension(executable).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
                info.ArgumentList.Add(Assembly.GetExecutingAssembly().Location);
            foreach (var arg in new[] { "--session-state-child", directory, action }) info.ArgumentList.Add(arg);
            var child = new Child(Process.Start(info) ?? throw new InvalidOperationException("Child process did not start."));
            try
            {
                if (await child.Process.StandardOutput.ReadLineAsync().WaitAsync(Limit) != "READY")
                    throw new InvalidOperationException("Child did not establish its captured state: " + await child._error.WaitAsync(Limit));
                return child;
            }
            catch { await child.DisposeAsync(); throw; }
        }
        public async ValueTask DisposeAsync()
        {
            try
            {
                if (!Process.HasExited) Process.Kill(entireProcessTree: true);
                await Process.WaitForExitAsync().WaitAsync(Limit);
                ProcessTerminationBarrier.Require(Process, Limit);
                var error = await _error.WaitAsync(Limit);
                if (error.Length != 0) Console.WriteLine("SESSION_PROCESS_DIAGNOSTIC " + error);
            }
            finally { Process.Dispose(); }
        }
    }
}
