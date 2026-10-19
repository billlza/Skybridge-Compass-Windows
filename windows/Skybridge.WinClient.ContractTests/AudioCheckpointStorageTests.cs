using System.Diagnostics;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Security.Cryptography;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.Audio;
using static AudioAccountMembershipTests;

internal static class AudioCheckpointStorageTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("audio checkpoint storage retains credentials login and original authority across rotation", RoundTrip),
        ("audio checkpoint storage stale callbacks cannot revive logout or replace a new login", StaleOwner),
        ("audio checkpoint storage advances the canonical revision and excludes competing writers", Revision),
        ("audio checkpoint storage rejects malformed oversized and ambiguous payloads", InvalidPayload),
        ("audio checkpoint storage migrates schema two and rejects audio in older or cleared records", Migration),
        ("audio checkpoint storage commit failures retain their exact before or after state", CommitFailure),
        ("audio checkpoint storage restores original evidence after its writer process exits", SeparateWriter)
    ];
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(20);
    private static ISessionProtector Protector() => OperatingSystem.IsWindows() ? new DpapiSessionProtector() : new PlainSessionProtector();
    private static SessionStore Store(string path) => new(path, Protector());
    private static SessionStoreWriteResult Write(SessionStore store, JsonElement state, SessionStoreLoadResult captured) =>
        ((ISessionAudioStateStore)store).WriteAudioState(state, captured.Version ?? throw new Exception("Missing version."),
            captured.LoginId ?? throw new Exception("Missing login."));
    private static PersistedSession Credentials(Fixture f) => new() { SchemaVersion = 1, Authority = f.Auth.Authority,
        Subject = f.Auth.Subject, AccessToken = f.Auth.AccessToken, RefreshToken = "synthetic-refresh",
        IssuedAtUnix = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), DisplayName = "Checkpoint fixture" };
    private static void Seed(SessionStore store, Fixture f)
    { Require(store.Save(Credentials(f), SessionStoreVersion.Missing, SessionStoreSaveMode.NewLogin).Succeeded, "Fixture seed failed."); }
    private static IAudioLogonContinuity Continuity() => OperatingSystem.IsWindows()
        ? WindowsAudioLogonContinuity.Instance : new AudioMembershipCheckpointTests.Continuity();
    private static async Task<AudioMembershipCheckpoint> Checkpoint(Fixture f, Guid login)
    {
        if (OperatingSystem.IsWindows()) f.Clock.Now = AudioAuthorizationTime.ReadWindows();
        var evidence = AudioAccountMembershipEvidence.Create(await f.Observe(), Local(f.Binding), Peer(f.Binding));
        return AudioMembershipCheckpoint.Capture(login, evidence, f.Clock.Read, Continuity());
    }
    private static AudioMembershipCheckpoint Payload(SessionStoreLoadResult read) =>
        read.AudioState?.Deserialize<AudioMembershipCheckpoint>() ?? throw new Exception("Stored checkpoint is absent.");
    private static AudioAccountMembershipEvidence Restore(Fixture f, SessionStoreLoadResult read)
    {
        var checkpoint = Payload(read);
        return checkpoint.Restore(read.LoginId ?? throw new Exception("Missing durable owner."), AudioAccountScope.From(f.Auth),
            Local(f.Binding), Peer(f.Binding), OperatingSystem.IsWindows() ? AudioAuthorizationTime.ReadWindows : f.Clock.Read, Continuity());
    }
    private static async Task RoundTrip()
    {
        using var dir = TempDir.Create(); using var f = new Fixture(); var store = Store(dir.Path); Seed(store, f);
        var original = store.Load(); var checkpoint = await Checkpoint(f, original.LoginId!.Value);
        Require(Write(store, JsonSerializer.SerializeToElement(checkpoint), original).Succeeded, "Checkpoint write failed.");
        var read = store.Load();
        Require(read.Session == original.Session && read.LoginId == original.LoginId && read.Version != original.Version,
            "Audio state changed credentials/login or failed to advance the revision.");
        Require(store.Save(read.Session! with { DisplayName = "Rotated profile" }, read.Version!, SessionStoreSaveMode.ContinueLogin).Succeeded,
            "Account continuation failed.");
        var after = store.Load(); var evidence = Restore(f, after);
        Require(after.AudioState?.GetRawText() == read.AudioState?.GetRawText() && after.LoginId == original.LoginId &&
            evidence.Id == checkpoint.EvidenceId && evidence.Issued == checkpoint.Issued && evidence.Expires == checkpoint.Expires,
            "Credential persistence discarded or renewed audio authority.");
    }
    private static async Task StaleOwner()
    {
        foreach (bool relogin in new[] { false, true })
        {
            using var dir = TempDir.Create(); using var f = new Fixture(); var store = Store(dir.Path); Seed(store, f);
            var captured = store.Load(); var payload = JsonSerializer.SerializeToElement(await Checkpoint(f, captured.LoginId!.Value));
            Require(Write(store, payload, captured).Succeeded, "Initial checkpoint write failed."); captured = store.Load();
            var replacement = relogin ? store.Save(Credentials(f), captured.Version!, SessionStoreSaveMode.NewLogin) : store.Clear(captured.Version!);
            Require(replacement.Succeeded, "Account transition failed.");
            Require(Write(store, payload, captured).Status == SessionStoreWriteStatus.Conflict, "Stale audio callback overwrote the account transition.");
            if (relogin)
                Require(((ISessionAudioStateStore)store).WriteAudioState(payload, replacement.Version!, captured.LoginId!.Value).Status == SessionStoreWriteStatus.Conflict,
                    "A current revision allowed an old login to write.");
            var current = store.Load(); Require(current.Version == replacement.Version && current.AudioState is null,
                "Logout/relogin retained prior audio state or was changed by the stale callback.");
        }
    }
    private static Task Revision()
    {
        using var dir = TempDir.Create(); using var f = new Fixture(); var store = Store(dir.Path); Seed(store, f);
        var before = store.Load(); var first = Write(store, JsonSerializer.SerializeToElement(new { operation = "one" }), before);
        Require(first.Succeeded, "First audio mutation failed.");
        Require(Write(store, JsonSerializer.SerializeToElement(new { operation = "two" }), before).Status == SessionStoreWriteStatus.Conflict,
            "A competing audio writer replaced a newer mutation.");
        Require(store.Clear(before.Version!).Status == SessionStoreWriteStatus.Conflict && store.Load().Version == first.Version,
            "A stale account writer bypassed an audio mutation.");
        return Task.CompletedTask;
    }
    private static Task InvalidPayload()
    {
        using var dir = TempDir.Create(); using var f = new Fixture(); var store = Store(dir.Path); Seed(store, f);
        var before = store.Load();
        using var duplicate = JsonDocument.Parse("{\"state\":1,\"state\":2}");
        using var nestedDuplicate = JsonDocument.Parse("{\"checkpoint\":{\"version\":1,\"version\":2}}");
        foreach (var value in new[] { default(JsonElement), JsonSerializer.SerializeToElement(new[] { 1 }),
            JsonSerializer.SerializeToElement<string?>(null), duplicate.RootElement, nestedDuplicate.RootElement })
            Require(Write(store, value, before).Status == SessionStoreWriteStatus.InvalidRecord, "Invalid audio payload was committed.");
        Require(Write(store, JsonSerializer.SerializeToElement(new { value = new string('x', 1_048_577) }), before).Status == SessionStoreWriteStatus.InvalidSession,
            "Oversized account state was committed.");
        Require(store.Load().Version == before.Version, "Rejected payload changed the protected record.");
        return Task.CompletedTask;
    }
    private sealed class FaultCommitter(bool after) : ISessionFileCommitter
    {
        public void Commit(string temporaryPath, string destinationPath)
        {
            if (after) AtomicSessionFileCommitter.Instance.Commit(temporaryPath, destinationPath);
            throw new IOException("Synthetic checkpoint commit failure.");
        }
    }
    private static Task Migration()
    {
        using var dir = TempDir.Create(); using var f = new Fixture(); var store = Store(dir.Path); Seed(store, f);
        string file = Path.Combine(dir.Path, "session.bin");
        var protector = Protector(); byte[] original = protector.Unprotect(File.ReadAllBytes(file));
        JsonObject document;
        try { document = JsonNode.Parse(original) as JsonObject ?? throw new Exception("Missing account object."); }
        finally { CryptographicOperations.ZeroMemory(original); }
        document["schemaVersion"] = 2; Rewrite();
        var legacy = store.Load(); Require(legacy.Succeeded && legacy.AudioState is null, "Schema-two account could not be read.");
        Require(Write(store, JsonSerializer.SerializeToElement(new { checkpoint = "migration fixture" }), legacy).Succeeded,
            "Schema-two audio update failed.");
        var current = store.Load();
        Require(current.Succeeded && current.LoginId == legacy.LoginId && current.Session == legacy.Session && current.AudioState is not null,
            "Migration changed credentials or lost the audio update.");
        Require(Write(store, JsonSerializer.SerializeToElement(new { late = true }), legacy).Status == SessionStoreWriteStatus.Conflict,
            "A pre-migration callback replaced the migrated record.");
        document["audioState"] = new JsonObject { ["checkpoint"] = "invalid schema-two payload" }; Rewrite();
        Require(store.Load().Status == SessionStoreLoadStatus.InvalidSession, "Schema two admitted undeclared audio state.");
        document["schemaVersion"] = 3; document["state"] = "cleared"; document["session"] = null; document["loginId"] = null; Rewrite();
        Require(store.Load().Status == SessionStoreLoadStatus.InvalidSession, "A cleared record carried audio authority.");
        document["schemaVersion"] = 99; Rewrite(); var unknown = File.ReadAllBytes(file);
        Require(store.Load().Status == SessionStoreLoadStatus.SchemaMismatch && File.ReadAllBytes(file).SequenceEqual(unknown),
            "Unknown schema was silently migrated or deleted.");
        return Task.CompletedTask;

        void Rewrite()
        {
            byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(document);
            try { File.WriteAllBytes(file, protector.Protect(bytes)); }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
    }
    private static Task CommitFailure()
    {
        foreach (bool after in new[] { false, true })
        {
            using var dir = TempDir.Create(); using var f = new Fixture(); var store = Store(dir.Path); Seed(store, f);
            var before = store.Load(); var faulty = new SessionStore(dir.Path, Protector(), new FaultCommitter(after));
            var result = Write(faulty, JsonSerializer.SerializeToElement(new { checkpoint = "fixture" }), before);
            Require(result.Status == SessionStoreWriteStatus.IoFailure && result.Failure?.Operation == "ReplaceRecord", "Commit failure lost its phase.");
            var read = store.Load();
            Require(read.Succeeded && read.LoginId == before.LoginId && read.Session == before.Session &&
                (after ? read.AudioState is not null && read.Version != before.Version : read.AudioState is null && read.Version == before.Version),
                "Commit failure was mistaken for a rollback or corrupted the account.");
            if (after) Require(store.Clear(before.Version!).Status == SessionStoreWriteStatus.Conflict, "An old owner erased the uncertain committed result.");
        }
        return Task.CompletedTask;
    }
    internal static async Task WriteChild(string directory)
    {
        using var f = new Fixture(); var store = Store(directory); var captured = store.Load();
        var checkpoint = await Checkpoint(f, captured.LoginId ?? throw new Exception("Missing child owner."));
        Require(Write(store, JsonSerializer.SerializeToElement(checkpoint), captured).Succeeded, "Child checkpoint commit failed.");
        Console.WriteLine(JsonSerializer.Serialize(new { checkpoint.EvidenceId, checkpoint.Issued, checkpoint.Expires }));
    }
    private static async Task SeparateWriter()
    {
        using var dir = TempDir.Create(); using var f = new Fixture(); var store = Store(dir.Path); Seed(store, f);
        string executable = Environment.ProcessPath ?? throw new Exception("Missing process executable.");
        var start = new ProcessStartInfo(executable) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
        if (Path.GetFileNameWithoutExtension(executable).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            start.ArgumentList.Add(Assembly.GetExecutingAssembly().Location);
        start.ArgumentList.Add("--audio-checkpoint-child"); start.ArgumentList.Add(dir.Path);
        using var child = Process.Start(start) ?? throw new Exception("Checkpoint child did not start.");
        var stdout = child.StandardOutput.ReadToEndAsync(); var stderr = child.StandardError.ReadToEndAsync();
        try
        {
            await child.WaitForExitAsync().WaitAsync(Limit); ProcessTerminationBarrier.Require(child, Limit);
            Require(child.ExitCode == 0 && string.IsNullOrEmpty(await stderr.WaitAsync(Limit)), "Checkpoint child failed.");
            using var original = JsonDocument.Parse(await stdout.WaitAsync(Limit));
            var restored = Restore(f, store.Load());
            Require(restored.Id == original.RootElement.GetProperty("EvidenceId").GetGuid() &&
                restored.Issued == original.RootElement.GetProperty("Issued").Deserialize<AudioAuthorizationTime>() &&
                restored.Expires == original.RootElement.GetProperty("Expires").Deserialize<AudioAuthorizationTime>(),
                "Restart changed original authority.");
            Console.WriteLine($"AUDIO_CHECKPOINT_PROCESS parent={Environment.ProcessId} writer={child.Id} protection={(OperatingSystem.IsWindows() ? "CurrentUser-DPAPI+same-logon" : "host-fixtures-only")}");
        }
        finally
        {
            if (!child.HasExited) child.Kill(entireProcessTree: true);
            ProcessTerminationBarrier.Require(child, Limit);
        }
    }
    private static void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
}
