using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.Audio;
using Skybridge.WinClient.ViewModels;
using static AudioAccountMembershipTests;

internal static partial class AudioObservationJournalTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("audio journal prepares canonical ownership before actual registry HTTP and settles exact requests", ProductRoundTrip),
        ("audio journal negative observations retire only matching checkpoints before restart readback", NegativeObservation),
        ("audio journal preserves finite grants on temporary reads and retires an uncertain removal target", TemporaryAndUncertain),
        ("audio journal failed preparation sends no HTTP and preserves committed uncertainty", PreparationFaults),
        ("audio journal cancellation during prepared replacement retains its completion owner", PreparedCancellation),
        ("audio journal failed negative commits preserve pending denial or the committed negative", CompletionFaults),
        ("audio journal independent requests cannot clear one another across token rotation", ConcurrentAndRotation),
        ("audio journal late completion cannot write after signout or same-account relogin", RetiredOwner),
        ("audio journal verified tenant rotation retires prior scope without transferring checkpoints", ScopeRotation),
        ("audio journal rejects external account mutations without adopting their ownership", ExternalWriter),
        ("audio journal rejects corrupt unknown and excessive state without replacing it", InvalidState),
        ("audio journal a positive registry list never issues or revives a checkpoint", NoIssuance),
        ("audio journal bounds pending requests and refuses recovery until every owner settles", PendingCapacity),
        ("audio journal protected file commits leave the caller UI context", OffUiCommit),
        ("audio membership journal commits fresh evidence before publishing its playback lease", FreshMembership),
        ("audio membership journal persists only fresh explicit continuation", ContinuedMembership),
        ("audio membership journal applies parsed negatives even after requester cancellation", CanceledNegativeMembership),
        ("audio membership journal durable contradictions stop late grants across provider instances", CrossProviderContradiction),
        ("audio membership journal superseded queries retain unrelated finite evidence", SupersededMembership),
        ("audio membership journal preparation failures send no network request", MembershipPreparationFaults),
        ("audio membership journal commit failures never publish a playback lease", MembershipCompletionFaults),
        ("audio membership journal classifies unavailable and terminal query outcomes without renewal", MembershipQueryFailures),
        ("audio membership journal cancellation during preparation and capture retains exact settlement", MembershipCancellation),
        ("audio membership journal sealing failure remains observable and issues no checkpoint", MembershipSealFailure),
        ("audio membership journal late results cannot write after account replacement", MembershipReplacement),
        ("audio membership journal migrates registry-only records without creating grant owners", LegacyJournal),
        ("audio membership journal rejects checkpoint binding and observation substitution", MembershipBinding),
        ("audio membership journal reclaims expired capacity but never evicts a valid grant to admit another", MembershipCapacity),
        ("audio credential journal covers refresh rotated-token writes and live-user verification", CredentialRefresh),
        ("audio credential journal prepares before startup identity verification without refreshing", CredentialHydration),
        ("audio credential journal preparation failure sends no authentication request", CredentialPreparationFailure),
        ("audio credential journal hard rejection survives failed clear and failed settlement", CredentialNegativeFailure),
        ("audio credential journal preserves only allowlisted temporary failures without renewal", CredentialTemporaryFailure),
        ("audio credential journal changed tenant retires old grants after a temporary user-check failure", CredentialScopeChange),
        ("audio credential journal preserves primary and completion exceptions", CredentialExceptions),
        ("audio credential journal failed final settlement never publishes new audio authority", CredentialCompletionFailure),
        ("audio credential journal stale verification cannot erase a replacement account", CredentialStaleOwner),
        ("audio credential journal a new live check retires uncertain prior audio without resetting login", CredentialInterrupted),
        ("audio credential journal storage binds exact operation and preserves it across audio mutations", CredentialStorageOwnership),
        ("audio credential journal schema migration and malformed markers stay explicit", CredentialStorageSchema)
    ];

    private sealed class PlainProtector : ISessionProtector
    {
        public byte[] Protect(byte[] bytes) => bytes.ToArray();
        public byte[] Unprotect(byte[] bytes) => bytes.ToArray();
    }
    private sealed class Committer : ISessionFileCommitter
    {
        internal int NextFault; // 1 = before replacement, 2 = after replacement
        internal Action? BeforeCommit;
        public void Commit(string temporaryPath, string destinationPath)
        {
            BeforeCommit?.Invoke();
            int fault = Interlocked.Exchange(ref NextFault, 0);
            if (fault == 1) throw new IOException("Synthetic journal failure before replacement.");
            AtomicSessionFileCommitter.Instance.Commit(temporaryPath, destinationPath);
            if (fault == 2) throw new IOException("Synthetic journal failure after replacement.");
        }
    }
    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    { protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) => send(request, token); }

    private sealed class Continuity : IAudioLogonContinuity
    {
        private readonly IAudioLogonContinuity _inner = OperatingSystem.IsWindows()
            ? WindowsAudioLogonContinuity.Instance : new AudioMembershipCheckpointTests.Continuity();
        internal Action? BeforeCreate;
        public AudioLogonSeal Create() { BeforeCreate?.Invoke(); return _inner.Create(); }
        public void RequireCurrent(AudioLogonSeal seal) => _inner.RequireCurrent(seal);
    }

    private sealed class Fixture : IAsyncDisposable
    {
        internal readonly string DirectoryPath = Path.Combine(Path.GetTempPath(), "skybridge-audio-journal-" + Guid.NewGuid().ToString("N"));
        internal readonly Committer Committer = new();
        internal readonly AccountAudioAuthorizationTests.Client Client = new();
        internal readonly Clock Clock = new();
        internal readonly Continuity Continuity = new();
        internal readonly AudioSessionIdentityBinding Binding = AudioAccountMembershipTests.Binding();
        internal readonly AudioDeviceIdentity Other = Peer(AudioAccountMembershipTests.Binding(peer: 1));
        internal readonly SessionStore Storage;
        internal AccountSessionCoordinator Owner;
        internal readonly AuthToken Token;
        internal readonly HttpClient Http;
        internal readonly AudioAccountMembershipProvider Provider;
        internal readonly AudioAccountRegistryObserver Observer;
        internal readonly AccountDeviceRosterClient Roster;
        internal readonly CurrentPathProtocolIdentityBinding Query;
        internal readonly List<JsonObject> Rows;
        internal Func<string, CancellationToken, Task<HttpResponseMessage>>? OnSend;
        internal int HttpCalls;
        internal AccountAudioAuthorization Epoch => Owner.RequireAudioAuthorization();
        internal AccountDeviceAuthentication Authentication => AccountDeviceAuthentication.FromVerifiedSession(
            Token.AccessToken!, Client.SessionAuthority, "audio-user").WithAudioAuthorization(Epoch);
        internal IAudioAccountObservationStore Journal => Epoch.Observations ?? throw new Exception("Missing product journal binding.");
        internal AudioCheckpointIdentity Target => AudioCheckpointIdentity.From(Peer(Binding));
        private static ISessionProtector Protector() => OperatingSystem.IsWindows() ? new DpapiSessionProtector() : new PlainProtector();
        private Fixture(int minutes, TimeSpan? queryTimeout)
        {
            Storage = new(DirectoryPath, Protector(), Committer); Owner = new(Client, Storage);
            Token = AccountAudioAuthorizationTests.Token(minutes: minutes);
            Query = AudioDeviceIdentity.QueryBinding(Binding.LocalDeviceId, Binding.LocalProtocolIdentity);
            Rows = [Row(Local(Binding), true), Row(Peer(Binding)), Row(Other)];
            Http = new(new Handler((request, token) => {
                HttpCalls++;
                string path = request.RequestUri?.AbsolutePath ?? throw new Exception("Missing registry path.");
                return OnSend?.Invoke(path, token) ?? Task.FromResult(Response(path));
            }));
            Provider = new(Http, () => Owner.ReadAudioAuthorization(), (epoch, token) => Owner.GetAudioAuthenticationAsync(epoch, token),
                Clock.Read, queryTimeout, Continuity);
            Observer = new(Provider, Clock.Read); Roster = new(Http, Observer);
        }
        internal static async Task<Fixture> Create(bool checkpoints = true, int minutes = 60, bool keepNearExpiry = false,
            TimeSpan? queryTimeout = null)
        {
            var f = new Fixture(minutes, queryTimeout);
            var login = await f.Owner.ApplyAuthAsync(f.Token);
            if (!login.Success)
            {
                var read = f.Storage.Load();
                throw new Exception($"Synthetic verified login failed: {login.FailureKind}/{login.ErrorCode}; store={read.Status}; operation={read.Failure?.Operation}; hresult={read.Failure?.HResult}.");
            }
            if (checkpoints)
            {
                var head = f.Storage.Load(); var scope = f.Epoch.Scope;
                var values = new[] { Peer(f.Binding), f.Other }.Select(peer => {
                    var observation = AudioRegistryObservation.FromResponse(f.Authentication, Local(f.Binding),
                        new(f.Clock.Now.WallMilliseconds, f.Binding.LocalDeviceId, false,
                            [Entry(Local(f.Binding), true), Entry(peer)]), f.Clock.Now, f.Clock.Now);
                    var evidence = AudioAccountMembershipEvidence.Create(observation, Local(f.Binding), peer);
                    return AudioMembershipCheckpoint.Capture(head.LoginId!.Value, evidence, f.Clock.Read, f.Continuity);
                }).ToArray();
                var state = AudioAccountJournalState.Empty(head.LoginId!.Value, scope) with { Checkpoints = values };
                Require(((ISessionAudioStateStore)f.Storage).WriteAudioState(JsonSerializer.SerializeToElement(state), head.Version!, head.LoginId.Value).Succeeded,
                    "Synthetic finite checkpoints did not persist.");
                if (keepNearExpiry) f.Client.RefreshedToken = f.Token;
                f.Owner = new(f.Client, f.Storage);
                Require((await f.Owner.HydrateFromStoreAsync()).Success, "Synthetic online owner hydration failed.");
            }
            return f;
        }
        internal AudioAccountJournalState Read()
        {
            // Use a distinct reader and the real protected record, not the last
            // in-memory object returned by a mutation.
            var read = new SessionStore(DirectoryPath, Protector()).Load();
            Require(read.Succeeded, "Canonical journal readback failed.");
            return read.AudioState is { } payload ? AudioAccountJournalState.Read(payload)
                : AudioAccountJournalState.Empty(read.LoginId!.Value, Epoch.Scope);
        }
        internal string ListBody() => new JsonObject { ["generatedAt"] = Clock.Now.WallMilliseconds,
            ["callerDeviceId"] = Binding.LocalDeviceId, ["truncated"] = false,
            ["devices"] = new JsonArray(Rows.Select(r => (JsonNode)r.DeepClone()).ToArray()) }.ToJsonString();
        internal HttpResponseMessage Response(string path) => path switch {
            "/api/presence/register" => Reply("{\"online\":true,\"ttlMs\":90000,\"expiresAt\":1800000090000,\"persisted\":true,\"persistReason\":\"written\"}"),
            "/api/devices/list" => Reply(ListBody()),
            "/api/devices/remove" => Reply(JsonSerializer.Serialize(new { removed = true, target = new {
                deviceId = Target.DeviceId, protocolSigningAlgorithm = Target.Algorithm,
                protocolPublicKeyFingerprint = Target.Fingerprint, status = "revoked" } })),
            _ => throw new Exception("Unexpected enrollment in an active registry fixture.")
        };
        internal Task Refresh(CancellationToken token = default) => Roster.RefreshAsync(Authentication, Query, new("Fixture", null, "Windows fixture", []), token);
        internal Task Remove(CancellationToken token = default) => Roster.RemoveAsync(Authentication, Query, Entry(Peer(Binding)), token);
        public async ValueTask DisposeAsync()
        { await Provider.DisposeAsync(); Http.Dispose(); if (Directory.Exists(DirectoryPath)) Directory.Delete(DirectoryPath, true); }
    }

    private static async Task ProductRoundTrip()
    {
        await using var f = await Fixture.Create(); var initial = f.Read(); var before = f.Storage.Load();
        var requests = new List<AccountDeviceRegistryRequest>();
        f.OnSend = (path, _) => {
            var state = f.Read(); var owned = state.Pending.Single(); requests.Add(owned.Kind);
            Require(state.LoginId == initial.LoginId && state.Scope == initial.Scope && state.Checkpoints.SequenceEqual(initial.Checkpoints),
                "Preparation changed finite authority or account ownership.");
            return Task.FromResult(f.Response(path));
        };
        await f.Refresh(); var after = f.Storage.Load(); var settled = f.Read();
        Require(requests.SequenceEqual(new[] { AccountDeviceRegistryRequest.Presence, AccountDeviceRegistryRequest.List }) && settled.Pending.Length == 0,
            "The product did not persist one owner per actual HTTP request.");
        Require(settled.Checkpoints.SequenceEqual(initial.Checkpoints) && after.Session == before.Session && after.LoginId == before.LoginId && after.Version != before.Version,
            "Observation completion renewed a grant or changed credentials.");
    }
    private static async Task NegativeObservation()
    {
        foreach (bool removal in new[] { false, true })
        {
            await using var f = await Fixture.Create(); var before = f.Read();
            if (removal) await f.Remove();
            else { f.Rows[1]["status"] = "frozen"; await f.Refresh(); }
            var after = f.Read();
            Require(after.Pending.Length == 0 && after.Checkpoints.Length == 1 && after.Checkpoints[0] == before.Checkpoints.Single(c => c.Peer.Matches(f.Other)),
                "Negative observation retained its target or changed an unrelated original checkpoint.");
        }
    }
    private static async Task TemporaryAndUncertain()
    {
        foreach (bool removal in new[] { false, true })
        {
            await using var f = await Fixture.Create(); var before = f.Read();
            f.OnSend = (_, _) => throw new HttpRequestException(HttpRequestError.ConnectionError, "synthetic unavailable route");
            await Throws<HttpRequestException>(() => removal ? f.Remove() : f.Refresh());
            var after = f.Read();
            Require(after.Pending.Length == 0 && (removal ? after.Checkpoints.Length == 1 && after.Checkpoints[0].Peer.Matches(f.Other)
                : after.Checkpoints.SequenceEqual(before.Checkpoints)), "Temporary outcome renewed authority or retained an uncertain removal target.");
        }
        foreach (bool tls in new[] { false, true })
        {
            await using var f = await Fixture.Create();
            f.OnSend = (_, _) => tls
                ? throw new HttpRequestException(HttpRequestError.SecureConnectionError, "synthetic TLS failure")
                : Task.FromResult(Reply("{\"error\":\"current_identity_mismatch\"}", HttpStatusCode.ServiceUnavailable));
            if (tls) await Throws<HttpRequestException>(() => f.Refresh());
            else await Throws<CurrentPathSignalServerException>(() => f.Refresh());
            Require(f.Read().Pending.Length == 0 && f.Read().Checkpoints.Length == 0,
                "A security failure or contradictory 503 retained offline authority as temporary unavailability.");
        }
    }
    private static async Task PreparationFaults()
    {
        foreach (int fault in new[] { 1, 2 })
        {
            await using var f = await Fixture.Create(); var original = f.Read(); f.Committer.NextFault = fault;
            var error = await Throws<AccountDeviceRegistryObservationException>(() => f.Refresh());
            var after = f.Read();
            Require(error.Stage == "preparation" && error.InnerException is AudioJournalStorageException && f.HttpCalls == 0 &&
                after.Checkpoints.SequenceEqual(original.Checkpoints) && after.Pending.Length == (fault == 1 ? 0 : 1) && f.Owner.ReadAudioAuthorization() is null,
                "Failed preparation sent HTTP, lost uncertainty or retained runtime authority.");
        }
    }
    private static async Task CompletionFaults()
    {
        foreach (int fault in new[] { 1, 2 })
        {
            await using var f = await Fixture.Create(); using var inbox = new Inbox(f.Binding); var lease = await f.Provider.LeaseAsync(inbox, default);
            var scope = f.Epoch.Scope;
            f.OnSend = (path, _) => { f.Committer.NextFault = fault; return Task.FromResult(f.Response(path)); };
            var error = await Throws<AccountDeviceRegistryObservationException>(() => f.Remove());
            var after = f.Read();
            Require(error.Stage == "completion" && error.InnerException is AudioJournalStorageException && after.Pending.Length == (fault == 1 ? 1 : 0) &&
                after.Checkpoints.Length == (fault == 1 ? 2 : 1), "Negative commit failure erased its pending barrier or misreported the committed state.");
            if (fault == 1) await Throws<AudioJournalPendingObservationException>(() => {
                _ = after.ReadRecoveryCandidates(after.LoginId, scope); return Task.CompletedTask;
            });
            else Require(after.ReadRecoveryCandidates(after.LoginId, scope).All(c => c.Peer != f.Target), "Committed negative allowed target recovery.");
            var revoked = await Throws<AudioMembershipException>(() => {
                lease.Evidence.RequireValid(scope, Local(f.Binding), Peer(f.Binding), f.Clock.Read()); return Task.CompletedTask;
            });
            Require(revoked.Reason == AudioMembershipFailure.Revoked && f.Owner.ReadAudioAuthorization() is null,
                "Storage failure concealed the confirmed runtime revocation.");
        }
    }
    private static async Task PreparedCancellation()
    {
        await using var f = await Fixture.Create(); using var canceled = new CancellationTokenSource(); var before = f.Read();
        f.Committer.BeforeCommit = () => { f.Committer.BeforeCommit = null; canceled.Cancel(); };
        await Throws<OperationCanceledException>(() => f.Refresh(canceled.Token));
        var after = f.Read();
        Require(f.HttpCalls == 0 && after.Pending.Length == 0 && after.Checkpoints.SequenceEqual(before.Checkpoints) && f.Epoch.IsCurrent,
            "Cancellation lost ownership of a committed preparation or sent an unowned request.");
    }
    private static async Task ConcurrentAndRotation()
    {
        await using var f = await Fixture.Create(checkpoints: false, minutes: 4); var journal = f.Journal; var epoch = f.Epoch;
        var first = await journal.BeginAsync(epoch, Local(f.Binding), AccountDeviceRegistryRequest.Presence, null, default);
        var second = await journal.BeginAsync(epoch, Local(f.Binding), AccountDeviceRegistryRequest.Presence, null, default);
        var login = f.Read().LoginId;
        await f.Owner.GetAudioAuthenticationAsync(epoch, default);
        Require(ReferenceEquals(f.Owner.RequireAudioAuthorization(), epoch) && f.Client.RefreshCalls == 1 && f.Read().Pending.Length == 2,
            "Credential rotation lost pending ownership or replaced the captured publication.");
        Require(await journal.CompleteAsync(first, new(null, null, false), null) == AudioJournalCompletion.Committed, "First observation did not commit.");
        Require(f.Read().Pending.Single() == second.Request && f.Read().LoginId == login, "One request cleared another request's marker.");
        await journal.CompleteAsync(second, new(null, null, false), null);
        Require(f.Read().Pending.Length == 0, "Second request could not settle after rotation.");
        await Throws<InvalidOperationException>(() => journal.CompleteAsync(first, new(null, null, false), null).AsTask());
    }
    private static async Task RetiredOwner()
    {
        foreach (bool replace in new[] { false, true })
        {
            await using var f = await Fixture.Create(); var journal = f.Journal;
            var ticket = await journal.BeginAsync(f.Epoch, Local(f.Binding), AccountDeviceRegistryRequest.Removal, f.Target, default);
            Require((await f.Owner.SignOutAsync()).Success, "Fixture sign-out failed.");
            if (replace) Require((await f.Owner.ApplyAuthAsync(f.Token)).Success, "Fixture relogin failed.");
            var current = f.Storage.Load();
            Require(await journal.CompleteAsync(ticket, new(null, f.Target, false), null) == AudioJournalCompletion.RetiredOwner &&
                f.Storage.Load().Version == current.Version, "A late completion mutated a signed-out or replacement login.");
        }
    }
    private static async Task ExternalWriter()
    {
        await using var f = await Fixture.Create(); var journal = f.Journal;
        var ticket = await journal.BeginAsync(f.Epoch, Local(f.Binding), AccountDeviceRegistryRequest.Presence, null, default);
        var head = f.Storage.Load(); var changed = f.Storage.Save(head.Session!, head.Version!, SessionStoreSaveMode.ContinueLogin);
        Require(changed.Succeeded, "Independent credential writer failed.");
        await Throws<AudioJournalStorageException>(() => journal.CompleteAsync(ticket, new(null, null, false), null).AsTask());
        Require(f.Storage.Load().Version == changed.Version && f.Read().Pending.Single() == ticket.Request && f.Owner.ReadAudioAuthorization() is null,
            "Stale journal writer adopted or overwrote an external account mutation.");
    }
    private static async Task ScopeRotation()
    {
        await using var f = await Fixture.Create(minutes: 4, keepNearExpiry: true);
        var oldEpoch = f.Epoch; var journal = f.Journal; var original = f.Read();
        var old = await journal.BeginAsync(oldEpoch, Local(f.Binding), AccountDeviceRegistryRequest.Presence, null, default);
        f.Client.RefreshedToken = AccountAudioAuthorizationTests.Token(app: new { tenant_id = "different-tenant" });
        await Throws<InvalidOperationException>(() => f.Owner.GetAudioAuthenticationAsync(oldEpoch, default));
        var nextEpoch = f.Epoch;
        Require(!oldEpoch.IsCurrent && nextEpoch.Scope.TenantId == "different-tenant" && f.Read().LoginId == original.LoginId,
            "Verified scope change did not preserve login ownership and retire its old publication.");
        Require(await journal.CompleteAsync(old, new(null, null, false), null) == AudioJournalCompletion.RetiredOwner,
            "Old scope completion was rebound to a new tenant.");
        var next = await journal.BeginAsync(nextEpoch, Local(f.Binding), AccountDeviceRegistryRequest.Presence, null, default);
        var changed = f.Read();
        Require(changed.Scope == nextEpoch.Scope && changed.Pending.Single() == next.Request && changed.Checkpoints.Length == 0,
            "New account scope inherited old checkpoints or pending request ownership.");
        await journal.CompleteAsync(next, new(null, null, false), null);
    }
    private static async Task InvalidState()
    {
        await using var f = await Fixture.Create(); var valid = f.Read();
        foreach (var invalid in new[] { valid with { SchemaVersion = 99 }, valid with { LoginId = Guid.Empty },
            valid with { Pending = [new(Guid.Empty, AccountDeviceRegistryRequest.List, f.Target, null)] },
            valid with { Pending = Enumerable.Repeat(new AudioJournalPending(Guid.NewGuid(), AccountDeviceRegistryRequest.List, f.Target, null), 33).ToArray() },
            valid with { Checkpoints = [valid.Checkpoints[0], valid.Checkpoints[0]] } })
            await Throws<InvalidDataException>(() => { AudioAccountJournalState.Read(JsonSerializer.SerializeToElement(invalid)); return Task.CompletedTask; });
        var extra = JsonSerializer.SerializeToNode(valid)!.AsObject(); extra["UnexpectedAuthority"] = true;
        await Throws<InvalidDataException>(() => { AudioAccountJournalState.Read(JsonSerializer.SerializeToElement(extra)); return Task.CompletedTask; });
        await Throws<InvalidDataException>(() => { _ = valid.ReadRecoveryCandidates(Guid.NewGuid(), valid.Scope); return Task.CompletedTask; });
        await Throws<InvalidDataException>(() => { _ = valid.ReadRecoveryCandidates(valid.LoginId, valid.Scope with { TenantId = "another-tenant" }); return Task.CompletedTask; });
        using var duplicate = JsonDocument.Parse("{\"SchemaVersion\":1,\"SchemaVersion\":1}");
        await Throws<InvalidDataException>(() => { AudioAccountJournalState.Read(duplicate.RootElement); return Task.CompletedTask; });
        var head = f.Storage.Load();
        Require(((ISessionAudioStateStore)f.Storage).WriteAudioState(JsonSerializer.SerializeToElement(valid with { SchemaVersion = 99 }), head.Version!, head.LoginId!.Value).Succeeded,
            "Unknown journal fixture did not persist.");
        f.Owner = new(f.Client, f.Storage);
        var original = f.Storage.Load();
        var invalidHydration = await f.Owner.HydrateFromStoreAsync();
        Require(!invalidHydration.Success && invalidHydration.ErrorCode == "InvalidAudioJournal" &&
            f.Storage.Load().Version == original.Version && f.HttpCalls == 0 && f.Owner.ReadAudioAuthorization() is null,
            "Unknown journal was replaced, ignored or reached account/audio admission.");
    }
    private static async Task NoIssuance()
    {
        await using var f = await Fixture.Create(); await f.Remove(); var remaining = f.Read().Checkpoints;
        await f.Refresh();
        Require(f.Read().Checkpoints.SequenceEqual(remaining), "A positive device list revived a removed checkpoint.");
    }
    private static async Task PendingCapacity()
    {
        await using var f = await Fixture.Create(); var journal = f.Journal; var epoch = f.Epoch;
        var original = f.Read().Checkpoints; var tickets = new List<AudioJournalTicket>();
        for (int i = 0; i < AudioAccountJournalState.Capacity; i++)
            tickets.Add(await journal.BeginAsync(epoch, Local(f.Binding), AccountDeviceRegistryRequest.Presence, null, default));
        var full = f.Storage.Load();
        await Throws<InvalidOperationException>(() => journal.BeginAsync(epoch, Local(f.Binding), AccountDeviceRegistryRequest.Presence, null, default).AsTask());
        Require(f.Storage.Load().Version == full.Version, "Over-capacity preparation mutated the journal.");
        foreach (var ticket in tickets)
        {
            await Throws<AudioJournalPendingObservationException>(() => {
                _ = f.Read().ReadRecoveryCandidates(ticket.LoginId, epoch.Scope); return Task.CompletedTask;
            });
            await journal.CompleteAsync(ticket, new(null, null, false), null);
        }
        Require(f.Read().ReadRecoveryCandidates(full.LoginId!.Value, epoch.Scope).SequenceEqual(original),
            "Settling observations changed the original finite checkpoints.");
    }
    private static async Task OffUiCommit()
    {
        await using var f = await Fixture.Create(checkpoints: false); var journal = f.Journal; var epoch = f.Epoch;
        var ui = new SynchronizationContext(); int commits = 0;
        f.Committer.BeforeCommit = () => {
            Require(!ReferenceEquals(SynchronizationContext.Current, ui), "Protected I/O ran inline on the caller UI context.");
            Interlocked.Increment(ref commits);
        };
        Task<AudioJournalTicket> preparing;
        var previous = SynchronizationContext.Current;
        SynchronizationContext.SetSynchronizationContext(ui);
        try { preparing = journal.BeginAsync(epoch, Local(f.Binding), AccountDeviceRegistryRequest.Presence, null, default).AsTask(); }
        finally { SynchronizationContext.SetSynchronizationContext(previous); }
        var ticket = await preparing;
        Task<AudioJournalCompletion> completing;
        previous = SynchronizationContext.Current;
        SynchronizationContext.SetSynchronizationContext(ui);
        try { completing = journal.CompleteAsync(ticket, new(null, null, false), null).AsTask(); }
        finally { SynchronizationContext.SetSynchronizationContext(previous); }
        Require(await completing == AudioJournalCompletion.Committed && commits == 2, "The UI-context check did not observe both real commits.");
    }
    private static async Task<T> Throws<T>(Func<Task> operation) where T : Exception
    { try { await operation(); } catch (T error) { return error; } throw new Exception($"Expected {typeof(T).Name}."); }
    private static void Require(bool condition, string message) { if (!condition) throw new Exception(message); }
}
