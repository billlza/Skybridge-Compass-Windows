using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Nodes;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.Audio;
using Skybridge.WinClient.ViewModels;
using static AudioAccountMembershipTests;

internal static class AudioAccountRegistryTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("audio registry observes actual device-page lists and captured request epochs", DevicePageList),
        ("audio registry ignores old same-account list and removal responses after relogin", RetiredResponses),
        ("audio registry retirement during observation admission cannot fail the device page", RetirementDuringObservation),
        ("audio registry preserves first negative evidence across enrollment and a later positive list", EnrollmentCannotRevive),
        ("audio registry observes parsed negative list before device-page cancellation", CancellationAfterList),
        ("audio registry confirmed removal survives cancellation and rejects ambiguous receipts", RemovalReceipt),
        ("audio registry presence denial revokes before successful registration recovery", PresenceRecovery),
        ("audio registry unavailable audio epoch preserves ordinary device-page behavior", NoAudioEpoch),
        ("audio registry shutdown revokes and drains membership requests", Shutdown),
        ("audio credential dispatcher keeps account awaits on the supplied UI context", DispatchContext),
        ("audio credential dispatcher bounds canceled queued work until it drains", DispatchCancellation),
        ("audio credential dispatcher preserves rejection and account failures", DispatchFailures),
        ("audio credential dispatcher shutdown waits for executing cleanup", DispatchShutdown),
        ("audio credential dispatcher reports an undrained queue and permits cleanup retry", DispatchTimeout)
    ];
    private static readonly AccountDeviceMetadata Metadata = new("Registry fixture", null, "Windows fixture", []);
    private const string Presence = "{\"online\":true,\"ttlMs\":90000,\"expiresAt\":1800000090000,\"persisted\":true,\"persistReason\":\"written\"}";
    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    { protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) => send(request, token); }
    private sealed class Fixture : IAsyncDisposable
    {
        internal readonly Clock Clock = new();
        internal readonly AudioSessionIdentityBinding Binding = AudioAccountMembershipTests.Binding();
        internal readonly AccountDeviceAuthentication BaseAuth = Authentication();
        internal readonly HttpClient Http;
        internal readonly AudioAccountMembershipProvider Provider;
        internal readonly AudioAccountRegistryObserver Observer;
        internal readonly AccountDeviceRosterClient Roster;
        internal readonly CurrentPathProtocolIdentityBinding QueryBinding;
        internal AccountAudioAuthorization Epoch;
        internal Func<AccountAudioAuthorization?>? ReadEpoch;
        internal readonly List<JsonObject> Rows;
        internal Func<int, CancellationToken, Task<HttpResponseMessage>>? OnList;
        internal Func<int, CancellationToken, Task<HttpResponseMessage>>? OnPresence;
        internal Func<CancellationToken, Task<HttpResponseMessage>>? OnRemove;
        internal int Lists, Presences, Registrations, Removals;
        internal AccountDeviceAuthentication Auth => BaseAuth.WithAudioAuthorization(Epoch);
        internal Fixture()
        {
            Epoch = new(AudioAccountScope.From(BaseAuth));
            QueryBinding = AudioDeviceIdentity.QueryBinding(Binding.LocalDeviceId, Binding.LocalProtocolIdentity);
            Rows = [Row(Local(Binding), true), Row(Peer(Binding))];
            Http = new(new Handler((request, token) => {
                Require(request.Headers.Authorization?.Parameter == BaseAuth.AccessToken, "Registry request lost captured authentication.");
                string path = request.RequestUri?.AbsolutePath ?? throw new Exception("Missing URI.");
                if (path == "/api/devices/list") { Lists++; return OnList?.Invoke(Lists, token) ?? Task.FromResult(Reply(Body())); }
                if (path == "/api/presence/register") { Presences++; return OnPresence?.Invoke(Presences, token) ?? Task.FromResult(Reply(Presence)); }
                if (path == "/api/devices/register-current")
                {
                    Registrations++; Rows[0]["status"] = "active";
                    return Task.FromResult(Reply(JsonSerializer.Serialize(new { registered = true, device = new {
                        tenant_id = BaseAuth.TenantId, user_id = BaseAuth.Subject, device_id = QueryBinding.DeviceId,
                        protocol_signing_algorithm = QueryBinding.ProtocolSigningAlgorithmWireName,
                        protocol_public_key_fingerprint = QueryBinding.ProtocolPublicKeyFingerprint, status = "active" } })));
                }
                if (path == "/api/devices/remove") { Removals++; return OnRemove?.Invoke(token) ?? Task.FromResult(Reply(RemovedBody())); }
                throw new Exception("Unexpected registry path.");
            }));
            Provider = new(Http, () => ReadEpoch is null ? Epoch : ReadEpoch(), (epoch, token) => { epoch.RequireAuthentication(Auth); return Task.FromResult(Auth); }, Clock.Read);
            Observer = new(Provider, Clock.Read); Roster = new(Http, Observer);
        }
        internal string Body() => new JsonObject { ["generatedAt"] = Clock.Now.WallMilliseconds,
            ["callerDeviceId"] = Binding.LocalDeviceId, ["truncated"] = false,
            ["devices"] = new JsonArray(Rows.Select(row => (JsonNode)row.DeepClone()).ToArray()) }.ToJsonString();
        internal string RemovedBody() => JsonSerializer.Serialize(new { removed = true, target = new {
            deviceId = Binding.PeerDeviceId, protocolSigningAlgorithm = Peer(Binding).Algorithm,
            protocolPublicKeyFingerprint = Peer(Binding).Fingerprint, status = "revoked" } });
        internal Task<AccountAudioMembershipLease> Lease(Inbox inbox, bool refresh = false) => Provider.LeaseAsync(inbox, default, refresh);
        internal Task<AccountDeviceRosterSnapshot> Refresh(AccountDeviceAuthentication? auth = null, CancellationToken token = default) => Roster.RefreshAsync(auth ?? Auth, QueryBinding, Metadata, token);
        public async ValueTask DisposeAsync() { await Provider.DisposeAsync(); Http.Dispose(); }
    }
    private static async Task DevicePageList()
    {
        await using var f = new Fixture(); using var inbox = new Inbox(f.Binding); var lease = await f.Lease(inbox);
        f.Rows[1]["status"] = "frozen"; var list = await f.Refresh();
        Require(list.Devices.Count == 2 && f.Registrations == 0 && f.Presences == 1, "Observation changed normal device-page operations.");
        await Revoked(lease);
    }
    private static async Task RetiredResponses()
    {
        foreach (bool remove in new[] { false, true })
        {
            await using var f = new Fixture(); var oldAuth = f.Auth;
            var entered = Signal(); var release = Signal();
            f.Rows[1]["status"] = "frozen"; string oldList = f.Body(); f.Rows[1]["status"] = "active";
            if (remove) f.OnRemove = async token => { entered.SetResult(); await release.Task.WaitAsync(token); return Reply(f.RemovedBody()); };
            else f.OnList = async (count, token) => { if (count == 1) { entered.SetResult(); await release.Task.WaitAsync(token); return Reply(oldList); } return Reply(f.Body()); };
            Task pending = remove ? f.Roster.RemoveAsync(oldAuth, f.QueryBinding, Entry(Peer(f.Binding)), default) : f.Refresh(oldAuth);
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
            f.Epoch.Revoke(); f.Epoch = new(f.Epoch.Scope);
            using var inbox = new Inbox(f.Binding); var current = await f.Lease(inbox);
            release.SetResult(); await pending; current.RequireCurrent();
            Require(!ReferenceEquals(oldAuth.AudioAuthorization, f.Epoch), "Fixture did not replace the same-account epoch.");
        }
    }
    private static async Task EnrollmentCannotRevive()
    {
        await using var f = new Fixture(); using var inbox = new Inbox(f.Binding); var previous = await f.Lease(inbox);
        var listEntered = Signal(); var listRelease = Signal(); var audioEntered = Signal(); var audioRelease = Signal();
        f.Rows[0]["status"] = "pending"; string negative = f.Body(); f.Rows[0]["status"] = "active";
        f.OnList = async (count, token) => {
            if (count == 2) { listEntered.SetResult(); await listRelease.Task.WaitAsync(token); return Reply(negative); }
            if (count == 3) { audioEntered.SetResult(); await audioRelease.Task.WaitAsync(token); }
            return Reply(f.Body());
        };
        var page = f.Refresh(); await listEntered.Task.WaitAsync(TimeSpan.FromSeconds(2));
        var audio = f.Lease(inbox, true); await audioEntered.Task.WaitAsync(TimeSpan.FromSeconds(2));
        listRelease.SetResult(); var refreshed = await page;
        Require(f.Registrations == 1 && f.Lists == 4 && refreshed.Devices.Single(row => row.IsCaller).Status == "active", "Existing enrollment path did not recover normally.");
        await Revoked(previous); audioRelease.SetResult(); await Throws<InvalidOperationException>(() => audio);
    }
    private static async Task RetirementDuringObservation()
    {
        foreach (bool stale in new[] { false, true })
        {
            await using var f = new Fixture();
            var captured = f.Observer.Begin(f.Auth, f.QueryBinding) ?? throw new Exception("Missing audio observation.");
            var snapshot = new AccountDeviceRosterSnapshot(f.Clock.Now.WallMilliseconds - (stale ? 60_000 : 0),
                f.Binding.LocalDeviceId, false, [Entry(Local(f.Binding), true), Entry(Peer(f.Binding), status: "frozen")]);
            bool switched = false;
            f.ReadEpoch = () => {
                var observed = f.Epoch;
                if (!switched) { switched = true; observed.Revoke(); f.Epoch = new(observed.Scope); }
                return observed;
            };
            captured.Listed(snapshot);
            Require(switched, "Fixture did not retire the epoch during observation admission.");
            using var inbox = new Inbox(f.Binding); (await f.Lease(inbox)).RequireCurrent();
        }
    }
    private static async Task CancellationAfterList()
    {
        await using var f = new Fixture(); using var inbox = new Inbox(f.Binding); var lease = await f.Lease(inbox);
        using var canceled = new CancellationTokenSource(); f.Rows[1]["status"] = "frozen";
        f.OnList = (_, _) => { var response = Reply(f.Body()); f.Clock.OnRead = canceled.Cancel; return Task.FromResult(response); };
        await using var page = new AccountDevicesCoordinator(f.Roster, _ => Task.FromResult<AccountDeviceAuthentication?>(f.Auth),
            _ => Task.FromResult(f.QueryBinding), _ => Task.FromResult(Metadata), key => key);
        page.SetAccount(f.Auth.Scope); await page.RefreshOnceAsync(canceled.Token);
        await Revoked(lease); Require(page.Devices.Count == 0 && page.Phase != "ready", "Canceled device-page response was published.");
    }
    private sealed class RemovalCancellationObserver(IAccountDeviceRegistryObserver inner, Action cancel) : IAccountDeviceRegistryObserver
    {
        public IAccountDeviceRegistryObservation? Begin(AccountDeviceAuthentication auth, CurrentPathProtocolIdentityBinding binding) =>
            inner.Begin(auth, binding) is { } captured ? new Observation(captured, cancel) : null;
        private sealed class Observation(IAccountDeviceRegistryObservation inner, Action cancel) : IAccountDeviceRegistryObservation
        {
            public void Listed(AccountDeviceRosterSnapshot snapshot) => inner.Listed(snapshot);
            public void Rejected(CurrentPathSignalServerException error) => inner.Rejected(error);
            public void Removed(AccountDeviceEntry target) { cancel(); inner.Removed(target); }
        }
    }
    private static async Task RemovalReceipt()
    {
        foreach (string mode in new[] { "confirmed", "wrong-target", "duplicate", "network" })
        {
            await using var f = new Fixture(); using var inbox = new Inbox(f.Binding); var lease = await f.Lease(inbox);
            using var canceled = new CancellationTokenSource();
            var client = new AccountDeviceRosterClient(f.Http, new RemovalCancellationObserver(f.Observer, canceled.Cancel));
            f.OnRemove = _ => mode == "network" ? throw new HttpRequestException("unconfirmed") : Task.FromResult(Reply(mode switch {
                "wrong-target" => f.RemovedBody().Replace(f.Binding.PeerDeviceId, "id:different-registry-peer", StringComparison.Ordinal),
                "duplicate" => f.RemovedBody().Replace("\"removed\":true", "\"removed\":false,\"removed\":true", StringComparison.Ordinal),
                _ => f.RemovedBody() }));
            if (mode == "confirmed")
            {
                await client.RemoveAsync(f.Auth, f.QueryBinding, Entry(Peer(f.Binding)), canceled.Token);
                Require(canceled.IsCancellationRequested, "Cancellation did not follow parsed confirmation."); await Revoked(lease);
            }
            else
            {
                if (mode == "network") await Throws<HttpRequestException>(() => client.RemoveAsync(f.Auth, f.QueryBinding, Entry(Peer(f.Binding)), default));
                else await Throws<InvalidDataException>(() => client.RemoveAsync(f.Auth, f.QueryBinding, Entry(Peer(f.Binding)), default));
                Require(!canceled.IsCancellationRequested, "Unconfirmed removal reached the observer."); lease.RequireCurrent();
            }
        }
    }
    private static async Task PresenceRecovery()
    {
        await using var f = new Fixture(); using var inbox = new Inbox(f.Binding); var lease = await f.Lease(inbox);
        f.OnPresence = (count, _) => Task.FromResult(count == 1 ? Reply("{\"error\":\"device_not_registered\"}", HttpStatusCode.Forbidden) : Reply(Presence));
        f.OnList = (count, _) => Task.FromResult(count == 2 ? Reply("{\"error\":\"device_not_registered\"}", HttpStatusCode.Forbidden) : Reply(f.Body()));
        var snapshot = await f.Refresh();
        Require(f.Registrations == 1 && snapshot.Devices.Single(row => row.IsCaller).Status == "active", "Presence recovery was changed by observation.");
        await Revoked(lease);
    }
    private static async Task NoAudioEpoch()
    {
        await using var f = new Fixture(); var list = await f.Refresh(f.BaseAuth);
        Require(list.Devices.Count == 2 && f.BaseAuth.AudioAuthorization is null, "Ordinary device page requires an audio epoch.");
        // An obsolete response must not fail the current page solely because its audio freshness elapsed.
        var old = f.Auth; f.Epoch.Revoke(); f.Epoch = new(f.Epoch.Scope);
        f.OnList = (_, _) => Task.FromResult(Reply(f.Body().Replace(f.Clock.Now.WallMilliseconds.ToString(), (f.Clock.Now.WallMilliseconds - 60_000).ToString(), StringComparison.Ordinal)));
        _ = await f.Refresh(old);
        await Throws<InvalidDataException>(() => f.Refresh());
    }
    private static async Task Shutdown()
    {
        await using var f = new Fixture(); using var inbox = new Inbox(f.Binding); var lease = await f.Lease(inbox);
        var entered = Signal(); f.OnList = async (_, token) => { entered.SetResult(); await Task.Delay(Timeout.Infinite, token); throw new Exception("Unreachable."); };
        var pending = f.Lease(inbox, true); await entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
        await f.Provider.DisposeAsync(); await Throws<OperationCanceledException>(() => pending); await Revoked(lease);
        await Throws<OperationCanceledException>(() => f.Lease(inbox));
        await f.Provider.DisposeAsync();
    }
    private sealed class UiQueue : SynchronizationContext, IDisposable
    {
        private readonly ConcurrentQueue<Action> _actions = new();
        private readonly SemaphoreSlim _available = new(0);
        internal bool Enqueue(Action action) { _actions.Enqueue(action); _available.Release(); return true; }
        public override void Post(SendOrPostCallback callback, object? state) => Enqueue(() => callback(state));
        internal async Task RunNext()
        {
            Require(await _available.WaitAsync(TimeSpan.FromSeconds(2)), "UI fixture callback did not arrive.");
            Require(_actions.TryDequeue(out var action), "UI fixture queue was empty.");
            var previous = Current; SetSynchronizationContext(this);
            try { (action ?? throw new Exception("Missing UI action."))(); }
            finally { SetSynchronizationContext(previous); }
        }
        public void Dispose() => _available.Dispose();
    }
    private static async Task DispatchContext()
    {
        using var ui = new UiQueue(); var auth = Authentication(); var epoch = new AccountAudioAuthorization(AudioAccountScope.From(auth));
        var entered = Signal(); var release = Signal(); var calls = 0;
        await using var dispatcher = new AudioAccountCredentialDispatcher(ui.Enqueue, async (captured, token) => {
            Require(ReferenceEquals(SynchronizationContext.Current, ui) && ReferenceEquals(epoch, captured), "Account access missed the owner context.");
            calls++; entered.SetResult(); await release.Task.WaitAsync(token);
            Require(ReferenceEquals(SynchronizationContext.Current, ui), "Account continuation left the owner context."); return auth;
        });
        var pending = dispatcher.AuthenticateAsync(epoch, default); Require(calls == 0, "Account accessed before dispatch.");
        await ui.RunNext(); await entered.Task; release.SetResult(); await ui.RunNext();
        Require(ReferenceEquals(await pending, auth) && calls == 1, "Dispatched result was changed or repeated.");
    }
    private static async Task DispatchCancellation()
    {
        using var ui = new UiQueue(); var auth = Authentication(); var epoch = new AccountAudioAuthorization(AudioAccountScope.From(auth)); var calls = 0;
        await using var dispatcher = new AudioAccountCredentialDispatcher(ui.Enqueue, (_, _) => { calls++; return Task.FromResult(auth); });
        using var canceled = new CancellationTokenSource(); var first = dispatcher.AuthenticateAsync(epoch, canceled.Token);
        canceled.Cancel(); await Throws<OperationCanceledException>(() => first);
        await Throws<InvalidOperationException>(() => dispatcher.AuthenticateAsync(epoch, default));
        await ui.RunNext(); Require(calls == 0, "Canceled queued request touched the account.");
        var second = dispatcher.AuthenticateAsync(epoch, default); await ui.RunNext(); _ = await second; Require(calls == 1, "Drained slot did not reopen.");
    }
    private static async Task DispatchFailures()
    {
        var auth = Authentication(); var epoch = new AccountAudioAuthorization(AudioAccountScope.From(auth));
        await using (var denied = new AudioAccountCredentialDispatcher(_ => false, (_, _) => throw new Exception("Must not execute.")))
            await Throws<InvalidOperationException>(() => denied.AuthenticateAsync(epoch, default));
        using var ui = new UiQueue(); var expected = new IOException("fixture account failure");
        await using var failed = new AudioAccountCredentialDispatcher(ui.Enqueue, (_, _) => throw expected);
        var pending = failed.AuthenticateAsync(epoch, default); await ui.RunNext();
        Require(ReferenceEquals(await Throws<IOException>(() => pending), expected), "Account failure was disguised.");
    }
    private static async Task DispatchShutdown()
    {
        using var ui = new UiQueue(); var auth = Authentication(); var epoch = new AccountAudioAuthorization(AudioAccountScope.From(auth));
        var entered = Signal(); var release = Signal();
        var dispatcher = new AudioAccountCredentialDispatcher(ui.Enqueue, async (_, _) => { entered.SetResult(); await release.Task; return auth; });
        var pending = dispatcher.AuthenticateAsync(epoch, default); await ui.RunNext(); await entered.Task;
        var stopped = dispatcher.DisposeAsync().AsTask(); Require(!stopped.IsCompleted, "Shutdown claimed completion before account cleanup.");
        release.SetResult(); await ui.RunNext(); await Throws<OperationCanceledException>(() => pending); await stopped;
        await Throws<OperationCanceledException>(() => dispatcher.AuthenticateAsync(epoch, default)); await dispatcher.DisposeAsync();
    }
    private static async Task DispatchTimeout()
    {
        using var ui = new UiQueue(); var auth = Authentication(); var epoch = new AccountAudioAuthorization(AudioAccountScope.From(auth));
        var dispatcher = new AudioAccountCredentialDispatcher(ui.Enqueue, (_, _) => Task.FromResult(auth), TimeSpan.FromMilliseconds(30));
        var pending = dispatcher.AuthenticateAsync(epoch, default);
        await Throws<TimeoutException>(() => dispatcher.DisposeAsync().AsTask()); await Throws<OperationCanceledException>(() => pending);
        await ui.RunNext(); await dispatcher.DisposeAsync();
    }
    private static TaskCompletionSource Signal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
    private static async Task Revoked(AccountAudioMembershipLease lease)
    { var error = await Throws<AudioMembershipException>(() => { lease.RequireCurrent(); return Task.CompletedTask; }); Require(error.Reason == AudioMembershipFailure.Revoked, "Grant was not revoked."); }
    private static async Task<T> Throws<T>(Func<Task> action) where T : Exception
    { try { await action(); } catch (T failure) { return failure; } throw new Exception($"Expected {typeof(T).Name}."); }
    private static void Require(bool value, string message) { if (!value) throw new Exception(message); }
}
