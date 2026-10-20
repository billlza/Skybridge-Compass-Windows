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
        ("audio registry prepares and settles each actual enrollment request separately", RequestLifecycle),
        ("audio registry preparation failure sends no unowned request", PreparationFailure),
        ("audio registry cancellation after preparation still settles its owned observation", PreparedCancellation),
        ("audio registry completion is awaited without inheriting UI cancellation", CompletionBoundary),
        ("audio registry failed and malformed requests retain their actual completion cause", FailedCompletion),
        ("audio registry cancellation cannot complete an unsettled transport", UnsettledCancellation),
        ("audio registry preserves request notification and completion failures together", CompletionFailures),
        ("audio registry observer failures cannot impersonate enrollment responses", ObserverFailureOrigin),
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
            var captured = await f.Observer.BeginAsync(f.Auth, f.QueryBinding, AccountDeviceRegistryRequest.List, default)
                ?? throw new Exception("Missing audio observation.");
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
        public async ValueTask<IAccountDeviceRegistryObservation?> BeginAsync(AccountDeviceAuthentication auth,
            CurrentPathProtocolIdentityBinding binding, AccountDeviceRegistryRequest request, CancellationToken cancellationToken,
            AccountDeviceEntry? removalTarget = null) =>
            await inner.BeginAsync(auth, binding, request, cancellationToken, removalTarget) is { } captured ? new Observation(captured, cancel) : null;
        private sealed class Observation(IAccountDeviceRegistryObservation inner, Action cancel) : IAccountDeviceRegistryObservation
        {
            public void Listed(AccountDeviceRosterSnapshot snapshot) => inner.Listed(snapshot);
            public void Rejected(CurrentPathSignalServerException error) => inner.Rejected(error);
            public void Removed(AccountDeviceEntry target) { cancel(); inner.Removed(target); }
            public ValueTask CompleteAsync(Exception? failure) => inner.CompleteAsync(failure);
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
        var failed = await Throws<AccountDeviceRegistryObservationException>(() => f.Refresh());
        Require(failed.Stage == "result" && failed.InnerException is InvalidDataException,
            "Invalid audio observation was confused with an HTTP response.");
        await using var page = new AccountDevicesCoordinator(f.Roster, _ => Task.FromResult<AccountDeviceAuthentication?>(f.Auth),
            _ => Task.FromResult(f.QueryBinding), _ => Task.FromResult(Metadata), key => key);
        page.SetAccount(f.Auth.Scope); await page.RefreshOnceAsync(default);
        Require(page.Status == "AccountDevicesInvalidResponse", "The result boundary lost the device page's invalid-response explanation.");
    }

    // Exercises the real roster HTTP/parse/callback order. This recorder is not
    // persisted audio authority; durable journal integration has separate gates.
    private sealed class LifecycleObserver(IAccountDeviceRegistryObserver inner) : IAccountDeviceRegistryObserver
    {
        internal readonly List<Observation> Operations = [];
        internal Func<AccountDeviceRegistryRequest, CancellationToken, Task>? Preparing;
        internal Func<Observation, Task>? Completing;
        internal Action? Listed;
        internal Action? Rejected;
        public async ValueTask<IAccountDeviceRegistryObservation?> BeginAsync(AccountDeviceAuthentication auth,
            CurrentPathProtocolIdentityBinding binding, AccountDeviceRegistryRequest request, CancellationToken cancellationToken,
            AccountDeviceEntry? removalTarget = null)
        {
            if (Preparing is not null) await Preparing(request, cancellationToken);
            var captured = await inner.BeginAsync(auth, binding, request, CancellationToken.None, removalTarget);
            var operation = new Observation(this, captured, request, auth);
            Operations.Add(operation);
            return operation;
        }
        internal sealed class Observation(LifecycleObserver owner, IAccountDeviceRegistryObservation? inner,
            AccountDeviceRegistryRequest kind, AccountDeviceAuthentication auth) : IAccountDeviceRegistryObservation
        {
            internal AccountDeviceRegistryRequest Kind { get; } = kind;
            internal AccountDeviceAuthentication Authentication { get; } = auth;
            internal readonly List<string> Events = [];
            internal Exception? Failure;
            internal int CompletionCalls;
            internal bool Completed;
            public void Listed(AccountDeviceRosterSnapshot snapshot)
            { inner?.Listed(snapshot); Events.Add("listed"); owner.Listed?.Invoke(); }
            public void Removed(AccountDeviceEntry target) { inner?.Removed(target); Events.Add("removed"); }
            public void Rejected(CurrentPathSignalServerException error)
            { inner?.Rejected(error); Events.Add("rejected"); owner.Rejected?.Invoke(); }
            public async ValueTask CompleteAsync(Exception? failure)
            {
                CompletionCalls++; Failure = failure; Events.Add("completing");
                if (inner is not null) await inner.CompleteAsync(failure);
                if (owner.Completing is not null) await owner.Completing(this);
                Completed = true; Events.Add("completed");
            }
        }
    }
    private static async Task RequestLifecycle()
    {
        await using var f = new Fixture(); var observer = new LifecycleObserver(f.Observer);
        var client = new AccountDeviceRosterClient(f.Http, observer); var auth = f.Auth;
        f.OnPresence = (count, _) => Task.FromResult(count == 1
            ? Reply("{\"error\":\"device_not_registered\"}", HttpStatusCode.Forbidden) : Reply(Presence));
        f.OnList = (count, _) => Task.FromResult(count == 1
            ? Reply("{\"error\":\"device_not_registered\"}", HttpStatusCode.Forbidden) : Reply(f.Body()));
        await client.RefreshAsync(auth, f.QueryBinding, Metadata, default);
        await client.RemoveAsync(auth, f.QueryBinding, Entry(Peer(f.Binding)), default);
        Require(observer.Operations.Select(o => o.Kind).SequenceEqual(new[] {
            AccountDeviceRegistryRequest.Presence, AccountDeviceRegistryRequest.List,
            AccountDeviceRegistryRequest.Registration, AccountDeviceRegistryRequest.Presence,
            AccountDeviceRegistryRequest.List, AccountDeviceRegistryRequest.Removal }), "Observation ownership did not match actual HTTP requests.");
        Require(observer.Operations.All(o => o.Completed && o.CompletionCalls == 1 && ReferenceEquals(o.Authentication, auth)),
            "A request was left open, settled twice or rebound to another authentication.");
        Require(observer.Operations.Take(2).All(o => o.Failure is CurrentPathSignalServerException && o.Events[0] == "rejected") &&
            observer.Operations.Skip(2).All(o => o.Failure is null), "Recovery hid an earlier denial or mislabeled success.");
        Require(observer.Operations[4].Events[0] == "listed" && observer.Operations[5].Events[0] == "removed", "Completion preceded the validated result.");
    }
    private static async Task PreparationFailure()
    {
        foreach (var kind in Enum.GetValues<AccountDeviceRegistryRequest>())
        {
            await using var f = new Fixture(); var expected = new IOException("synthetic prepare failure");
            var observer = new LifecycleObserver(f.Observer) { Preparing = (request, _) => request == kind
                ? Task.FromException(expected) : Task.CompletedTask };
            var client = new AccountDeviceRosterClient(f.Http, observer);
            if (kind == AccountDeviceRegistryRequest.Registration) f.Rows[0]["status"] = "pending";
            var failure = await Throws<AccountDeviceRegistryObservationException>(() => kind == AccountDeviceRegistryRequest.Removal
                ? client.RemoveAsync(f.Auth, f.QueryBinding, Entry(Peer(f.Binding)), default)
                : client.RefreshAsync(f.Auth, f.QueryBinding, Metadata, default));
            Require(failure.Stage == "preparation" && ReferenceEquals(failure.InnerException, expected), "Preparation failure was disguised.");
            int sent = kind switch { AccountDeviceRegistryRequest.Presence => f.Presences,
                AccountDeviceRegistryRequest.List => f.Lists, AccountDeviceRegistryRequest.Registration => f.Registrations, _ => f.Removals };
            Require(sent == 0 && observer.Operations.All(o => o.Completed && o.CompletionCalls == 1),
                "Failed preparation sent a request or abandoned an earlier observation.");
        }
    }
    private static async Task PreparedCancellation()
    {
        await using var f = new Fixture(); using var canceled = new CancellationTokenSource();
        var entered = Signal(); var release = Signal();
        var observer = new LifecycleObserver(f.Observer) { Preparing = async (_, _) => { entered.SetResult(); await release.Task; } };
        var client = new AccountDeviceRosterClient(f.Http, observer);
        var pending = client.RefreshAsync(f.Auth, f.QueryBinding, Metadata, canceled.Token);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
        Require(f.Presences == 0 && !pending.IsCompleted, "HTTP began before observation preparation finished.");
        canceled.Cancel(); release.SetResult();
        var failure = await Throws<OperationCanceledException>(() => pending);
        var operation = observer.Operations.Single();
        Require(f.Presences == 0 && operation.Completed && operation.CompletionCalls == 1 && ReferenceEquals(operation.Failure, failure),
            "A prepared but canceled operation lost ownership or sent HTTP.");
    }
    private static async Task CompletionBoundary()
    {
        await using var f = new Fixture(); using var inbox = new Inbox(f.Binding); var lease = await f.Lease(inbox);
        using var canceled = new CancellationTokenSource(); var entered = Signal(); var release = Signal();
        var observer = new LifecycleObserver(f.Observer) { Completing = async operation => {
            if (operation.Kind == AccountDeviceRegistryRequest.Removal) { entered.SetResult(); await release.Task; }
        } };
        var client = new AccountDeviceRosterClient(f.Http, observer);
        var pending = client.RemoveAsync(f.Auth, f.QueryBinding, Entry(Peer(f.Binding)), canceled.Token);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(2)); canceled.Cancel();
        await Revoked(lease);
        var operation = observer.Operations.Single();
        Require(!pending.IsCompleted && operation.CompletionCalls == 1 && !operation.Completed && operation.Failure is null,
            "Cancellation discarded a confirmed removal or completed its outstanding journal callback.");
        release.SetResult(); await pending;
        Require(operation.Completed && operation.Events.SequenceEqual(new[] { "removed", "completing", "completed" }),
            "Confirmed removal was not settled once after completion.");
    }
    private static async Task FailedCompletion()
    {
        foreach (string kind in new[] { "transport", "unexpected", "malformed", "canceled" })
        {
            await using var f = new Fixture(); var observer = new LifecycleObserver(f.Observer);
            using var canceled = new CancellationTokenSource();
            f.OnPresence = (_, _) => kind switch {
                "transport" => throw new HttpRequestException("synthetic network failure"),
                "unexpected" => throw new InvalidOperationException("synthetic unexpected failure"),
                "malformed" => Task.FromResult(Reply("{}")),
                _ => Cancel()
            };
            Task<HttpResponseMessage> Cancel() { canceled.Cancel(); throw new OperationCanceledException(canceled.Token); }
            var client = new AccountDeviceRosterClient(f.Http, observer);
            var failure = await Throws<Exception>(() => client.RefreshAsync(f.Auth, f.QueryBinding, Metadata, canceled.Token));
            var operation = observer.Operations.Single();
            Require(operation.Completed && operation.CompletionCalls == 1 && ReferenceEquals(operation.Failure, failure) &&
                operation.Events.SequenceEqual(new[] { "completing", "completed" }) && f.Lists == 0,
                "Failed request was recorded as success, not settled, or allowed a later GET.");
        }
    }
    private static async Task UnsettledCancellation()
    {
        await using var f = new Fixture(); using var canceled = new CancellationTokenSource();
        var entered = Signal(); var release = Signal();
        f.OnPresence = async (_, _) => { entered.SetResult(); await release.Task; throw new HttpRequestException("settled after UI cancellation"); };
        var observer = new LifecycleObserver(f.Observer); var client = new AccountDeviceRosterClient(f.Http, observer);
        var pending = client.RefreshAsync(f.Auth, f.QueryBinding, Metadata, canceled.Token);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(2)); canceled.Cancel();
        Require(!pending.IsCompleted && observer.Operations.Single().CompletionCalls == 0, "Canceled UI waiter settled a still-running request.");
        release.SetResult(); var failure = await Throws<Exception>(() => pending);
        Require(observer.Operations.Single() is { Completed: true, CompletionCalls: 1 } completed && ReferenceEquals(completed.Failure, failure),
            "Transport termination did not settle its captured observation.");
    }
    private static async Task CompletionFailures()
    {
        foreach (bool denied in new[] { false, true })
        {
            await using var f = new Fixture(); using var inbox = new Inbox(f.Binding); var lease = await f.Lease(inbox);
            var notification = new InvalidOperationException("synthetic observer failure");
            var commit = new IOException("synthetic completion failure");
            var observer = new LifecycleObserver(f.Observer) { Completing = operation =>
                operation.Kind == AccountDeviceRegistryRequest.List ? Task.FromException(commit) : Task.CompletedTask };
            if (denied)
            {
                f.OnList = (_, _) => Task.FromResult(Reply("{\"error\":\"device_revoked\"}", HttpStatusCode.Forbidden));
                observer.Rejected = () => throw notification;
            }
            else { f.Rows[1]["status"] = "frozen"; observer.Listed = () => throw notification; }
            var client = new AccountDeviceRosterClient(f.Http, observer);
            var failure = await Throws<AggregateException>(() => client.RefreshAsync(f.Auth, f.QueryBinding, Metadata, default));
            await Revoked(lease);
            var causes = failure.Flatten().InnerExceptions;
            Require(causes.Count == (denied ? 3 : 2) && causes.Any(e => e is AccountDeviceRegistryObservationException { Stage: "result" or "rejection" } && ReferenceEquals(e.InnerException, notification)) &&
                causes.Any(e => e is AccountDeviceRegistryObservationException { Stage: "completion" } && ReferenceEquals(e.InnerException, commit)) &&
                (!denied || causes.Any(e => e is CurrentPathSignalServerException)), "Completion erased an original request or callback failure.");
            var operation = observer.Operations.Last();
            Require(operation.CompletionCalls == 1 && !operation.Completed && operation.Failure is not null && f.Registrations == 0,
                "A failed completion was retried, reported as complete or triggered enrollment.");
        }
    }
    private static async Task ObserverFailureOrigin()
    {
        foreach (string stage in new[] { "preparation", "result", "completion" })
        {
            await using var f = new Fixture(); var observer = new LifecycleObserver(f.Observer);
            var expected = new CurrentPathSignalServerException("{\"error\":\"device_not_registered\"}", HttpStatusCode.Forbidden);
            if (stage == "preparation") observer.Preparing = (_, _) => Task.FromException(expected);
            if (stage == "result") observer.Listed = () => throw expected;
            if (stage == "completion") observer.Completing = _ => Task.FromException(expected);
            var client = new AccountDeviceRosterClient(f.Http, observer);
            var failure = await Throws<AccountDeviceRegistryObservationException>(() => client.RefreshAsync(f.Auth, f.QueryBinding, Metadata, default));
            Require(failure.Stage == stage && ReferenceEquals(failure.InnerException, expected) && f.Registrations == 0 &&
                observer.Operations.All(o => !o.Events.Contains("rejected")), "A local observer failure was treated as server enrollment denial.");
        }
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
