using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.Audio;

internal static class AudioAccountMembershipTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("audio membership rejects malformed negative identity observations without revoking", MalformedNegative),
        ("audio membership uses only identity-bound GET and accepts registered offline devices", RequestShape),
        ("audio membership offline reconnect preserves the original finite evidence", OfflineReconnect),
        ("audio membership consumer revocation preserves its first cause without revoking other consumers", ConsumerRevocationCause),
        ("audio membership explicit refresh replaces and revokes previous evidence", Refresh),
        ("audio membership continuation advances only the exact live consumer", Continuation),
        ("audio membership continuation retains existing consent without creating new consumers", ContinuationConsent),
        ("audio membership continuation rejects changed inbox epoch and revoked consumers before HTTP", ContinuationBinding),
        ("audio membership late renewal cannot resurrect an expired consumer", ContinuationExpiry),
        ("audio membership revoked consumer and negative observations defeat pending renewal", ContinuationRevocation),
        ("audio membership continuation cancellation and expiry are checked at publication", ContinuationPublication),
        ("audio membership failed continuation preserves finite authority without fallback", ContinuationFailure),
        ("audio membership request retry classification preserves denials and rejects TLS errors", ContinuationRequestFailures),
        ("audio membership expiry and clock rollback are terminal in either time domain", ClockBoundaries),
        ("audio membership rejects stale slow and truncated positive evidence", Freshness),
        ("audio membership distinguishes truncated absence from explicit negative observations", NegativeObservations),
        ("audio membership known device denials revoke but transport and unknown errors do not", QueryFailures),
        ("audio membership confirmed removal prevents late positive publication", RemovalDuringRequest),
        ("audio membership fresh negative observation prevents late positive publication", NegativeDuringRequest),
        ("audio membership completed negative observation survives requester cancellation and closure", EndedRequester),
        ("audio membership unrelated scope and stale observations cannot revoke", WrongObservation),
        ("audio membership bounds capacity without silently evicting active evidence", Capacity),
        ("audio membership rejects account replacement and cannot revive prior epochs", AccountReplacement),
        ("audio membership HTTP deadline cancellation and request cleanup remain distinct", Deadlines),
        ("audio membership cancellation at lease publication cannot replace old evidence", PublicationCancellation),
        ("audio membership identity and scope mismatch cannot poison the correct lease", WrongLeaseIdentity),
        ("audio membership expiry blocks encrypted positive replies while Stop and MAIN remain live", EncryptedAdmission),
        ("audio membership production clock has explicit Windows platform semantics", ProductionClock)
    ];
    private static readonly SessionAuthority Authority = SessionAuthority.ForSupabaseProject("https://audio-membership-test.supabase.co");
    internal static AccountDeviceAuthentication Authentication(string subject = "membership-user")
    {
        static string B(object value) => Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(value))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        string token = B(new { alg = "EdDSA", typ = "JWT" }) + "." + B(new {
            iss = Authority.Issuer, sub = subject, aud = "authenticated", role = "authenticated",
            exp = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds(), app_metadata = new { tenant_id = "membership-tenant" }
        }) + ".dGVzdA";
        return AccountDeviceAuthentication.FromVerifiedSession(token, Authority, subject);
    }
    // Synthetic identities/account port; real HTTP parsing and production membership state machine.
    // EncryptedAdmission additionally exercises the actual framed TCP reader/writer with fixture keys.
    internal static AudioSessionIdentityBinding Binding(int peer = 0, bool mlDsa = false)
    {
        const string localId = "9A770257-EE43-4D15-9031-D39B7A4AE045";
        string peerId = "id:android-membership-" + peer;
        using var keys = new ProductSessionKeys(ProductHandshakeRole.Initiator, Guid.NewGuid().ToString(), new byte[32], new byte[32], new byte[32]);
        var algorithm = mlDsa ? WebRtcProductSignatureAlgorithm.MlDsa65 : WebRtcProductSignatureAlgorithm.Ed25519;
        var local = ProductHandshakeProtocolIdentity.Capture(new WebRtcProductProtocolIdentityPublicKey(
            algorithm, Enumerable.Repeat((byte)31, mlDsa ? 1952 : 32).ToArray()).Encode(), "local fixture");
        var remote = ProductHandshakeProtocolIdentity.Capture(new WebRtcProductProtocolIdentityPublicKey(
            algorithm, Enumerable.Repeat((byte)32, mlDsa ? 1952 : 32).ToArray()).Encode(), "peer fixture");
        var soa = new RemoteControlHandshakeSoa(RemoteControlHandshakeBinding.PeerId(localId), RemoteControlHandshakeBinding.PeerId(peerId), new byte[16]);
        return AudioSessionIdentityBinding.Capture(keys, localId, peerId, local, remote, soa.EncodeTlv());
    }
    internal static AudioDeviceIdentity Local(AudioSessionIdentityBinding binding) => AudioDeviceIdentity.From(binding.LocalDeviceId, binding.LocalProtocolIdentity);
    internal static AudioDeviceIdentity Peer(AudioSessionIdentityBinding binding) => AudioDeviceIdentity.From(binding.PeerDeviceId, binding.PeerProtocolIdentity);
    internal static JsonObject Row(AudioDeviceIdentity identity, bool caller = false, string status = "active") => new() {
        ["deviceId"] = identity.DeviceId, ["protocolSigningAlgorithm"] = identity.Algorithm,
        ["protocolPublicKeyFingerprint"] = identity.Fingerprint, ["status"] = status, ["online"] = false, ["isCaller"] = caller
    };
    internal static AccountDeviceEntry Entry(AudioDeviceIdentity identity, bool caller = false, string status = "active") =>
        new(identity.DeviceId, identity.DeviceId, status, identity.Algorithm, identity.Fingerprint, null, null, null, null, null, false, caller);
    internal static HttpResponseMessage Reply(string body, HttpStatusCode status = HttpStatusCode.OK) => new(status) {
        Content = new StringContent(body, Encoding.UTF8, "application/json")
    };
    internal sealed class Clock
    {
        internal AudioAuthorizationTime Now = new(1_800_000_000_000, 1000);
        internal Action? OnRead;
        internal AudioAuthorizationTime Read() { var action = OnRead; OnRead = null; action?.Invoke(); return Now; }
        internal void Advance(long value) => Now = new(Now.WallMilliseconds + value, Now.ContinuousMilliseconds + value);
    }
    internal sealed class Inbox(AudioSessionIdentityBinding binding) : ILanAudioStreamInbox
    {
        private volatile bool _live = true;
        public Guid StreamId { get; } = Guid.NewGuid();
        public AudioSessionIdentityBinding Binding { get; } = binding;
        public AudioPlaybackSource Source { get; } = new AudioPlaybackSource.CapturedPcm(new(48000, 2, AudioStreamingEncoding.Float32, 32, 3));
        public void RequireCurrent() { if (!_live) throw new InvalidOperationException("Fixture inbox closed."); }
        public void RequireEffectCurrent() => RequireCurrent();
        public Task<AudioStreamingMessage> ReadAsync(CancellationToken cancellationToken) => throw new NotSupportedException();
        public void Dispose() => _live = false;
    }
    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    { protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) => send(request, ct); }
    internal sealed class Fixture : IDisposable
    {
        internal readonly Clock Clock = new();
        internal readonly AccountDeviceAuthentication Auth = Authentication();
        internal AccountAudioAuthorization Epoch;
        internal readonly AudioSessionIdentityBinding Binding;
        internal readonly List<JsonObject> Rows;
        internal readonly HttpClient Http;
        internal readonly AudioAccountMembershipProvider Provider;
        internal int HttpCalls, AuthCalls;
        internal Func<CancellationToken, Task<HttpResponseMessage>>? Respond;
        internal Fixture(AudioSessionIdentityBinding? binding = null, TimeSpan? timeout = null)
        {
            Binding = binding ?? AudioAccountMembershipTests.Binding();
            Epoch = new(AudioAccountScope.From(Auth));
            Rows = [Row(Local(Binding), true), Row(Peer(Binding))];
            Http = new(new Handler((request, ct) => {
                HttpCalls++;
                var uri = request.RequestUri ?? throw new Exception("Missing request URI.");
                Require(request.Method == HttpMethod.Get && request.Content is null && uri.AbsolutePath == "/api/devices/list", "Audio performed a non-GET registry operation.");
                Require(request.Headers.Authorization?.Parameter == Auth.AccessToken &&
                    request.Headers.GetValues("X-SkyBridge-Tenant-Id").Single() == Auth.TenantId &&
                    request.Headers.GetValues("X-SkyBridge-Client-Version").Single() == "1.0.2" &&
                    request.Headers.GetValues("X-SkyBridge-Protocol-Version").Single() == "1", "GET lost its captured account or version.");
                var query = uri.Query.TrimStart('?').Split('&').Select(part => part.Split('=', 2))
                    .ToDictionary(part => Uri.UnescapeDataString(part[0]), part => Uri.UnescapeDataString(part[1]));
                var local = Local(Binding);
                Require(query.Count == 3 && query["deviceId"] == local.DeviceId && query["protocolSigningAlgorithm"] == local.Algorithm &&
                    query["protocolPublicKeyFingerprint"] == local.Fingerprint, "GET changed the actual MAIN signer or raw device ID.");
                return Respond is null ? Task.FromResult(Reply(Body())) : Respond(ct);
            }));
            Provider = new(Http, () => Epoch, (epoch, ct) => { AuthCalls++; epoch.RequireAuthentication(Auth); return Task.FromResult(Auth); }, Clock.Read, timeout);
        }
        internal string Body(bool truncated = false, long? generatedAt = null) => new JsonObject {
            ["generatedAt"] = generatedAt ?? Clock.Now.WallMilliseconds, ["callerDeviceId"] = Binding.LocalDeviceId,
            ["truncated"] = truncated, ["devices"] = new JsonArray(Rows.Select(row => (JsonNode)row.DeepClone()).ToArray())
        }.ToJsonString();
        internal Task<AccountAudioMembershipLease> Lease(ILanAudioStreamInbox inbox, bool refresh = false, CancellationToken ct = default) => Provider.LeaseAsync(inbox, ct, refresh);
        internal Task<AudioRegistryObservation> Observe() => new AudioAccountMembershipClient(Http, Clock.Read).QueryAsync(Auth, Binding, default);
        public void Dispose() { Provider.DisposeAsync().AsTask().GetAwaiter().GetResult(); Http.Dispose(); }
    }
    private static async Task MalformedNegative()
    {
        foreach (var algorithm in new[] { false, true })
        foreach (string field in new[] { "protocolSigningAlgorithm", "deviceId", "duplicate" })
        {
            using var f = new Fixture(Binding(mlDsa: algorithm)); using var inbox = new Inbox(f.Binding);
            var lease = await f.Lease(inbox);
            var row = f.Rows[1]; row["status"] = "frozen";
            if (field == "duplicate") f.Respond = _ => Task.FromResult(Reply(f.Body().Replace("\"truncated\":false", "\"truncated\":true,\"truncated\":false", StringComparison.Ordinal)));
            else row[field] = " " + row[field]!.GetValue<string>() + " ";
            await Throws<InvalidDataException>(() => f.Lease(inbox, true));
            lease.RequireCurrent();
            Require(f.HttpCalls == 2, "Malformed response was silently retried.");
        }
    }
    private static async Task RequestShape()
    {
        foreach (bool mlDsa in new[] { false, true })
        {
            using var f = new Fixture(Binding(mlDsa: mlDsa)); using var inbox = new Inbox(f.Binding);
            var lease = await f.Lease(inbox); lease.RequireCurrent();
            Require(f.HttpCalls == 1 && f.AuthCalls == 1 && lease.StreamId == inbox.StreamId && lease.SessionId == inbox.Binding.SessionId,
                "GET evidence lost its exact stream binding.");
        }
    }
    private static async Task OfflineReconnect()
    {
        using var f = new Fixture(); using var oldInbox = new Inbox(f.Binding); var first = await f.Lease(oldInbox);
        f.Clock.Advance(123_000); oldInbox.Dispose(); using var next = new Inbox(Binding());
        f.Respond = _ => throw new HttpRequestException("offline");
        var cached = await f.Lease(next); cached.RequireCurrent();
        Require(ReferenceEquals(first.Evidence, cached.Evidence) && cached.Evidence.Expires == first.Evidence.Expires && f.HttpCalls == 1 && f.AuthCalls == 1,
            "Offline reconnect refreshed account credentials or extended the lease.");
        await Throws<InvalidOperationException>(() => Check(first.RequireCurrent));
    }
    private static async Task Refresh()
    {
        using var f = new Fixture(); using var inbox = new Inbox(f.Binding); var old = await f.Lease(inbox);
        f.Clock.Advance(1000); var next = await f.Lease(inbox, true);
        Require(next.Evidence.Id != old.Evidence.Id && next.Evidence.Issued == f.Clock.Now && f.HttpCalls == 2, "Explicit refresh did not issue a fresh grant.");
        await Failure(AudioMembershipFailure.Revoked, old.RequireCurrent); next.RequireCurrent();
    }
    private static async Task ConsumerRevocationCause()
    {
        using var f = new Fixture();
        using var firstInbox = new Inbox(f.Binding);
        using var otherInbox = new Inbox(f.Binding);
        var first = await f.Lease(firstInbox);
        var other = await f.Lease(otherInbox);
        var cause = new TimeoutException("Fixture attempt deadline.");
        first.Revoke(cause);
        var failure = await Throws<AudioMembershipException>(() => Check(first.RequireEffectCurrent));
        Require(failure.Reason == AudioMembershipFailure.Revoked && ReferenceEquals(failure.InnerException, cause),
            "Effect revocation lost its terminal cause.");
        first.Revoke(new IOException("Later fixture cleanup failure."));
        first.Revoke();
        var repeated = await Throws<AudioMembershipException>(() => Check(first.RequireCurrent));
        Require(ReferenceEquals(repeated.InnerException, cause), "Later revocation replaced the first terminal cause.");
        Require(ReferenceEquals(first.Evidence, other.Evidence), "Fixture did not share the original finite evidence.");
        other.RequireCurrent();
    }
    private static async Task Continuation()
    {
        using var f = new Fixture(); using var inbox = new Inbox(f.Binding);
        var live = await f.Lease(inbox); var previous = live.Evidence;
        using var otherInbox = new Inbox(Binding()); var other = await f.Lease(otherInbox);
        Require(ReferenceEquals(other.Evidence, previous), "Fixture did not share the finite cached grant.");
        f.Clock.Advance(1000);
        var continued = await f.Provider.RenewAsync(inbox, live, default);
        Require(ReferenceEquals(live, continued) && live.Evidence.Id != previous.Id &&
            live.Evidence.Issued == f.Clock.Now && live.Evidence.Expires.WallMilliseconds > previous.Expires.WallMilliseconds &&
            live.Evidence.Expires.ContinuousMilliseconds > previous.Expires.ContinuousMilliseconds && f.HttpCalls == 2,
            "Explicit continuation did not atomically advance its original consumer.");
        live.RequireCurrent(); live.RequireEffectCurrent();
        await Failure(AudioMembershipFailure.Revoked, other.RequireEffectCurrent);
        Require(ReferenceEquals((await f.Lease(inbox)).Evidence, live.Evidence), "Cache did not publish the committed continuation.");
    }
    private static async Task ContinuationConsent()
    {
        using var f = new Fixture(); using var inbox = new Inbox(f.Binding); var live = await f.Lease(inbox);
        var request = new AudioPlaybackApprovalRequest(inbox, live, "fixture-output");
        var permission = new AudioPlaybackPermission(request, default, default); var initial = request.MembershipId;
        request.RequireInitialMembership(); f.Clock.Advance(1000);
        await f.Provider.RenewAsync(inbox, live, default);
        permission.RequireCurrent(inbox, inbox.Source, "fixture-output");
        permission.RequireEffectCurrent(inbox, inbox.Source, "fixture-output");
        Require(request.MembershipId == initial && initial != live.Evidence.Id, "Renewal rewrote the displayed consent identity.");
        await Throws<InvalidDataException>(() => Check(request.RequireInitialMembership));
        await Throws<InvalidDataException>(() => Check(() => permission.RequireCurrent(inbox, inbox.Source, "other-output")));
        permission.Revoke();
        await Throws<AudioPlaybackApprovalException>(() => Check(() => permission.RequireEffectCurrent(inbox, inbox.Source, "fixture-output")));
    }
    private static async Task ContinuationBinding()
    {
        foreach (string mode in new[] { "inbox", "epoch", "revoked", "closed" })
        {
            using var f = new Fixture(); using var inbox = new Inbox(f.Binding); var live = await f.Lease(inbox);
            using var otherInbox = new Inbox(f.Binding);
            if (mode == "epoch") f.Epoch = new(f.Epoch.Scope);
            if (mode == "revoked") live.Revoke();
            if (mode == "closed") inbox.Dispose();
            f.Clock.Advance(1000);
            Func<Task> renew = () => f.Provider.RenewAsync(mode == "inbox" ? otherInbox : inbox, live, default);
            if (mode == "inbox") await Throws<InvalidDataException>(renew);
            else if (mode == "epoch") await Failure(AudioMembershipFailure.ScopeChanged, renew);
            else if (mode == "revoked") await Failure(AudioMembershipFailure.Revoked, renew);
            else await Throws<InvalidOperationException>(renew);
            Require(f.HttpCalls == 1 && f.AuthCalls == 1, "A foreign or ended consumer began a new account request.");
        }
    }
    private static async Task ContinuationExpiry()
    {
        using var f = new Fixture(); using var inbox = new Inbox(f.Binding); var live = await f.Lease(inbox); var previous = live.Evidence;
        f.Clock.Advance(AudioAccountMembershipEvidence.MaximumLifetimeMilliseconds - 1000);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Respond = async ct => { entered.SetResult(); await release.Task.WaitAsync(ct); return Reply(f.Body()); };
        var pending = f.Provider.RenewAsync(inbox, live, default); await entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
        f.Clock.Advance(2000); release.SetResult();
        await Failure(AudioMembershipFailure.Expired, () => pending);
        Require(ReferenceEquals(previous, live.Evidence), "Late fresh evidence resurrected the expired consumer.");
        await Failure(AudioMembershipFailure.Expired, live.RequireEffectCurrent);
    }
    private static async Task ContinuationRevocation()
    {
        foreach (string mode in new[] { "consumer", "removal", "negative" })
        {
            using var f = new Fixture(); using var inbox = new Inbox(f.Binding); var live = await f.Lease(inbox); var previous = live.Evidence;
            f.Clock.Advance(1000);
            var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            string positive = f.Body();
            f.Respond = async ct => {
                if (f.HttpCalls == 2) { entered.SetResult(); await release.Task.WaitAsync(ct); return Reply(positive); }
                return Reply(f.Body());
            };
            var pending = f.Provider.RenewAsync(inbox, live, default); await entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
            if (mode == "consumer") live.Revoke();
            else if (mode == "removal") f.Provider.Removed(f.Epoch, Entry(Peer(f.Binding)));
            else { f.Rows[1]["status"] = "frozen"; f.Provider.ObserveFresh(f.Epoch, await f.Observe()); }
            release.SetResult();
            if (mode == "consumer") await Failure(AudioMembershipFailure.Revoked, () => pending);
            else await Throws<InvalidOperationException>(() => pending);
            Require(ReferenceEquals(previous, live.Evidence), "A rejected continuation changed its consumer's grant.");
            await Failure(AudioMembershipFailure.Revoked, live.RequireEffectCurrent);
        }
    }
    private static async Task ContinuationPublication()
    {
        foreach (bool cancel in new[] { true, false })
        {
            using var f = new Fixture(); using var inbox = new Inbox(f.Binding); var live = await f.Lease(inbox); var previous = live.Evidence;
            f.Clock.Advance(1000);
            var replacement = AudioAccountMembershipEvidence.Create(await f.Observe(), Local(f.Binding), Peer(f.Binding));
            using var source = new CancellationTokenSource();
            // Change state on the final handoff clock read, after its earlier consumer check.
            f.Clock.OnRead = () => f.Clock.OnRead = () => { if (cancel) source.Cancel(); else f.Clock.Now = previous.Expires; };
            if (cancel) await Throws<OperationCanceledException>(() => Check(() => live.ContinueWith(previous, replacement, source.Token)));
            else await Failure(AudioMembershipFailure.Expired, () => Check(() => live.ContinueWith(previous, replacement, source.Token)));
            Require(ReferenceEquals(previous, live.Evidence), "Canceled or expired publication replaced the finite grant.");
            if (cancel) live.RequireEffectCurrent(); else await Failure(AudioMembershipFailure.Expired, live.RequireEffectCurrent);
        }
    }
    private static async Task ContinuationFailure()
    {
        using var f = new Fixture(); using var inbox = new Inbox(f.Binding); var live = await f.Lease(inbox); var previous = live.Evidence;
        f.Clock.Advance(1000);
        var failure = new HttpRequestException("Fixture unavailable.");
        f.Respond = _ => throw failure;
        var observed = await Throws<HttpRequestException>(() => f.Provider.RenewAsync(inbox, live, default));
        Require(ReferenceEquals(failure, observed) && ReferenceEquals(previous, live.Evidence) && f.HttpCalls == 2,
            "Failed continuation swallowed its cause, retried or changed the finite expiry.");
        live.RequireEffectCurrent(); f.Clock.Now = previous.Expires;
        await Failure(AudioMembershipFailure.Expired, live.RequireEffectCurrent);
    }
    private static async Task ContinuationRequestFailures()
    {
        foreach (string mode in new[] { "connection", "tls", "503", "401", "revoked-503", "identity-503", "json" })
        {
            using var f = new Fixture(); using var inbox = new Inbox(f.Binding); var live = await f.Lease(inbox); var previous = live.Evidence;
            f.Clock.Advance(1000);
            var transport = new HttpRequestException(mode == "tls" ? HttpRequestError.SecureConnectionError : HttpRequestError.ConnectionError,
                "Fixture account query failed.");
            f.Respond = _ => mode is "connection" or "tls" ? throw transport : Task.FromResult(
                mode == "json" ? Reply("{invalid") : Reply(JsonSerializer.Serialize(new { error = mode == "revoked-503" ? "device_revoked" : mode == "identity-503" ? "current_identity_mismatch" : "fixture-unavailable" }),
                mode == "401" ? HttpStatusCode.Unauthorized : HttpStatusCode.ServiceUnavailable));
            Func<Task> renew = () => f.Provider.RenewAsync(inbox, live, default);
            if (mode is "connection" or "503")
            {
                var failure = await Throws<AudioMembershipRequestUnavailableException>(renew);
                Require(mode == "connection" ? ReferenceEquals(failure.InnerException, transport) : failure.InnerException is CurrentPathSignalServerException,
                    "Temporary renewal lost its original request cause.");
            }
            else if (mode == "tls") Require(ReferenceEquals(transport, await Throws<HttpRequestException>(renew)), "TLS failure was rewritten.");
            else if (mode == "json") await Throws<InvalidDataException>(renew);
            else await Throws<CurrentPathSignalServerException>(renew);
            Require(f.HttpCalls == 2 && ReferenceEquals(previous, live.Evidence), "Failed renewal retried or extended its grant.");
            if (mode == "revoked-503") await Failure(AudioMembershipFailure.Revoked, live.RequireCurrent); else live.RequireCurrent();
        }
    }
    private static async Task ClockBoundaries()
    {
        foreach (bool wall in new[] { false, true }) foreach (bool rollback in new[] { false, true })
        {
            using var f = new Fixture(); using var inbox = new Inbox(f.Binding); var lease = await f.Lease(inbox); var initial = f.Clock.Now;
            long value = rollback ? -1 : AudioAccountMembershipEvidence.MaximumLifetimeMilliseconds;
            f.Clock.Now = wall ? new(initial.WallMilliseconds + value, initial.ContinuousMilliseconds) : new(initial.WallMilliseconds, initial.ContinuousMilliseconds + value);
            var reason = rollback ? AudioMembershipFailure.ClockChanged : AudioMembershipFailure.Expired;
            await Failure(reason, lease.RequireCurrent); f.Clock.Now = initial; await Failure(reason, lease.RequireCurrent);
            lease.Evidence.Revoke(); await Failure(reason, lease.RequireCurrent);
        }
    }
    private static async Task Freshness()
    {
        foreach (string mode in new[] { "wall", "continuous", "stale", "future", "truncated", "rollback" })
        {
            using var f = new Fixture(); using var inbox = new Inbox(f.Binding);
            f.Respond = _ => {
                if (mode == "wall") f.Clock.Now = f.Clock.Now with { WallMilliseconds = f.Clock.Now.WallMilliseconds + 30_001 };
                if (mode == "continuous") f.Clock.Now = f.Clock.Now with { ContinuousMilliseconds = f.Clock.Now.ContinuousMilliseconds + 30_001 };
                if (mode == "rollback") f.Clock.Advance(-1);
                long generated = f.Clock.Now.WallMilliseconds + (mode == "stale" ? -30_001 : mode == "future" ? 30_001 : 0);
                return Task.FromResult(Reply(f.Body(mode == "truncated", generated)));
            };
            await Failure(AudioMembershipFailure.InvalidResponse, () => f.Lease(inbox));
            Require(f.HttpCalls == 1, "Invalid evidence was retried.");
        }
        using var good = new Fixture(); var observation = await good.Observe();
        foreach (long lifetime in new long[] { 0, -1, 3_600_001 })
            await Failure(AudioMembershipFailure.InvalidResponse, () => Check(() => AudioAccountMembershipEvidence.Create(observation, Local(good.Binding), Peer(good.Binding), lifetime)));
        var nearLimit = new AudioAuthorizationTime(good.Clock.Now.WallMilliseconds, long.MaxValue - 1);
        var overflow = AudioRegistryObservation.FromResponse(good.Auth, Local(good.Binding), observation.Snapshot, nearLimit, nearLimit);
        await Failure(AudioMembershipFailure.InvalidResponse, () => Check(() => AudioAccountMembershipEvidence.Create(overflow, Local(good.Binding), Peer(good.Binding))));
    }
    private static async Task NegativeObservations()
    {
        foreach (string mode in new[] { "truncated-absent", "truncated-frozen", "complete-absent", "complete-frozen" })
        {
            using var f = new Fixture(); using var inbox = new Inbox(f.Binding); var old = await f.Lease(inbox);
            if (mode.EndsWith("absent", StringComparison.Ordinal)) f.Rows.RemoveAt(1); else f.Rows[1]["status"] = "frozen";
            f.Respond = _ => Task.FromResult(Reply(f.Body(mode.StartsWith("truncated", StringComparison.Ordinal))));
            await Failure(mode.StartsWith("truncated", StringComparison.Ordinal) ? AudioMembershipFailure.InvalidResponse : AudioMembershipFailure.InactiveDevice,
                () => f.Lease(inbox, true));
            if (mode == "truncated-absent") old.RequireCurrent(); else await Failure(AudioMembershipFailure.Revoked, old.RequireCurrent);
        }
    }
    private static async Task QueryFailures()
    {
        foreach (string code in new[] { "device_not_registered", "device_not_active", "device_frozen", "device_revoked", "current_identity_mismatch", "registry_unavailable", "unknown_auth", "rate_limit", "network" })
        {
            using var f = new Fixture(); using var inbox = new Inbox(f.Binding); var old = await f.Lease(inbox);
            f.Respond = _ => code == "network" ? throw new HttpRequestException("offline") : Task.FromResult(Reply(JsonSerializer.Serialize(new { error = code }),
                code == "registry_unavailable" ? HttpStatusCode.ServiceUnavailable : code == "rate_limit" ? HttpStatusCode.TooManyRequests : HttpStatusCode.Forbidden));
            if (code == "network") await Throws<HttpRequestException>(() => f.Lease(inbox, true));
            else await Throws<CurrentPathSignalServerException>(() => f.Lease(inbox, true));
            if (code.StartsWith("device_", StringComparison.Ordinal)) await Failure(AudioMembershipFailure.Revoked, old.RequireCurrent);
            else { old.RequireCurrent(); Require(ReferenceEquals((await f.Lease(inbox)).Evidence, old.Evidence), "Recoverable failure replaced valid cached evidence."); }
            Require(f.HttpCalls == 2, "Forced-refresh failure retried or silently fell back.");
        }
        foreach (string body in new[] { "{\"error\":\" device_frozen \"}", "{\"error\":\"forbidden\",\"error\":\"device_frozen\"}",
            "{\"code\":\"device_frozen\",\"error\":\"forbidden\"}" })
        {
            using var f = new Fixture(); using var inbox = new Inbox(f.Binding); var old = await f.Lease(inbox);
            f.Respond = _ => Task.FromResult(Reply(body, HttpStatusCode.Forbidden));
            await Throws<CurrentPathSignalServerException>(() => f.Lease(inbox, true)); old.RequireCurrent();
        }
    }
    private static async Task RemovalDuringRequest()
    {
        using var f = new Fixture(); using var inbox = new Inbox(f.Binding);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Respond = async ct => { entered.SetResult(); await release.Task.WaitAsync(ct); return Reply(f.Body()); };
        var pending = f.Lease(inbox); await entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
        await Throws<InvalidOperationException>(() => f.Lease(new Inbox(Binding(1))));
        f.Provider.Removed(f.Epoch, Entry(Peer(f.Binding))); release.SetResult();
        await Throws<InvalidOperationException>(() => pending);
        f.Respond = null; (await f.Lease(inbox)).RequireCurrent();
    }
    private static async Task NegativeDuringRequest()
    {
        using var f = new Fixture(); using var inbox = new Inbox(f.Binding);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        string positive = f.Body();
        f.Respond = async ct => { if (f.HttpCalls == 1) { entered.SetResult(); await release.Task.WaitAsync(ct); return Reply(positive); } return Reply(f.Body()); };
        var pending = f.Lease(inbox); await entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
        f.Rows[1]["status"] = "frozen"; f.Provider.ObserveFresh(f.Epoch, await f.Observe());
        release.SetResult(); await Throws<InvalidOperationException>(() => pending);
    }
    private static async Task EndedRequester()
    {
        foreach (bool cancel in new[] { false, true })
        {
            using var f = new Fixture(); var binding2 = Binding(1); f.Rows.Add(Row(Peer(binding2)));
            using var otherInbox = new Inbox(binding2); var other = await f.Lease(otherInbox);
            using var requester = new Inbox(f.Binding); using var canceled = new CancellationTokenSource();
            f.Rows[2]["status"] = "frozen";
            f.Respond = _ => { var response = Reply(f.Body()); f.Clock.OnRead = () => { if (cancel) canceled.Cancel(); else requester.Dispose(); }; return Task.FromResult(response); };
            if (cancel) await Throws<OperationCanceledException>(() => f.Lease(requester, ct: canceled.Token));
            else await Throws<InvalidOperationException>(() => f.Lease(requester));
            await Failure(AudioMembershipFailure.Revoked, other.RequireCurrent);
            // No grant may be published for the ended requester.
            f.Respond = _ => throw new HttpRequestException("offline"); using var replacement = new Inbox(f.Binding);
            await Throws<HttpRequestException>(() => f.Lease(replacement));
        }
    }
    private static async Task WrongObservation()
    {
        using var f = new Fixture(); using var inbox = new Inbox(f.Binding); var old = await f.Lease(inbox);
        f.Rows[1]["status"] = "frozen"; var negative = await f.Observe();
        var foreign = AudioRegistryObservation.FromResponse(Authentication("other"), Local(f.Binding), negative.Snapshot, negative.Started, negative.Received);
        await Failure(AudioMembershipFailure.ScopeChanged, () => Check(() => f.Provider.ObserveFresh(f.Epoch, foreign)));
        f.Clock.Advance(30_001);
        await Failure(AudioMembershipFailure.InvalidResponse, () => Check(() => f.Provider.ObserveFresh(f.Epoch, negative)));
        old.RequireCurrent();
    }
    private static async Task Capacity()
    {
        using var f = new Fixture();
        var bindings = Enumerable.Range(0, 33).Select(index => Binding(index)).ToArray();
        f.Rows.Clear(); f.Rows.Add(Row(Local(f.Binding), true)); f.Rows.AddRange(bindings.Select(binding => Row(Peer(binding))));
        var leases = new List<AccountAudioMembershipLease>();
        foreach (var binding in bindings.Take(32)) leases.Add(await f.Lease(new Inbox(binding)));
        await Throws<InvalidOperationException>(() => f.Lease(new Inbox(bindings[32])));
        foreach (var lease in leases) lease.RequireCurrent();
        var replacement = await f.Lease(new Inbox(bindings[0]), true); replacement.RequireCurrent();
        await Failure(AudioMembershipFailure.Revoked, leases[0].RequireCurrent);
        f.Provider.Removed(f.Epoch, Entry(Peer(bindings[1])));
        (await f.Lease(new Inbox(bindings[32]))).RequireCurrent();
    }
    private static async Task AccountReplacement()
    {
        using var f = new Fixture(); using var inbox = new Inbox(f.Binding); var lease = await f.Lease(inbox); var oldEpoch = f.Epoch;
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Respond = async ct => { entered.SetResult(); await release.Task.WaitAsync(ct); return Reply(f.Body()); };
        var pending = f.Lease(inbox, true); await entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
        oldEpoch.Revoke(); f.Epoch = new(oldEpoch.Scope); release.SetResult();
        await Throws<InvalidOperationException>(() => pending); await Throws<InvalidOperationException>(() => Check(lease.RequireCurrent));
        f.Respond = null; var next = await f.Lease(inbox); Require(next.Evidence.Id != lease.Evidence.Id, "Re-login reused old account evidence.");
    }
    private static async Task Deadlines()
    {
        foreach (bool callerCancel in new[] { false, true })
        {
            using var f = new Fixture(timeout: TimeSpan.FromMilliseconds(100)); using var inbox = new Inbox(f.Binding); using var caller = new CancellationTokenSource();
            var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            f.Respond = async ct => { entered.SetResult(); await Task.Delay(Timeout.Infinite, ct); throw new Exception("Unreachable."); };
            var pending = f.Lease(inbox, ct: caller.Token); await entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
            if (callerCancel) { caller.Cancel(); await Throws<OperationCanceledException>(() => pending); }
            else await Throws<TimeoutException>(() => pending);
            f.Respond = null; (await f.Lease(inbox)).RequireCurrent();
        }
    }
    private static async Task PublicationCancellation()
    {
        foreach (bool refresh in new[] { false, true })
        {
            using var f = new Fixture(); using var inbox = new Inbox(f.Binding); var old = await f.Lease(inbox); using var cancel = new CancellationTokenSource();
            // Trigger at the new lease's first clock read, after earlier request checks.
            if (refresh) f.Respond = _ => { f.Clock.OnRead = () => f.Clock.OnRead = () => f.Clock.OnRead = () => f.Clock.OnRead = cancel.Cancel; return Task.FromResult(Reply(f.Body())); };
            else f.Clock.OnRead = () => f.Clock.OnRead = cancel.Cancel;
            await Throws<OperationCanceledException>(() => f.Lease(inbox, refresh, cancel.Token));
            old.RequireCurrent();
            Require(ReferenceEquals((await f.Lease(inbox)).Evidence, old.Evidence), "Canceled publication replaced old evidence.");
        }
    }
    private static async Task WrongLeaseIdentity()
    {
        using var f = new Fixture(); using var inbox = new Inbox(f.Binding); var lease = await f.Lease(inbox); var e = lease.Evidence;
        await Failure(AudioMembershipFailure.ScopeChanged, () => Check(() => e.RequireValid(AudioAccountScope.From(Authentication("other")), e.Local, e.Peer, f.Clock.Now)));
        await Failure(AudioMembershipFailure.IdentityChanged, () => Check(() => e.RequireValid(e.Scope, e.Local, Peer(Binding(2)), f.Clock.Now)));
        lease.RequireCurrent();
    }
    private static async Task EncryptedAdmission()
    {
        await using var lan = await LanProductControlSessionTests.Fixture.ConnectForAudio(); await lan.Admit();
        using var inbox = await lan.OpenAudioInbox(); using var f = new Fixture(inbox.Binding); var lease = await f.Lease(inbox);
        await lan.Session.SendAudioReplyAsync(inbox, new(inbox.StreamId, new AudioStreamingBody.Accept(4096)), lease.RequireEffectCurrent, lan.Token);
        Require((await lan.ReadAudio()).Body is AudioStreamingBody.Accept, "Current evidence could not send an encrypted reply.");
        await using var held = lan.HoldWriter(); await held.Entered.WaitAsync(lan.Token);
        var queued = lan.Session.SendAudioReplyAsync(inbox, new(inbox.StreamId, new AudioStreamingBody.Credit(1)), lease.RequireEffectCurrent, lan.Token);
        Require(!queued.IsCompleted, "Fixture did not hold writer admission.");
        f.Clock.Advance(AudioAccountMembershipEvidence.MaximumLifetimeMilliseconds); held.Release(); await held.Completion;
        await Failure(AudioMembershipFailure.Expired, () => queued); await lan.ReadWriterBarrier();
        await lan.Session.SendAudioStopAsync(inbox, AudioStreamingStopReason.PermissionRevoked, lan.Token);
        Require((await lan.ReadAudio()).Body is AudioStreamingBody.Stop && lan.Session.IsReady, "Expired positive reply reached wire or blocked permitted Stop.");
        await lan.Barrier();
    }
    private static Task ProductionClock()
    {
        if (!OperatingSystem.IsWindows()) return Throws<PlatformNotSupportedException>(() => Check(() => AudioAuthorizationTime.ReadWindows()));
        var now = AudioAuthorizationTime.ReadWindows(); Require(now.WallMilliseconds > 0 && now.ContinuousMilliseconds >= 0, "Invalid native clock sample.");
        return Task.CompletedTask;
    }
    private static Task Check(Action action) { action(); return Task.CompletedTask; }
    private static Task Failure(AudioMembershipFailure reason, Action action) => Failure(reason, () => Check(action));
    private static async Task Failure(AudioMembershipFailure reason, Func<Task> action)
    { var error = await Throws<AudioMembershipException>(action); Require(error.Reason == reason, $"Expected {reason}, got {error.Reason}."); }
    private static async Task<T> Throws<T>(Func<Task> action) where T : Exception
    { try { await action(); } catch (T error) { return error; } throw new Exception($"Expected {typeof(T).Name}."); }
    private static void Require(bool condition, string reason) { if (!condition) throw new Exception(reason); }
}
