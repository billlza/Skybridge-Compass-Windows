using Skybridge.WinClient.Services.FileTransfer;
using System.Net.Http;
using System.Text.Json;
using System.Runtime.Versioning;
using Skybridge.WinClient.Services.RemoteControl;

namespace Skybridge.WinClient.Services;

/// <summary>Exactly one account-bound issued/listened or redeemed room per window.</summary>
[SupportedOSPlatform("windows10.0.19041")]
internal sealed class WindowsLiveConnectionCodes(
    WindowsDeviceWorkspace workspace, Func<CancellationToken, Task<AccountDeviceAuthentication?>> authenticate,
    string helperPath, string stateDirectory, WindowsWebRtcReceiveOptions receive) : IAsyncDisposable
{
    private readonly object _gate = new();
    private readonly HttpClient _http = new(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(10), MaxResponseContentBufferSize = 128 * 1024 };
    private Operation? _current;
    private bool _disposed;
    internal event Action<object, string, bool>? Changed;
    private sealed class Operation
    {
        internal readonly CancellationTokenSource Stop = new();
        internal readonly TaskCompletionSource<CrossNetworkConnectionSnapshot> Started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Ended = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    internal bool IsCurrent(object owner) { lock (_gate) return ReferenceEquals(owner, _current); }

    internal async Task<CrossNetworkConnectionSnapshot> StartAsync(CrossNetworkConnectionRequest request)
    {
        Operation? old;
        var next = new Operation();
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            old = _current;
            _current = next;
            _fileSession = null;
            old?.Stop.Cancel();
        }
        _ = RunAsync(next, old, request);
        return await next.Started.Task.ConfigureAwait(false);
    }

    private async Task RunAsync(Operation op, Operation? old, CrossNetworkConnectionRequest request)
    {
        try
        {
            if (old is not null) { await old.Ended.Task; old.Stop.Dispose(); }
            var token = op.Stop.Token;
            token.ThrowIfCancellationRequested();
            if (!File.Exists(helperPath)) throw new FileNotFoundException("The packaged SkyBridge WebRTC helper is missing.");
            using var setup = CancellationTokenSource.CreateLinkedTokenSource(token);
            setup.CancelAfter(TimeSpan.FromSeconds(30));
            var auth = await authenticate(setup.Token) ?? throw new InvalidOperationException("Sign in before using a connection code.");
            var identity = await workspace.GetConnectionIdentityAsync(setup.Token).ConfigureAwait(false);
            var local = identity.PublicMaterial;
            var binding = new CurrentPathProtocolIdentityBinding(local.DeviceId, CurrentPathProtocolSigningAlgorithm.MLDsa65,
                local.ProtocolPublicKey, local.ProtocolPublicKeyFingerprint);
            var api = new CurrentPathSignalServerClient(_http, new CurrentPathSignalServerClientOptions(
                bearerTokenProvider: _ => Task.FromResult(auth.AccessToken), tenantIdProvider: _ => Task.FromResult(auth.TenantId),
                clientVersion: "1.0.2"));
            var challenge = await api.RequestAdmissionChallengeAsync(binding, setup.Token).ConfigureAwait(false);
            if (challenge.TenantId != auth.TenantId || challenge.UserId != auth.Subject || challenge.ExpiresAt <= DateTimeOffset.UtcNow ||
                challenge.ClientVersion != "1.0.2" || challenge.ProtocolVersion != CurrentPathSignalServerClient.DefaultProtocolVersion)
                throw new InvalidDataException("The admission challenge does not belong to the current account and protocol.");
            var signature = identity.SignConnectionCodeChallenge(challenge, binding);
            var admission = await api.CompleteAdmissionAsync(challenge, binding, signature, setup.Token).ConfigureAwait(false);
            if (admission.State is not ("active" or "admitted")) throw new InvalidDataException("The signaling service did not admit the device.");
            bool hosting = request.Action is CrossNetworkConnectionAction.GenerateCode or CrossNetworkConnectionAction.RegenerateCode;
            CurrentPathConnectionCodeLease? lease = null;
            CurrentPathConnectionCodeLookup? lookup = null;
            var ttl = request.LeaseMode == CrossNetworkCodeLeaseMode.DayStable ? TimeSpan.FromHours(24) : TimeSpan.FromMinutes(10);
            if (hosting) lease = await api.RegisterConnectionCodeAsync(admission.Token, local.DeviceName, ttl, setup.Token).ConfigureAwait(false);
            else lookup = await api.LookupConnectionCodeAsync(admission.Token, CrossNetworkConnectionClient.NormalizeCodeInput(
                request.CodeInput, CrossNetworkConnectionClient.DefaultCodeInputPolicy), setup.Token).ConfigureAwait(false);
            var origin = lease?.SignalingServerOrigin ?? lookup!.SignalingServerOrigin;
            if (CurrentPathOriginPolicy.CanonicalOrigin(origin) != CurrentPathOriginPolicy.CanonicalOrigin(CurrentPathSignalServerClient.DefaultBaseUrl))
                throw new InvalidDataException("The code returned a signaling authority outside the configured product origin.");
            string room = lease?.SessionId ?? lookup!.SessionId;
            var wsOptions = new CurrentPathWebSocketSignalingClientOptions(origin, lease?.WsPath ?? lookup!.WsPath, room,
                lease?.SessionToken ?? lookup!.SessionToken, local.DeviceId, clientVersion: "1.0.2", connectTimeout: TimeSpan.FromSeconds(8));
            using var waiting = CancellationTokenSource.CreateLinkedTokenSource(token);
            if (lease is not null)
            {
                if (lease.ExpiresIn <= 0 || !new CrossNetworkConnectionClient().CanConnectWithCode(lease.Code) ||
                    CrossNetworkConnectionClient.NormalizeCodeInput(lease.Code, CrossNetworkConnectionClient.DefaultCodeInputPolicy) != lease.Code)
                    throw new InvalidDataException("The server returned an invalid or expired connection code.");
                waiting.CancelAfter(TimeSpan.FromSeconds(Math.Min(lease.ExpiresIn, ttl.TotalSeconds)));
            }
            await using var ws = new CurrentPathWebSocketSignalingClient(wsOptions);
            await ws.ConnectAndBindAsync(setup.Token).ConfigureAwait(false);
            if (ws.BoundRole != (hosting ? "initiator" : "responder"))
                throw new InvalidDataException("The server did not bind the requested room role.");
            var localJoin = JoinPayload(local);
            await ws.SendAsync(new(room, local.DeviceId, null, CurrentPathWebRtcSignalingMessageType.Join, localJoin,
                sentAt: DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000d), setup.Token).ConfigureAwait(false);

            string remoteId, fingerprint;
            if (lease is not null)
            {
                op.Started.TrySetResult(new(DateTimeOffset.UtcNow, "Waiting for a paired device", lease.Code, []));
                var peer = await WaitForPeerAsync(ws, room, local.DeviceId, identity, waiting.Token).ConfigureAwait(false);
                (remoteId, fingerprint) = peer;
            }
            else
            {
                if (lookup!.InitiatorProtocolSigningAlgorithm != CurrentPathProtocolSigningAlgorithm.MLDsa65)
                    throw new InvalidDataException("The advertised device does not meet the ML-DSA identity policy.");
                remoteId = lookup.InitiatorDeviceId;
                fingerprint = lookup.InitiatorProtocolPublicKeyFingerprint;
            }

            using var connecting = CancellationTokenSource.CreateLinkedTokenSource(token);
            connecting.CancelAfter(TimeSpan.FromSeconds(30));
            var sessionToken = hosting ? connecting.Token : setup.Token;
            var paired = RequirePaired(identity, remoteId, fingerprint);
            var remoteCaps = new PeerCapabilities(CorePeerPlatform.Unknown, false, false, false, true, false, false);
            var path = NetworkPath.CrossNatPath();
            var selected = await new CoreBridge().SelectTransportAsync(PeerCapabilities.Windows(), remoteCaps, path).ConfigureAwait(false);
            var adapter = new WindowsTransportAdapterRequest(
                new(CoreDiscoveryServiceKind.Unknown, remoteId, paired.DeviceName, CorePeerPlatform.Unknown, "", fingerprint,
                    "webrtc", CurrentPathSignalServerClient.DefaultProtocolVersion, remoteCaps),
                new(remoteId, paired.DeviceName, "", fingerprint, paired.ProtocolPublicKey.ToArray(), true, "authenticated-code-and-paired-identity"),
                selected.Kind, selected.AuditCode, selected.RelayRequired, selected.RelayAllowed, PeerCapabilities.Windows(), remoteCaps, path);
            var directory = Path.Combine(stateDirectory, "webrtc", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            try
            {
                var turn = await FetchTurnAsync(origin, local.DeviceId, lease?.TurnAdmissionToken ?? lookup!.TurnAdmissionToken, sessionToken).ConfigureAwait(false);
                var connector = new CurrentPathWebRtcProductControlSessionConnector(
                    new WebRtcHelperLaunchClient(new(helperPath, directory, iceServersCsv: "stun:stun.l.google.com:19302",
                        launchTimeout: TimeSpan.FromSeconds(30), iceCredentialsJson: turn)), ws, new CurrentPathWebRtcHelperSignalingBridge(localJoin),
                    new(room, local.DeviceId, remoteId, fingerprint, CurrentPathProtocolSigningAlgorithm.MLDsa65,
                        TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30)));
                await using var transport = new WebRtcProductControlTransportProvider(connector, new(!hosting, 0, 15_000, useProductFraming: true));
                var context = await transport.PrepareAsync(adapter, sessionToken).ConfigureAwait(false);
                var store = new WebRtcProductSecureSessionStore();
                using var crypto = hosting ? identity.CreateInitiatorCryptoProvider(remoteId, fingerprint) : identity.CreateCryptoProvider();
                var handshake = new WebRtcProductHandshakeDriver(crypto, store, new(TimeSpan.FromSeconds(15)));
                var established = hosting ? await handshake.StartInitiatorAsync(context, sessionToken).ConfigureAwait(false)
                    : await handshake.StartResponderAsync(context, sessionToken).ConfigureAwait(false);
                try
                {
                    sessionToken.ThrowIfCancellationRequested();
                    // The helper pump was established under the bounded setup token; disarm its deadline
                    // once FIN1 succeeded. Parent cancellation remains bound to the real room lifetime.
                    (hosting ? connecting : setup).CancelAfter(Timeout.InfiniteTimeSpan);
                    RequirePaired(identity, remoteId, fingerprint);
                    using var keys = store.RequireEstablishedKeys(established);
                    await using var secure = new WindowsWebRtcFileSession(established, keys, local, paired, receive);
                    lock (_gate)
                    {
                        token.ThrowIfCancellationRequested();
                        if (!ReferenceEquals(_current, op)) throw new OperationCanceledException(token);
                        _fileSession = secure;
                    }
                    var status = $"Connected to {paired.DeviceName} · WebRTC";
                    op.Started.TrySetResult(new(DateTimeOffset.UtcNow, status, null, []));
                    Changed?.Invoke(op, status, true);
                    await secure.RunAsync(token).ConfigureAwait(false);
                }
                finally { lock (_gate) { if (ReferenceEquals(_current, op)) _fileSession = null; } store.Clear(established); }
            }
            finally { Directory.Delete(directory, recursive: true); }
        }
        catch (OperationCanceledException) when (op.Stop.IsCancellationRequested) { op.Started.TrySetCanceled(); }
        catch (Exception error)
        {
            var failure = error is OperationCanceledException ? new TimeoutException("The invitation or connection timed out.", error) : error;
            op.Started.TrySetException(failure);
            if (IsCurrent(op)) Changed?.Invoke(op, SafeFailure(failure), true);
        }
        finally
        {
            op.Ended.TrySetResult();
        }
    }

    private async Task<string> FetchTurnAsync(string origin, string localDeviceId, string turnAdmissionToken, CancellationToken token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(new Uri(origin), "/api/turn/credentials"));
        request.Headers.Add("X-API-Key", CurrentPathSignalServerClient.DefaultClientApiKey);
        request.Headers.Add("X-SkyBridge-Turn-Admission", turnAdmissionToken);
        request.Headers.Add("X-Device-Id", localDeviceId);
        using var response = await _http.SendAsync(request, token).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync(token).ConfigureAwait(false),
            new JsonDocumentOptions { AllowDuplicateProperties = false, MaxDepth = 8 });
        var root = doc.RootElement;
        string Secret(string name) => root.GetProperty(name).GetString() is { Length: > 0 and < 2048 } value && !value.Any(char.IsControl)
            ? value : throw new InvalidDataException("Invalid TURN credentials.");
        if (root.GetProperty("ttl").GetInt32() <= 0 || root.GetProperty("expiresAt").GetInt64() <= DateTimeOffset.UtcNow.ToUnixTimeSeconds())
            throw new InvalidDataException("The TURN lease has expired.");
        var urls = root.GetProperty("uris").EnumerateArray().Select(e => e.GetString()).ToArray();
        if (urls.Length is 0 or > 16 || urls.Any(u => string.IsNullOrWhiteSpace(u) || u.Length > 2048 ||
            !Uri.TryCreate(u, UriKind.Absolute, out var uri) || uri.Scheme is not ("turn" or "turns") || u.Contains('@') || u.Any(char.IsControl)))
            throw new InvalidDataException("The admitted TURN service returned invalid relay endpoints.");
        return JsonSerializer.Serialize(new { iceServers = new[] { new { urls, username = Secret("username"), credential = Secret("password") } } });
    }

    private static string SafeFailure(Exception error) => error switch
    {
        CurrentPathSignalServerException server => $"Connection service returned HTTP {(int)server.StatusCode}.",
        CurrentPathWebSocketSignalingException signal => $"Signaling failed ({signal.FailureClass}).",
        TimeoutException => "The invitation or connection timed out.",
        _ => $"Unable to establish this paired connection ({error.GetType().Name})."
    };

    private WindowsWebRtcFileSession? _fileSession;
    internal WindowsWebRtcFileRecipient? FileRecipient { get { lock (_gate) return _fileSession?.Recipient; } }
    internal Task<ClassicFileTransferResult> SendFileAsync(WindowsWebRtcFileRecipient recipient, string id, string path,
        IProgress<ClassicFileTransferProgress>? progress, CancellationToken token)
    {
        lock (_gate)
        {
            var session = _fileSession;
            if (session is null || session.Recipient != recipient) throw new InvalidOperationException("The selected WebRTC session ended.");
            return session.SendFileAsync(id, path, progress, token);
        }
    }

    internal static RemoteControlPairingMaterial RequirePaired(RemoteControlIdentityStore identity, string deviceId, string fingerprint) =>
        identity.TrustedMaterials.SingleOrDefault(p => p.DeviceId == RemoteControlHandshakeBinding.CanonicalDeviceId(deviceId) &&
            p.ProtocolPublicKeyFingerprint == fingerprint) ?? throw new InvalidOperationException("Pair this device and verify its identity before using a connection code.");

    internal static CurrentPathWebRtcSignalingPayload JoinPayload(RemoteControlPairingMaterial local) =>
        new(protocolSigningAlgorithm: local.ProtocolSigningAlgorithm, protocolPublicKeyFingerprint: local.ProtocolPublicKeyFingerprint,
            protocolPublicKeyBytes: local.ProtocolPublicKey.ToArray(), kemPublicKeys: [new(0x0101, local.MlKem768PublicKey.ToArray())],
            platform: "Windows", osVersion: Environment.OSVersion.Version.ToString());

    private static async Task<(string Id, string Fingerprint)> WaitForPeerAsync(CurrentPathWebSocketSignalingClient socket, string room,
        string localId, RemoteControlIdentityStore identity, CancellationToken token)
    {
        while (true)
        {
            var inbound = await socket.ReceiveNextAsync(token).ConfigureAwait(false);
            if (inbound.Envelope is not { Type: CurrentPathWebRtcSignalingMessageType.Join } join || join.SessionId != room ||
                join.From == localId || (join.To is not null && join.To != localId)) continue;
            var paired = identity.TrustedMaterials.SingleOrDefault(p => p.DeviceId == RemoteControlHandshakeBinding.CanonicalDeviceId(join.From));
            if (paired is null) throw new InvalidDataException("The joining device has no verified pairing.");
            if (join.Payload is { } fields && (fields.ProtocolPublicKeyBytes != null || fields.ProtocolPublicKeyFingerprint != null || fields.ProtocolSigningAlgorithm != null) &&
                (fields.ProtocolSigningAlgorithm != paired.ProtocolSigningAlgorithm || fields.ProtocolPublicKeyFingerprint != paired.ProtocolPublicKeyFingerprint ||
                fields.ProtocolPublicKeyBytes is null || !fields.ProtocolPublicKeyBytes.AsSpan().SequenceEqual(paired.ProtocolPublicKey.Span)))
                throw new InvalidDataException("The joining device no longer matches its paired identity.");
            return (join.From, paired.ProtocolPublicKeyFingerprint);
        }
    }

    internal async Task StopAsync()
    {
        Operation? previous;
        lock (_gate) { previous = _current; _current = null; _fileSession = null; previous?.Stop.Cancel(); }
        if (previous is not null) { await previous.Ended.Task.ConfigureAwait(false); previous.Stop.Dispose(); }
    }
    public async ValueTask DisposeAsync()
    {
        lock (_gate) _disposed = true;
        await StopAsync().ConfigureAwait(false);
        _http.Dispose();
    }
}
