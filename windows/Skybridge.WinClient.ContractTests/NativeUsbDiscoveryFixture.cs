using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Linq;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.Connection;
using Skybridge.WinClient.Services.RemoteControl;

// Test-only local service. It never imports user identities or grants an account/session.
internal sealed class NativeUsbDiscoveryFixture : IAsyncDisposable
{
    internal const string DeviceName = "USB iPad fixture";
    internal const string Serial = "00008132-1111111111111111";
    private readonly MLDsa _key;
    private readonly UsbPeerIdentity _identity;
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly SemaphoreSlim _signing = new(1, 1);
    private readonly SemaphoreSlim _markers = new(1, 1);
    private readonly string? _observationsPath;
    private readonly List<Task> _workers = [];
    private readonly Task _accepting;
    private readonly Func<bool> _closedPort;
    private readonly TaskCompletionSource _responded = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _responses, _portRefusals, _earlyCloses;
    private readonly LanPibResponder? _pairing;
    private readonly MLKem? _kem;
    private readonly QPeriaptRuntimeSession? _qSession;
    private readonly QPeriaptKeyPair? _qKey;
    private readonly DirectoryInfo? _qDirectory;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, string> _paired = new(StringComparer.Ordinal);
    internal int KeyRefreshReplies { get; private set; }
    internal int MainAttempts { get; private set; }
    internal Func<CancellationToken, Task>? BeforeMainReply { get; set; }
    internal bool ExpectClientHandshakeAbort { get; set; }
    internal Exception? MainFailure { get; private set; }
    internal TaskCompletionSource<ushort> MainEstablished { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource MainEnded { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal int PairingCommits { get; private set; }
    internal int Responses => Volatile.Read(ref _responses);
    internal EndPoint Endpoint => _listener.LocalEndpoint;

    internal NativeUsbDiscoveryFixture(int port = 0, Func<bool>? closedPort = null, string? observationsPath = null,
        ILanPibApprovalPresenter? pairingApproval = null, bool policyBoundMain = false)
    {
        if (!OperatingSystem.IsWindows() || !MLDsa.IsSupported)
            throw new PlatformNotSupportedException("The native USB fixture requires Windows ML-DSA.");
        _key = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        try
        {
            var publicKey = _key.ExportMLDsaPublicKey().ToImmutableArray();
            _identity = new(Guid.NewGuid().ToString("D"), "ML-DSA-65", publicKey,
                WebRtcProductProtocolIdentityPublicKey.ComputeAuthoritativeFingerprint(WebRtcProductSignatureAlgorithm.MlDsa65, publicKey.AsSpan()));
            if (pairingApproval is not null)
            {
                _kem = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
                if (policyBoundMain)
                {
                    _qDirectory = Directory.CreateTempSubdirectory("skybridge-usb-peer-q-");
                    _qSession = QPeriaptRuntimeSession.Prepare(new QPeriaptTrustedStateStore(_qDirectory.FullName,
                        new DpapiSessionProtector(), AtomicSessionFileCommitter.Instance), identityAlreadyEnrolled: false);
                    _qKey = QPeriaptNativeClient.GenerateKeyPair(_qSession.Decision);
                }
                _pairing = new(new("id:" + _identity.DeviceID, DeviceName, publicKey),
                    bytes => _key.SignData(bytes).ToImmutableArray(),
                    (peer, bytes, signature) =>
                    {
                        using var verifier = MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm.MLDsa65, peer.AsSpan());
                        if (!verifier.VerifyData(bytes, signature.AsSpan())) throw new CryptographicException("Fixture rejected the request signature.");
                    }, _ => { }, (material, guard, _) =>
                    {
                        guard(); _paired[material.DeviceId] = material.ProtocolPublicKeyFingerprint;
                        PairingCommits++; return Task.CompletedTask;
                    }, pairingApproval, _lifetime.Token.ThrowIfCancellationRequested);
            }
            _closedPort = closedPort ?? (() => false);
            _observationsPath = observationsPath;
            _listener = new(IPAddress.Loopback, port);
            _listener.Start();
            _accepting = AcceptAsync();
        }
        catch (Exception failure)
        {
            var cleanup = new List<Exception>();
            try { _kem?.Dispose(); } catch (Exception error) { cleanup.Add(error); }
            try { _qKey?.Dispose(); } catch (Exception error) { cleanup.Add(error); }
            try { _qDirectory?.Delete(recursive: true); } catch (Exception error) { cleanup.Add(error); }
            try { _key.Dispose(); } catch (Exception error) { cleanup.Add(error); }
            if (cleanup.Count > 0) throw new AggregateException("USB fixture construction and cleanup failed.", new[] { failure }.Concat(cleanup));
            throw;
        }
    }

    private async Task AcceptAsync()
    {
        while (!_lifetime.IsCancellationRequested)
        {
            var client = await _listener.AcceptTcpClientAsync(_lifetime.Token).ConfigureAwait(false);
            if (_workers.Count >= 128) { client.Dispose(); throw new IOException("USB fixture request capacity exceeded."); }
            _workers.Add(ServeAsync(client));
        }
    }

    private async Task ServeAsync(TcpClient client)
    {
        ProductControlStreamTransport? owner = null;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);
        deadline.CancelAfter(TimeSpan.FromSeconds(8));
        try
        {
            var stream = client.GetStream();
            byte[] header = new byte[16]; await stream.ReadExactlyAsync(header, deadline.Token);
            uint length = BinaryPrimitives.ReadUInt32LittleEndian(header);
            uint tag = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(12));
            if (length is < 16 or > 65_536 || tag is not (1 or 2)) throw new InvalidDataException("Invalid fixture request header.");
            byte[] packet = new byte[checked((int)length)]; header.CopyTo(packet, 0);
            await stream.ReadExactlyAsync(packet.AsMemory(16), deadline.Token);
            using var frame = new MemoryStream(packet);
            var request = await UsbMuxProtocol.ReadAsync(frame, tag, deadline.Token);
            string kind = UsbMuxProtocol.Required(request, "MessageType", "string").Value;
            if (kind == "ListDevices")
            {
                var row = UsbMuxProtocol.Dictionary(("DeviceID", new("integer", 7)), ("Properties",
                    UsbMuxProtocol.Dictionary(("DeviceID", new("integer", 7)), ("ProductID", new("integer", 4779)),
                        ("SerialNumber", new("string", Serial)), ("ConnectionType", new("string", "USB")))));
                await stream.WriteAsync(UsbMuxProtocol.Packet(UsbMuxProtocol.Dictionary(("DeviceList", new("array", row))), tag), deadline.Token);
                return;
            }
            if (kind != "Connect" || UsbMuxProtocol.Integer(request, "DeviceID") != 7 ||
                UsbMuxProtocol.Integer(request, "PortNumber") != BinaryPrimitives.ReverseEndianness(UsbMuxConnector.ControlPort))
                throw new InvalidDataException("Fixture received an unexpected device or port.");
            bool closed = _closedPort();
            await stream.WriteAsync(UsbMuxProtocol.Packet(UsbMuxProtocol.Dictionary(
                ("MessageType", new("string", "Result")), ("Number", new("integer", closed ? 3 : 0))), tag), deadline.Token);
            if (closed)
            {
                Interlocked.Increment(ref _portRefusals);
                await PublishObservationsAsync();
                return;
            }
            owner = new(client, LanBootstrapWire.MaximumBytes, LanBootstrapWire.MaximumBytes);
            var payload = await owner.ReadAsync(deadline.Token);
            if (_kem is not null && !payload.IsEmpty && payload.Span[0] != (byte)'{')
            {
                var mainOwner = owner; owner = null;
                deadline.CancelAfter(TimeSpan.FromSeconds(20));
                await ServeMainAsync(mainOwner, payload, ((IPEndPoint)client.Client.RemoteEndPoint!).Address, deadline.Token);
                return;
            }
            string message = LanBootstrapWire.ReadDiscriminator(payload.Span);
            if (_pairing is { } pairing && message is "protocolIdentityBindingRequest" or "protocolIdentityBindingConfirm")
            {
                var reply = message == "protocolIdentityBindingRequest"
                    ? LanPibWire.EncodeCandidate(pairing.CreateCandidate(LanPibWire.DecodeRequest(payload.Span), deadline.Token))
                    : LanPibWire.EncodeFinalAck(await pairing.ConfirmAsync(LanPibWire.DecodeConfirm(payload.Span), deadline.Token));
                await owner.SendAsync(reply, deadline.Token);
                return;
            }
            if (_kem is { } kem && message == "kemRefreshRequest")
            {
                var refresh = SignedLanKemRefreshWire.DecodeRequest(payload.Span);
                SignedLanKemRefreshCanonical.RequireRequestFreshness(refresh, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
                if (!_paired.TryGetValue(RemoteControlHandshakeBinding.CanonicalDeviceId(refresh.RequesterDeviceId), out var pin) ||
                    pin != refresh.RequesterProtocolIdentityFingerprint || refresh.TargetDeviceId != _identity.DeviceID ||
                    refresh.TargetProtocolIdentityFingerprint != _identity.Fingerprint)
                    throw new InvalidDataException("The native fixture has no matching approved requester.");
                long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                double sent = now / 1000.0 - 978307200.0;
                ImmutableArray<int> permitted = _qSession is null ? [257] : [18,257];
                var common = SignedLanKemRefreshCanonical.Intersection(refresh.RequestedSuiteWireIds, permitted,
                    refresh.QPeriaptAuthProfile, _qSession?.AuthProfile);
                var keyList = new List<LanKemRefreshPublicKey>();
                if (common.Contains(18)) keyList.Add(new(18,QPeriaptKeyEncoding.ExportPublic(_qKey ?? throw new InvalidOperationException("Missing native Q key.")).ToImmutableArray()));
                if (common.Contains(257)) keyList.Add(new(257,kem.ExportEncapsulationKey().ToImmutableArray()));
                var keys = keyList.ToImmutableArray();
                // Advertise only the native keys this isolated service owns.
                var response = new LanSignedKemRefresh(_identity.DeviceID, "ML-DSA-65", _identity.PublicKey,
                    _identity.Fingerprint, keys, SignedLanKemRefreshResponder.KeyId(_identity.Fingerprint, keys), now,
                    sent, sent + 300, refresh.Nonce, [], 3, [], SignedLanKemRefreshCanonical.RequestHash(refresh),
                    BonjourEndpointDigest: refresh.BonjourEndpointDigest, Platform: _qSession is null ? "ios" : "windows",
                    OsVersion: _qSession is null ? "iOS 27.0" : QPeriaptPeerPlatform.LocalVersion(),
                    PermittedSuiteWireIds: permitted, QPeriaptAuthProfile: _qSession?.AuthProfile);
                response = response with { Signature = _key.SignData(SignedLanKemRefreshCanonical.ResponsePreimage(response)).ToImmutableArray() };
                await owner.SendAsync(SignedLanKemRefreshWire.EncodeResponse(response), deadline.Token);
                KeyRefreshReplies++;
                return;
            }
            var discovery = LanBootstrapWire.Decode<UsbPeerDiscoveryRequest>(payload.Span, "usbPeerDiscoveryRequest");
            var unsigned = new UsbPeerDiscoveryResponse(discovery, _identity, DeviceName, "ios", []);
            ImmutableArray<byte> signature;
            await _signing.WaitAsync(deadline.Token);
            try { signature = _key.SignData(UsbPeerDiscoveryWire.SigningData(unsigned)).ToImmutableArray(); }
            finally { _signing.Release(); }
            await owner.SendAsync(LanBootstrapWire.Encode("usbPeerDiscoveryResponse", unsigned with { Signature = signature }), deadline.Token);
            Interlocked.Increment(ref _responses);
            await PublishObservationsAsync();
            _responded.TrySetResult();
        }
        catch (EndOfStreamException) { Interlocked.Increment(ref _earlyCloses); }
        finally
        {
            if (owner is not null) await owner.DisposeAsync();
            else client.Dispose();
        }
    }

    private async Task ServeMainAsync(ProductControlStreamTransport transport, ReadOnlyMemory<byte> first,
        IPAddress remoteAddress, CancellationToken token)
    {
        MainAttempts++;
        LanProductControlSession? session = null;
        try
        {
            var candidate = RemoteControlHandshakeBinding.ValidateAndResolveMessageA(first, "id:" + _identity.DeviceID,
                _paired.Select(p => new RemoteControlTrustedPeer(p.Key, p.Value)).ToArray());
            if (BeforeMainReply is { } pause) await pause(token);
            var kem = _kem ?? throw new InvalidOperationException("Fixture MAIN requires its actual native KEM key.");
            byte[] signing = _key.ExportMLDsaPrivateKey(), decapsulation = kem.ExportDecapsulationKey();
            byte[] qPrivate = _qKey is null ? [] : QPeriaptKeyEncoding.ExportPrivate(_qKey);
            WebRtcProductPqcHandshakeCryptoProvider crypto;
            try
            {
                crypto = _qSession is { } policy
                    ? new(new(signing, ReadOnlyMemory<byte>.Empty, decapsulation, policy, ReadOnlyMemory<byte>.Empty, qPrivate))
                    : new(new(signing, ReadOnlyMemory<byte>.Empty, decapsulation));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(signing); CryptographicOperations.ZeroMemory(decapsulation);
                CryptographicOperations.ZeroMemory(qPrivate);
            }
            ushort suite;
            using (crypto)
            using (var handshake = await new ProductHandshakeCore(crypto).AcceptResponderAsync(transport, candidate.Peer, candidate.MessageAFrame, token))
            {
                suite = handshake.SuiteWireId;
                var material = RemoteControlPairingMaterial.Create("id:" + _identity.DeviceID, DeviceName,
                    _identity.PublicKey.AsSpan(), kem.ExportEncapsulationKey());
                var identity = new RemoteControlSecurityIdentity("USB fixture", "fixture", material.DeviceId, material.DeviceName);
                // The emulated service has a real TCP endpoint on the test runner;
                // only the Windows product's client carrier is a typed USB route.
                session = new(transport, handshake.Keys, candidate.Peer,
                    LanProductControlMessages.LocalIdentity(identity, material, null, DateTimeOffset.UtcNow),
                    null, remoteAddress, _lifetime.Token, handshake.LocalProtocolIdentity,
                    handshake.PeerProtocolIdentity, handshake.ExportInitiatorExtensions());
            }
            await session.CompleteAdmissionAsync(token);
            MainEstablished.TrySetResult(suite);
            await session.Completion;
        }
        catch (IOException error) when (ExpectClientHandshakeAbort)
        {
            // Only explicit client-revocation/identity-rejection tests permit a transport abort.
            // Preserve the actual failure; no session or success is fabricated.
            MainFailure = error;
        }
        finally
        {
            try
            {
                if (session is not null) await session.DisposeAsync();
                else await transport.DisposeAsync();
            }
            finally { MainEnded.TrySetResult(); }
        }
    }

    public async ValueTask DisposeAsync()
    {
        _lifetime.Cancel(); _listener.Stop();
        var failures = new List<Exception>();
        foreach (var task in new[] { _accepting })
        {
            try { await task.ConfigureAwait(false); }
            catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { }
            catch (Exception error) { failures.Add(error); }
        }
        foreach (var task in _workers)
        {
            try { await task.ConfigureAwait(false); }
            catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { }
            catch (Exception error) { failures.Add(error); }
        }
        try { _key.Dispose(); } catch (Exception error) { failures.Add(error); }
        try { _kem?.Dispose(); } catch (Exception error) { failures.Add(error); }
        try { _qKey?.Dispose(); } catch (Exception error) { failures.Add(error); }
        try { _qDirectory?.Delete(recursive: true); } catch (Exception error) { failures.Add(error); }
        _signing.Dispose(); _markers.Dispose(); _lifetime.Dispose();
        if (failures.Count > 0) throw new AggregateException("Native USB fixture failed.", failures);
    }

    private string Observations(bool drained) => JsonSerializer.Serialize(new
    {
        responses = Responses, portRefusals = Volatile.Read(ref _portRefusals), earlyCloses = Volatile.Read(ref _earlyCloses),
        drained, mode = "synthetic-service", actualAppleService = false, actualUsbDevice = false, audioPlayed = false
    });
    private async Task PublishObservationsAsync()
    {
        if (_observationsPath is not { } path) return;
        await _markers.WaitAsync();
        try { await WriteAtomicAsync(path, Observations(drained: false)); }
        finally { _markers.Release(); }
    }
    private static async Task WriteAtomicAsync(string path, string contents)
    {
        string temporary = path + ".tmp";
        await File.WriteAllTextAsync(temporary, contents);
        File.Move(temporary, path, overwrite: true);
    }

    internal static async Task RoundTrip()
    {
        await using var server = new NativeUsbDiscoveryFixture();
        var connector = new UsbMuxConnector(token => UsbMuxConnector.ConnectSocket(server.Endpoint, token));
        var client = new UsbPeerDiscoveryClient(connector);
        using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(12));
        var result = await client.InspectAsync(Serial, limit.Token);
        await server._responded.Task.WaitAsync(limit.Token);
        if (result.Response.Identity.DeviceID != server._identity.DeviceID ||
            result.Response.Identity.Algorithm != server._identity.Algorithm ||
            result.Response.Identity.Fingerprint != server._identity.Fingerprint ||
            !result.Response.Identity.PublicKey.AsSpan().SequenceEqual(server._identity.PublicKey.AsSpan()) ||
            result.Response.Name != DeviceName || server.Responses != 1)
            throw new InvalidDataException("Actual native USB discovery did not bind its signed peer.");
    }

    internal static async Task RunUiAsync(string directory)
    {
        if (Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true")
            throw new InvalidOperationException("The fixed-port UI fixture is restricted to the owned CI runner.");
        directory = Path.GetFullPath(directory); Directory.CreateDirectory(directory);
        string ready = Path.Combine(directory, "ready.json"), stop = Path.Combine(directory, "stop"), closedPort = Path.Combine(directory, "closed-port");
        if (Directory.EnumerateFileSystemEntries(directory).Any()) throw new IOException("Choose a fresh USB fixture directory.");
        string observations = Path.Combine(directory, "observations.json");
        var server = new NativeUsbDiscoveryFixture(27015, () => File.Exists(closedPort), observations);
        try
        {
            await server.PublishObservationsAsync();
            await WriteAtomicAsync(ready, JsonSerializer.Serialize(new { processId = Environment.ProcessId, name = DeviceName,
                mode = "synthetic-service", actualAppleService = false, actualUsbDevice = false }));
            var expires = DateTimeOffset.UtcNow.AddMinutes(5);
            while (!File.Exists(stop))
            {
                if (DateTimeOffset.UtcNow >= expires) throw new TimeoutException("The UI fixture reached its five-minute limit.");
                if (server._accepting.IsCompleted) { await server._accepting; throw new IOException("The fixture listener ended before stop."); }
                await Task.Delay(100);
            }
        }
        finally { await server.DisposeAsync(); }
        await WriteAtomicAsync(observations, server.Observations(drained: true));
    }
}
