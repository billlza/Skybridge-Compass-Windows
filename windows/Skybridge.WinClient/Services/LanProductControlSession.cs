using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Skybridge.WinClient.Services.Connection;

namespace Skybridge.WinClient.Services;

/// <summary>One authenticated compatible-LAN control session shared by native feature operations.</summary>
internal sealed partial class LanProductControlSession : IAsyncDisposable
{
    private readonly ProductControlStreamTransport _transport;
    private readonly ProductSessionKeys _keys;
    private readonly WebRtcAppSecureSessionKeys _appKeys;
    private readonly ProductHandshakePeerContext _peer;
    private readonly LanProductIdentity _localIdentity;
    private readonly byte[] _initiatorExtensions;
    // Incoming TCP identifies its actual remote address, not a discovered listening
    // endpoint. It cannot authorize a selected outbound file route by implication.
    private readonly Func<bool> _isAuthorityCurrent;
    private readonly CancellationTokenSource _lifetime;
    private readonly Audio.LanAudioReceiver _audio;
    private readonly TaskCompletionSource _admitted = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _readyForHeartbeat = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly object _stateGate = new();
    private readonly ulong _admissionPing = BinaryPrimitives.ReadUInt64BigEndian(RandomNumberGenerator.GetBytes(8));
    private readonly Task _receiver;
    private readonly Task _heartbeat;
    private readonly Task<Exception?> _completion;
    private readonly SemaphoreSlim _disposal = new(1, 1);
    private int _disposed;
    private Exception? _disposalFailure;
    private int _admissionStarted;
    private bool _ready;
    private bool _receivedAdmissionPong;
    private LanProductIdentity? _remoteIdentity;
    private long _unavailableAudioFrames;
    private long _audioQueueOverflows;
    private volatile bool _captureReceiverEnabled;
    private volatile bool _originalFileReceiverEnabled;
    private volatile bool _flacFileReceiverEnabled;
    private volatile bool _alacFileReceiverEnabled;
    private Audio.AudioOriginalFileReceiveRegistry.UsbRegistration? _usbFileReceiver;
    internal const string CaptureReceiveCapability = "audio_capture_receive_v1";
    internal const string OriginalFileReceiveCapability = "audio_file_receive_v1";
    internal const string FlacFileReceiveCapability = "audio_flac_file_receive_v1";
    internal const string AlacFileReceiveCapability = "audio_alac_file_receive_v1";
    internal ushort? LocalFileTransferPort => _localIdentity.FileTransferPort;

    internal LanProductControlSession(ProductControlStreamTransport transport, ProductSessionKeys keys,
        ProductHandshakePeerContext peer, LanProductIdentity localIdentity, DiscoveryPeerEndpoint? controlEndpoint,
        IPAddress remoteAddress, CancellationToken cancellationToken,
        ProductHandshakeProtocolIdentity localHandshakeIdentity, ProductHandshakeProtocolIdentity peerHandshakeIdentity,
        ReadOnlyMemory<byte> initiatorExtensions)
        : this(transport, keys, peer, localIdentity, new ProductControlCarrier.Network(remoteAddress, controlEndpoint),
            cancellationToken, localHandshakeIdentity, peerHandshakeIdentity, initiatorExtensions, static () => true) { }

    internal LanProductControlSession(ProductControlStreamTransport transport, ProductSessionKeys keys,
        ProductHandshakePeerContext peer, LanProductIdentity localIdentity, ProductControlCarrier carrier,
        CancellationToken cancellationToken,
        ProductHandshakeProtocolIdentity localHandshakeIdentity, ProductHandshakeProtocolIdentity peerHandshakeIdentity,
        ReadOnlyMemory<byte> initiatorExtensions, Func<bool> isAuthorityCurrent, CancellationToken ownerLifetime = default)
    {
        ArgumentNullException.ThrowIfNull(carrier); ArgumentNullException.ThrowIfNull(isAuthorityCurrent);
        if (carrier is ProductControlCarrier.Network { RemoteAddress: null } || carrier is ProductControlCarrier.Usb { Route: null } ||
            carrier is ProductControlCarrier.Usb usb && (usb.Route.PeerDeviceId != peer.PeerDeviceId || usb.Route.Fingerprint != peer.PeerPublicKeyFingerprint))
            throw new InvalidDataException("The control carrier does not match the authenticated peer.");
        if (carrier is ProductControlCarrier.Usb usbCarrier)
        {
            ArgumentNullException.ThrowIfNull(usbCarrier.AccountScope);
            usbCarrier.AccountScope.Validate();
        }
        ArgumentNullException.ThrowIfNull(localHandshakeIdentity);
        ArgumentNullException.ThrowIfNull(peerHandshakeIdentity);
        if (peerHandshakeIdentity.Fingerprint != peer.PeerPublicKeyFingerprint)
            throw new InvalidDataException("LAN handshake identity differs from the selected peer.");
        LanProductControlMessages.ValidateLocalIdentity(localIdentity, localHandshakeIdentity);
        LocalHandshakeIdentity = localHandshakeIdentity;
        PeerHandshakeIdentity = peerHandshakeIdentity;
        _initiatorExtensions = initiatorExtensions.ToArray();
        _transport = transport;
        _keys = keys.Clone();
        _appKeys = WebRtcProductHandshakeSessionKeys.ToWebRtcKeys(keys);
        _peer = peer;
        _localIdentity = localIdentity;
        Carrier = carrier; _isAuthorityCurrent = isAuthorityCurrent;
        _lifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, ownerLifetime);
        Lifetime = _lifetime.Token;
        _audio = new(() => IsReady, Lifetime);
        _receiver = ReceiveAsync();
        _heartbeat = HeartbeatAsync();
        _completion = ObserveAsync();
    }

    internal Task<Exception?> Completion => _completion;
    internal CancellationToken Lifetime { get; }
    internal ProductControlCarrier Carrier { get; }
    internal IPAddress RemoteAddress => Carrier is ProductControlCarrier.Network network ? network.RemoteAddress
        : throw new InvalidOperationException("USB sessions have no remote IP address.");
    internal string SessionId => _keys.SessionId;
    internal string PeerDeviceId => _peer.PeerDeviceId;
    internal LanProductIdentity LocalIdentity => _localIdentity;
    // Historical handshake evidence; callers must also enforce this owner's current IsReady/Lifetime.
    internal ProductHandshakeProtocolIdentity LocalHandshakeIdentity { get; }
    internal ProductHandshakeProtocolIdentity PeerHandshakeIdentity { get; }
    internal bool IsReady => Volatile.Read(ref _ready) && !Lifetime.IsCancellationRequested && Volatile.Read(ref _disposed) == 0 && _isAuthorityCurrent();
    internal long UnavailableAudioFrames => Interlocked.Read(ref _unavailableAudioFrames);
    internal long AudioQueueOverflows => Interlocked.Read(ref _audioQueueOverflows);
    internal string PeerDisplayName => Volatile.Read(ref _remoteIdentity)?.DeviceName ?? _peer.PeerDeviceId;

    internal static async Task<LanProductControlSession> ConnectAsync(ProductPeerAuthentication authentication,
        ushort? localFileTransferPort, CancellationToken cancellationToken)
    {
        using var authority = authentication;
        var endpoint = authority.Endpoint;
        if (endpoint.Service != SkyBridgeProtocolConstants.TcpControlDnsSdService || endpoint.Provenance != "resolved-dns-sd-endpoint" ||
            string.IsNullOrWhiteSpace(endpoint.HostName) || endpoint.Port == 0)
            throw new InvalidDataException("LAN control requires the selected resolved product-control endpoint.");
        var client = new TcpClient();
        ProductControlStreamTransport? transport = null;
        LanProductControlSession? session = null;
        try
        {
            using (var connecting = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                connecting.CancelAfter(TimeSpan.FromSeconds(10));
                try { await client.ConnectAsync(endpoint.HostName, endpoint.Port, connecting.Token).ConfigureAwait(false); }
                catch (OperationCanceledException error) when (!cancellationToken.IsCancellationRequested && connecting.IsCancellationRequested)
                { throw new TimeoutException("The selected peer did not accept the LAN control connection within 10 seconds.", error); }
            }
            transport = new(client, LanProductControlMessages.MaximumFrameBytes, LanProductControlMessages.MaximumFrameBytes);
            using var handshake = await new ProductHandshakeCore(authority.Crypto)
                .StartInitiatorAsync(transport, authority.Peer, cancellationToken).ConfigureAwait(false);
            var remoteAddress = (client.Client.RemoteEndPoint as IPEndPoint)?.Address
                ?? throw new IOException("The authenticated TCP connection has no IP endpoint.");
            session = new(transport, handshake.Keys, authority.Peer,
                LanProductControlMessages.LocalIdentity(authority, localFileTransferPort, DateTimeOffset.UtcNow),
                endpoint, remoteAddress, cancellationToken, handshake.LocalProtocolIdentity, handshake.PeerProtocolIdentity,
                handshake.ExportInitiatorExtensions());
            transport = null;
            await session.CompleteAdmissionAsync(cancellationToken).ConfigureAwait(false);
            return session;
        }
        catch (Exception failure)
        {
            try
            {
                if (session is not null) await session.DisposeAsync().ConfigureAwait(false);
                else if (transport is not null) await transport.DisposeAsync().ConfigureAwait(false);
                else client.Dispose();
            }
            catch (Exception cleanup) { throw new AggregateException("LAN connection and cleanup failed.", failure, cleanup); }
            throw;
        }
    }

    internal async Task CompleteAdmissionAsync(CancellationToken cancellationToken)
    {
        if (Interlocked.Exchange(ref _admissionStarted, 1) != 0)
            throw new InvalidOperationException("This control session has already started peer admission.");
        await SendAsync(LanControlMessageKind.Identity, _localIdentity, cancellationToken).ConfigureAwait(false);
        await SendAsync(LanControlMessageKind.Ping, new LanProductPing(_admissionPing), cancellationToken).ConfigureAwait(false);
        // This ordered pong follows the peer's identity/approval commit and its
        // admission of the exact control-session keys for classic transfers.
        var admission = await Task.WhenAny(_admitted.Task, _completion)
            .WaitAsync(TimeSpan.FromSeconds(60), cancellationToken).ConfigureAwait(false);
        if (admission == _completion)
            throw new IOException("The peer did not complete authenticated LAN admission.", await _completion.ConfigureAwait(false));
        await _admitted.Task.ConfigureAwait(false);
        if (Lifetime.IsCancellationRequested) throw new IOException("The LAN session ended during peer admission.");
        RequireAuthorityCurrent();
        Volatile.Write(ref _ready, true);
        _readyForHeartbeat.TrySetResult();
    }

    internal Audio.AudioSessionIdentityBinding RequireAudioIdentityBinding()
    {
        lock (_stateGate)
        {
            if (!IsReady) throw new InvalidOperationException("Audio requires a live admitted MAIN session.");
            _audio.RequireLiveOwner();
            var remote = Volatile.Read(ref _remoteIdentity) ?? throw new InvalidOperationException("Peer identity is not established.");
            return Audio.AudioSessionIdentityBinding.Capture(_keys, _localIdentity.DeviceId, remote.DeviceId,
                LocalHandshakeIdentity, PeerHandshakeIdentity, _initiatorExtensions);
        }
    }

    internal Task<Audio.ILanAudioStreamInbox> AcceptAudioOfferAsync(CancellationToken cancellationToken) =>
        _audio.AcceptOfferAsync(RequireAudioIdentityBinding(), cancellationToken);

    internal void RequireOwnedAudioInbox(Audio.ILanAudioStreamInbox inbox) => _audio.RequireOwnedInbox(inbox);

    internal Task SetCaptureReceiverEnabledAsync(bool enabled, CancellationToken cancellationToken) =>
        SetAudioReceiverCapabilitiesAsync(enabled, false, cancellationToken);

    internal Task SetAudioReceiverCapabilitiesAsync(bool capture, bool originalFile, CancellationToken cancellationToken) =>
        SetAudioReceiverCapabilitiesAsync(capture, originalFile ? Audio.AudioOriginalFileReceiveSupport.Wave :
            Audio.AudioOriginalFileReceiveSupport.Unavailable, cancellationToken);

    internal async Task SetAudioReceiverCapabilitiesAsync(bool capture, Audio.AudioOriginalFileReceiveSupport fileSupport, CancellationToken cancellationToken,
        Audio.AudioOriginalFileReceiveRegistry.UsbRegistration? usbReceiver = null)
    {
        if (!Enum.IsDefined(fileSupport)) throw new ArgumentOutOfRangeException(nameof(fileSupport));
        bool originalFile = fileSupport != Audio.AudioOriginalFileReceiveSupport.Unavailable;
        lock (_stateGate)
        {
            if (originalFile)
            {
                if (Carrier is ProductControlCarrier.Usb)
                    (usbReceiver ?? throw new InvalidOperationException("USB file reception requires its installed return owner.")).RequireCurrentFor(this);
                else if (_localIdentity.FileTransferPort is null or 0 || usbReceiver is not null)
                    throw new InvalidOperationException("Original-file reception requires its actual authenticated listener port.");
            }
            _audio.SetConsumerAdvertisement(capture || originalFile);
            _captureReceiverEnabled = capture; _originalFileReceiverEnabled = originalFile;
            _flacFileReceiverEnabled = fileSupport is Audio.AudioOriginalFileReceiveSupport.WaveAndFlac or Audio.AudioOriginalFileReceiveSupport.WaveFlacAndAlac;
            _alacFileReceiverEnabled = fileSupport is Audio.AudioOriginalFileReceiveSupport.WaveAndAlac or Audio.AudioOriginalFileReceiveSupport.WaveFlacAndAlac;
            _usbFileReceiver = originalFile ? usbReceiver : null;
        }
        // A retired session has no peer to notify; disabling is still immediate.
        if (!IsReady && !capture && !originalFile) return;
        await PublishCurrentCapabilitiesAsync(identity: true, cancellationToken).ConfigureAwait(false);
    }
    private async Task PublishCurrentCapabilitiesAsync(bool identity, CancellationToken cancellationToken)
    {
        await _transport.SendAdmittedAsync(() =>
        {
            lock (_stateGate)
            {
                if (!IsReady) throw new InvalidOperationException("Audio capability publication requires an admitted MAIN session.");
                // Resolve the newest state only after acquiring the shared writer.
                // A queued enable cannot restore capability after local disabling.
                double now = LanProductControlMessages.Timestamp(DateTimeOffset.UtcNow);
                var plaintext = identity
                    ? LanProductControlMessages.Encode(LanControlMessageKind.Identity, _localIdentity with { Capabilities = CurrentCapabilities(), SentAt = now })
                    : LanProductControlMessages.Encode(LanControlMessageKind.Heartbeat,
                        new LanProductHeartbeat(now, _localIdentity.DeviceId, CurrentCapabilities(), _localIdentity.FileTransferPort));
                try { return ProductControlTrafficPadding.Wrap(WebRtcControlChannelCodec.EncryptAppleLegacyAppPayload(plaintext, _appKeys)); }
                finally { CryptographicOperations.ZeroMemory(plaintext); }
            }
        }, cancellationToken).ConfigureAwait(false);
    }
    private string[] CurrentCapabilities()
    {
        bool usbReturn = _originalFileReceiverEnabled && _usbFileReceiver?.IsCurrentFor(this) == true;
        bool file = _originalFileReceiverEnabled && (Carrier is ProductControlCarrier.Network || usbReturn);
        return (_localIdentity.Capabilities ?? [])
            .Where(value => value != CaptureReceiveCapability && value != OriginalFileReceiveCapability && value != FlacFileReceiveCapability && value != AlacFileReceiveCapability &&
                value != Audio.AudioStreamingWire.UsbFileReturnReceiveCapability && value != FileTransfer.ClassicFileTransferWire.ApprovalCapability)
            .Concat(_captureReceiverEnabled ? [CaptureReceiveCapability] : Array.Empty<string>())
            .Concat(file ? [OriginalFileReceiveCapability] : Array.Empty<string>())
            .Concat(file && _flacFileReceiverEnabled ? [FlacFileReceiveCapability] : Array.Empty<string>())
            .Concat(file && _alacFileReceiverEnabled ? [AlacFileReceiveCapability] : Array.Empty<string>())
            .Concat(usbReturn ? [Audio.AudioStreamingWire.UsbFileReturnReceiveCapability, FileTransfer.ClassicFileTransferWire.ApprovalCapability] : Array.Empty<string>()).ToArray();
    }

    private async Task DeclineUnattendedAudioOfferAsync(Guid streamId)
    {
        // Only a validated offer retired atomically by this MAIN reader reaches
        // here. This is a negative reply; it grants neither a stream nor playback.
        var bytes = Audio.AudioStreamingLanEnvelope.Encode(new(streamId,
            new Audio.AudioStreamingBody.Stop(Audio.AudioStreamingStopReason.ReceiverDeclined)));
        try
        {
            await _transport.SendAdmittedAsync(() =>
            {
                if (!IsReady) throw new InvalidOperationException("The MAIN owner ended before declining audio.");
                return ProductControlTrafficPadding.Wrap(WebRtcControlChannelCodec.EncryptAppleLegacyAppPayload(bytes, _appKeys));
            }, Lifetime).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    // The service must supply a bounded, synchronous account-lease and playback-permission check.
    // It runs under the exact owner locks after the shared TCP writer is acquired; no I/O or re-entry.
    internal Task SendAudioReplyAsync(Audio.ILanAudioStreamInbox inbox, Audio.AudioStreamingMessage message,
        Action requireEffectAuthorization, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requireEffectAuthorization);
        ArgumentNullException.ThrowIfNull(message);
        if (message.Body is not (Audio.AudioStreamingBody.Accept or Audio.AudioStreamingBody.Credit or
            Audio.AudioStreamingBody.ContentVerified or Audio.AudioStreamingBody.OutputReady or Audio.AudioStreamingBody.PlaybackComplete))
            throw new InvalidDataException("This interface accepts only authorized audio receiver replies.");
        return SendAudioAsync(inbox, message, requireEffectAuthorization, cancellationToken);
    }

    // A rejection/stop may be sent after playback permission was revoked, but never on a stale owner.
    internal Task SendAudioStopAsync(Audio.ILanAudioStreamInbox inbox, Audio.AudioStreamingStopReason reason,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(inbox);
        return SendAudioAsync(inbox, new(inbox.StreamId, new Audio.AudioStreamingBody.Stop(reason)), null, cancellationToken);
    }

    private async Task SendAudioAsync(Audio.ILanAudioStreamInbox inbox, Audio.AudioStreamingMessage message,
        Action? requireEffectAuthorization, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var send = _audio.BeginSend(inbox, message.StreamId);
        var plaintext = Audio.AudioStreamingLanEnvelope.Encode(message);
        try
        {
            await _transport.SendAdmittedAsync(() =>
            {
                lock (_stateGate)
                {
                    if (!IsReady) throw new InvalidOperationException("Audio reply requires its live MAIN owner.");
                    return send.Admit<ReadOnlyMemory<byte>>(() =>
                    {
                        requireEffectAuthorization?.Invoke();
                        return ProductControlTrafficPadding.Wrap(
                            WebRtcControlChannelCodec.EncryptAppleLegacyAppPayload(plaintext, _appKeys));
                    });
                }
            }, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            send.RequireCurrent();
        }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    internal byte[] AuthorizeFileTransfer(DiscoveryBrowserPeerCandidate candidate, string transferId)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        lock (_stateGate)
        {
            RequireFileTransferRoute(candidate);
            return FileTransfer.ClassicFileTransferWire.DeriveTransferKey(_keys, transferId);
        }
    }

    internal void RequireFileTransferRoute(DiscoveryBrowserPeerCandidate candidate)
    {
        lock (_stateGate)
        {
            if (!IsReady) throw new InvalidOperationException("An established LAN control session is required for file transfer.");
            if (Carrier is not ProductControlCarrier.Network { OutboundEndpoint: { } controlEndpoint })
                throw new InvalidDataException("An incoming MAIN session has no admitted outbound discovery route.");
            var identity = Volatile.Read(ref _remoteIdentity) ?? throw new InvalidOperationException("Peer identity is not established.");
            var route = candidate.Routes.FileTransfer ?? throw new InvalidOperationException("The peer has no resolved file-transfer route.");
            var control = candidate.Routes.Control ?? throw new InvalidOperationException("The peer has no resolved control route.");
            if (RemoteControlHandshakeBinding.CanonicalDeviceId(candidate.Peer.DeviceId) != _peer.PeerDeviceId ||
                candidate.Peer.PublicKeyFingerprint != _peer.PeerPublicKeyFingerprint || control != controlEndpoint ||
                route.Service != SkyBridgeProtocolConstants.FileTransferDnsSdService || route.Provenance != "resolved-dns-sd-endpoint" ||
                !string.Equals(route.HostName.TrimEnd('.'), control.HostName.TrimEnd('.'), StringComparison.OrdinalIgnoreCase) ||
                route.Port != identity.FileTransferPort || identity.Capabilities?.Contains("file_transfer", StringComparer.Ordinal) != true)
                throw new InvalidDataException("The authenticated control identity did not admit the selected file-transfer route.");
        }
    }

    internal byte[] AuthorizeIncomingTransfer(FileTransfer.ClassicFileMetadata metadata, IPAddress remoteAddress)
    {
        lock (_stateGate)
        {
            if (!IsReady || Carrier is not ProductControlCarrier.Network network ||
                !network.RemoteAddress.MapToIPv6().Equals(remoteAddress.MapToIPv6()) || metadata.SenderDeviceId is null ||
                RemoteControlHandshakeBinding.CanonicalDeviceId(metadata.SenderDeviceId) != _peer.PeerDeviceId)
                throw new InvalidDataException("The incoming transfer has no matching live authenticated peer session.");
            var key = FileTransfer.ClassicFileTransferWire.DeriveTransferKey(_keys, metadata.TransferId);
            try
            {
                FileTransfer.ClassicFileTransferWire.Verify(metadata, key);
                return key;
            }
            catch
            {
                CryptographicOperations.ZeroMemory(key);
                throw;
            }
        }
    }

    private async Task SendAsync<T>(LanControlMessageKind kind, T message, CancellationToken cancellationToken)
    {
        var plaintext = LanProductControlMessages.Encode(kind, message);
        try
        {
            await _transport.SendAdmittedAsync(() =>
            {
                RequireAuthorityCurrent();
                return ProductControlTrafficPadding.Wrap(WebRtcControlChannelCodec.EncryptAppleLegacyAppPayload(plaintext, _appKeys));
            }, cancellationToken).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    private async Task ReceiveAsync()
    {
        while (true)
        {
            var frame = await _transport.ReadAsync(_lifetime.Token).ConfigureAwait(false);
            RequireAuthorityCurrent();
            var encrypted = ProductControlTrafficPadding.Unwrap(frame.ToArray());
            var plaintext = WebRtcControlChannelCodec.DecryptAppleLegacyAppPayload(encrypted, _appKeys);
            try
            {
                if (Audio.AudioStreamingLanEnvelope.DecodeIfPresent(plaintext) is { } audio)
                {
                    switch (_audio.Receive(audio))
                    {
                        case Audio.LanAudioReceiveDisposition.DeclinedOffer:
                            await DeclineUnattendedAudioOfferAsync(audio.StreamId).ConfigureAwait(false);
                            break;
                        case Audio.LanAudioReceiveDisposition.Unavailable:
                            Interlocked.Increment(ref _unavailableAudioFrames);
                            break;
                        case Audio.LanAudioReceiveDisposition.QueueOverflow:
                            Interlocked.Increment(ref _audioQueueOverflows);
                            break;
                    }
                    continue;
                }
                var message = LanProductControlMessages.Decode(plaintext);
                switch (message.Kind)
                {
                    case LanControlMessageKind.Identity:
                        var identity = LanProductControlMessages.Payload<LanProductIdentity>(message);
                        LanProductControlMessages.ValidateIdentity(identity, _peer);
                        // A casing/prefix change can identify a different exact account registry row,
                        // even when the peer's canonical SOA hash and signer remain unchanged.
                        if (_remoteIdentity is { } previous && previous.DeviceId != identity.DeviceId)
                            _audio.InvalidateIdentity();
                        Volatile.Write(ref _remoteIdentity, identity);
                        if (_receivedAdmissionPong) _admitted.TrySetResult();
                        break;
                    case LanControlMessageKind.Heartbeat:
                        var heartbeat = LanProductControlMessages.Payload<LanProductHeartbeat>(message);
                        if (!double.IsFinite(heartbeat.SentAt) || (heartbeat.DeviceId is not null &&
                            RemoteControlHandshakeBinding.CanonicalDeviceId(heartbeat.DeviceId) != _peer.PeerDeviceId))
                            throw new InvalidDataException("Heartbeat identity conflicts with this authenticated peer.");
                        break;
                    case LanControlMessageKind.Ping:
                        await SendAsync(LanControlMessageKind.Pong, LanProductControlMessages.Payload<LanProductPing>(message), _lifetime.Token).ConfigureAwait(false);
                        break;
                    case LanControlMessageKind.Pong:
                        if (LanProductControlMessages.Payload<LanProductPing>(message).Id != _admissionPing)
                            throw new InvalidDataException("Peer admission pong does not match the current request.");
                        _receivedAdmissionPong = true;
                        if (_remoteIdentity is not null) _admitted.TrySetResult();
                        break;
                    case LanControlMessageKind.Disconnecting:
                        throw new IOException("The peer ended its LAN control session.");
                    default: throw new InvalidDataException("Unsupported LAN control message.");
                }
            }
            finally { CryptographicOperations.ZeroMemory(plaintext); }
        }
    }

    private void RequireAuthorityCurrent()
    {
        Lifetime.ThrowIfCancellationRequested();
        if (!_isAuthorityCurrent()) throw new InvalidOperationException("The control-session account authority has ended.");
    }

    private async Task HeartbeatAsync()
    {
        // Admission can legitimately await peer approval for 60 seconds. Publishing
        // at 20 seconds before IsReady used to terminate that pending admission.
        await _readyForHeartbeat.Task.WaitAsync(_lifetime.Token).ConfigureAwait(false);
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(20));
        while (await timer.WaitForNextTickAsync(_lifetime.Token).ConfigureAwait(false))
            await PublishCurrentCapabilitiesAsync(identity: false, _lifetime.Token).ConfigureAwait(false);
    }

    private async Task<Exception?> ObserveAsync()
    {
        var first = await Task.WhenAny(_receiver, _heartbeat).ConfigureAwait(false);
        var failures = new List<Exception>();
        try { await first.ConfigureAwait(false); }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { }
        catch (Exception error) { failures.Add(error); }
        Volatile.Write(ref _ready, false);
        try { _lifetime.Cancel(); }
        catch (Exception error) { failures.Add(error); }
        _transport.Close();
        foreach (var worker in new[] { _receiver, _heartbeat })
        {
            try { await worker.ConfigureAwait(false); }
            catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { }
            catch (Exception error) { if (!failures.Contains(error)) failures.Add(error); }
        }
        var failure = failures.Count switch
        {
            0 => null,
            1 => failures[0],
            _ => new AggregateException("LAN session workers failed.", failures)
        };
        return failure;
    }

    public async ValueTask DisposeAsync()
    {
        await _disposal.WaitAsync().ConfigureAwait(false);
        try
        {
            if (Volatile.Read(ref _disposed) == 0)
            {
                var failures = new List<Exception>();
                try { _lifetime.Cancel(); } catch (Exception error) { failures.Add(error); }
                _transport.Close();
                try { await _completion.ConfigureAwait(false); } catch (Exception error) { failures.Add(error); }
                try { await _transport.DisposeAsync().ConfigureAwait(false); } catch (Exception error) { failures.Add(error); }
                try { _audio.Dispose(); } catch (Exception error) { failures.Add(error); }
                // A failed carrier release must not keep authenticated key material alive.
                // These in-memory owners are retired even when disposal reports a failure.
                lock (_stateGate)
                {
                    _appKeys.Dispose();
                    _keys.Dispose();
                    _lifetime.Dispose();
                    _disposalFailure = failures.Count switch
                    {
                        0 => null,
                        1 => failures[0],
                        _ => new AggregateException("Control session resource release failed.", failures)
                    };
                    Volatile.Write(ref _disposed, 1);
                }
            }
            if (_disposalFailure is { } failure)
                System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw();
        }
        finally { _disposal.Release(); }
    }
}
