using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Channels;
using Skybridge.WinClient.Services.FileTransfer;
using Skybridge.WinClient.Services.RemoteControl;

namespace Skybridge.WinClient.Services;

internal sealed record WindowsWebRtcFileRecipient(WebRtcProductSessionIncarnation Owner, string DeviceId, string Name);
internal sealed class WindowsWebRtcFileSession : IAsyncDisposable
{
    private readonly IWebRtcProductControlPlane _plane;
    private readonly WebRtcAppSecureSessionKeys _keys;
    private readonly RemoteControlPairingMaterial _local, _peer;
    private readonly WebRtcAppSecureReplayWindow _replay = new();
    private readonly Channel<byte[]> _input = Channel.CreateBounded<byte[]>(16);
    private readonly SemaphoreSlim _write = new(1, 1), _file = new(1, 1);
    private readonly CancellationTokenSource _lifetime = new();
    private readonly object _gate = new();
    private readonly CancellationToken _token;
    private Pending? _waiting;
    private ulong _counter;
    private long _lastHeartbeat = Stopwatch.GetTimestamp();
    private readonly WindowsWebRtcIncomingFiles? _incoming;
    private bool _disposed;
    private sealed record Pending(string Id, string Op, int? Index,
        TaskCompletionSource<JsonElement> Result);

    internal WindowsWebRtcFileSession(LiveWebRtcProductControlContext context, WebRtcAppSecureSessionKeys keys,
        RemoteControlPairingMaterial local, RemoteControlPairingMaterial paired, WindowsWebRtcReceiveOptions? receive = null)
    {
        if (context.SecureSessionState != WebRtcProductControlSecureSessionState.Established ||
            context.SessionIncarnation is not { } owner || context.PeerPublicKeyFingerprint != paired.ProtocolPublicKeyFingerprint ||
            RemoteControlHandshakeBinding.CanonicalDeviceId(context.PeerDeviceId) != paired.DeviceId)
            throw new InvalidDataException("A current authenticated peer is required.");
        owner.RequireValid();
        Recipient = new(owner, paired.DeviceId, paired.DeviceName);
        _local = local; _peer = paired; _keys = keys; _plane = context.ControlPlane; _token = _lifetime.Token;
        _incoming = receive is null ? null : new(paired, receive,
            (response, token) => SendAsync(WebRtcAppSecurePacketType.FileTransfer, JsonSerializer.SerializeToUtf8Bytes(response), token));
        _plane.MessageReceived += Inbound;
    }
    internal WindowsWebRtcFileRecipient Recipient { get; }
    private void Inbound(byte[] payload)
    {
        if (!_input.Writer.TryWrite(payload))
            _input.Writer.TryComplete(new IOException("The secure message queue is full."));
    }
    internal async Task RunAsync(CancellationToken cancellationToken)
    {
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(_token, cancellationToken);
        var control = ControlAsync(stop.Token);
        var heartbeat = HeartbeatAsync(stop.Token);
        var workers = _incoming is null ? new[] { control, heartbeat } : new[] { control, heartbeat, _incoming.RunAsync(stop.Token) };
        try { await await Task.WhenAny(workers).ConfigureAwait(false); }
        finally
        {
            stop.Cancel();
            _lifetime.Cancel();
            try { await Task.WhenAll(workers).ConfigureAwait(false); }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
        }
    }
    private async Task HeartbeatAsync(CancellationToken token)
    {
        var identity = new LanProductIdentity(_local.DeviceId, [new(0x0101, _local.MlKem768PublicKey.ToArray())],
            LanProductControlMessages.Timestamp(DateTimeOffset.UtcNow), [new(_local.ProtocolSigningAlgorithm, _local.ProtocolPublicKey.ToArray())],
            DeviceName: _local.DeviceName, Platform: "Windows", OsVersion: Environment.OSVersion.Version.ToString(), Capabilities: _incoming is null ? [] : ["file_transfer"]);
        await SendAsync(WebRtcAppSecurePacketType.AppControl, LanProductControlMessages.Encode(LanControlMessageKind.Identity, identity), token).ConfigureAwait(false);
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(2));
        do
        {
            token.ThrowIfCancellationRequested();
            if (!_plane.IsConnected || Stopwatch.GetElapsedTime(Interlocked.Read(ref _lastHeartbeat)) > TimeSpan.FromSeconds(12))
                throw new IOException("The remote authenticated heartbeat timed out.");
            var heartbeat = new LanProductHeartbeat(LanProductControlMessages.Timestamp(DateTimeOffset.UtcNow), _local.DeviceId);
            await SendAsync(WebRtcAppSecurePacketType.AppControl, LanProductControlMessages.Encode(LanControlMessageKind.Heartbeat, heartbeat), token).ConfigureAwait(false);
        } while (await timer.WaitForNextTickAsync(token).ConfigureAwait(false));
    }

    private async Task ControlAsync(CancellationToken token)
    {
        await foreach (var frame in _input.Reader.ReadAllAsync(token).ConfigureAwait(false))
        {
            var clear = WebRtcControlChannelCodec.DecryptAppPayload(frame, _keys, Enum.GetValues<WebRtcAppSecurePacketType>());
            try
            {
                _replay.ValidateAndRecord(clear);
                if (clear.PacketType is not (WebRtcAppSecurePacketType.AppControl or WebRtcAppSecurePacketType.FileTransfer)) continue;
                using var doc = JsonDocument.Parse(clear.Payload, new JsonDocumentOptions { AllowDuplicateProperties = false, MaxDepth = 16 });
                var root = doc.RootElement;
                if (clear.PacketType == WebRtcAppSecurePacketType.AppControl)
                {
                    if (root.TryGetProperty("heartbeat", out var beat))
                    {
                        string id = beat.GetProperty("deviceId").GetString() ?? throw new InvalidDataException("Heartbeat has no sender.");
                        if (RemoteControlHandshakeBinding.CanonicalDeviceId(id) != _peer.DeviceId)
                            throw new InvalidDataException("Heartbeat sender does not match the paired session.");
                        Interlocked.Exchange(ref _lastHeartbeat, Stopwatch.GetTimestamp());
                    }
                    else if (root.TryGetProperty("pairingIdentityExchange", out _))
                    {
                        var identity = LanProductControlMessages.Payload<LanProductIdentity>(LanProductControlMessages.Decode(clear.Payload));
                        LanProductControlMessages.ValidateIdentity(identity, new(_peer.DeviceId, _peer.ProtocolPublicKeyFingerprint));
                    }
                    else if (root.TryGetProperty("peerDisconnecting", out _)) throw new IOException("The paired device disconnected.");
                    else if (root.TryGetProperty("ping", out var ping))
                        await SendAsync(WebRtcAppSecurePacketType.AppControl, JsonSerializer.SerializeToUtf8Bytes(new { pong = ping }), token).ConfigureAwait(false);
                    continue;
                }
                if (root.GetProperty("version").GetInt32() != 1) throw new InvalidDataException("Invalid file-transfer version.");
                var idText = root.GetProperty("transferId").GetString();
                if (!Guid.TryParseExact(idText, "D", out var identifier) || identifier.ToString("D") != idText)
                    throw new InvalidDataException("Invalid transfer identifier.");
                var op = root.GetProperty("op").GetString();
                if (op is "metadata" or "chunk" or "complete" or "cancel")
                {
                    if (_incoming is not null) { _incoming.Enqueue(root); continue; }
                    await SendAsync(WebRtcAppSecurePacketType.FileTransfer, JsonSerializer.SerializeToUtf8Bytes(new {
                        version = 1, op = "error", transferId = idText, message = "This receiver does not accept incoming WebRTC files."
                    }), token).ConfigureAwait(false);
                    continue;
                }
                lock (_gate)
                {
                    if (_waiting is not { } expected || expected.Id != idText) continue;
                    if (op == "error") expected.Result.TrySetException(new IOException("The peer rejected this file."));
                    else if (op == expected.Op && (expected.Index is null || (root.TryGetProperty("chunkIndex", out var index) && index.GetInt32() == expected.Index)))
                        expected.Result.TrySetResult(root.Clone());
                }
            }
            finally { CryptographicOperations.ZeroMemory(clear.Payload); }
        }
    }

    private async Task SendAsync(WebRtcAppSecurePacketType type, byte[] data, CancellationToken token)
    {
        await _write.WaitAsync(token).ConfigureAwait(false);
        try
        {
            token.ThrowIfCancellationRequested();
            var frame = WebRtcControlChannelCodec.EncryptAppPayload(data, _keys, type, checked(++_counter));
            await _plane.SendAsync(frame, token).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(data); _write.Release(); }
    }

    private async Task<JsonElement> ExchangeAsync(string id, string expected, int? index, object message, CancellationToken token)
    {
        var pending = new Pending(id, expected, index, new(TaskCreationOptions.RunContinuationsAsynchronously));
        lock (_gate) { if (_waiting is not null) throw new InvalidOperationException("A file operation is already pending."); _waiting = pending; }
        try
        {
            await SendAsync(WebRtcAppSecurePacketType.FileTransfer, JsonSerializer.SerializeToUtf8Bytes(message), token).ConfigureAwait(false);
            return await pending.Result.Task.WaitAsync(TimeSpan.FromSeconds(expected == "metadataAck" ? 60 : 30), token).ConfigureAwait(false);
        }
        finally { lock (_gate) { if (ReferenceEquals(_waiting, pending)) _waiting = null; } }
    }

    internal async Task<ClassicFileTransferResult> SendFileAsync(string id, string path, IProgress<ClassicFileTransferProgress>? progress, CancellationToken token)
    {
        using var operation = CancellationTokenSource.CreateLinkedTokenSource(token, _token);
        token = operation.Token;
        await _file.WaitAsync(token).ConfigureAwait(false);
        try
        {
            token.ThrowIfCancellationRequested();
            await using var source = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            var size = source.Length;
            const int chunkSize = 64 * 1024;
            if (size > ClassicFileTransferWire.MaximumFileBytes) throw new InvalidDataException("File exceeds the supported size.");
            var chunks = checked((int)((size + chunkSize - 1) / chunkSize));
            var name = Path.GetFileName(path);
            var hash = await SHA256.HashDataAsync(source, token).ConfigureAwait(false);
            source.Position = 0;
            await ExchangeAsync(id, "metadataAck", null, new { version = 1, op = "metadata", transferId = id, fileName = name,
                senderDeviceId = _local.DeviceId, senderDeviceName = _local.DeviceName, fileSize = size, chunkSize, totalChunks = chunks, fileSha256 = hash }, token).ConfigureAwait(false);
            using var recheck = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            long sent = 0;
            for (var i = 0; i < chunks; i++)
            {
                var bytes = new byte[Math.Min(chunkSize, size - sent)];
                await source.ReadExactlyAsync(bytes, token).ConfigureAwait(false);
                recheck.AppendData(bytes);
                var ack = await ExchangeAsync(id, "chunkAck", i, new { version = 1, op = "chunk", transferId = id,
                    chunkIndex = i, rawSize = bytes.Length, chunkSha256 = SHA256.HashData(bytes), chunkData = bytes }, token).ConfigureAwait(false);
                sent += bytes.Length;
                if (ack.GetProperty("receivedBytes").GetInt64() != sent) throw new InvalidDataException("The peer acknowledged a different file offset.");
                progress?.Report(new(id, name, sent, size, false));
            }
            if (source.Length != size || !recheck.GetHashAndReset().AsSpan().SequenceEqual(hash))
                throw new IOException("The selected file changed during transmission.");
            try
            {
                var ack = await ExchangeAsync(id, "completeAck", null, new { version = 1, op = "complete", transferId = id,
                    fileSha256 = hash, receivedBytes = sent }, token).ConfigureAwait(false);
                if (ack.GetProperty("receivedBytes").GetInt64() != size || !ack.GetProperty("fileSha256").GetBytesFromBase64().AsSpan().SequenceEqual(hash))
                    throw new InvalidDataException("The saved-file receipt has the wrong length or SHA-256.");
            }
            catch (Exception failure) when (failure is OperationCanceledException or IOException or TimeoutException)
            { throw new IOException("File delivery is unconfirmed. Check the receiver before sending again.", failure); }
            return new(id, name, sent, Convert.ToHexStringLower(hash));
        }
        finally { _file.Release(); }
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;
        _lifetime.Cancel(); _plane.MessageReceived -= Inbound; _input.Writer.TryComplete();
        await _file.WaitAsync().ConfigureAwait(false);
        _file.Release(); _lifetime.Dispose();
    }
}
