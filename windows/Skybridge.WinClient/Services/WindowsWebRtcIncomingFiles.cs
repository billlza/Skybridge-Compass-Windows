using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Channels;
using Skybridge.WinClient.Services.FileTransfer;
using Skybridge.WinClient.Services.RemoteControl;

namespace Skybridge.WinClient.Services;

internal sealed record WindowsWebRtcReceiveOptions(Func<string> Destination,
    Func<ClassicFileMetadata, string, CancellationToken, Task<bool>> Approve,
    Action<ClassicFileTransferProgress> Progress, Action<ClassicFileMetadata, ClassicFileTransferResult?, Exception?> Completed);

/// <summary>One approved ordinary file per secure session. The DataChannel control reader keeps processing heartbeats.</summary>
internal sealed class WindowsWebRtcIncomingFiles(RemoteControlPairingMaterial peer, WindowsWebRtcReceiveOptions options,
    Func<object, CancellationToken, Task> reply, Action<Action> authorizeCommit)
{
    private readonly Channel<JsonElement> _messages = Channel.CreateBounded<JsonElement>(4);
    internal void Enqueue(JsonElement value)
    {
        if (!_messages.Writer.TryWrite(value.Clone())) throw new InvalidDataException("Incoming file queue is full.");
    }

    internal async Task RunAsync(CancellationToken token)
    {
        string? lastCompleted = null;
        long completedBytes = 0;
        byte[]? completedHash = null;
        while (true)
        {
            var first = await _messages.Reader.ReadAsync(token).ConfigureAwait(false);
            var id = first.GetProperty("transferId").GetString()!;
            var op = first.GetProperty("op").GetString();
            if (lastCompleted == id && op == "complete" && completedHash != null &&
                first.GetProperty("receivedBytes").GetInt64() == completedBytes &&
                first.GetProperty("fileSha256").GetBytesFromBase64().AsSpan().SequenceEqual(completedHash))
            {
                await reply(new { version = 1, op = "completeAck", transferId = id, receivedBytes = completedBytes, fileSha256 = completedHash }, token);
                continue;
            }
            ClassicFileMetadata? metadata = null;
            try
            {
                if (op != "metadata" || lastCompleted == id) throw new InvalidDataException("Expected a new file offer.");
                if (RemoteControlHandshakeBinding.CanonicalDeviceId(first.GetProperty("senderDeviceId").GetString()!) != peer.DeviceId)
                    throw new InvalidDataException("File sender does not match the authenticated session.");
                var name = first.GetProperty("fileName").GetString() ?? throw new InvalidDataException("Missing file name.");
                ClassicFileTransferReceiver.ValidateWindowsFileName(name);
                long size = first.GetProperty("fileSize").GetInt64();
                int chunkSize = first.GetProperty("chunkSize").GetInt32(), count = first.GetProperty("totalChunks").GetInt32();
                if (size is < 0 or > ClassicFileTransferWire.MaximumFileBytes || chunkSize is <= 0 or > ClassicFileTransferWire.MaximumChunkBytes ||
                    count is < 0 or > 65_536 || count != (size + chunkSize - 1) / chunkSize)
                    throw new InvalidDataException("Invalid incoming file dimensions.");
                byte[]? declaredHash = first.TryGetProperty("fileSha256", out var sha) ? sha.GetBytesFromBase64() : null;
                if (declaredHash is not null && declaredHash.Length != 32) throw new InvalidDataException("Invalid offered file digest.");
                RejectUnsupportedIntegrity(first);
                metadata = new(id, name, size, declaredHash is null ? "" : Convert.ToHexStringLower(declaredHash),
                    chunkSize, 2, SenderDeviceId: peer.DeviceId, SenderDeviceName: peer.DeviceName);
                var destination = ClassicFileTransferReceiver.ValidateReceiveDirectory(options.Destination());
                using var approval = CancellationTokenSource.CreateLinkedTokenSource(token);
                approval.CancelAfter(TimeSpan.FromSeconds(45));
                if (!await options.Approve(metadata, destination, approval.Token).ConfigureAwait(false))
                    throw new ClassicFileTransferRejectedException("The receiver declined this file.");
                var result = await ReceiveAsync(metadata, count, destination, declaredHash, token).ConfigureAwait(false);
                lastCompleted = id; completedHash = Convert.FromHexString(result.FileHash); completedBytes = result.Bytes;
                options.Completed(metadata, result, null);
                await reply(new { version = 1, op = "completeAck", transferId = id, receivedBytes = result.Bytes, fileSha256 = completedHash }, token);
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
            catch (Exception failure) when (failure is IOException or InvalidDataException or UnauthorizedAccessException or
                ArgumentException or FormatException or InvalidOperationException or KeyNotFoundException or OperationCanceledException or TimeoutException)
            {
                await reply(new { version = 1, op = "error", transferId = id, message = "The receiver declined or could not verify this transfer." }, token);
                if (metadata is not null && lastCompleted != id) options.Completed(metadata, null, failure);
            }
        }
    }

    private async Task<ClassicFileTransferResult> ReceiveAsync(ClassicFileMetadata meta, int count, string root, byte[]? declared, CancellationToken token)
    {
        string partial = Path.Combine(root, ".skybridge-" + Guid.NewGuid().ToString("N") + ".part");
        bool owned = false;
        try
        {
            long received = 0;
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            byte[]? lastChunkHash = null;
            var index = 0;
            var source = new FileStream(partial, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 64 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            owned = true;
            byte[] digest;
            await using (source)
            {
                var id = meta.TransferId;
                await reply(new { version = 1, op = "metadataAck", transferId = id }, token);
                while (true)
                {
                    using var idle = CancellationTokenSource.CreateLinkedTokenSource(token);
                    idle.CancelAfter(TimeSpan.FromSeconds(35));
                    var msg = await _messages.Reader.ReadAsync(idle.Token).ConfigureAwait(false);
                    var other = msg.GetProperty("transferId").GetString();
                    if (other != id)
                    {
                        await reply(new { version = 1, op = "error", transferId = other, message = "The receiver is busy." }, token);
                        continue;
                    }
                    var op = msg.GetProperty("op").GetString();
                    if (op == "complete")
                    {
                        RejectUnsupportedIntegrity(msg);
                        digest = hash.GetHashAndReset();
                        if (index != count || received != meta.FileSize || msg.GetProperty("receivedBytes").GetInt64() != received ||
                            !msg.GetProperty("fileSha256").GetBytesFromBase64().AsSpan().SequenceEqual(digest) ||
                            (declared is not null && !declared.AsSpan().SequenceEqual(digest)))
                            throw new InvalidDataException("The completed file length or SHA-256 does not match.");
                        source.Flush(flushToDisk: true);
                        source.Position = 0;
                        if (!(await SHA256.HashDataAsync(source, token)).AsSpan().SequenceEqual(digest))
                            throw new IOException("The saved file did not match the authenticated digest.");
                        break;
                    }
                    if (op != "chunk") throw new InvalidDataException("Unexpected file operation.");
                    int at = msg.GetProperty("chunkIndex").GetInt32();
                    var bytes = msg.GetProperty("chunkData").GetBytesFromBase64();
                    var checksum = msg.GetProperty("chunkSha256").GetBytesFromBase64();
                    if (at < 0 || at >= count || bytes.Length != Math.Min(meta.ChunkSize, meta.FileSize - (long)at * meta.ChunkSize) ||
                        bytes.Length != msg.GetProperty("rawSize").GetInt32() || !SHA256.HashData(bytes).AsSpan().SequenceEqual(checksum))
                        throw new InvalidDataException("An incoming chunk failed verification.");
                    if (at == index)
                    {
                        await source.WriteAsync(bytes, token).ConfigureAwait(false);
                        hash.AppendData(bytes); received += bytes.Length; index++; lastChunkHash = checksum;
                        options.Progress(new(id, meta.FileName, received, meta.FileSize, true));
                    }
                    else if (at != index - 1 || lastChunkHash is null || !checksum.AsSpan().SequenceEqual(lastChunkHash))
                        throw new InvalidDataException("An incoming chunk has the wrong index.");
                    await reply(new { version = 1, op = "chunkAck", transferId = id, chunkIndex = at, receivedBytes = received }, token);
                }
            }
            token.ThrowIfCancellationRequested();
            string? saved = null;
            authorizeCommit(() =>
            {
                token.ThrowIfCancellationRequested();
                saved = ClassicFileTransferReceiver.CommitWithoutOverwrite(partial, root, meta.FileName);
                owned = false;
            });
            return new(meta.TransferId, meta.FileName, received, Convert.ToHexStringLower(digest), saved);
        }
        finally { if (owned) File.Delete(partial); }
    }

    private static void RejectUnsupportedIntegrity(JsonElement message)
    {
        if (message.TryGetProperty("merkleRoot", out _) || message.TryGetProperty("merkleRootSignature", out _))
            throw new InvalidDataException("This receiver requires the ordinary SHA-256 transfer profile.");
    }
}
