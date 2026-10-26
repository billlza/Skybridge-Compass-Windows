using System.Buffers.Binary;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;

namespace Skybridge.WinClient.Services.Audio;

internal sealed record AudioAlacDecodeReceipt(ulong SourceFrames, ulong Packets, ulong EncodedAudioBytes);
internal abstract record AudioAlacDecodeStep
{
    internal sealed record Frame(ulong FirstIndex, uint FrameCount, byte[] Bytes) : AudioAlacDecodeStep;
    internal sealed record Complete(AudioAlacDecodeReceipt Receipt) : AudioAlacDecodeStep;
}

// One sequential owner over the same immutable/commitment-verified source that
// supplied the index. Next runs on a worker, never on UI or native output threads.
// Dispose requests closure immediately but defers native destruction until an
// active read/callback returns, including a reentrant closure from authorization.
// A successful prefix or native frame is not a complete-file witness.
internal sealed class AudioAlacPcmDecoder : IDisposable
{
    private readonly object _gate = new();
    private readonly AudioAlacNative.DecoderHandle _handle;
    private readonly Func<long, int, CancellationToken, Task<byte[]>> _read;
    private readonly AudioAlacMetadata _metadata;
    private readonly AudioAlacPacketCursor _cursor;
    private readonly AudioAlacNative.CancelCallback _cancelCallback;
    private readonly int _capacity;
    private Action? _authorization;
    private CancellationToken _token;
    private ExceptionDispatchInfo? _callbackFailure, _failure;
    private AudioAlacDecodeReceipt? _receipt;
    private ulong _frames, _packets, _encodedBytes;
    private bool _active, _closed;

    internal AudioAlacPcmDecoder(Func<long, int, CancellationToken, Task<byte[]>> read, AudioAlacMetadata metadata)
    {
        ArgumentNullException.ThrowIfNull(read); ArgumentNullException.ThrowIfNull(metadata);
        if (metadata.Configuration.Length != 24 || metadata.TotalFrames <= 0 || metadata.PacketCount <= 0 || metadata.EncodedAudioBytes <= 0)
            throw new InvalidDataException("ALAC decoding requires finite validated source declarations.");
        _capacity = checked((int)(metadata.MaximumFramesPerPacket * metadata.DecodedFormat.BytesPerFrame));
        if (_capacity is < 1 or > 524_288) throw new InvalidDataException("ALAC frame exceeds the bounded PCM buffer.");
        AudioAlacNative.RequireCompatible();
        var bytes = metadata.Configuration.Span;
        var source = new AudioAlacNative.Source
        {
            Configuration0 = BinaryPrimitives.ReadUInt64LittleEndian(bytes),
            Configuration1 = BinaryPrimitives.ReadUInt64LittleEndian(bytes[8..]),
            Configuration2 = BinaryPrimitives.ReadUInt64LittleEndian(bytes[16..]),
            TotalFrames = checked((ulong)metadata.TotalFrames), PacketCount = checked((ulong)metadata.PacketCount)
        };
        var status = AudioAlacNative.Create(source, out var pointer, out var result);
        var handle = new AudioAlacNative.DecoderHandle(pointer);
        if (status != AudioAlacDecoderStatus.Ready || handle.IsInvalid)
        {
            handle.Dispose();
            throw new AudioAlacDecodeException(status == AudioAlacDecoderStatus.Ready ? AudioAlacDecoderStatus.InvalidArgument : status, result.CodecError);
        }
        if (result.Status != status || result.CodecError != 0)
        { handle.Dispose(); throw new InvalidDataException("The native ALAC initialization result is inconsistent."); }
        _handle = handle; _read = read; _metadata = metadata; _cursor = metadata.MakePacketCursor(); _cancelCallback = Cancelled;
    }

    internal AudioAlacDecodeStep Next(Action requireAuthorization, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(requireAuthorization);
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_closed, this);
            if (_active) throw new InvalidOperationException("ALAC decoding permits one active operation and no callback reentry.");
            _failure?.Throw(); _active = true;
        }
        _authorization = requireAuthorization; _token = token;
        try
        {
            RequireCurrent();
            if (_receipt is { } receipt) return new AudioAlacDecodeStep.Complete(receipt);
            var packet = _cursor.NextAsync(_read, RequireCurrent, token).GetAwaiter().GetResult();
            var control = new AudioAlacNative.Control { IsCancelled = Marshal.GetFunctionPointerForDelegate(_cancelCallback) };
            AudioAlacNative.Result result;
            AudioAlacDecoderStatus status;
            byte[] output;
            if (packet is not null)
            {
                if ((ulong)packet.Index != _packets || (ulong)packet.FirstFrameIndex != _frames)
                    throw new InvalidDataException("ALAC packet order differs from the validated index.");
                var input = ReadPacket(packet);
                RequireCurrent(); output = new byte[_capacity];
                status = AudioAlacNative.Decode(_handle, control, _packets, _frames, input, (nuint)input.Length,
                    packet.FrameCount, output, (nuint)output.Length, out result);
            }
            else
            {
                // Null is the index's checked exact EOF. Read failures never reach this branch.
                RequireCurrent(); output = [];
                status = AudioAlacNative.Finish(_handle, control, out result);
            }
            _callbackFailure?.Throw(); RequireCurrent();
            if (status != (packet is null ? AudioAlacDecoderStatus.Complete : AudioAlacDecoderStatus.Frame))
                throw new AudioAlacDecodeException(status, result.CodecError);
            if (result.Status != status || result.CodecError != 0)
                throw new InvalidDataException("The native ALAC result contradicts its status.");
            if (packet is not null)
            {
                if (result.PacketIndex != _packets || result.FirstFrameIndex != _frames || result.FrameCount != packet.FrameCount ||
                    result.DecodedFrames != _frames + packet.FrameCount || result.DecodedPackets != _packets + 1 ||
                    result.ByteCount != (nuint)packet.FrameCount * _metadata.DecodedFormat.BytesPerFrame || result.ByteCount > (nuint)output.Length ||
                    _encodedBytes > (ulong)_metadata.EncodedAudioBytes || (ulong)packet.ByteCount > (ulong)_metadata.EncodedAudioBytes - _encodedBytes)
                    throw new InvalidDataException("The native ALAC frame is not the exact indexed extent.");
                Array.Resize(ref output, checked((int)result.ByteCount));
                RequireCurrent();
                _frames = result.DecodedFrames; _packets = result.DecodedPackets; _encodedBytes += (ulong)packet.ByteCount;
                return new AudioAlacDecodeStep.Frame(result.FirstFrameIndex, result.FrameCount, output);
            }
            if (result.FrameCount != 0 || result.ByteCount != 0 || result.DecodedFrames != (ulong)_metadata.TotalFrames ||
                result.DecodedPackets != (ulong)_metadata.PacketCount || _frames != result.DecodedFrames || _packets != result.DecodedPackets ||
                _encodedBytes != (ulong)_metadata.EncodedAudioBytes)
                throw new InvalidDataException("ALAC completion lacks exact packet/frame counts, payload bytes or clean EOF.");
            RequireCurrent(); _receipt = new(_frames, _packets, _encodedBytes);
            return new AudioAlacDecodeStep.Complete(_receipt);
        }
        catch (Exception failure)
        {
            lock (_gate) _failure ??= ExceptionDispatchInfo.Capture(failure);
            throw;
        }
        finally
        {
            _authorization = null; _token = default; _callbackFailure = null; GC.KeepAlive(_cancelCallback);
            lock (_gate)
            {
                _active = false;
                if (_closed || _failure is not null || _receipt is not null) _handle.Dispose();
            }
        }
    }

    private byte[] ReadPacket(AudioAlacPacket packet)
    {
        var bytes = new byte[packet.ByteCount];
        for (int copied = 0; copied < bytes.Length;)
        {
            RequireCurrent(); int count = Math.Min(AudioAlacFile.MaximumReadBytes, bytes.Length - copied);
            var block = _read(packet.ByteOffset + copied, count, _token).GetAwaiter().GetResult();
            RequireCurrent();
            if (block is null || block.Length != count) throw new InvalidDataException("ALAC source returned a non-exact packet range.");
            block.CopyTo(bytes, copied); copied += count;
        }
        RequireCurrent(); return bytes;
    }
    private void RequireCurrent()
    {
        _token.ThrowIfCancellationRequested();
        lock (_gate) ObjectDisposedException.ThrowIf(_closed, this);
        (_authorization ?? throw new InvalidOperationException("No active ALAC read authority."))();
        _token.ThrowIfCancellationRequested();
        lock (_gate) ObjectDisposedException.ThrowIf(_closed, this);
    }
    private int Cancelled(nint context)
    {
        if (_callbackFailure is not null) return 1;
        try
        {
            if (context != 0) throw new InvalidOperationException("ALAC callback escaped its borrowed control.");
            RequireCurrent(); return 0;
        }
        catch (Exception failure) { _callbackFailure ??= ExceptionDispatchInfo.Capture(failure); return 1; }
    }
    public void Dispose()
    {
        lock (_gate) { _closed = true; if (!_active) _handle.Dispose(); }
    }
}
