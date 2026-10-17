using System.Buffers.Binary;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;

namespace Skybridge.WinClient.Services.Audio;

internal sealed record AudioFlacDecodeReceipt(ulong SourceFrames, ulong EncodedBytes, bool Md5Available, bool Md5Verified);
internal abstract record AudioFlacDecodeStep
{
    internal sealed record Frame(ulong FirstIndex, uint FrameCount, byte[] Bytes) : AudioFlacDecodeStep;
    internal sealed record Complete(AudioFlacDecodeReceipt Receipt) : AudioFlacDecodeStep;
}

/// <summary>One serialized, sequential decoder over a caller-owned verified read boundary.
/// Call on a worker, never on the UI/native output thread. Native callbacks are synchronous
/// and borrow no state after Next returns. Source and authorization exceptions retain identity.
/// A decoded prefix is not a whole-file validation or a playback authorization.</summary>
internal sealed class AudioFlacPcmDecoder : IDisposable
{
    private readonly object _gate = new();
    private readonly AudioFlacNative.DecoderHandle _handle;
    private readonly Func<long, int, CancellationToken, Task<byte[]>> _read;
    private readonly AudioFlacMetadata _metadata;
    private readonly ulong _fileBytes, _frameCount;
    private readonly int _capacity;
    private readonly AudioFlacNative.ReadCallback _readCallback;
    private readonly AudioFlacNative.CancelCallback _cancelCallback;
    private Action? _authorization;
    private CancellationToken _token;
    private ExceptionDispatchInfo? _callbackFailure, _failure;
    private AudioFlacDecodeReceipt? _receipt;
    private ulong _frames, _encodedBytes;
    private bool _active, _closed;

    internal AudioFlacPcmDecoder(long fileBytes, Func<long, int, CancellationToken, Task<byte[]>> read, AudioFlacMetadata metadata)
    {
        ArgumentNullException.ThrowIfNull(read); ArgumentNullException.ThrowIfNull(metadata);
        var format = metadata.DecodedFormat;
        if (fileBytes <= 0 || metadata.TotalFrames is not > 0 || format.FloatingPoint ||
            format.ValidBits is < 4 or > 32 || format.Channels is < 1 or > 8 ||
            format.ContainerBits != ((format.ValidBits + 7) / 8) * 8 || metadata.FirstFrameByteOffset < 0)
            throw new InvalidDataException("Finite FLAC decoding requires exact integer declarations and a positive frame count.");
        _capacity = checked((int)(metadata.MaximumBlockFrames * format.BytesPerFrame));
        if (_capacity is < 1 or > 2_097_120) throw new InvalidDataException("FLAC frame exceeds the decode buffer limit.");
        AudioFlacNative.RequireCompatible();
        var source = new AudioFlacNative.Source
        {
            SampleRate = format.SampleRate, Channels = format.Channels, ValidBits = format.ValidBits,
            MinimumBlockFrames = metadata.MinimumBlockFrames, MaximumBlockFrames = metadata.MaximumBlockFrames,
            MinimumFrameBytes = metadata.MinimumFrameBytes ?? 0, MaximumFrameBytes = metadata.MaximumFrameBytes ?? 0,
            TotalFrames = checked((ulong)metadata.TotalFrames.Value), FirstFrameByteOffset = checked((ulong)metadata.FirstFrameByteOffset)
        };
        if (metadata.PcmMd5Hex is { } hex)
        {
            var md5 = Convert.FromHexString(hex);
            if (md5.Length != 16 || md5.AsSpan().IndexOfAnyExcept((byte)0) < 0)
                throw new InvalidDataException("Invalid declared FLAC MD5.");
            source.Md5Low = BinaryPrimitives.ReadUInt64LittleEndian(md5);
            source.Md5High = BinaryPrimitives.ReadUInt64LittleEndian(md5.AsSpan(8));
        }
        var status = AudioFlacNative.Create(source, checked((ulong)fileBytes), source.TotalFrames, out var pointer);
        var handle = new AudioFlacNative.DecoderHandle(pointer);
        if (status != AudioFlacDecoderStatus.Ready || handle.IsInvalid)
        {
            handle.Dispose();
            throw new AudioFlacDecodeException(status == AudioFlacDecoderStatus.Ready ? AudioFlacDecoderStatus.InvalidArgument : status);
        }
        _handle = handle; _read = read; _metadata = metadata;
        _fileBytes = (ulong)fileBytes; _frameCount = source.TotalFrames;
        _readCallback = Read; _cancelCallback = Cancelled;
    }

    internal AudioFlacDecodeStep Next(Action requireAuthorization, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(requireAuthorization);
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_closed, this);
            if (_active) throw new InvalidOperationException("FLAC callbacks cannot reenter their decoder.");
            _failure?.Throw();
            _authorization = requireAuthorization; _token = token; _active = true;
            try
            {
                RequireCurrent();
                if (_receipt is { } receipt) return new AudioFlacDecodeStep.Complete(receipt);
                var access = new AudioFlacNative.ReadAccess
                {
                    Read = Marshal.GetFunctionPointerForDelegate(_readCallback),
                    IsCancelled = Marshal.GetFunctionPointerForDelegate(_cancelCallback)
                };
                var output = new byte[_capacity];
                var status = AudioFlacNative.Next(_handle, access, output, (nuint)output.Length, out var result);
                _callbackFailure?.Throw();
                RequireCurrent();
                if (status is not (AudioFlacDecoderStatus.Frame or AudioFlacDecoderStatus.Complete))
                    throw new AudioFlacDecodeException(status, result.CodecError);
                if (result.Status != status || result.CodecError != -1 || result.TotalFrames > _frameCount ||
                    result.EncodedBytesConsumed < _encodedBytes || result.EncodedBytesConsumed > _fileBytes ||
                    result.Md5Available != (_metadata.PcmMd5Hex is null ? 0 : 1))
                    throw new InvalidDataException("The native FLAC result contradicts the verified source.");
                if (status == AudioFlacDecoderStatus.Frame)
                {
                    if (result.FirstFrameIndex != _frames || result.FrameCount == 0 || result.FrameCount > _metadata.MaximumBlockFrames ||
                        result.TotalFrames != _frames + result.FrameCount || result.Md5Verified != 0 ||
                        result.ByteCount != (nuint)result.FrameCount * _metadata.DecodedFormat.BytesPerFrame || result.ByteCount > (nuint)output.Length)
                        throw new InvalidDataException("The native FLAC frame is not an exact sequential source extent.");
                    Array.Resize(ref output, checked((int)result.ByteCount));
                    _frames = result.TotalFrames; _encodedBytes = result.EncodedBytesConsumed;
                    return new AudioFlacDecodeStep.Frame(result.FirstFrameIndex, result.FrameCount, output);
                }
                if (result.TotalFrames != _frameCount || _frames != _frameCount || result.EncodedBytesConsumed != _fileBytes ||
                    result.ByteCount != 0 || result.FrameCount != 0 || result.Md5Verified != result.Md5Available)
                    throw new InvalidDataException("FLAC completion lacks exact frame count, EOF or available MD5 verification.");
                _receipt = new(_frames, _fileBytes, result.Md5Available == 1, result.Md5Verified == 1);
                return new AudioFlacDecodeStep.Complete(_receipt);
            }
            catch (Exception failure) { _failure = ExceptionDispatchInfo.Capture(failure); throw; }
            finally
            {
                _active = false; _authorization = null; _token = default; _callbackFailure = null;
                GC.KeepAlive(_readCallback); GC.KeepAlive(_cancelCallback);
            }
        }
    }
    private void RequireCurrent()
    {
        _token.ThrowIfCancellationRequested();
        (_authorization ?? throw new InvalidOperationException("No active decoder read authority."))();
        _token.ThrowIfCancellationRequested();
    }
    private int Read(nint context, ulong offset, nint buffer, nuint capacity, out nuint bytesRead)
    {
        bytesRead = 0;
        try
        {
            if (!_active || context != 0 || buffer == 0 || capacity is < 1 or > 65_536 ||
                offset > _fileBytes || capacity > _fileBytes - offset)
                throw new InvalidDataException("FLAC requested a read outside its borrowed verified source.");
            RequireCurrent();
            var bytes = _read(checked((long)offset), checked((int)capacity), _token).GetAwaiter().GetResult();
            RequireCurrent();
            if (bytes is null || bytes.Length != (int)capacity) throw new InvalidDataException("FLAC source returned a non-exact range.");
            Marshal.Copy(bytes, 0, buffer, bytes.Length); bytesRead = (nuint)bytes.Length;
            return 0;
        }
        catch (Exception failure) { _callbackFailure ??= ExceptionDispatchInfo.Capture(failure); return -1; }
    }
    private int Cancelled(nint context)
    {
        if (_callbackFailure is not null) return 1;
        try
        {
            if (!_active || context != 0) throw new InvalidOperationException("FLAC callback escaped its operation.");
            RequireCurrent(); return 0;
        }
        catch (Exception failure) { _callbackFailure ??= ExceptionDispatchInfo.Capture(failure); return 1; }
    }
    public void Dispose()
    {
        lock (_gate)
        {
            if (_active) throw new InvalidOperationException("A decoder callback cannot destroy its owner.");
            _closed = true; _handle.Dispose();
        }
    }
}
