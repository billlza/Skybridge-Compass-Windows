using System.Security.Cryptography;

namespace Skybridge.WinClient.Services.Audio;

internal enum AudioCaptureReceiveState { Receiving, ContentVerified, Faulted, Disposed }
internal sealed record AudioCaptureContentReceipt(long TotalBytes, long SourceFrames, string Sha256Hex);

/// <summary>Accounting owned by the same synchronous worker as native PCM submission.
/// Enqueue must accept the complete immutable packet or throw; an uncertain/partial
/// native write faults this flow and cannot be retried. Retirement is not playback
/// completion: this type deliberately cannot produce a PlaybackComplete message.</summary>
internal sealed class AudioCaptureReceiveFlow : IDisposable
{
    private readonly int _ownerThread = Environment.CurrentManagedThreadId;
    private readonly IncrementalHash _digest;
    private bool _submitting;
    internal AudioCaptureReceiveFlow(Guid streamId, AudioStreamingPcmFormat format, uint windowBytes)
    {
        ArgumentNullException.ThrowIfNull(format);
        _ = AudioStreamingWire.Encode(new(streamId, new AudioStreamingBody.CaptureOffer(format)));
        if (windowBytes == 0 || windowBytes > AudioStreamingWire.MaximumReceiveWindowBytes || windowBytes % format.BytesPerFrame != 0)
            throw new InvalidDataException("PCM receive window must contain whole frames within the protocol bound.");
        StreamId = streamId; Format = format; WindowBytes = windowBytes;
        _digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    }
    internal Guid StreamId { get; }
    internal AudioStreamingPcmFormat Format { get; }
    internal uint WindowBytes { get; }
    internal AudioCaptureReceiveState State { get; private set; }
    internal long ReceivedBytes { get; private set; }
    internal long RetiredBytes { get; private set; }
    internal AudioCaptureContentReceipt? ContentReceipt { get; private set; }

    // The synchronous port must copy these bytes without mutation or retention.
    // A bounded snapshot prevents the caller's wire array changing during native admission.
    internal void Enqueue(AudioStreamingMessage message, Action<byte[]> enqueue)
    {
        RequireOwner(); ArgumentNullException.ThrowIfNull(enqueue);
        try
        {
            RequireReceiving();
            if (message.StreamId != StreamId || message.Body is not AudioStreamingBody.PcmData data ||
                data.Bytes is null || data.Bytes.Length == 0 || data.Bytes.Length > AudioStreamingWire.MaximumPcmDataBytes ||
                data.ByteOffset != ReceivedBytes || data.ByteOffset > long.MaxValue - data.Bytes.Length)
                throw new InvalidDataException("Captured PCM stream, sequence or extent is invalid.");
            if (data.Bytes.Length % Format.BytesPerFrame != 0)
                throw new InvalidDataException("Captured PCM contains a partial frame.");
            long outstanding = ReceivedBytes - RetiredBytes;
            if (outstanding < 0 || outstanding > WindowBytes || data.Bytes.Length > WindowBytes - outstanding)
                throw new InvalidDataException("Captured PCM exceeded the unretired receive window.");
            var frozen = data.Bytes.ToArray();
            _submitting = true;
            try { enqueue(frozen); }
            finally { _submitting = false; }
            // Commit only after the actual output owner accepts the whole packet.
            _digest.AppendData(frozen);
            ReceivedBytes += frozen.Length;
        }
        catch { Fault(); throw; }
    }

    // Cumulative source frames from this exact output owner. Padding/device clock
    // ticks cannot be counted here. Repeated observations grant no new credit.
    internal AudioStreamingBody.Credit? Retire(long sourceFrames)
    {
        RequireOwner();
        try
        {
            RequireLive();
            if (sourceFrames < 0 || sourceFrames > ReceivedBytes / Format.BytesPerFrame)
                throw new InvalidDataException("PCM retirement exceeds accepted source frames.");
            long bytes = sourceFrames * Format.BytesPerFrame;
            if (bytes < RetiredBytes) throw new InvalidDataException("PCM retirement moved backwards.");
            if (bytes == RetiredBytes) return null;
            RetiredBytes = bytes;
            return new(bytes);
        }
        catch { Fault(); throw; }
    }

    internal AudioCaptureContentReceipt VerifyEnd(AudioStreamingMessage message)
    {
        RequireOwner();
        try
        {
            RequireReceiving();
            if (message.StreamId != StreamId || message.Body is not AudioStreamingBody.End end ||
                end.TotalBytes != ReceivedBytes || end.Sha256 is null || end.Sha256.Length != 32)
                throw new InvalidDataException("PCM end does not match this stream's accepted bytes.");
            var digest = _digest.GetHashAndReset();
            if (!CryptographicOperations.FixedTimeEquals(digest, end.Sha256))
                throw new InvalidDataException("Captured PCM content digest differs from the sender's digest.");
            ContentReceipt = new(ReceivedBytes, ReceivedBytes / Format.BytesPerFrame, Convert.ToHexStringLower(digest));
            State = AudioCaptureReceiveState.ContentVerified;
            return ContentReceipt;
        }
        catch { Fault(); throw; }
    }

    private void RequireOwner()
    {
        if (Environment.CurrentManagedThreadId != _ownerThread || _submitting)
            throw new InvalidOperationException("PCM accounting requires its sole native worker without reentrant submission.");
    }
    private void RequireLive()
    {
        if (State is AudioCaptureReceiveState.Faulted or AudioCaptureReceiveState.Disposed)
            throw new InvalidOperationException("Captured PCM accounting has ended.");
    }
    private void RequireReceiving()
    {
        RequireLive();
        if (State != AudioCaptureReceiveState.Receiving) throw new InvalidDataException("Captured PCM input has already ended.");
    }
    private void Fault()
    {
        if (State != AudioCaptureReceiveState.Disposed) State = AudioCaptureReceiveState.Faulted;
    }
    public void Dispose()
    {
        RequireOwner();
        if (State == AudioCaptureReceiveState.Disposed) return;
        _digest.Dispose(); State = AudioCaptureReceiveState.Disposed;
    }
}
