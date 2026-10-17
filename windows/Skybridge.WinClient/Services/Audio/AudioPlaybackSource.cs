namespace Skybridge.WinClient.Services.Audio;

// Frozen at actual offer admission. No mutable wire arrays or file-name guesses
// participate in a receiver's one-stream approval.
internal abstract record AudioPlaybackSource
{
    private AudioPlaybackSource() { }
    internal sealed record OriginalFile(Guid TransferId, long Length, string Sha256Hex) : AudioPlaybackSource;
    internal sealed record CapturedPcm(AudioStreamingPcmFormat Format) : AudioPlaybackSource;

    internal static AudioPlaybackSource FromOffer(AudioStreamingMessage offer)
    {
        var frozen = AudioStreamingWire.Decode(AudioStreamingWire.Encode(offer));
        return frozen.Body switch
        {
            AudioStreamingBody.FileOffer file => new OriginalFile(file.TransferId, file.Length, Convert.ToHexStringLower(file.Sha256)),
            AudioStreamingBody.CaptureOffer capture => new CapturedPcm(capture.Format),
            _ => throw new InvalidDataException("Playback approval requires an original-file or captured-PCM offer.")
        };
    }
}
