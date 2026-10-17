using System.Text.Json;
using Skybridge.WinClient.Services.Audio;

internal static class AudioStreamingLanEnvelopeTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("LAN audio envelope preserves all 31 shared SBAU vectors", Vectors),
        ("recognized LAN audio never falls through on truncation corruption or oversize", Malformed),
        ("LAN audio prefix distinguishes legacy JSON and other business kinds", OtherCarrier)
    ];
    private static Task Vectors()
    {
        using var document = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "audio-streaming-v1-vectors.json")));
        foreach (var vector in document.RootElement.GetProperty("vectors").EnumerateArray())
        {
            var payload = Convert.FromHexString(vector.GetProperty("hex").GetString()!);
            var expected = Convert.FromHexString("53424531020000000000000000").Concat(payload).ToArray();
            var encoded = AudioStreamingLanEnvelope.Encode(AudioStreamingWire.Decode(payload));
            Require(expected.SequenceEqual(encoded), "SBE1 changed the shared payload or header.");
            var decoded = AudioStreamingLanEnvelope.DecodeIfPresent(encoded) ?? throw new Exception("Audio carrier not recognized.");
            encoded.AsSpan().Clear();
            Require(AudioStreamingWire.Encode(decoded).SequenceEqual(payload), "Decoded payload retained mutable carrier bytes.");
        }
        return Task.CompletedTask;
    }
    private static byte[] Envelope() => AudioStreamingLanEnvelope.Encode(new(Guid.NewGuid(), new AudioStreamingBody.Credit(7)));
    private static Task Malformed()
    {
        var valid = Envelope();
        for (var length = 5; length < valid.Length; length++) Reject(valid[..length]);
        for (var index = 5; index < AudioStreamingLanEnvelope.HeaderBytes; index++)
        { var bad = valid.ToArray(); bad[index] = 1; Reject(bad); }
        var badPayload = valid.ToArray(); badPayload[13] = 0; Reject(badPayload);
        Reject([..valid, 0]);
        var maximum = AudioStreamingLanEnvelope.Encode(new(Guid.NewGuid(),
            new AudioStreamingBody.PcmData(0, new byte[AudioStreamingWire.MaximumPcmDataBytes])));
        Require(maximum.Length == AudioStreamingLanEnvelope.MaximumBytes, "Envelope maximum changed.");
        Require(AudioStreamingLanEnvelope.DecodeIfPresent(maximum) is not null, "Exact maximum was rejected.");
        Reject([..maximum, 0]);
        return Task.CompletedTask;
    }
    private static Task OtherCarrier()
    {
        foreach (var bytes in new[] { Array.Empty<byte>(), "SBE1"u8.ToArray(), "{\"ping\":{\"id\":1}}"u8.ToArray(),
            new byte[] { 83, 66, 69, 49, 1 }, new byte[] { 83, 66, 69, 49, 3 } })
            Require(AudioStreamingLanEnvelope.DecodeIfPresent(bytes) is null, "Another carrier was claimed as audio.");
        return Task.CompletedTask;
    }
    private static void Reject(byte[] bytes)
    {
        try { _ = AudioStreamingLanEnvelope.DecodeIfPresent(bytes); }
        catch (InvalidDataException) { return; }
        throw new Exception("Recognized malformed audio did not fail.");
    }
    private static void Require(bool condition, string reason) { if (!condition) throw new Exception(reason); }
}
