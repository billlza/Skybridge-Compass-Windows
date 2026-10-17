using System.Security.Cryptography;
using Skybridge.WinClient.Services.Audio;

internal static class AudioCaptureReceiveFlowTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("PCM receiver preserves bytes and verifies content independently of retirement", () => Run(ValidStream)),
        ("PCM receiver credits only cumulative retired source frames", () => Run(Window)),
        ("PCM receiver rejects malformed sequences before native enqueue", () => Run(InvalidData)),
        ("PCM receiver native enqueue failure cannot grant bytes credit or retry", () => Run(EnqueueFailure)),
        ("PCM receiver snapshots caller bytes before synchronous native admission", () => Run(Snapshot)),
        ("PCM receiver end mismatch is terminal and cannot claim content verification", () => Run(InvalidEnd)),
        ("PCM receiver accepts empty source content without inventing playback completion", () => Run(Empty)),
        ("PCM receiver rejects padding retirement and backwards source progress", () => Run(InvalidProgress)),
        ("PCM receiver requires its single native worker and rejects reentrancy", () => Run(Ownership)),
        ("PCM receiver validates format stream and bounded whole-frame window", () => Run(Construction))
    ];
    private static Task Run(Action action) { action(); return Task.CompletedTask; }
    private static readonly AudioStreamingPcmFormat Format = new(48000, 2, AudioStreamingEncoding.Float32, 32, 3);
    private static AudioStreamingMessage Data(AudioCaptureReceiveFlow flow, long offset, byte[] bytes) => new(flow.StreamId, new AudioStreamingBody.PcmData(offset, bytes));
    private static AudioStreamingMessage End(AudioCaptureReceiveFlow flow, byte[] bytes) => new(flow.StreamId, new AudioStreamingBody.End(bytes.Length, SHA256.HashData(bytes)));
    private static AudioCaptureReceiveFlow Flow(uint window = 32) => new(Guid.NewGuid(), Format, window);
    private static void ValidStream()
    {
        using var flow = Flow(); byte[] bytes = Enumerable.Range(0, 24).Select(n => (byte)n).ToArray();
        var received = new List<byte>();
        flow.Enqueue(Data(flow, 0, bytes[..16]), packet => received.AddRange(packet));
        flow.Enqueue(Data(flow, 16, bytes[16..]), packet => received.AddRange(packet));
        var receipt = flow.VerifyEnd(End(flow, bytes));
        Require(received.SequenceEqual(bytes) && receipt.TotalBytes == 24 && receipt.SourceFrames == 3 &&
            receipt.Sha256Hex == Convert.ToHexStringLower(SHA256.HashData(bytes)), "PCM bytes/format/content accounting changed.");
        Require(flow.State == AudioCaptureReceiveState.ContentVerified && flow.RetiredBytes == 0, "Content verification invented source retirement.");
        Require(flow.Retire(3)?.RetiredBytes == 24 && flow.Retire(3) is null, "Final cumulative retirement/duplicate credit changed.");
        Require(flow.State == AudioCaptureReceiveState.ContentVerified, "Queue retirement invented playback completion.");
        Throws<InvalidDataException>(() => flow.Enqueue(Data(flow, 24, new byte[8]), _ => throw new Exception("Late native enqueue.")));
    }
    private static void Window()
    {
        using var flow = Flow(16); var all = new List<byte>();
        void Accept(byte[] bytes) => all.AddRange(bytes);
        flow.Enqueue(Data(flow, 0, new byte[16]), Accept);
        Require(flow.ReceivedBytes == 16 && flow.RetiredBytes == 0, "Enqueue granted sender credit.");
        Require(flow.Retire(1)?.RetiredBytes == 8, "Retirement did not count exact source frames.");
        flow.Enqueue(Data(flow, 16, new byte[8]), Accept);
        Require(flow.Retire(1) is null, "Repeated native position granted new credit.");
        Throws<InvalidDataException>(() => flow.Enqueue(Data(flow, 24, new byte[8]), Accept));
        Require(all.Count == 24 && flow.ReceivedBytes == 24 && flow.State == AudioCaptureReceiveState.Faulted, "Over-window packet reached native output.");
    }
    private static void InvalidData()
    {
        foreach (int variant in Enumerable.Range(0, 7))
        {
            using var flow = Flow(); int calls = 0;
            AudioStreamingMessage packet = variant switch
            {
                0 => new(Guid.NewGuid(), new AudioStreamingBody.PcmData(0, new byte[8])),
                1 => Data(flow, 8, new byte[8]),
                2 => Data(flow, 0, []),
                3 => Data(flow, 0, new byte[7]),
                4 => Data(flow, long.MaxValue, new byte[8]),
                5 => Data(flow, 0, new byte[AudioStreamingWire.MaximumPcmDataBytes + 1]),
                _ => new(flow.StreamId, new AudioStreamingBody.Accept(32))
            };
            Throws<InvalidDataException>(() => flow.Enqueue(packet, _ => calls++));
            Require(calls == 0 && flow.ReceivedBytes == 0 && flow.State == AudioCaptureReceiveState.Faulted, "Invalid PCM reached output or remained reusable.");
        }
    }
    private static void EnqueueFailure()
    {
        using var flow = Flow(); var cause = new IOException("native submission uncertain");
        var actual = Throws<IOException>(() => flow.Enqueue(Data(flow, 0, new byte[8]), _ => throw cause));
        Require(ReferenceEquals(cause, actual) && flow.ReceivedBytes == 0 && flow.RetiredBytes == 0, "Uncertain submission lost its cause or counted bytes.");
        Throws<InvalidOperationException>(() => flow.Enqueue(Data(flow, 0, new byte[8]), _ => throw new Exception("Retried uncertain submission.")));
        Throws<InvalidOperationException>(() => flow.VerifyEnd(End(flow, [])));
    }
    private static void Snapshot()
    {
        using var flow = Flow(); byte[] source = [1, 2, 3, 4, 5, 6, 7, 8]; byte[] original = source.ToArray();
        flow.Enqueue(Data(flow, 0, source), packet => {
            Array.Fill(source, (byte)99);
            Require(packet.SequenceEqual(original), "Source mutation changed the admitted native packet.");
        });
        Require(flow.VerifyEnd(End(flow, original)).Sha256Hex == Convert.ToHexStringLower(SHA256.HashData(original)), "Digest followed the mutated caller buffer.");
    }
    private static void InvalidEnd()
    {
        foreach (int variant in Enumerable.Range(0, 4))
        {
            using var flow = Flow(); flow.Enqueue(Data(flow, 0, new byte[8]), _ => { });
            AudioStreamingMessage end = variant switch
            {
                0 => new(Guid.NewGuid(), new AudioStreamingBody.End(8, SHA256.HashData(new byte[8]))),
                1 => new(flow.StreamId, new AudioStreamingBody.End(16, SHA256.HashData(new byte[8]))),
                2 => new(flow.StreamId, new AudioStreamingBody.End(8, new byte[32])),
                _ => new(flow.StreamId, new AudioStreamingBody.End(8, new byte[31]))
            };
            Throws<InvalidDataException>(() => flow.VerifyEnd(end));
            Require(flow.ContentReceipt is null && flow.State == AudioCaptureReceiveState.Faulted, "Invalid end produced verification.");
            Throws<InvalidOperationException>(() => flow.VerifyEnd(End(flow, new byte[8])));
        }
    }
    private static void Empty()
    {
        using var flow = Flow(); var receipt = flow.VerifyEnd(End(flow, []));
        Require(receipt.SourceFrames == 0 && receipt.TotalBytes == 0 && flow.Retire(0) is null, "Empty capture invented output frames.");
        Throws<InvalidDataException>(() => flow.VerifyEnd(End(flow, [])));
    }
    private static void InvalidProgress()
    {
        foreach (long progress in new long[] { -1, 0, 2, long.MaxValue })
        {
            using var flow = Flow(); flow.Enqueue(Data(flow, 0, new byte[8]), _ => { });
            _ = flow.Retire(1);
            Throws<InvalidDataException>(() => flow.Retire(progress));
            Require(flow.RetiredBytes == 8 && flow.State == AudioCaptureReceiveState.Faulted, "Invalid progress expanded credit.");
        }
    }
    private static void Ownership()
    {
        using var flow = Flow();
        flow.Enqueue(Data(flow, 0, new byte[8]), _ => {
            Throws<InvalidOperationException>(() => flow.Retire(0));
            Throws<InvalidOperationException>(flow.Dispose);
        });
        Exception? wrongThread = null;
        var thread = new Thread(() => { try { flow.Retire(1); } catch (Exception error) { wrongThread = error; } });
        thread.Start(); thread.Join();
        Require(wrongThread is InvalidOperationException && flow.RetiredBytes == 0 && flow.State == AudioCaptureReceiveState.Receiving, "Foreign worker mutated accounting.");
        Require(flow.Retire(1)?.RetiredBytes == 8, "Owner could not resume after rejected foreign access.");
    }
    private static void Construction()
    {
        foreach (uint window in new uint[] { 0, 7, AudioStreamingWire.MaximumReceiveWindowBytes + 8 })
            Throws<InvalidDataException>(() => Flow(window));
        Throws<InvalidDataException>(() => new AudioCaptureReceiveFlow(Guid.Empty, Format, 32));
        using var flow = new AudioCaptureReceiveFlow(Guid.NewGuid(), new(44100, 2, AudioStreamingEncoding.Signed24, 20, null), 30);
        Require(flow.Format.ValidBits == 20 && flow.Format.ContainerBits == 24 && flow.Format.WaveChannelMask is null,
            "Accounting silently changed precision or inferred unknown layout.");
        flow.Dispose(); Throws<InvalidOperationException>(() => flow.Retire(0));
    }
    private static T Throws<T>(Action action) where T : Exception
    { try { action(); } catch (T error) { return error; } throw new Exception($"Expected {typeof(T).Name}."); }
    private static void Require(bool condition, string reason) { if (!condition) throw new Exception(reason); }
}
