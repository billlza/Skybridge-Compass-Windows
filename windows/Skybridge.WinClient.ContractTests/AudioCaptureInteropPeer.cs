using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using Skybridge.WinClient.Services.Audio;

/// <summary>Explicit test peer for another runtime's PCM sender. The binary stdin
/// bridge carries SBAU messages into the existing encrypted loopback MAIN fixture.
/// Account responses and the PCM output device are controlled test boundaries;
/// this never opens WASAPI, reads credentials or accepts a network listener.</summary>
internal static class AudioCaptureInteropPeer
{
    internal static async Task RunAsync(string scenario, string byteCount, string frameCount, string sha256)
    {
        if (scenario is not ("complete" or "decline" or "bad-digest") ||
            !int.TryParse(byteCount, out int expectedBytes) || expectedBytes is <= 0 or > 2 * 1024 * 1024 ||
            !int.TryParse(frameCount, out int expectedFrames) || expectedFrames <= 0 ||
            sha256.Length != 64 || sha256.Any(c => !Uri.IsHexDigit(c)))
            throw new ArgumentException("Use a named PCM contract scenario and bounded fixture extent/digest.");
        using var input = Console.OpenStandardInput();
        await using var f = await AudioCaptureReceiveSessionTests.Fixture.Create();
        f.Native.AllowRetirement = true;
        if (scenario == "decline") f.Decide = (_, _) => Task.FromResult(false);
        f.Run = f.Receiver.RunAsync(f.Caller.Token);
        await f.Receiver.ReadyForOffer.WaitAsync(f.Lan.Token);
        Write(new { kind = "ready", scenario, scope = "synthetic-account-and-output; encrypted-loopback-MAIN" });
        long acceptedInput = 0; int credits = 0; Guid? streamId = null; bool offerReceived = false;
        var incoming = ForwardInput();
        var outgoing = ForwardReplies();
        AudioPlaybackReceiveReceipt? receipt = null;
        AudioCaptureReceiveException? failure = null;
        try
        {
            if (scenario == "complete") receipt = await f.Run.WaitAsync(f.Lan.Token);
            else failure = await f.Failure();
            await outgoing.WaitAsync(f.Lan.Token);
            // The sender closes its owned stdin after its session/cleanup ends.
            await incoming.WaitAsync(f.Lan.Token);
            if (scenario == "complete")
            {
                Require(receipt is AudioPlaybackReceiveReceipt.Captured captured &&
                    captured.Content.TotalBytes == expectedBytes && captured.Content.SourceFrames == expectedFrames &&
                    string.Equals(captured.Content.Sha256Hex, sha256, StringComparison.OrdinalIgnoreCase),
                    "Receiver content receipt differs from the sender fixture.");
                f.NativeReleased();
            }
            else
            {
                var expectedReason = scenario == "decline" ? AudioStreamingStopReason.ReceiverDeclined : AudioStreamingStopReason.ContentMismatch;
                Require(failure?.Reason == expectedReason && failure.CleanupFailures.Count == 0 && f.Receiver.ResourcesReleaseConfirmed,
                    "Receiver failure lost its exact reason or resource outcome.");
                if (scenario == "decline")
                    Require(f.Device.Activations == 0 && f.Native.StartCalls == 0 && acceptedInput == 0,
                        "Declined playback opened the output or received PCM.");
                else f.NativeReleased();
            }
            byte[] submitted = f.Native.Submissions.SelectMany(p => p).ToArray();
            string submittedHash = Convert.ToHexStringLower(SHA256.HashData(submitted));
            if (scenario != "decline")
                Require(submitted.Length == expectedBytes && string.Equals(submittedHash, sha256, StringComparison.OrdinalIgnoreCase),
                    "Native-boundary fixture bytes were converted, lost, duplicated or padded.");
            await f.Lan.Barrier();
            Write(new { kind = "result", scenario, status = failure is null ? "completed" : "expected-rejection",
                reason = failure?.Reason.ToString(), bytes = submitted.Length, sha256 = submittedHash,
                creditMessages = credits, nativeReleased = f.Receiver.ResourcesReleaseConfirmed,
                mainStillUsable = true, physicalPlaybackQualified = false });
        }
        catch (Exception error)
        {
            var errors = new List<Exception> { error };
            f.Caller.Cancel(); f.Lan.Cancel(); input.Dispose();
            foreach (var task in new[] { incoming, outgoing })
            {
                try { await task.WaitAsync(TimeSpan.FromSeconds(2)); }
                catch (OperationCanceledException canceled) when (canceled.CancellationToken == f.Lan.Token && f.Lan.Token.IsCancellationRequested) { }
                catch (Exception observerFailure) { if (!errors.Contains(observerFailure)) errors.Add(observerFailure); }
            }
            var retained = errors.Count == 1 ? error : new AggregateException("Peer operation and relay cleanup failed.", errors);
            Write(new { kind = "error", scenario, error = retained.ToString() });
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(retained).Throw();
        }

        async Task ForwardInput()
        {
            byte[] header = new byte[4];
            while (await input.ReadAsync(header.AsMemory(0, 1), f.Lan.Token) != 0)
            {
                await input.ReadExactlyAsync(header.AsMemory(1), f.Lan.Token);
                int length = BinaryPrimitives.ReadInt32BigEndian(header);
                Require(length is > 0 and <= AudioStreamingWire.MaximumMessageBytes, "Invalid bridge message size.");
                byte[] bytes = new byte[length];
                await input.ReadExactlyAsync(bytes, f.Lan.Token);
                var message = AudioStreamingWire.Decode(bytes);
                Require(AudioStreamingWire.Encode(message).AsSpan().SequenceEqual(bytes), "Bridge normalized noncanonical wire bytes.");
                streamId ??= message.StreamId;
                Require(message.StreamId == streamId, "Bridge changed its selected stream.");
                if (message.Body is AudioStreamingBody.CaptureOffer offer)
                {
                    Require(!offerReceived && (long)offer.Format.BytesPerFrame * expectedFrames == expectedBytes,
                        "Offer repeated or changed the predeclared source extent.");
                    offerReceived = true;
                    f.Native.ExpectedFormat = offer.Format.RequireExactOutputFormat();
                }
                Require(offerReceived, "Bridge sent media before its source declaration.");
                if (message.Body is AudioStreamingBody.PcmData data)
                {
                    acceptedInput = checked(acceptedInput + data.Bytes.Length);
                    Require(acceptedInput <= expectedBytes, "Bridge exceeded its predeclared source extent.");
                }
                await f.Lan.SendAudio(message);
            }
        }
        async Task ForwardReplies()
        {
            for (int count = 0; count < 10_000; count++)
            {
                var message = await f.Lan.ReadAudio();
                if (message.Body is AudioStreamingBody.Credit) credits++;
                Write(new { kind = "frame", payload = Convert.ToBase64String(AudioStreamingWire.Encode(message)) });
                if (message.Body is AudioStreamingBody.PlaybackComplete or AudioStreamingBody.Stop) return;
            }
            throw new InvalidDataException("Receiver exceeded the bounded reply count.");
        }
    }

    private static readonly object OutputGate = new();
    private static void Write(object value)
    { lock (OutputGate) { Console.WriteLine(JsonSerializer.Serialize(value)); Console.Out.Flush(); } }
    private static void Require(bool condition, string message)
    { if (!condition) throw new InvalidDataException(message); }
}
