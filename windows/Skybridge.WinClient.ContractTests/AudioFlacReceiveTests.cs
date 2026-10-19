using Skybridge.WinClient.Services.Audio;

internal static class AudioFlacReceiveTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("FLAC product receives unchanged original file and submits exact 24-bit PCM", () => Complete("golden-24-2")),
        ("FLAC product preserves actual 32-bit 192 kHz reference PCM", () => Complete("reference-true32-stereo")),
        ("FLAC product preserves six-channel 24-bit reference PCM", () => Complete("reference-s24-48000-6ch")),
        ("FLAC product validates missing optional MD5 without claiming it was verified", () => Complete("md5-explicitly-unavailable")),
        ("FLAC product rejects frame CRC corruption before any output open", () => Reject("frame-crc-mismatch")),
        ("FLAC product rejects whole-file MD5 mismatch before any output open", () => Reject("valid-crc-wrong-pcm-md5")),
        ("FLAC product rejects missing silence instead of native recovery", () => Reject("missing-silent-middle-must-not-recover")),
        ("FLAC product rejects unknown duration before any output open", () => Reject("unknown-length-not-admitted-by-finite-decoder")),
        ("FLAC host advertises only its installed exact file role and retires it", Capability)
    ];
    private static async Task Complete(string name)
    {
        await using var f = await AudioOriginalFileReceiveSessionTests.Fixture.Create();
        f.Bytes = AudioFlacDecoderTests.Bytes(name);
        var pcm = AudioFlacDecoderTests.Bytes(name, ".pcm");
        var metadata = await AudioFlacFile.InspectAsync(f.Bytes.Length,
            (offset, count, _) => Task.FromResult(f.Bytes.AsSpan((int)offset, count).ToArray()), f.Main.Lan.Token);
        long frames = metadata.TotalFrames ?? throw new Exception("Missing fixture sample count.");
        f.Main.Native.ExpectedFormat = metadata.DecodedFormat.RequireExactOutputFormat();
        f.Main.Native.AllowRetirement = true;
        await f.Offer(); await f.Transfer();
        var output = await f.Main.Read();
        if (output.Body is AudioStreamingBody.Stop)
        {
            var failure = await f.Main.Failure();
            Trace();
            throw new Exception("FLAC product failed before OutputReady: " + failure.Reason, failure);
        }
        Require(output.Body is AudioStreamingBody.OutputReady ready && ready.Format == metadata.DecodedFormat,
            "OutputReady substituted FLAC precision, rate, channel order or container.");
        var final = await f.Main.Read();
        if (final.Body is AudioStreamingBody.Stop)
        {
            var failure = await f.Main.Failure();
            Trace();
            throw new Exception("FLAC product failed after OutputReady: " + failure.Reason, failure);
        }
        Require(final.Body is AudioStreamingBody.PlaybackComplete complete &&
            complete.SourceFrames == metadata.TotalFrames && complete.TrailingPaddingFrames == 0, "Incorrect FLAC playback receipt.");
        var received = await f.Main.Run!.WaitAsync(f.Main.Lan.Token);
        Require(received is AudioPlaybackReceiveReceipt.OriginalFile file && file.FileBytes == f.Bytes.Length &&
            file.FileSha256Hex == f.Metadata.FileHash && file.Format == metadata.DecodedFormat &&
            file.Output.SourceFrames == (ulong)frames, "File, format and rendered extent were not bound.");
        Require(f.Main.Native.Submissions.SelectMany(bytes => bytes).SequenceEqual(pcm), "FLAC decoding changed reference sample bytes.");
        Trace();
        f.Released(); f.Main.NativeReleased(); await f.Main.Lan.Barrier();
        void Trace() => Console.WriteLine("FLAC_PROGRESS " + System.Text.Json.JsonSerializer.Serialize(new
        {
            fixture = name, sourceFrames = frames, format = metadata.DecodedFormat,
            runtime = Environment.Version.ToString(), processors = Environment.ProcessorCount,
            threadPoolThreads = ThreadPool.ThreadCount, pendingWork = ThreadPool.PendingWorkItemCount,
            nativeReleaseConfirmed = f.Main.Receiver.NativeReleaseConfirmed,
            pacing = f.Main.Native.PacingKind,
            nativePacingReleased = f.Main.Native.NativePacingReleased,
            observations = f.Main.Native.ObservedWaits, retained = f.Main.Native.WaitObservations()
        }));
    }
    private static async Task Reject(string name)
    {
        await using var f = await AudioOriginalFileReceiveSessionTests.Fixture.Create();
        f.Bytes = AudioFlacDecoderTests.Bytes(name);
        await f.Offer(); await f.Transfer();
        var failure = await f.Main.Failure();
        Require(failure.Reason == AudioStreamingStopReason.UnsupportedSource && f.Main.Device.Activations == 0 &&
            f.Main.Device.OwnerThread == 0 && f.Main.Native.Submissions.Count == 0, "Invalid FLAC opened or submitted to native output.");
        var controls = await f.Main.UntilStop();
        Require(controls.Count == 1 && controls[0] is AudioStreamingBody.Stop, "Invalid FLAC announced output readiness or completion.");
        f.Released(); await f.Main.Lan.Barrier();
    }
    private static async Task Capability()
    {
        await using var f = await AudioOriginalFileReceiveSessionTests.Fixture.Create();
        await using var host = new AudioReceiveHost((session, endpoint) => f.Main.Receiver, f.Registry);
        await host.AttachAsync(f.Main.Lan.Session, f.Main.Lan.Token);
        await host.EnableAsync(AudioCaptureReceiveSessionTests.Endpoint, f.Main.Lan.Token);
        var identity = Skybridge.WinClient.Services.LanProductControlMessages.Payload<Skybridge.WinClient.Services.LanProductIdentity>(await f.Main.Lan.Read());
        Require(identity.FileTransferPort == f.Endpoint.Port && identity.Capabilities is { } capabilities &&
            capabilities.Contains("audio_flac_file_receive_v1") && capabilities.Contains("audio_file_receive_v1") &&
            !capabilities.Contains("file_transfer"), "FLAC role did not bind the exact listener or overstated authority.");
        await host.DisableAsync();
        var disabled = Skybridge.WinClient.Services.LanProductControlMessages.Payload<Skybridge.WinClient.Services.LanProductIdentity>(await f.Main.Lan.Read());
        Require(disabled.Capabilities?.Any(value => value is "audio_file_receive_v1" or "audio_flac_file_receive_v1" or "audio_capture_receive_v1") != true,
            "Disabled receiver retained a published audio role.");
    }
    internal static async Task UnavailableComponent(bool malformed)
    {
        await using var f = await AudioOriginalFileReceiveSessionTests.Fixture.Create();
        Require(AudioFlacNative.IsPackaged == malformed, "Component fixture does not match the intended package state.");
        if (malformed)
        {
            try { _ = f.Registry.ReceiveSupportFor(f.Main.Lan.Session); }
            catch (AudioFlacComponentException error)
            {
                Require(error.InnerException is DllNotFoundException or BadImageFormatException or EntryPointNotFoundException,
                    "Malformed package lost its loader failure.");
                Require(f.Main.Device.OwnerThread == 0, "Broken component opened native output."); return;
            }
            throw new Exception("Malformed decoder was treated as an available or silently absent role.");
        }
        Require(f.Registry.ReceiveSupportFor(f.Main.Lan.Session) == AudioOriginalFileReceiveSupport.Wave,
            "A missing FLAC component was advertised or disabled existing WAVE support.");
        f.Bytes = AudioFlacDecoderTests.Bytes("golden-24-2"); await f.Offer(); await f.Transfer();
        var failure = await f.Main.Failure();
        Require(failure.Reason == AudioStreamingStopReason.UnsupportedSource && f.Main.Device.OwnerThread == 0,
            "Unavailable decoder fell back to an implicit conversion or native output.");
        Require((await f.Main.UntilStop()).Count == 1, "Unavailable decoder announced output readiness."); f.Released();
    }
    private static void Require(bool value, string message) { if (!value) throw new Exception(message); }
}
