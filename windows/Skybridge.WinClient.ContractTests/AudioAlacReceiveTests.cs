using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.Audio;

internal static class AudioAlacReceiveTests
{
    internal static IEnumerable<(string Name, Func<Task> Run)> Cases
    {
        get
        {
            using var manifest = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory,
                "Fixtures", "alac-decoder-v1", "manifest.json")));
            foreach (var item in manifest.RootElement.GetProperty("cases").EnumerateArray())
            {
                string name = item.GetProperty("name").GetString() ?? throw new Exception("Missing ALAC fixture name.");
                yield return ($"ALAC product receives the original file and submits exact reference PCM: {name}", () => Complete(name));
            }
            yield return ("ALAC product inspects actual content rather than the filename", () => Complete("48000-2-s24", "original.wav"));
            yield return ("ALAC product rejects a corrupt final packet before opening output", CorruptTail);
            yield return ("ALAC product rejects container/native sample-count disagreement before output", WrongFrameCount);
            yield return ("M4A naming cannot turn an unsupported AAC declaration into ALAC", UnsupportedEncoding);
            yield return ("ALAC preparation adapter failure is not attributed to an unopened output", PreparationFailure);
            yield return ("ALAC output failure retains its cause and never submits converted samples", OutputFailure);
            yield return ("ALAC account revocation after full validation prevents sample submission", RevokedBeforePlayback);
            yield return ("ALAC render cancellation stops and releases without playback completion", CancelRendering);
            yield return ("ALAC completion waits for native release and then private-file release", TailRelease);
            yield return ("ALAC host advertises qualified codecs independently and withdraws all disabled roles", Capability);
            yield return ("ALAC host accepts its advertised original-file offer and returns exact playback completion", HostReception);
            yield return ("ALAC USB original file preserves 20 valid bits through the actual return protocol", () => AudioUsbFileReceiveTests.CompleteAlac("44100-2-s20"));
            yield return ("ALAC USB original file preserves true 32-bit PCM through the actual return protocol", () => AudioUsbFileReceiveTests.CompleteAlac("96000-2-s32"));
            yield return ("ALAC USB capability requires the exact installed return owner", AudioUsbFileReceiveTests.AlacCapability);
            foreach (var test in AudioAlacPreparationTests.Cases) yield return test;
        }
    }

    private static async Task Complete(string name, string fileName = "original.m4a")
    {
        await using var f = await AudioOriginalFileReceiveSessionTests.Fixture.Create();
        f.Bytes = AudioAlacDecoderTests.Bytes(name); f.FileName = fileName;
        var pcm = AudioAlacDecoderTests.Bytes(name, ".pcm");
        var metadata = await AudioAlacDecoderTests.Metadata(f.Bytes);
        f.Main.Native.ExpectedFormat = metadata.DecodedFormat.RequireExactOutputFormat();
        f.Main.Native.AllowRetirement = true;
        await f.Offer(); await f.Transfer();
        var output = await f.Main.Read();
        if (output.Body is AudioStreamingBody.Stop)
        {
            var failure = await f.Main.Failure();
            throw new Exception("ALAC product failed before OutputReady: " + failure.Reason, failure);
        }
        Require(output.Body is AudioStreamingBody.OutputReady ready && ready.Format == metadata.DecodedFormat,
            "OutputReady changed ALAC precision, rate, channels or container.");
        var final = await f.Main.Read();
        if (final.Body is AudioStreamingBody.Stop)
        {
            var failure = await f.Main.Failure();
            throw new Exception("ALAC product failed after OutputReady: " + failure.Reason, failure);
        }
        Require(final.Body is AudioStreamingBody.PlaybackComplete complete &&
            complete.SourceFrames == metadata.TotalFrames && complete.TrailingPaddingFrames == 0,
            "ALAC completion did not cover exactly the source frames.");
        var received = await f.Main.Run!.WaitAsync(f.Main.Lan.Token);
        Require(received is AudioPlaybackReceiveReceipt.OriginalFile file && file.FileBytes == f.Bytes.Length &&
            file.FileSha256Hex == f.Metadata.FileHash && file.Format == metadata.DecodedFormat &&
            file.Output.SourceFrames == (ulong)metadata.TotalFrames,
            "Original M4A, exact format and native frame extent were not bound.");
        Require(f.Main.Native.Submissions.SelectMany(bytes => bytes).SequenceEqual(pcm),
            "ALAC product PCM differs from the independent integer reference.");
        f.Released(); f.Main.NativeReleased(); await f.Main.Lan.Barrier();
    }

    private static async Task CorruptTail()
    {
        var bytes = AudioAlacDecoderTests.Bytes(); var metadata = await AudioAlacDecoderTests.Metadata(bytes);
        var cursor = metadata.MakePacketCursor(); AudioAlacPacket? last = null;
        while (await cursor.NextAsync((o, c, _) => Task.FromResult(bytes.AsSpan((int)o, c).ToArray()), () => { }, default) is { } packet)
            last = packet;
        var tail = last ?? throw new Exception("Fixture has no packet.");
        Require(tail.Index > 0, "Corruption must follow a valid prefix.");
        bytes.AsSpan((int)tail.ByteOffset, tail.ByteCount).Clear();
        await Reject(bytes, AudioStreamingStopReason.ContentMismatch);
    }
    private static async Task WrongFrameCount()
    {
        var bytes = AudioAlacDecoderTests.Bytes();
        int stts = Payload(bytes, "stts"), mdhd = Payload(bytes, "mdhd");
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(stts + 12), BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(stts + 12)) - 1);
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(mdhd + 16), BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(mdhd + 16)) - 1);
        await Reject(bytes, AudioStreamingStopReason.ContentMismatch);
    }
    private static Task UnsupportedEncoding()
    {
        var bytes = AudioAlacDecoderTests.Bytes();
        "mp4a"u8.CopyTo(bytes.AsSpan(Payload(bytes, "alac") - 4));
        return Reject(bytes, AudioStreamingStopReason.UnsupportedSource);
    }
    private static int Payload(byte[] bytes, string type)
    {
        int index = bytes.AsSpan().IndexOf(Encoding.ASCII.GetBytes(type));
        Require(index >= 4, "Missing known fixture box: " + type); return index + 4;
    }
    private static async Task Reject(byte[] bytes, AudioStreamingStopReason reason)
    {
        await using var f = await AudioOriginalFileReceiveSessionTests.Fixture.Create();
        f.Bytes = bytes; f.FileName = "original.m4a";
        await f.Offer(); await f.Transfer();
        var failure = await f.Main.Failure();
        Require(failure.Reason == reason && f.Main.Device.OwnerThread == 0 && f.Main.Device.Activations == 0 &&
            f.Main.Native.Submissions.Count == 0, "Invalid ALAC opened output or lost its failure category: " + failure.Reason);
        Require((await f.Main.UntilStop()).Count == 1, "Invalid ALAC announced output readiness or completion.");
        f.Released(); await f.Main.Lan.Barrier();
    }
    private static async Task OutputFailure()
    {
        await using var f = await ReadySource();
        var failure = new IOException("controlled endpoint preparation failure");
        f.Main.Native.PrepareFailure = failure;
        await f.Offer(); await f.Transfer(); var failed = await f.Main.Failure();
        Require(failed.Reason == AudioStreamingStopReason.UnsupportedOutput && ReferenceEquals(failed.Cause, failure) &&
            f.Main.Native.Submissions.Count == 0, "The receiver converted samples or hid an output failure.");
        Require((await f.Main.UntilStop()).Count == 1, "Failed output announced readiness or completion.");
        f.Released(); f.Main.NativeReleased();
    }
    private static async Task PreparationFailure()
    {
        await using var f = await ReadySource();
        var failure = new IOException("controlled preparation adapter failure"); int receiverThread = 0;
        f.Main.SelectOutput = _ =>
        {
            receiverThread = Environment.CurrentManagedThreadId;
            return Task.FromResult(AudioCaptureReceiveSessionTests.Endpoint);
        };
        // Inject through the prepass's real TimeProvider dependency. The native
        // receiver thread's timer remains operational, so the fault originates
        // in the awaited preparation task, before any device has been opened.
        f.Main.Clock.TimestampRead = () =>
        {
            if (f.Main.Receiver.Phase == AudioCaptureReceivePhase.Preparing &&
                Environment.CurrentManagedThreadId != Volatile.Read(ref receiverThread)) throw failure;
        };
        await f.Offer(); await f.Transfer(); var failed = await f.Main.Failure();
        Require(failed.Reason == AudioStreamingStopReason.SourceFailed && ReferenceEquals(failed.Cause, failure) &&
            f.Main.Device.OwnerThread == 0 && f.Main.Native.Submissions.Count == 0,
            "Preparation failure was hidden behind output incompatibility: " + failed.Reason);
        Require((await f.Main.UntilStop()).Count == 1, "Failed preparation announced output readiness.");
        f.Released(); await f.Main.Lan.Barrier();
    }
    private static async Task RevokedBeforePlayback()
    {
        await using var f = await ReadySource();
        f.Main.Native.PrepareAction = f.Main.Epoch.Revoke;
        await f.Offer(); await f.Transfer(); var failure = await f.Main.Failure();
        Require(failure.Reason == AudioStreamingStopReason.AccountRevoked && f.Main.Native.Submissions.Count == 0,
            "A validated ALAC witness bypassed live account authorization.");
        Require((await f.Main.UntilStop()).Count == 1, "Revocation announced output readiness or completion.");
        f.Released(); f.Main.NativeReleased();
    }
    private static async Task CancelRendering()
    {
        await using var f = await ReadySource(); f.Main.Native.BlockRenderingProgress = true;
        await f.Offer(); await f.Transfer();
        Require((await f.Main.Read()).Body is AudioStreamingBody.OutputReady, "Missing ALAC output declaration.");
        await f.Main.Native.RenderingProgressEntered.Task.WaitAsync(f.Main.Lan.Token);
        f.Main.Caller.Cancel();
        Require(!f.Main.Run!.IsCompleted, "Cancellation abandoned the blocked native owner.");
        f.Main.Native.ProgressRelease.Set(); var failure = await f.Main.Failure();
        Require(failure.Reason == AudioStreamingStopReason.UserStopped && f.Main.Native.StartCalls == 1 && f.Main.Native.Submissions.Count > 0,
            "The case did not cancel an actual ALAC render.");
        await f.Main.UntilStop(); f.Released(); f.Main.NativeReleased();
    }
    private static async Task TailRelease()
    {
        await using var f = await ReadySource(); f.Main.Native.BlockDispose = true;
        await f.Offer(); await f.Transfer();
        Require((await f.Main.Read()).Body is AudioStreamingBody.OutputReady, "Missing ALAC output declaration.");
        await f.Main.Native.DisposeEntered.Task.WaitAsync(f.Main.Lan.Token);
        Require(!f.Main.Run!.IsCompleted && !f.Main.Receiver.FileReleaseConfirmed && Directory.GetFiles(f.Root).Length == 1,
            "Native disposal entry was mistaken for release of output and source.");
        var completion = f.Main.Read(); await Task.Delay(25, f.Main.Lan.Token);
        Require(!completion.IsCompleted, "Playback completion preceded native release.");
        f.Main.Native.DisposeRelease.Set();
        Require((await completion).Body is AudioStreamingBody.PlaybackComplete, "No receipt after confirmed native release.");
        await f.Main.Run; f.Released(); f.Main.NativeReleased();
    }
    private static async Task<AudioOriginalFileReceiveSessionTests.Fixture> ReadySource()
    {
        var f = await AudioOriginalFileReceiveSessionTests.Fixture.Create();
        try
        {
            f.Bytes = AudioAlacDecoderTests.Bytes(); f.FileName = "original.m4a";
            var metadata = await AudioAlacDecoderTests.Metadata(f.Bytes);
            f.Main.Native.ExpectedFormat = metadata.DecodedFormat.RequireExactOutputFormat(); f.Main.Native.AllowRetirement = true;
            return f;
        }
        catch { await f.DisposeAsync(); throw; }
    }
    private static Task Capability() => Package("both");
    private static async Task HostReception()
    {
        await using var f = await ReadySource();
        var metadata = await AudioAlacDecoderTests.Metadata(f.Bytes);
        await using var host = new AudioReceiveHost((session, endpoint) =>
        {
            Require(ReferenceEquals(session, f.Main.Lan.Session) && endpoint == AudioCaptureReceiveSessionTests.Endpoint,
                "The host changed its actual MAIN or output owner.");
            return f.Main.Receiver;
        }, f.Registry);
        await host.AttachAsync(f.Main.Lan.Session, f.Main.Lan.Token);
        await host.EnableAsync(AudioCaptureReceiveSessionTests.Endpoint, f.Main.Lan.Token);
        var identity = LanProductControlMessages.Payload<LanProductIdentity>(await f.Main.Lan.Read());
        Require(Has(identity, LanProductControlSession.AlacFileReceiveCapability) && identity.FileTransferPort == f.Endpoint.Port,
            "The host did not advertise its qualified ALAC file role.");
        await f.Main.Lan.SendAudio(new(f.Main.StreamId, new AudioStreamingBody.FileOffer(f.TransferId, f.Bytes.Length, SHA256.HashData(f.Bytes))));
        Require((await f.Main.Read()).Body is AudioStreamingBody.Accept { ReceiveWindowBytes: 0 }, "The host did not accept original-file mode.");
        await f.Transfer();
        Require((await f.Main.Read()).Body is AudioStreamingBody.OutputReady ready && ready.Format == metadata.DecodedFormat,
            "The host changed the decoded ALAC format.");
        Require((await f.Main.Read()).Body is AudioStreamingBody.PlaybackComplete complete &&
            complete.SourceFrames == metadata.TotalFrames && complete.TrailingPaddingFrames == 0, "The host changed the source extent.");
        while (host.ReadSnapshot() is not { Phase: null, ListeningDevices: 1 }) await Task.Delay(1, f.Main.Lan.Token);
        Require(host.ReadSnapshot().Failure is null &&
            f.Main.Native.Submissions.SelectMany(bytes => bytes).SequenceEqual(AudioAlacDecoderTests.Bytes("48000-2-s24", ".pcm")),
            "The advertised host failed or changed the reference PCM.");
        f.Released(); f.Main.NativeReleased();
        await host.DisableAsync();
        var disabled = LanProductControlMessages.Payload<LanProductIdentity>(await f.Main.Lan.Read());
        Require(!Has(disabled, LanProductControlSession.AlacFileReceiveCapability) && host.ReadSnapshot().NativeReleaseConfirmed,
            "The host retained ALAC reception or output resources after disabling.");
        await f.Main.Lan.Barrier();
    }
    internal static async Task Package(string state)
    {
        bool flac = state is "flac" or "both" or "invalid" or "old-abi" or "missing-decode";
        bool alac = state is "alac" or "both";
        bool invalid = state is "invalid" or "old-abi" or "missing-decode";
        Require(state is "none" or "flac" or "alac" or "both" || invalid, "Unknown package fixture.");
        Require(AudioFlacNative.IsPackaged == flac && AudioAlacNative.IsPackaged == (alac || invalid), "Incorrect isolated codec package state.");
        await using var f = await AudioOriginalFileReceiveSessionTests.Fixture.Create();
        await using var host = new AudioReceiveHost((session, endpoint) => f.Main.Receiver, f.Registry);
        await host.AttachAsync(f.Main.Lan.Session, f.Main.Lan.Token);
        if (invalid)
        {
            try { await host.EnableAsync(AudioCaptureReceiveSessionTests.Endpoint, f.Main.Lan.Token); }
            catch (Exception error) when (error is AudioAlacComponentException or AggregateException)
            {
                // Enable reports its admission failure and the same terminal
                // listener failure retained by Stop. Reject unrelated cleanup errors.
                var failures = error is AggregateException aggregate ? aggregate.Flatten().InnerExceptions.ToArray() : [error];
                if (failures.Length == 0 || failures[0] is not AudioAlacComponentException component ||
                    failures.Any(item => !ReferenceEquals(item, component)))
                    throw new Exception("Package rejection lost its cause or acquired an unrelated cleanup failure.", error);
                if (state == "invalid") Require(component.InnerException is DllNotFoundException or BadImageFormatException,
                    "Broken binary lost its original loader diagnostic.");
                Require(!host.ReadSnapshot().Enabled && host.ReadSnapshot().NativeReleaseConfirmed &&
                    !Has(f.Main.Lan.Session.LocalIdentity, LanProductControlSession.AlacFileReceiveCapability) &&
                    !Has(f.Main.Lan.Session.LocalIdentity, LanProductControlSession.OriginalFileReceiveCapability) &&
                    f.Main.Device.OwnerThread == 0, "Broken ALAC silently advertised a receiving role.");
                return;
            }
            throw new Exception("The host ignored a present, invalid ALAC native component.");
        }
        await host.EnableAsync(AudioCaptureReceiveSessionTests.Endpoint, f.Main.Lan.Token);
        var identity = LanProductControlMessages.Payload<LanProductIdentity>(await f.Main.Lan.Read());
        Require(identity.FileTransferPort == f.Endpoint.Port && Has(identity, LanProductControlSession.OriginalFileReceiveCapability) &&
            Has(identity, LanProductControlSession.AlacFileReceiveCapability) == alac && Has(identity, LanProductControlSession.FlacFileReceiveCapability) == flac &&
            !Has(identity, "file_transfer"), "The host overstated available codecs, listener identity or file authority.");
        await host.DisableAsync();
        var disabled = LanProductControlMessages.Payload<LanProductIdentity>(await f.Main.Lan.Read());
        Require(disabled.Capabilities?.Any(value => value is "audio_file_receive_v1" or "audio_flac_file_receive_v1" or
            "audio_alac_file_receive_v1" or "audio_capture_receive_v1") != true, "Disabled host retained a receiving role.");
        f.Registry.Unbind(f.Listener);
        Require(f.Registry.ReceiveSupportFor(f.Main.Lan.Session) == AudioOriginalFileReceiveSupport.Unavailable,
            "Codecs alone enabled reception after removing the actual listener.");
        // A missing ALAC component still cannot decode an unsolicited codec offer.
        if (!alac)
        {
            f.Registry.Bind(f.Listener, f.Root); f.Bytes = AudioAlacDecoderTests.Bytes(); f.FileName = "original.m4a";
            await f.Offer(); await f.Transfer(); var failure = await f.Main.Failure();
            Require(failure.Reason == AudioStreamingStopReason.UnsupportedSource && f.Main.Device.OwnerThread == 0,
                "Missing ALAC fell back to a different decoder or output path.");
            Require((await f.Main.UntilStop()).Count == 1, "Missing ALAC announced output readiness."); f.Released();
        }
    }
    private static bool Has(LanProductIdentity identity, string capability) => identity.Capabilities?.Contains(capability) == true;
    private static void Require(bool value, string message) { if (!value) throw new Exception(message); }
}
