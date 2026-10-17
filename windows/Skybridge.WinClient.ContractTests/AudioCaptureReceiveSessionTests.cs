using System.Buffers.Binary;
using System.Security.Cryptography;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.Audio;

internal static class AudioCaptureReceiveSessionTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("capture receiver rejects a foreign accepted inbox before creating native ownership", ForeignAcceptedInbox),
        ("capture receiver sustains more than three receive windows using cumulative native retirement", CreditDrivenStream),
        ("capture receiver permits delayed End after the last frame but rejects new PCM after exhaustion", ExhaustedEndpoint),
        ("capture receiver does not report completion while final native release is still blocked", FinalReleaseCancellation),
        ("capture receiver preserves encrypted multi-packet PCM and a one-frame tail through both completions", CompleteStream),
        ("capture receiver permits an empty source after more than ten seconds of WouldBlock", EmptyAfterIdle),
        ("capture receiver rejects an End hash mismatch without claiming content or playback completion", HashMismatch),
        ("capture receiver rejects non-finite capture before native submission", NonFinite),
        ("capture receiver decline sends Stop without opening native output", Declined),
        ("capture receiver cancellation retains noncooperative authorization until its actual return", AuthorizationCancellation),
        ("capture receiver cancellation waits for native preparation on its original worker", PrepareCancellation),
        ("capture receiver open cleanup failure retains the exact native owners and causes", OpenCleanupFailure),
        ("capture receiver final native release failure cannot produce playbackComplete", FinalCleanupFailure),
        ("capture receiver active cancellation drains its writer without inventing cleanup failure", ActiveCancellation),
        ("capture receiver peer Stop ends only its audio operation and retains MAIN", PeerStop),
        ("capture receiver input after End invalidates a pending native tail", InputAfterEnd),
        ("capture receiver admission uses a cumulative budget across individually valid phases", CumulativeAdmissionDeadline)
    ];

    internal const string Endpoint = "capture-session-exact-output";
    private static readonly AudioStreamingPcmFormat Format = new(48000, 2, AudioStreamingEncoding.Float32, 32, 3);
    private static TaskCompletionSource Signal() => new(TaskCreationOptions.RunContinuationsAsynchronously);

    // Real loopback TCP, established-session crypto, SBE1/SBAU framing, MAIN reader and
    // writer are exercised. Account evidence and native output are controlled boundaries;
    // these cases do not contact an account service, run WASAPI, or prove physical playback.
    internal sealed class Fixture : IAsyncDisposable
    {
        internal readonly TestClock Clock = new();
        internal readonly CancellationTokenSource Caller = new();
        internal readonly Guid StreamId = Guid.NewGuid();
        internal readonly AccountAudioAuthorization Epoch = new(AudioAccountScope.From(AudioAccountMembershipTests.Authentication()));
        internal LanProductControlSessionTests.Fixture Lan { get; }
        internal NativeDevice Device { get; }
        internal NativeClient Native => Device.Client;
        internal AudioPlaybackApprovalService Approvals { get; }
        internal AudioCaptureReceiveSession Receiver { get; }
        internal Func<ILanAudioStreamInbox, CancellationToken, Task<AccountAudioMembershipLease>>? Authorize;
        internal Func<CancellationToken, Task<string>>? SelectOutput;
        internal Func<AudioPlaybackApprovalRequest, CancellationToken, Task<bool>> Decide = (_, _) => Task.FromResult(true);
        internal Action? ReleaseAdmission;
        internal Task<AudioPlaybackReceiveReceipt>? Run;
        internal uint Window;
        private AudioCaptureReceiveException? _observedFailure;

        private Fixture(LanProductControlSessionTests.Fixture lan, AudioOriginalFileReceiveRegistry? originalFiles = null)
        {
            Lan = lan; Device = new(Clock);
            Approvals = new(new Presenter((request, token) => Decide(request, token)), Clock.AuthorizationNow);
            Receiver = new(lan.Session,
                (inbox, token) => Authorize?.Invoke(inbox, token) ?? Task.FromResult(Lease(inbox)),
                token => SelectOutput?.Invoke(token) ?? Task.FromResult(Endpoint), Approvals,
                endpoint => { Require(endpoint == Endpoint, "Native open substituted the approved endpoint."); Device.Touch(); return Device; }, Clock, originalFiles);
        }
        internal static async Task<Fixture> Create(AudioOriginalFileReceiveRegistry? originalFiles = null, ushort? localFilePort = 8080)
        {
            var lan = await LanProductControlSessionTests.Fixture.ConnectForAudio(localFilePort, generalFiles: originalFiles is null);
            try { await lan.Admit(); return new(lan, originalFiles); }
            catch { await lan.DisposeAsync(); throw; }
        }
        internal AccountAudioMembershipLease Lease(ILanAudioStreamInbox inbox)
        {
            var authentication = AudioAccountMembershipTests.Authentication();
            var local = AudioAccountMembershipTests.Local(inbox.Binding); var peer = AudioAccountMembershipTests.Peer(inbox.Binding);
            var now = Clock.AuthorizationNow();
            var observation = AudioRegistryObservation.FromResponse(authentication, local,
                new(now.WallMilliseconds, local.DeviceId, false,
                    [AudioAccountMembershipTests.Entry(local, true), AudioAccountMembershipTests.Entry(peer)]), now, now);
            return new(AudioAccountMembershipEvidence.Create(observation, local, peer), Epoch, inbox, Clock.AuthorizationNow);
        }
        internal async Task Offer()
        {
            Run = Receiver.RunAsync(Caller.Token);
            await Receiver.ReadyForOffer.WaitAsync(Lan.Token);
            await Lan.SendAudio(new(StreamId, new AudioStreamingBody.CaptureOffer(Format)));
        }
        internal async Task Ready()
        {
            await Offer();
            var accepted = await Read();
            Require(accepted.Body is AudioStreamingBody.Accept, "First positive reply was not Accept.");
            Window = ((AudioStreamingBody.Accept)accepted.Body).ReceiveWindowBytes;
            Require(Window >= Format.BytesPerFrame && Window % Format.BytesPerFrame == 0 && Window <= AudioStreamingWire.MaximumReceiveWindowBytes,
                "Capture acceptance did not supply a bounded whole-frame window.");
            var ready = await Read();
            Require(ready.Body is AudioStreamingBody.OutputReady output && output.Format == Format, "OutputReady changed the offered PCM format or order.");
        }
        internal async Task<AudioStreamingMessage> Read()
        {
            var message = await Lan.ReadAudio();
            Require(message.StreamId == StreamId, "Receiver replied on a different stream."); return message;
        }
        internal Task Data(long offset, byte[] bytes) => Lan.SendAudio(new(StreamId, new AudioStreamingBody.PcmData(offset, bytes)));
        internal Task End(byte[] bytes) => Lan.SendAudio(new(StreamId, new AudioStreamingBody.End(bytes.Length, SHA256.HashData(bytes))));
        internal async Task<AudioCaptureReceiveException> Failure()
        {
            var failure = await Throws<AudioCaptureReceiveException>(() => (Run ?? throw new Exception("Receiver was not started.")).WaitAsync(Lan.Token));
            _observedFailure = failure; return failure;
        }
        internal async Task<List<AudioStreamingBody>> UntilStop()
        {
            var replies = new List<AudioStreamingBody>();
            for (int i = 0; i < 12; i++)
            {
                var body = (await Read()).Body; replies.Add(body);
                if (body is AudioStreamingBody.Stop) return replies;
                Require(body is not AudioStreamingBody.PlaybackComplete, "Failed operation announced playback completion.");
            }
            throw new Exception("Receiver did not send a bounded terminal Stop sequence.");
        }
        internal void NativeReleased()
        {
            Require(Receiver.NativeReleaseConfirmed && Native.DisposeCalls == 1 && Device.DisposeCalls == 1,
                "Receiver did not confirm exactly one native release.");
            Require(Device.OwnerThread != 0 && !Device.WrongThread, "Native operations or cleanup escaped their sole worker.");
        }
        public async ValueTask DisposeAsync()
        {
            ReleaseAdmission?.Invoke(); Native.PrepareRelease.Set(); Native.ProgressRelease.Set(); Native.DisposeRelease.Set();
            var errors = new List<Exception>();
            try { Caller.Cancel(); } catch (Exception error) { errors.Add(error); }
            try { await Receiver.DisposeAsync(); }
            catch (Exception error) when (ReferenceEquals(error, _observedFailure)) { }
            catch (Exception error) { errors.Add(error); }
            try { await Approvals.DisposeAsync(); } catch (Exception error) { errors.Add(error); }
            try { await Lan.DisposeAsync(); } catch (Exception error) { errors.Add(error); }
            Caller.Dispose(); Native.PrepareRelease.Dispose(); Native.ProgressRelease.Dispose(); Native.DisposeRelease.Dispose();
            if (errors.Count != 0) throw new AggregateException("Capture test fixture cleanup failed.", errors);
        }
    }

    private sealed class Presenter(Func<AudioPlaybackApprovalRequest, CancellationToken, Task<bool>> show) : IAudioPlaybackApprovalPresenter
    { public Task<bool> ShowAsync(AudioPlaybackApprovalRequest request, CancellationToken cancellationToken) => show(request, cancellationToken); }

    private static async Task ForeignAcceptedInbox()
    {
        await using var f = await Fixture.Create();
        await using var other = await LanProductControlSessionTests.Fixture.ConnectForAudio(); await other.Admit();
        using var inbox = await other.OpenAudioInbox();
        await Throws<InvalidDataException>(() => f.Receiver.RunAcceptedAsync(inbox, f.Caller.Token));
        inbox.RequireCurrent();
        Require(f.Native.StartCalls == 0 && f.Device.Activations == 0 && !f.Receiver.ReadyForOffer.IsCompleted,
            "Foreign inbox validation opened native resources or claimed the borrowed owner.");
    }

    private static async Task CreditDrivenStream()
    {
        await using var f = await Fixture.Create(); await f.Ready();
        var bytes = Pcm(checked((int)f.Window * 3 + 8));
        int maximum = AudioStreamingWire.MaximumPcmDataBytes / (int)Format.BytesPerFrame * (int)Format.BytesPerFrame;
        long sent = 0, retired = 0; int credits = 0;
        while (sent < bytes.Length)
        {
            long available = f.Window - (sent - retired);
            if (available < Format.BytesPerFrame)
            {
                f.Native.AllowRetirement = true;
                var body = (await f.Read()).Body;
                Require(body is AudioStreamingBody.Credit, "Continuous source received completion or rejection before End.");
                long next = ((AudioStreamingBody.Credit)body).RetiredBytes;
                Require(next > retired && next <= sent && next % Format.BytesPerFrame == 0,
                    "Cumulative credit invented, repeated or misaligned source bytes.");
                retired = next; credits++; continue;
            }
            int count = checked((int)Math.Min(Math.Min(maximum, available), bytes.Length - sent));
            count -= count % (int)Format.BytesPerFrame;
            await f.Data(sent, bytes.AsSpan(checked((int)sent), count).ToArray()); sent += count;
        }
        await f.End(bytes); await AssertCompletion(f, bytes);
        Require(credits >= 3 && f.Native.Submissions.SelectMany(packet => packet).SequenceEqual(bytes),
            "Credit-driven source did not span windows or changed its accepted PCM.");
        f.NativeReleased(); await f.Lan.Barrier();
    }

    private static async Task ExhaustedEndpoint()
    {
        foreach (bool morePcm in new[] { false, true })
        {
            await using var f = await Fixture.Create(); await f.Ready();
            int maximum = AudioStreamingWire.MaximumPcmDataBytes / (int)Format.BytesPerFrame * (int)Format.BytesPerFrame;
            var bytes = Pcm(maximum * 4);
            for (int offset = 0; offset < bytes.Length; offset += maximum)
                await f.Data(offset, bytes.AsSpan(offset, maximum).ToArray());
            f.Native.AllowRetirement = true;
            await Until(() => Volatile.Read(ref f.Native.StartCalls) == 1 && f.Native.QueuedFrames == 0, f.Lan.Token);
            f.Clock.Advance(TimeSpan.FromSeconds(11)); int observed = f.Clock.AuthorizationReads;
            await Until(() => f.Clock.AuthorizationReads > observed, f.Lan.Token);
            Require(!f.Run!.IsCompleted, "Endpoint exhaustion invented EOF or an idle timeout.");
            if (morePcm)
            {
                await f.Data(bytes.Length, Pcm(8)); var failure = await f.Failure();
                Require(failure.Reason == AudioStreamingStopReason.OutputLost && f.Native.StartCalls == 1 &&
                    f.Native.Submissions.SelectMany(packet => packet).SequenceEqual(bytes),
                    "PCM after exhaustion resynchronized output, changed history, or reached native submission.");
                _ = await f.UntilStop();
            }
            else { await f.End(bytes); await AssertCompletion(f, bytes); }
            f.NativeReleased(); await f.Lan.Barrier();
        }
    }

    private static async Task FinalReleaseCancellation()
    {
        await using var f = await Fixture.Create(); f.Native.BlockDispose = true;
        await f.Ready(); await f.End([]);
        Require((await f.Read()).Body is AudioStreamingBody.ContentVerified, "Content verification was not separate from native release.");
        await f.Native.DisposeEntered.Task.WaitAsync(f.Lan.Token);
        Require(!f.Run!.IsCompleted && !f.Receiver.NativeReleaseConfirmed && f.Device.DisposeCalls == 0,
            "Blocked final release was reported as successful playback or completed native ownership.");
        f.Caller.Cancel(); f.Native.DisposeRelease.Set(); var failure = await f.Failure();
        Require(failure.Reason == AudioStreamingStopReason.UserStopped && failure.CleanupFailures.Count == 0,
            "Cancellation during actual release lost its cause or added a fabricated cleanup failure.");
        _ = await f.UntilStop(); f.NativeReleased(); await f.Lan.Barrier();
    }

    private static async Task CompleteStream()
    {
        await using var f = await Fixture.Create(); await f.Ready();
        int maximum = AudioStreamingWire.MaximumPcmDataBytes / (int)Format.BytesPerFrame * (int)Format.BytesPerFrame;
        var bytes = Pcm(maximum * 4 + (int)Format.BytesPerFrame);
        Require(bytes.Length <= f.Window, "Fixture must send this bounded burst without unearned credit.");
        for (int offset = 0; offset < bytes.Length; offset += maximum)
            await f.Data(offset, bytes.AsSpan(offset, Math.Min(maximum, bytes.Length - offset)).ToArray());
        await f.End(bytes); f.Native.AllowRetirement = true;
        await AssertCompletion(f, bytes);
        Require(f.Native.Submissions.Count >= 5 && f.Native.Submissions.SelectMany(packet => packet).SequenceEqual(bytes),
            "Multiple packets or the one-frame tail were altered, dropped or padded.");
        Require(f.Native.StartCalls == 1, "Nonempty native output was not started exactly once.");
        f.NativeReleased(); await f.Lan.Barrier();
    }

    private static async Task EmptyAfterIdle()
    {
        await using var f = await Fixture.Create(); await f.Ready();
        f.Clock.Advance(TimeSpan.FromSeconds(11));
        int observed = f.Clock.AuthorizationReads;
        await Until(() => f.Clock.AuthorizationReads > observed, f.Lan.Token);
        Require(!f.Run!.IsCompleted && f.Native.StartCalls == 0 && f.Native.Submissions.Count == 0,
            "WouldBlock became EOF, an idle failure, or fabricated native silence.");
        await f.End([]); await AssertCompletion(f, []);
        Require(f.Native.StartCalls == 0 && f.Native.Submissions.Count == 0 && f.Native.WaitCalls == 0,
            "Empty capture invented output frames or device-tail activity.");
        f.NativeReleased(); await f.Lan.Barrier();
    }

    private static async Task HashMismatch()
    {
        await using var f = await Fixture.Create(); await f.Ready(); var bytes = Pcm(24);
        await f.Data(0, bytes);
        await f.Lan.SendAudio(new(f.StreamId, new AudioStreamingBody.End(bytes.Length, new byte[32])));
        var failure = await f.Failure();
        Require(failure.Reason == AudioStreamingStopReason.ContentMismatch, "Bad End digest lost its content-mismatch cause.");
        var replies = await f.UntilStop();
        Require(replies.All(body => body is not AudioStreamingBody.ContentVerified), "Bad hash produced content verification.");
        Require(f.Native.StartCalls == 0, "A finite sub-prefill invalid source was started before its End was verified.");
        f.NativeReleased(); await f.Lan.Barrier();
    }

    private static async Task NonFinite()
    {
        foreach (uint sample in new uint[] { 0x7fc00001, 0x7f800000, 0xff800000 })
        {
            await using var f = await Fixture.Create(); await f.Ready(); var bytes = new byte[8];
            BinaryPrimitives.WriteUInt32LittleEndian(bytes, sample); await f.Data(0, bytes);
            var failure = await f.Failure();
            Require(failure.Reason == AudioStreamingStopReason.UnsupportedSource && f.Native.Submissions.Count == 0,
                "Non-finite capture reached native output or changed its failure reason.");
            _ = await f.UntilStop(); f.NativeReleased(); await f.Lan.Barrier();
        }
    }

    private static async Task Declined()
    {
        await using var f = await Fixture.Create(); f.Decide = (_, _) => Task.FromResult(false); await f.Offer();
        Require((await f.Read()).Body is AudioStreamingBody.Stop { Reason: AudioStreamingStopReason.ReceiverDeclined },
            "Decline emitted positive admission or the wrong terminal reason.");
        var failure = await f.Failure();
        Require(failure.Reason == AudioStreamingStopReason.ReceiverDeclined && f.Device.Activations == 0 && f.Receiver.NativeReleaseConfirmed,
            "Declined playback opened native output or reported uncertain resources that were never opened.");
        await f.Lan.Barrier();
    }

    private static async Task AuthorizationCancellation()
    {
        await using var f = await Fixture.Create(); var entered = Signal();
        var release = new TaskCompletionSource<AccountAudioMembershipLease>(TaskCreationOptions.RunContinuationsAsynchronously);
        ILanAudioStreamInbox? captured = null;
        f.Authorize = (inbox, _) => { captured = inbox; entered.TrySetResult(); return release.Task; };
        f.ReleaseAdmission = () => release.TrySetCanceled();
        await f.Offer(); await entered.Task.WaitAsync(f.Lan.Token); f.Caller.Cancel();
        Require(!f.Run!.IsCompleted && f.Device.Activations == 0, "Cancellation abandoned the live authorization adapter.");
        release.SetResult(f.Lease(captured ?? throw new Exception("No captured inbox.")));
        var failure = await f.Failure();
        Require(failure.Reason == AudioStreamingStopReason.UserStopped && failure.CleanupFailures.Count == 0 && f.Device.Activations == 0,
            "Late authorization resumed playback or clean cancellation gained a cleanup error.");
        _ = await f.UntilStop(); await f.Lan.Barrier();
    }

    private static async Task PrepareCancellation()
    {
        await using var f = await Fixture.Create(); f.Native.BlockPrepare = true; await f.Offer();
        await f.Native.PrepareEntered.Task.WaitAsync(f.Lan.Token); f.Caller.Cancel();
        Require(!f.Run!.IsCompleted && f.Native.DisposeCalls == 0 && !f.Receiver.NativeReleaseConfirmed,
            "Receiver released or declared success while native preparation still owned the worker.");
        f.Native.PrepareRelease.Set(); var failure = await f.Failure();
        Require(failure.Reason == AudioStreamingStopReason.UserStopped && failure.CleanupFailures.Count == 0,
            "Preparation cancellation lost its cause or introduced an unearned cleanup error.");
        Require(f.Native.StartCalls == 0 && f.Native.Submissions.Count == 0, "Canceled preparation reached playback.");
        _ = await f.UntilStop(); f.NativeReleased(); await f.Lan.Barrier();
    }

    private static async Task OpenCleanupFailure()
    {
        await using var f = await Fixture.Create(); var prepare = new IOException("fixture prepare failed");
        var close = new IOException("fixture client release unconfirmed"); var device = new IOException("fixture device release unconfirmed");
        f.Native.PrepareFailure = prepare; f.Native.DisposeFailure = close; f.Device.DisposeFailure = device;
        await f.Offer(); var failure = await f.Failure();
        var retained = Errors(failure).OfType<ExclusivePcmOpenCleanupException>().Single();
        Require(ReferenceEquals(retained.RetainedDevice, f.Device) && ReferenceEquals(retained.RetainedClient, f.Native),
            "Failed open discarded its exact native references.");
        Require(new[] { prepare, close, device }.All(cause => Errors(failure).Any(error => ReferenceEquals(error, cause))),
            "Open failure lost a primary or native cleanup cause.");
        Require(!failure.NativeReleaseConfirmed && !f.Receiver.NativeReleaseConfirmed && ReferenceEquals(f.Receiver.Failure, failure),
            "Unconfirmed open cleanup was reported or published as released.");
        Require(f.Native.DisposeCalls == 1 && f.Device.DisposeCalls == 1 && !f.Device.WrongThread, "Open cleanup repeated or escaped its worker.");
        Require(ReferenceEquals(await Throws<AudioCaptureReceiveException>(() => f.Receiver.DisposeAsync().AsTask()), failure),
            "A repeated receiver close forgot its retained native failure.");
        _ = await f.UntilStop(); await f.Lan.Barrier();
    }

    private static async Task FinalCleanupFailure()
    {
        await using var f = await Fixture.Create(); var cause = new IOException("fixture final client release unconfirmed");
        f.Native.DisposeFailure = cause; await f.Ready(); await f.End([]);
        var failure = await f.Failure();
        Require(!failure.NativeReleaseConfirmed && !f.Receiver.NativeReleaseConfirmed && Errors(failure).Any(error => ReferenceEquals(error, cause)),
            "Final release failure disappeared behind a successful endpoint drain.");
        _ = await f.UntilStop();
        Require(f.Native.DisposeCalls == 1 && f.Device.DisposeCalls == 1 && !f.Device.WrongThread, "Uncertain cleanup was retried or moved threads.");
        Require(ReferenceEquals(await Throws<AudioCaptureReceiveException>(() => f.Receiver.DisposeAsync().AsTask()), failure),
            "Repeated close converted uncertain native cleanup into success.");
        await f.Lan.Barrier();
    }

    private static async Task ActiveCancellation()
    {
        await using var f = await Fixture.Create(); await f.Ready(); f.Caller.Cancel();
        var failure = await f.Failure();
        Require(failure.Reason == AudioStreamingStopReason.UserStopped && failure.CleanupFailures.Count == 0,
            "Clean receiver cancellation was reported as a linked-writer cleanup failure: " + failure);
        _ = await f.UntilStop(); f.NativeReleased(); await f.Lan.Barrier();
    }

    private static async Task PeerStop()
    {
        await using var f = await Fixture.Create(); await f.Ready();
        await f.Lan.SendAudio(new(f.StreamId, new AudioStreamingBody.Stop(AudioStreamingStopReason.UserStopped)));
        var failure = await f.Failure();
        Require(failure.Reason == AudioStreamingStopReason.UserStopped && Errors(failure).Any(error => error is LanAudioStreamException),
            "Peer Stop lost the exact retired-inbox cause.");
        f.NativeReleased(); await f.Lan.Barrier();
    }

    private static async Task InputAfterEnd()
    {
        await using var f = await Fixture.Create(); f.Native.BlockProgress = true; await f.Ready(); var bytes = Pcm(8);
        await f.Data(0, bytes); await f.End(bytes);
        Require((await f.Read()).Body is AudioStreamingBody.ContentVerified, "Short capture did not verify before waiting for its native tail.");
        await f.Native.ProgressEntered.Task.WaitAsync(f.Lan.Token);
        await f.Data(bytes.Length, Pcm(8)); await f.Lan.Barrier();
        Require(!f.Run!.IsCompleted, "Input retirement abandoned the blocked native owner.");
        f.Native.ProgressRelease.Set(); var failure = await f.Failure();
        Require(failure.Reason == AudioStreamingStopReason.ProtocolViolation && f.Native.Submissions.Sum(packet => packet.Length) == bytes.Length,
            "Post-End input reached native output or failed without protocol evidence.");
        f.NativeReleased(); await f.Lan.Barrier();
    }

    private static async Task CumulativeAdmissionDeadline()
    {
        await using var f = await Fixture.Create();
        f.Authorize = (inbox, _) => { f.Clock.Advance(TimeSpan.FromSeconds(44)); return Task.FromResult(f.Lease(inbox)); };
        f.SelectOutput = _ => { f.Clock.Advance(TimeSpan.FromSeconds(4)); return Task.FromResult(Endpoint); };
        f.Decide = (_, _) => { f.Clock.Advance(TimeSpan.FromSeconds(59)); return Task.FromResult(true); };
        f.Native.PrepareAction = () => f.Clock.Advance(TimeSpan.FromSeconds(4));
        await f.Offer(); var failure = await f.Failure();
        Require(failure.Reason == AudioStreamingStopReason.TimedOut && f.Native.StartCalls == 0,
            "Individually valid stages exceeded the total admission budget without terminating.");
        var replies = await f.UntilStop();
        Require(replies.Count == 1, "Expired admission emitted Accept or OutputReady before Stop.");
        f.NativeReleased(); await f.Lan.Barrier();
    }

    private static async Task AssertCompletion(Fixture f, byte[] expected)
    {
        bool verified = false, complete = false; long credit = 0;
        for (int i = 0; i < 16 && !complete; i++)
        {
            switch ((await f.Read()).Body)
            {
                case AudioStreamingBody.Credit retired:
                    Require(retired.RetiredBytes >= credit && retired.RetiredBytes <= expected.Length && retired.RetiredBytes % Format.BytesPerFrame == 0,
                        "Credit invented, regressed, or misaligned retired source bytes."); credit = retired.RetiredBytes; break;
                case AudioStreamingBody.ContentVerified content:
                    Require(!verified && content.TotalBytes == expected.Length && content.Sha256.SequenceEqual(SHA256.HashData(expected)),
                        "Content verification repeated or differs from the original PCM bytes."); verified = true; break;
                case AudioStreamingBody.PlaybackComplete playback:
                    Require(verified && playback.SourceFrames == expected.Length / Format.BytesPerFrame && playback.TrailingPaddingFrames == 0,
                        "Playback completion preceded verification or counted padding as source."); complete = true; break;
                default: throw new Exception("Receiver emitted an unexpected reply during source completion.");
            }
        }
        Require(complete, "Receiver did not provide bounded ordered completion.");
        var receipt = await f.Run!.WaitAsync(f.Lan.Token);
        Require(f.Receiver.Phase == AudioCaptureReceivePhase.Completed && receipt.StreamId == f.StreamId && receipt.Format == Format &&
            receipt is AudioPlaybackReceiveReceipt.Captured capture &&
            capture.Content.TotalBytes == expected.Length && capture.Content.SourceFrames == expected.Length / Format.BytesPerFrame &&
            capture.Content.Sha256Hex == Convert.ToHexStringLower(SHA256.HashData(expected)) && receipt.Output.SourceFrames == (ulong)(expected.Length / Format.BytesPerFrame),
            "Local completion receipt differs from the authenticated wire/native evidence.");
        Require(expected.Length == 0 ? receipt.Output.Tail is null : receipt.Output.Tail is not null,
            "Empty/nonempty source acquired the wrong native-tail evidence.");
    }

    internal sealed class TestClock : TimeProvider
    {
        private long _ticks;
        private int _authorizationReads;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => Interlocked.Read(ref _ticks);
        internal int AuthorizationReads => Volatile.Read(ref _authorizationReads);
        internal void Advance(TimeSpan elapsed) => Interlocked.Add(ref _ticks, elapsed.Ticks);
        internal AudioAuthorizationTime AuthorizationNow()
        {
            long milliseconds = Interlocked.Read(ref _ticks) / TimeSpan.TicksPerMillisecond;
            Interlocked.Increment(ref _authorizationReads);
            return new(1_800_000_000_000 + milliseconds, 1000 + milliseconds);
        }
    }

    internal sealed class NativeDevice : IExclusivePcmDevice
    {
        internal readonly NativeClient Client;
        internal int OwnerThread, Activations, DisposeCalls;
        internal bool WrongThread;
        internal Exception? DisposeFailure;
        internal NativeDevice(TestClock clock) { Client = new(this, clock); }
        internal void Touch()
        {
            int thread = Environment.CurrentManagedThreadId;
            int original = Interlocked.CompareExchange(ref OwnerThread, thread, 0);
            if (original != 0 && original != thread) { WrongThread = true; throw new InvalidOperationException("Native fixture changed worker."); }
        }
        public IExclusivePcmClient Activate() { Touch(); Activations++; return Client; }
        public void Dispose() { Touch(); DisposeCalls++; if (DisposeFailure is { } error) throw error; }
    }

    internal sealed class NativeClient(NativeDevice owner, TestClock clock) : IExclusivePcmClient
    {
        internal readonly ManualResetEventSlim PrepareRelease = new(), ProgressRelease = new(), DisposeRelease = new();
        internal readonly TaskCompletionSource PrepareEntered = Signal(), ProgressEntered = Signal(), DisposeEntered = Signal();
        internal readonly List<byte[]> Submissions = [];
        internal volatile bool AllowRetirement, BlockPrepare, BlockProgress, BlockDispose;
        internal int StartCalls, WaitCalls, DisposeCalls;
        internal Exception? PrepareFailure, DisposeFailure;
        internal Action? PrepareAction;
        internal ExactPcmFormat ExpectedFormat = Format.RequireExactOutputFormat();
        private const uint Frames = 9600;
        private uint _queued;
        internal uint QueuedFrames => Volatile.Read(ref _queued);
        private ulong _position;
        private bool _running;
        public int IsExactFormatSupported(ExactPcmFormat format) { owner.Touch(); Require(format == ExpectedFormat, "Native format changed."); return 0; }
        public int Initialize(ExactPcmFormat format, long bufferDuration100Nanoseconds) { owner.Touch(); Require(bufferDuration100Nanoseconds > 0, "Native period was empty."); return 0; }
        public uint GetBufferFrames() { owner.Touch(); return Frames; }
        public int GetStreamLatency(out long latency100Nanoseconds) { owner.Touch(); latency100Nanoseconds = TimeSpan.TicksPerMillisecond; return 0; }
        public void Prepare()
        {
            owner.Touch(); PrepareEntered.TrySetResult(); if (BlockPrepare) PrepareRelease.Wait();
            PrepareAction?.Invoke(); if (PrepareFailure is { } error) throw error;
        }
        public uint GetQueuedFrames() { owner.Touch(); return _queued; }
        public int GetClockPosition(out ulong position, out ulong frequency) { owner.Touch(); position = _position; frequency = ExpectedFormat.SampleRate; return 0; }
        public void Submit(byte[] bytes, int offset, int count, uint frames)
        {
            owner.Touch(); Require(frames > 0 && frames <= Frames - _queued && (long)frames * ExpectedFormat.BytesPerFrame == count,
                "Native fixture received a partial or over-capacity packet.");
            Submissions.Add(bytes.AsSpan(offset, count).ToArray()); _queued += frames;
        }
        public void Start() { owner.Touch(); StartCalls++; Require(!_running && _queued > 0, "Native start was repeated or empty."); _running = true; }
        public void WaitForProgress(TimeSpan delay, CancellationToken cancellationToken)
        {
            owner.Touch(); WaitCalls++; ProgressEntered.TrySetResult(); if (BlockProgress) ProgressRelease.Wait();
            cancellationToken.ThrowIfCancellationRequested(); clock.Advance(delay);
            if (_running && AllowRetirement)
            {
                ulong frames = Math.Max(1UL, (ulong)delay.Ticks * ExpectedFormat.SampleRate / TimeSpan.TicksPerSecond);
                _position += frames; _queued -= (uint)Math.Min(_queued, frames);
            }
            Thread.Sleep(1); cancellationToken.ThrowIfCancellationRequested();
        }
        public void Stop() { owner.Touch(); _running = false; }
        public void Dispose()
        {
            owner.Touch(); DisposeCalls++; DisposeEntered.TrySetResult(); if (BlockDispose) DisposeRelease.Wait();
            if (DisposeFailure is { } error) throw error;
        }
    }

    private static byte[] Pcm(int count)
    {
        Require(count % Format.BytesPerFrame == 0, "Fixture PCM must contain whole frames.");
        var bytes = new byte[count];
        for (int offset = 0; offset < count; offset += 4)
            BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(offset), BitConverter.SingleToInt32Bits((offset / 4 % 13 - 6) / 16f));
        return bytes;
    }
    private static IEnumerable<Exception> Errors(Exception error)
    {
        var pending = new Stack<Exception>(); var visited = new HashSet<Exception>(ReferenceEqualityComparer.Instance); pending.Push(error);
        while (pending.TryPop(out var next))
        {
            if (!visited.Add(next)) continue; yield return next;
            if (next is AggregateException aggregate) foreach (var inner in aggregate.InnerExceptions) pending.Push(inner);
            else if (next.InnerException is { } inner) pending.Push(inner);
        }
    }
    private static async Task Until(Func<bool> condition, CancellationToken token)
    { while (!condition()) await Task.Delay(1, token); }
    private static async Task<T> Throws<T>(Func<Task> action) where T : Exception
    { try { await action(); } catch (T error) { return error; } throw new Exception($"Expected {typeof(T).Name}."); }
    private static void Require(bool condition, string message) { if (!condition) throw new Exception(message); }
}
