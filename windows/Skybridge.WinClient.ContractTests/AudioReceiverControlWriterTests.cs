using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.Audio;

internal static class AudioReceiverControlWriterTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("file progress coalesces at one hertz and never substitutes for completion", FileProgress),
        ("file progress requires both roles and an original-file stream", FileProgressRoles),
        ("file progress rechecks peer compatibility after shared writer admission", FileProgressRoleChanged),
        ("audio control writer preserves foreign cancellation and nested errors during cleanup", CancellationCause),
        ("audio control writer enforces owner deadline after shared TCP writer admission", OwnerDeadline),
        ("audio control writer preserves order freezes hashes and coalesces cumulative credits", Ordered),
        ("audio control writer overflow fails pending replies and waits for actual in-flight cleanup", Overflow),
        ("audio control writer rechecks permission after waiting for the real shared TCP writer", Revoked),
        ("audio control writer local disposal drains admission without corrupting MAIN framing", Disposal),
        ("audio control writer caller cancellation terminates its actual pending send", Cancellation),
        ("audio control writer rejects unsupported malformed and backwards controls without sending them", InvalidControls),
        ("audio control writer peer Stop retires queued positive replies and preserves MAIN", PeerStop),
        ("audio control writer cannot send on a foreign MAIN owner", ForeignOwner),
        ("audio control writer empty drain seals admission without inventing a playback reply", EmptyDrain)
    ];
    private static async Task CancellationCause()
    {
        foreach (bool foreignToken in new[] { false, true })
        {
            await using var f = await Fixture.Create(); await f.Writer.DrainAsync();
            int reject = 0; var cause = new IOException("owned callback cleanup failed");
            using var foreign = new CancellationTokenSource(); foreign.Cancel();
            var failure = new OperationCanceledException("canceled with retained cause", foreignToken ? null : cause,
                foreignToken ? foreign.Token : f.Caller.Token);
            var writer = new AudioReceiverControlWriter(f.Lan.Session, f.Inbox, f.Permission, f.Caller.Token, () =>
            {
                if (Volatile.Read(ref reject) == 0) return;
                f.Caller.Cancel(); throw failure;
            });
            await using var held = f.Lan.HoldWriter(); await held.Entered.WaitAsync(f.Lan.Token);
            var delivery = writer.Queue(new AudioStreamingBody.Accept(4096));
            await Until(() => writer.PendingCount.Sending);
            Volatile.Write(ref reject, 1); held.Release(); await held.Completion; await f.Lan.ReadWriterBarrier();
            Require(ReferenceEquals(failure, await Throws<OperationCanceledException>(() => writer.Completion)), "Cancellation lost its foreign or nested failure.");
            Require(ReferenceEquals(failure, await Throws<OperationCanceledException>(() => delivery)), "Delivery lost its foreign or nested failure.");
            Require(ReferenceEquals(failure, await Throws<OperationCanceledException>(() => writer.DisposeAsync().AsTask())), "Disposal swallowed the foreign or nested cleanup error.");
            await f.Lan.Barrier();
        }
    }

    private static async Task OwnerDeadline()
    {
        await using var f = await Fixture.Create();
        await f.Writer.DrainAsync();
        int expired = 0;
        var timeout = new TimeoutException("admission budget ended");
        var writer = new AudioReceiverControlWriter(f.Lan.Session, f.Inbox, f.Permission, f.Caller.Token,
            () => { if (Volatile.Read(ref expired) != 0) throw timeout; });
        await using var held = f.Lan.HoldWriter(); await held.Entered.WaitAsync(f.Lan.Token);
        var delivery = writer.Queue(new AudioStreamingBody.Accept(4096));
        await Until(() => writer.PendingCount.Sending);
        Volatile.Write(ref expired, 1); held.Release(); await held.Completion; await f.Lan.ReadWriterBarrier();
        Require(ReferenceEquals(timeout, await Throws<TimeoutException>(() => writer.Completion)), "Admission lost the owner deadline.");
        Require(ReferenceEquals(timeout, await Throws<TimeoutException>(() => delivery)), "Pending control reported successful delivery.");
        Require(ReferenceEquals(timeout, await Throws<TimeoutException>(() => writer.DisposeAsync().AsTask())), "Cleanup lost the deadline failure.");
        await f.Lan.Barrier(); // A leaked audio control would appear before this MAIN barrier.
    }
    private static readonly AudioStreamingPcmFormat Format = new(48000, 2, AudioStreamingEncoding.Float32, 32, 3);
    private sealed class Presenter : IAudioPlaybackApprovalPresenter
    { public Task<bool> ShowAsync(AudioPlaybackApprovalRequest request, CancellationToken cancellationToken) => Task.FromResult(true); }
    private sealed class Fixture : IAsyncDisposable
    {
        internal readonly CancellationTokenSource Caller = new();
        internal LanProductControlSessionTests.Fixture Lan { get; }
        internal ILanAudioStreamInbox Inbox { get; }
        internal AudioPlaybackApprovalService Approvals { get; }
        internal AudioPlaybackPermission Permission { get; }
        internal AudioReceiverControlWriter Writer { get; }
        private Exception? _observedFailure;
        private Fixture(LanProductControlSessionTests.Fixture lan, ILanAudioStreamInbox inbox,
            AudioPlaybackApprovalService approvals, AudioPlaybackPermission permission, TimeProvider? time = null)
        {
            Lan = lan; Inbox = inbox; Approvals = approvals; Permission = permission;
            Writer = new(lan.Session, inbox, permission, Caller.Token, time: time);
        }
        internal static async Task<Fixture> Create(bool originalFile = false, bool reportFileProgress = false,
            bool receiveFileProgress = false, TimeProvider? time = null)
        {
            var lan = await LanProductControlSessionTests.Fixture.ConnectForAudio(); await lan.Admit();
            var inbox = await lan.OpenAudioInbox(originalFile);
            await lan.Session.SetAudioReceiverCapabilitiesAsync(true,
                originalFile ? AudioOriginalFileReceiveSupport.Wave : AudioOriginalFileReceiveSupport.Unavailable,
                lan.Token, reportFileOutputProgress: reportFileProgress);
            var published = LanProductControlMessages.Payload<LanProductIdentity>(await lan.Read());
            Require((published.Capabilities?.Contains(AudioStreamingWire.FileOutputProgressReportCapability) == true) ==
                (originalFile && reportFileProgress), "Reporter role did not reflect the installed original-file consumer.");
            await lan.PublishPeerFileOutputProgress(receiveFileProgress); await lan.Barrier();
            var auth = AudioAccountMembershipTests.Authentication(); var epoch = new AccountAudioAuthorization(AudioAccountScope.From(auth));
            var local = AudioAccountMembershipTests.Local(inbox.Binding); var peer = AudioAccountMembershipTests.Peer(inbox.Binding);
            AudioAuthorizationTime Clock() => new(1_800_000_000_000, 1000);
            var now = Clock();
            var observation = AudioRegistryObservation.FromResponse(auth, local, new(now.WallMilliseconds, local.DeviceId, false,
                [AudioAccountMembershipTests.Entry(local, true), AudioAccountMembershipTests.Entry(peer)]), now, now);
            var lease = new AccountAudioMembershipLease(AudioAccountMembershipEvidence.Create(observation, local, peer), epoch, inbox, Clock);
            var approvals = new AudioPlaybackApprovalService(new Presenter(), Clock);
            var permission = await approvals.RequestAsync(inbox, lease, "exact-output", lan.Token);
            return new(lan, inbox, approvals, permission, time);
        }
        internal async Task<T> ExpectFailure<T>() where T : Exception
        {
            var error = await Throws<T>(() => Writer.Completion.WaitAsync(TimeSpan.FromSeconds(2)));
            _observedFailure = error; return error;
        }
        public async ValueTask DisposeAsync()
        {
            try
            {
                try { await Writer.DisposeAsync(); }
                // Only the exact terminal delivery failure already asserted by the test.
                catch (Exception error) when (ReferenceEquals(error, _observedFailure)) { }
            }
            finally { await Approvals.DisposeAsync(); Inbox.Dispose(); await Lan.DisposeAsync(); Caller.Dispose(); }
        }
    }
    private sealed class ProgressClock : TimeProvider
    {
        private long _ticks;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => Interlocked.Read(ref _ticks);
        internal void Advance() => Interlocked.Add(ref _ticks, TimeSpan.TicksPerSecond);
    }
    private static async Task FileProgress()
    {
        var clock = new ProgressClock();
        await using var f = await Fixture.Create(true, true, true, clock);
        await f.Writer.Queue(new AudioStreamingBody.OutputReady(Format));
        Require((await f.Lan.ReadAudio()).Body is AudioStreamingBody.OutputReady, "Progress preceded exact-output readiness.");
        f.Writer.ObserveFileOutputProgress(0); await f.Lan.Barrier();
        await using (var held = f.Lan.HoldWriter())
        {
            await held.Entered.WaitAsync(f.Lan.Token);
            f.Writer.ObserveFileOutputProgress(1); await Until(() => f.Writer.PendingCount.Sending);
            for (int n = 2; n <= 1000; n++) f.Writer.ObserveFileOutputProgress(n);
            Require(f.Writer.PendingCount == (0, true), "Progress allocated a queued control per observation.");
            held.Release(); await held.Completion; await f.Lan.ReadWriterBarrier();
            Require((await f.Lan.ReadAudio()).Body is AudioStreamingBody.FileOutputProgress { SourceFrames: 1 }, "In-flight progress changed.");
        }
        await Until(() => !f.Writer.PendingCount.Sending);
        f.Writer.ObserveFileOutputProgress(1000); await f.Lan.Barrier(); // No second report inside the interval.
        clock.Advance(); f.Writer.ObserveFileOutputProgress(1000);
        Require((await f.Lan.ReadAudio()).Body is AudioStreamingBody.FileOutputProgress { SourceFrames: 1000 }, "Latest native progress was lost.");
        await Until(() => !f.Writer.PendingCount.Sending);
        Require(!f.Writer.Completion.IsCompleted, "Progress was treated as native drain completion.");
        await Throws<InvalidDataException>(() => Call(() => f.Writer.ObserveFileOutputProgress(999)));
        clock.Advance();
        await using (var held = f.Lan.HoldWriter())
        {
            await held.Entered.WaitAsync(f.Lan.Token);
            f.Writer.ObserveFileOutputProgress(1001); await Until(() => f.Writer.PendingCount.Sending);
            f.Writer.ObserveFileOutputProgress(1002);
            var final = f.Writer.Queue(new AudioStreamingBody.PlaybackComplete(1002, 0));
            held.Release(); await held.Completion; await f.Lan.ReadWriterBarrier();
            Require((await f.Lan.ReadAudio()).Body is AudioStreamingBody.FileOutputProgress { SourceFrames: 1001 }, "Already owned progress was discarded.");
            Require((await f.Lan.ReadAudio()).Body is AudioStreamingBody.PlaybackComplete { SourceFrames: 1002 }, "Advisory progress delayed final completion.");
            await final; await f.Writer.Completion;
        }
        await f.Lan.Barrier(); // No stale progress may follow the terminal reply.
    }
    private static async Task FileProgressRoles()
    {
        foreach (var (file, report, receive) in new[] { (false, true, true), (true, false, true), (true, true, false) })
        {
            await using var f = await Fixture.Create(file, report, receive);
            await Throws<InvalidOperationException>(() => Call(() => f.Writer.ObserveFileOutputProgress(1)));
            await f.Writer.DrainAsync(); await f.Lan.Barrier();
        }
    }
    private static async Task FileProgressRoleChanged()
    {
        await using var f = await Fixture.Create(true, true, true);
        await using var held = f.Lan.HoldWriter(); await held.Entered.WaitAsync(f.Lan.Token);
        f.Writer.ObserveFileOutputProgress(1); await Until(() => f.Writer.PendingCount.Sending);
        await f.Lan.PublishPeerFileOutputProgress(false);
        await Until(() => !f.Lan.Session.CanReportFileOutputProgress);
        held.Release(); await held.Completion; await f.Lan.ReadWriterBarrier();
        await f.ExpectFailure<InvalidOperationException>(); await f.Lan.Barrier();
    }
    private static async Task Ordered()
    {
        await using var f = await Fixture.Create(); await using var held = f.Lan.HoldWriter(); await held.Entered.WaitAsync(f.Lan.Token);
        var accept = f.Writer.Queue(new AudioStreamingBody.Accept(4096)); await Until(() => f.Writer.PendingCount.Sending);
        var ready = f.Writer.Queue(new AudioStreamingBody.OutputReady(Format));
        var credit = f.Writer.Queue(new AudioStreamingBody.Credit(8));
        for (int i = 2; i <= 1000; i++)
            Require(ReferenceEquals(credit, f.Writer.Queue(new AudioStreamingBody.Credit(i * 8))), "Coalescing retained a separate credit waiter.");
        Require(ReferenceEquals(credit, f.Writer.Queue(new AudioStreamingBody.Credit(8000))), "Duplicate absolute credit created a second delivery.");
        byte[] digest = Enumerable.Range(0, 32).Select(n => (byte)n).ToArray(); var expected = digest.ToArray();
        var verified = f.Writer.Queue(new AudioStreamingBody.ContentVerified(8000, digest)); digest[0] = 255;
        var completed = f.Writer.Queue(new AudioStreamingBody.PlaybackComplete(1000, 0));
        Require(f.Writer.PendingCount == (4, true), "Control queue exceeded its declared bound or drained past the held writer.");
        await Throws<InvalidOperationException>(() => Call(() => f.Writer.Queue(new AudioStreamingBody.Credit(8008))));
        held.Release(); await held.Completion; await f.Lan.ReadWriterBarrier();
        await Task.WhenAll(accept, ready, credit, verified, completed).WaitAsync(f.Lan.Token); await f.Writer.Completion;
        Require((await f.Lan.ReadAudio()).Body is AudioStreamingBody.Accept { ReceiveWindowBytes: 4096 }, "Accept order changed.");
        Require((await f.Lan.ReadAudio()).Body is AudioStreamingBody.OutputReady { Format: var format } && format == Format, "Exact output format changed.");
        Require((await f.Lan.ReadAudio()).Body is AudioStreamingBody.Credit { RetiredBytes: 8000 }, "Latest cumulative credit was not delivered.");
        Require((await f.Lan.ReadAudio()).Body is AudioStreamingBody.ContentVerified content && content.Sha256.SequenceEqual(expected), "Mutable metadata changed after queue admission.");
        Require((await f.Lan.ReadAudio()).Body is AudioStreamingBody.PlaybackComplete { SourceFrames: 1000, TrailingPaddingFrames: 0 }, "Completion order changed.");
        await f.Lan.Barrier();
    }
    private static async Task Overflow()
    {
        await using var f = await Fixture.Create(); await using var held = f.Lan.HoldWriter(); await held.Entered.WaitAsync(f.Lan.Token);
        var sending = f.Writer.Queue(new AudioStreamingBody.Accept(4096)); await Until(() => f.Writer.PendingCount.Sending);
        var pending = Enumerable.Range(0, 4).Select(_ => f.Writer.Queue(new AudioStreamingBody.OutputReady(Format))).ToArray();
        var overflow = await Throws<IOException>(() => Call(() => f.Writer.Queue(new AudioStreamingBody.ContentVerified(8, new byte[32]))));
        Require(!sending.IsCompleted && !f.Writer.Completion.IsCompleted, "Overflow abandoned the actual shared-writer wait.");
        foreach (var task in pending) Require(ReferenceEquals(overflow, await Throws<IOException>(() => task)), "Queued reply lost overflow cause.");
        held.Release(); await held.Completion; await f.Lan.ReadWriterBarrier();
        Require(ReferenceEquals(overflow, await f.ExpectFailure<IOException>()), "Writer lost its first overflow failure.");
        await Throws<IOException>(() => sending); await f.Lan.Barrier();
    }
    private static async Task Revoked()
    {
        await using var f = await Fixture.Create(); await using var held = f.Lan.HoldWriter(); await held.Entered.WaitAsync(f.Lan.Token);
        var sending = f.Writer.Queue(new AudioStreamingBody.Accept(4096)); await Until(() => f.Writer.PendingCount.Sending);
        var queued = f.Writer.Queue(new AudioStreamingBody.OutputReady(Format)); f.Permission.Revoke();
        held.Release(); await held.Completion; await f.Lan.ReadWriterBarrier();
        var failure = await f.ExpectFailure<AudioPlaybackApprovalException>();
        Require(failure.Reason == AudioPlaybackApprovalFailure.Revoked, "Playback revocation cause changed.");
        await Throws<AudioPlaybackApprovalException>(() => sending); await Throws<AudioPlaybackApprovalException>(() => queued);
        await f.Lan.Barrier();
    }
    private static async Task Disposal()
    {
        await using var f = await Fixture.Create(); await using var held = f.Lan.HoldWriter(); await held.Entered.WaitAsync(f.Lan.Token);
        var sending = f.Writer.Queue(new AudioStreamingBody.Accept(4096)); await Until(() => f.Writer.PendingCount.Sending);
        var queued = f.Writer.Queue(new AudioStreamingBody.OutputReady(Format)); var disposal = f.Writer.DisposeAsync().AsTask();
        Require(!disposal.IsCompleted && !sending.IsCompleted, "Disposal abandoned a pending real send.");
        await Throws<OperationCanceledException>(() => queued);
        held.Release(); await held.Completion; await f.Lan.ReadWriterBarrier(); await disposal;
        await Throws<OperationCanceledException>(() => sending); f.Inbox.RequireCurrent();
        await f.Lan.Session.SendAudioStopAsync(f.Inbox, AudioStreamingStopReason.UserStopped, f.Lan.Token);
        Require((await f.Lan.ReadAudio()).Body is AudioStreamingBody.Stop, "Writer disposal consumed the caller-owned inbox or retained its send slot.");
        await f.Lan.Barrier();
    }
    private static async Task Cancellation()
    {
        await using var f = await Fixture.Create(); await using var held = f.Lan.HoldWriter(); await held.Entered.WaitAsync(f.Lan.Token);
        var sending = f.Writer.Queue(new AudioStreamingBody.Accept(4096)); await Until(() => f.Writer.PendingCount.Sending);
        f.Caller.Cancel(); await f.ExpectFailure<OperationCanceledException>(); await Throws<OperationCanceledException>(() => sending);
        held.Release(); await held.Completion; await f.Lan.ReadWriterBarrier(); await f.Lan.Barrier();
    }
    private static async Task InvalidControls()
    {
        await using var f = await Fixture.Create(); await using var held = f.Lan.HoldWriter(); await held.Entered.WaitAsync(f.Lan.Token);
        var credit = f.Writer.Queue(new AudioStreamingBody.Credit(8)); await Until(() => f.Writer.PendingCount.Sending);
        foreach (var invalid in new AudioStreamingBody[] { new AudioStreamingBody.Credit(4),
            new AudioStreamingBody.End(8, new byte[32]), new AudioStreamingBody.Accept(uint.MaxValue),
            new AudioStreamingBody.ContentVerified(8, new byte[31]), new AudioStreamingBody.Stop(AudioStreamingStopReason.UserStopped) })
            await Throws<InvalidDataException>(() => Call(() => f.Writer.Queue(invalid)));
        var drained = f.Writer.DrainAsync(); held.Release(); await held.Completion; await f.Lan.ReadWriterBarrier(); await drained; await credit;
        Require((await f.Lan.ReadAudio()).Body is AudioStreamingBody.Credit { RetiredBytes: 8 }, "Invalid controls altered the valid queued reply.");
        await f.Lan.Barrier();
    }
    private static async Task PeerStop()
    {
        await using var f = await Fixture.Create(); await using var held = f.Lan.HoldWriter(); await held.Entered.WaitAsync(f.Lan.Token);
        var sending = f.Writer.Queue(new AudioStreamingBody.Accept(4096)); await Until(() => f.Writer.PendingCount.Sending);
        await f.Lan.SendAudio(new(f.Inbox.StreamId, new AudioStreamingBody.Stop(AudioStreamingStopReason.UserStopped)));
        await Until(() => { try { f.Inbox.RequireEffectCurrent(); return false; } catch (LanAudioStreamException) { return true; } });
        held.Release(); await held.Completion; await f.Lan.ReadWriterBarrier();
        var failure = await f.ExpectFailure<LanAudioStreamException>(); Require(failure.Reason == AudioStreamingStopReason.UserStopped, "Peer Stop reason changed.");
        await Throws<LanAudioStreamException>(() => sending); await f.Lan.Barrier();
    }
    private static async Task ForeignOwner()
    {
        await using var f = await Fixture.Create(); await using var other = await LanProductControlSessionTests.Fixture.ConnectForAudio(); await other.Admit();
        var foreign = new AudioReceiverControlWriter(other.Session, f.Inbox, f.Permission, other.Token);
        var sending = foreign.Queue(new AudioStreamingBody.Accept(4096));
        await Throws<InvalidDataException>(() => foreign.Completion); await Throws<InvalidDataException>(() => sending);
        await Throws<InvalidDataException>(() => foreign.DisposeAsync().AsTask());
        await f.Lan.Barrier(); await other.Barrier();
    }
    private static async Task EmptyDrain()
    {
        await using var f = await Fixture.Create(); await f.Writer.DrainAsync();
        await Throws<InvalidOperationException>(() => Call(() => f.Writer.Queue(new AudioStreamingBody.Accept(4096))));
        Require(f.Writer.PendingCount == (0, false), "Empty drain invented pending output."); await f.Lan.Barrier();
    }
    private static async Task Until(Func<bool> predicate)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        while (!predicate()) await Task.Delay(1, timeout.Token);
    }
    private static Task Call(Action action) { action(); return Task.CompletedTask; }
    private static async Task<T> Throws<T>(Func<Task> action) where T : Exception
    { try { await action(); } catch (T error) { return error; } throw new Exception($"Expected {typeof(T).Name}."); }
    private static void Require(bool condition, string reason) { if (!condition) throw new Exception(reason); }
}
