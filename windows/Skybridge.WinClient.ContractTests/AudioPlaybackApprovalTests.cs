using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.Audio;

internal static class AudioPlaybackApprovalTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("playback approval binds the admitted source sender membership and exact endpoint", ExactApproval),
        ("playback approval freezes the actual file offer before mutable wire bytes escape", FrozenFile),
        ("playback approval cannot borrow a lease from another inbox of the same pair", ForeignLease),
        ("playback approval serializes prompts and releases a genuinely closed decline", BusyAndDecline),
        ("playback canceled prompt retains its slot until cleanup and ignores late allow", LateDecision),
        ("playback decision delivery rechecks cancellation and original account evidence", DecisionRace),
        ("playback approval enforces both absolute clock deadlines and rollback", Deadlines),
        ("playback watcher cancels a revoked or peer-stopped pending approval", Watcher),
        ("playback disposal waits for real prompt cleanup and revokes active permission", Disposal),
        ("playback presenter failures remain failures and release only completed tasks", PresenterFailure),
        ("playback primary failure preserves cancellation-shaped prompt cleanup errors", CleanupFailure),
        ("playback effect gate remains nonblocking while the carrier admission lock is held", EffectGate),
        ("playback permission revocation blocks queued encrypted replies before wire admission", EncryptedReply),
        ("encrypted peer Stop invalidates pending approval while MAIN control remains live", EncryptedStop)
    ];
    private const string Endpoint = "{0.0.0.00000000}.{exact-output-fixture}";
    private static readonly AudioStreamingPcmFormat Format = new(48000, 2, AudioStreamingEncoding.Float32, 32, 3);
    private static TaskCompletionSource Signal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
    private sealed class Presenter(Func<AudioPlaybackApprovalRequest, CancellationToken, Task<bool>> show) : IAudioPlaybackApprovalPresenter
    {
        public Task<bool> ShowAsync(AudioPlaybackApprovalRequest request, CancellationToken cancellationToken) => show(request, cancellationToken);
    }
    private sealed class Prompt(bool cooperate = false) : IAudioPlaybackApprovalPresenter
    {
        internal readonly TaskCompletionSource<bool> Decision = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Displayed = Signal(), Canceled = Signal();
        internal AudioPlaybackApprovalRequest? Request;
        internal int Calls;
        public async Task<bool> ShowAsync(AudioPlaybackApprovalRequest request, CancellationToken cancellationToken)
        {
            Calls++; Request = request;
            using var registration = cancellationToken.Register(() => {
                Canceled.TrySetResult(); if (cooperate) Decision.TrySetCanceled(cancellationToken);
            });
            Displayed.TrySetResult();
            return await Decision.Task.ConfigureAwait(false);
        }
    }
    private sealed class Clock
    {
        private readonly object _gate = new();
        private AudioAuthorizationTime _now = new(1_800_000_000_000, 1000);
        internal AudioAuthorizationTime Read() { lock (_gate) return _now; }
        internal void Move(long wall, long continuous) { lock (_gate) _now = new(_now.WallMilliseconds + wall, _now.ContinuousMilliseconds + continuous); }
    }
    private sealed class Fixture : IAsyncDisposable
    {
        internal readonly Clock Clock = new();
        internal readonly AccountAudioAuthorization Epoch = new(AudioAccountScope.From(AudioAccountMembershipTests.Authentication()));
        internal LanAudioReceiver Carrier { get; }
        internal ILanAudioStreamInbox Inbox { get; }
        internal AccountAudioMembershipLease Lease { get; }
        internal AudioPlaybackApprovalService Service { get; }
        private Fixture(LanAudioReceiver carrier, ILanAudioStreamInbox inbox, IAudioPlaybackApprovalPresenter presenter)
        {
            Carrier = carrier; Inbox = inbox; Lease = MakeLease(inbox, Epoch, Clock.Read);
            Service = new(presenter, Clock.Read);
        }
        internal static async Task<Fixture> Create(IAudioPlaybackApprovalPresenter presenter, AudioStreamingBody? source = null)
        {
            // This carrier is supplied below so both its admitted descriptor and actual
            // stream lifetime are exercised; credentials/identities are synthetic fixtures.
            var receiver = new LanAudioReceiver(() => true, CancellationToken.None);
            var accept = receiver.AcceptOfferAsync(AudioAccountMembershipTests.Binding(), default);
            receiver.Receive(new(Guid.NewGuid(), source ?? new AudioStreamingBody.CaptureOffer(Format)));
            return new Fixture(receiver, await accept, presenter);
        }
        internal Task<AudioPlaybackPermission> Request(CancellationToken token = default) => Service.RequestAsync(Inbox, Lease, Endpoint, token);
        public async ValueTask DisposeAsync() { await Service.DisposeAsync(); Inbox.Dispose(); Carrier.Dispose(); }
    }
    private static AccountAudioMembershipLease MakeLease(ILanAudioStreamInbox inbox, AccountAudioAuthorization epoch, Func<AudioAuthorizationTime> clock)
    {
        var auth = AudioAccountMembershipTests.Authentication(); var now = clock();
        var local = AudioAccountMembershipTests.Local(inbox.Binding); var peer = AudioAccountMembershipTests.Peer(inbox.Binding);
        var observation = AudioRegistryObservation.FromResponse(auth, local, new(now.WallMilliseconds, local.DeviceId, false,
            [AudioAccountMembershipTests.Entry(local, true), AudioAccountMembershipTests.Entry(peer)]), now, now);
        return new(AudioAccountMembershipEvidence.Create(observation, local, peer), epoch, inbox, clock);
    }
    private static Task<bool> Allow(AudioPlaybackApprovalRequest request, CancellationToken token) => Task.FromResult(true);
    private static void Check(AudioPlaybackPermission permission, Fixture f) => permission.RequireEffectCurrent(f.Inbox, f.Inbox.Source, Endpoint);
    private static async Task ExactApproval()
    {
        AudioPlaybackApprovalRequest? shown = null;
        await using var f = await Fixture.Create(new Presenter((request, _) => { shown = request; return Task.FromResult(true); }));
        var permission = await f.Request(); Check(permission, f);
        var displayed = shown ?? throw new Exception("No displayed request.");
        Require(ReferenceEquals(displayed, permission.Request) && displayed.StreamId == f.Inbox.StreamId && displayed.SessionId == f.Lease.SessionId &&
            displayed.MembershipId == f.Lease.Evidence.Id && displayed.Sender == f.Lease.Evidence.Peer && displayed.Source == f.Inbox.Source,
            "Displayed approval did not bind the admitted identities/source.");
        await Throws<InvalidDataException>(() => Call(() => permission.RequireEffectCurrent(f.Inbox, f.Inbox.Source, Endpoint + "-other")));
        await Throws<InvalidDataException>(() => Call(() => permission.RequireEffectCurrent(f.Inbox,
            new AudioPlaybackSource.CapturedPcm(new(44100, 2, AudioStreamingEncoding.Float32, 32, 3)), Endpoint)));
        using var foreign = new AudioAccountMembershipTests.Inbox(f.Inbox.Binding);
        await Throws<InvalidDataException>(() => Call(() => permission.RequireCurrent(foreign, f.Inbox.Source, Endpoint)));
        Check(permission, f); permission.Revoke(); await Failure(AudioPlaybackApprovalFailure.Revoked, () => Call(() => Check(permission, f)));
        await Throws<InvalidDataException>(() => f.Service.RequestAsync(f.Inbox, f.Lease, "", default));
    }
    private static async Task FrozenFile()
    {
        byte[] hash = Enumerable.Range(0, 32).Select(n => (byte)n).ToArray(); string expected = Convert.ToHexStringLower(hash);
        var transfer = Guid.NewGuid(); await using var f = await Fixture.Create(new Presenter(Allow), new AudioStreamingBody.FileOffer(transfer, 1234, hash));
        var wire = await f.Inbox.ReadAsync(default); hash[0] = 90;
        if (wire.Body is not AudioStreamingBody.FileOffer read) throw new Exception("Missing file offer.");
        read.Sha256[1] = 91;
        var permission = await f.Request();
        Require(permission.Request.Source == new AudioPlaybackSource.OriginalFile(transfer, 1234, expected), "Approval borrowed mutable file digest bytes.");
        await Throws<InvalidDataException>(() => Call(() => permission.RequireEffectCurrent(f.Inbox, AudioPlaybackSource.FromOffer(wire), Endpoint)));
        Check(permission, f);
    }
    private static async Task ForeignLease()
    {
        var prompt = new Prompt(); await using var f = await Fixture.Create(prompt);
        using var other = new AudioAccountMembershipTests.Inbox(f.Inbox.Binding);
        var sameEvidence = new AccountAudioMembershipLease(f.Lease.Evidence, f.Epoch, other, f.Clock.Read);
        await Throws<InvalidDataException>(() => f.Service.RequestAsync(f.Inbox, sameEvidence, Endpoint, default));
        Require(prompt.Calls == 0, "A foreign lease reached local approval.");
    }
    private static async Task BusyAndDecline()
    {
        var first = new Prompt(); var second = new Prompt(); int calls = 0;
        await using var f = await Fixture.Create(new Presenter((r, ct) => (++calls == 1 ? first : second).ShowAsync(r, ct)));
        var pending = f.Request(); await first.Displayed.Task.WaitAsync(TimeSpan.FromSeconds(2));
        await Failure(AudioPlaybackApprovalFailure.Busy, () => f.Request());
        first.Decision.SetResult(false); await Failure(AudioPlaybackApprovalFailure.Declined, () => pending);
        var next = f.Request(); await second.Displayed.Task.WaitAsync(TimeSpan.FromSeconds(2));
        Require(first.Request?.Id != second.Request?.Id && calls == 2, "New prompt inherited the old request.");
        Require(!first.Decision.TrySetResult(true) && !next.IsCompleted, "Stale decision answered a successor.");
        second.Decision.SetResult(true); Check(await next, f);
    }
    private static async Task LateDecision()
    {
        var prompt = new Prompt(); await using var f = await Fixture.Create(prompt); using var cancel = new CancellationTokenSource();
        var pending = f.Request(cancel.Token); await prompt.Displayed.Task.WaitAsync(TimeSpan.FromSeconds(2));
        cancel.Cancel(); await prompt.Canceled.Task.WaitAsync(TimeSpan.FromSeconds(2));
        Require(!pending.IsCompleted, "Cancellation abandoned live prompt cleanup.");
        await Failure(AudioPlaybackApprovalFailure.Busy, () => f.Request());
        prompt.Decision.SetResult(true); await Throws<OperationCanceledException>(() => pending);
    }
    private static async Task DecisionRace()
    {
        foreach (int variant in Enumerable.Range(0, 4))
        {
            using var cancel = new CancellationTokenSource(); Fixture? fixture = null;
            await using var f = fixture = await Fixture.Create(new Presenter((_, _) => {
                if (variant == 0) cancel.Cancel();
                else if (variant == 1) fixture!.Epoch.Revoke();
                else if (variant == 2) fixture!.Lease.Evidence.Revoke();
                else fixture!.Inbox.Dispose();
                return Task.FromResult(true);
            }));
            var error = await Throws<Exception>(() => f.Request(cancel.Token));
            Require(variant switch {
                0 => Has<OperationCanceledException>(error), 1 => Has<InvalidOperationException>(error),
                2 => Has<AudioMembershipException>(error), _ => Has<LanAudioStreamException>(error)
            }, "Decision race failed without preserving its actual cause.");
        }
    }
    private static async Task Deadlines()
    {
        foreach (var delta in new[] { (60_000L, 0L), (0L, 60_000L), (-1L, 0L), (0L, -1L) })
        {
            var prompt = new Prompt(); await using var f = await Fixture.Create(prompt);
            var pending = f.Request(); await prompt.Displayed.Task.WaitAsync(TimeSpan.FromSeconds(2));
            f.Clock.Move(delta.Item1, delta.Item2); prompt.Decision.SetResult(true);
            var error = await Throws<Exception>(() => pending);
            Require(Has<AudioPlaybackApprovalException>(error) || Has<AudioMembershipException>(error), "Late/clock-invalid approval became permission.");
        }
    }
    private static async Task Watcher()
    {
        foreach (int variant in Enumerable.Range(0, 4))
        {
            var prompt = new Prompt(true); await using var f = await Fixture.Create(prompt);
            var pending = f.Request(); await prompt.Displayed.Task.WaitAsync(TimeSpan.FromSeconds(2));
            if (variant == 0) f.Lease.Evidence.Revoke();
            else if (variant == 1) f.Carrier.Receive(new(f.Inbox.StreamId, new AudioStreamingBody.Stop(AudioStreamingStopReason.UserStopped)));
            else if (variant == 2) f.Clock.Move(60_000, 60_000);
            else for (int i = 0; i < LanAudioReceiver.MessageCapacity; i++) f.Carrier.Receive(new(f.Inbox.StreamId, new AudioStreamingBody.PcmData(0, new byte[8])));
            await prompt.Canceled.Task.WaitAsync(TimeSpan.FromSeconds(2));
            var error = await Throws<Exception>(() => pending.WaitAsync(TimeSpan.FromSeconds(2)));
            Require(variant switch {
                0 => Has<AudioMembershipException>(error), 2 => Has<AudioPlaybackApprovalException>(error), _ => Has<LanAudioStreamException>(error)
            }, "Watcher discarded the authority failure behind UI cancellation.");
        }
    }
    private static async Task Disposal()
    {
        var prompt = new Prompt(); await using (var f = await Fixture.Create(prompt))
        {
            var pending = f.Request(); var disposal = f.Service.DisposeAsync().AsTask();
            await prompt.Canceled.Task.WaitAsync(TimeSpan.FromSeconds(2));
            Require(!pending.IsCompleted && !disposal.IsCompleted, "Service disposal abandoned a live prompt.");
            await Throws<ObjectDisposedException>(() => f.Request());
            prompt.Decision.SetResult(true); await Throws<OperationCanceledException>(() => pending); await disposal;
        }
        await using var active = await Fixture.Create(new Presenter(Allow)); var permission = await active.Request();
        await active.Service.DisposeAsync(); await Throws<OperationCanceledException>(() => Call(() => Check(permission, active)));
    }
    private static async Task PresenterFailure()
    {
        var cause = new IOException("presenter failed after closing its prompt"); int calls = 0;
        await using var f = await Fixture.Create(new Presenter((_, _) => ++calls == 1 ? Task.FromException<bool>(cause) : Task.FromResult(true)));
        Require(ReferenceEquals(cause, await Throws<IOException>(() => f.Request())), "Presenter failure was masked.");
        Check(await f.Request(), f);
    }
    private static async Task CleanupFailure()
    {
        foreach (bool inner in new[] { true, false })
        {
            var displayed = Signal(); var cause = new IOException("prompt cleanup failed");
            using var foreign = new CancellationTokenSource(); foreign.Cancel();
            async Task<bool> Present(AudioPlaybackApprovalRequest request, CancellationToken token)
            {
                displayed.SetResult();
                try { await Task.Delay(Timeout.InfiniteTimeSpan, token); }
                catch (OperationCanceledException) when (token.IsCancellationRequested)
                {
                    if (inner) throw new OperationCanceledException("prompt cleanup reported a failure", cause, token);
                    throw new OperationCanceledException("unrelated cancellation during cleanup", foreign.Token);
                }
                throw new Exception("Infinite prompt wait completed without cancellation.");
            }
            await using var f = await Fixture.Create(new Presenter(Present));
            var pending = f.Request(); await displayed.Task.WaitAsync(TimeSpan.FromSeconds(2));
            f.Clock.Move(60_000, 60_000);
            var error = await Throws<Exception>(() => pending.WaitAsync(TimeSpan.FromSeconds(2)));
            Require(error is AggregateException aggregate && aggregate.Flatten().InnerExceptions.Any(e =>
                e is OperationCanceledException canceled && (inner ? ReferenceEquals(canceled.InnerException, cause) : canceled.CancellationToken == foreign.Token)),
                "Primary approval failure concealed the prompt cleanup error.");
        }
    }
    private static async Task EffectGate()
    {
        await using var f = await Fixture.Create(new Presenter(Allow)); var permission = await f.Request();
        using var send = f.Carrier.BeginSend(f.Inbox, f.Inbox.StreamId);
        var entered = Signal(); using var release = new ManualResetEventSlim();
        var holder = Task.Run(() => send.Admit(() => { entered.SetResult(); if (!release.Wait(TimeSpan.FromSeconds(3))) throw new TimeoutException("Carrier fixture stuck."); return true; }));
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
        try { await Task.Run(() => Check(permission, f)).WaitAsync(TimeSpan.FromSeconds(1)); }
        finally { release.Set(); await holder; }
        f.Carrier.InvalidateIdentity(); await Throws<LanAudioStreamException>(() => Call(() => Check(permission, f)));
    }
    private static async Task EncryptedReply()
    {
        await using var lan = await LanProductControlSessionTests.Fixture.ConnectForAudio(); await lan.Admit();
        using var inbox = await lan.OpenAudioInbox(); var clock = new Clock();
        var epoch = new AccountAudioAuthorization(AudioAccountScope.From(AudioAccountMembershipTests.Authentication()));
        var lease = MakeLease(inbox, epoch, clock.Read); await using var service = new AudioPlaybackApprovalService(new Presenter(Allow), clock.Read);
        var permission = await service.RequestAsync(inbox, lease, Endpoint, lan.Token);
        void Effect() => permission.RequireEffectCurrent(inbox, inbox.Source, Endpoint);
        await lan.Session.SendAudioReplyAsync(inbox, new(inbox.StreamId, new AudioStreamingBody.Accept(4096)), Effect, lan.Token);
        Require((await lan.ReadAudio()).Body is AudioStreamingBody.Accept, "Approved reply failed to reach encrypted MAIN.");
        await using var held = lan.HoldWriter(); await held.Entered.WaitAsync(lan.Token);
        var queued = lan.Session.SendAudioReplyAsync(inbox, new(inbox.StreamId, new AudioStreamingBody.Credit(8)), Effect, lan.Token);
        Require(!queued.IsCompleted, "Writer admission did not wait."); permission.Revoke(); held.Release(); await held.Completion;
        await Failure(AudioPlaybackApprovalFailure.Revoked, () => queued); await lan.ReadWriterBarrier();
        await lan.Session.SendAudioStopAsync(inbox, AudioStreamingStopReason.PermissionRevoked, lan.Token);
        Require((await lan.ReadAudio()).Body is AudioStreamingBody.Stop, "Revoked positive reply wrote bytes or blocked Stop."); await lan.Barrier();
    }
    private static async Task EncryptedStop()
    {
        await using var lan = await LanProductControlSessionTests.Fixture.ConnectForAudio(); await lan.Admit();
        using var inbox = await lan.OpenAudioInbox(); var clock = new Clock();
        var epoch = new AccountAudioAuthorization(AudioAccountScope.From(AudioAccountMembershipTests.Authentication()));
        var lease = MakeLease(inbox, epoch, clock.Read); var prompt = new Prompt(true);
        await using var service = new AudioPlaybackApprovalService(prompt, clock.Read);
        var pending = service.RequestAsync(inbox, lease, Endpoint, lan.Token); await prompt.Displayed.Task.WaitAsync(lan.Token);
        await lan.SendAudio(new(inbox.StreamId, new AudioStreamingBody.Stop(AudioStreamingStopReason.UserStopped))); await lan.Barrier();
        var error = await Throws<Exception>(() => pending.WaitAsync(TimeSpan.FromSeconds(2)));
        Require(Has<LanAudioStreamException>(error) && lan.Session.IsReady, "Peer Stop did not cancel only its approval.");
        await Throws<LanAudioStreamException>(() => Call(inbox.RequireEffectCurrent));
    }
    private static Task Call(Action action) { action(); return Task.CompletedTask; }
    private static bool Has<T>(Exception error) where T : Exception => error is T || error is AggregateException aggregate && aggregate.Flatten().InnerExceptions.Any(e => e is T);
    private static async Task Failure(AudioPlaybackApprovalFailure reason, Func<Task> action)
    { var error = await Throws<AudioPlaybackApprovalException>(action); Require(error.Reason == reason, $"Expected {reason}, got {error.Reason}."); }
    private static async Task<T> Throws<T>(Func<Task> action) where T : Exception
    { try { await action(); } catch (T error) { return error; } throw new Exception($"Expected {typeof(T).Name}."); }
    private static void Require(bool condition, string reason) { if (!condition) throw new Exception(reason); }
}
