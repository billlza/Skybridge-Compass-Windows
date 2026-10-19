using System.Collections.Concurrent;
using System.Security.Cryptography;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.Audio;
using CaptureFixture = AudioCaptureReceiveSessionTests.Fixture;
using NativeDevice = AudioCaptureReceiveSessionTests.NativeDevice;

internal static class AudioReceiveHostTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("an immediate rearm-gap withdrawal preserves ordered MAIN traffic", RearmGapWithdrawal),
        ("audio product host skips retired MAIN entries and drains current peer closure", ClosedMain),
        ("audio product host advertises only installed consumers and receives successive streams", SuccessiveStreams),
        ("audio product host rejects a competing peer without preempting an approval owner", CompetingPeer),
        ("audio product host keeps listening after a peer cancels its pending approval", PeerCancellation),
        ("audio product host survives immediate withdrawn offers on the same MAIN session", WithdrawnOffers),
        ("audio product host stop waits for real native preparation and release", StopPreparation),
        ("audio product host retains uncertain native owners and blocks replacement playback", RetainedNative),
        ("queued audio capability publication cannot restore reception after disabling", QueuedCapabilities),
        ("an advertised receiver declines an offer in the consumer rearm gap without closing MAIN", RearmGap)
    ];
    private static async Task ClosedMain()
    {
        await using var retired = await CaptureFixture.Create(); await using var live = await CaptureFixture.Create();
        await using var host = Host(live, new());
        await host.AttachAsync(retired.Lan.Session, retired.Lan.Token); await host.AttachAsync(live.Lan.Session, live.Lan.Token);
        await retired.Lan.Session.DisposeAsync();
        await host.EnableAsync(AudioCaptureReceiveSessionTests.Endpoint, live.Lan.Token); await Capabilities(live.Lan, true);
        Require(host.ReadSnapshot() is { Enabled: true, ConnectedDevices: 1, ListeningDevices: 1 },
            "A retired MAIN entry blocked or inflated the current audio consumer.");
        await live.Lan.Session.DisposeAsync();
        await Until(() => host.ReadSnapshot().ListeningDevices == 0, live.Lan.Token);
        await host.DisableAsync();
        Require(host.ReadSnapshot() is { Enabled: false, ConnectedDevices: 0, NativeReleaseConfirmed: true, NativeReleaseUnconfirmed: false },
            "A fully retired MAIN owner left native or listener resources behind.");
        await host.DetachAsync(live.Lan.Session);
        Require(!host.OwnsSession(live.Lan.Session), "A released listener still claimed ownership during MAIN teardown.");
    }
    private static readonly AudioStreamingPcmFormat Format = new(48000, 2, AudioStreamingEncoding.Float32, 32, 3);
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(3);
    private static AudioReceiveHost Host(CaptureFixture authority, ConcurrentBag<NativeDevice> devices, Action<NativeDevice>? configure = null)
        => new((session, endpoint) =>
        {
            var device = new NativeDevice(authority.Clock); configure?.Invoke(device); devices.Add(device);
            return new(session, (inbox, _) => Task.FromResult(authority.Lease(inbox)), null, _ => Task.FromResult(endpoint),
                authority.Approvals, _ => { device.Touch(); return device; }, authority.Clock);
        });
    private static async Task Capabilities(LanProductControlSessionTests.Fixture lan, bool enabled)
    {
        var message = await lan.Read();
        Require(message.Kind == LanControlMessageKind.Identity, "Capability publication used a different message kind.");
        var identity = LanProductControlMessages.Payload<LanProductIdentity>(message);
        Require((identity.Capabilities?.Contains(LanProductControlSession.CaptureReceiveCapability) == true) == enabled,
            "The advertised capture capability differs from the actual consumer state.");
        Require(identity.Capabilities?.Contains("file_transfer") == true && identity.Capabilities?.Contains("audio_file_receive_v1") != true,
            "Capture publication removed an existing capability or invented original-file reception.");
    }
    private static Task Offer(LanProductControlSessionTests.Fixture lan, Guid id)
        => lan.SendAudio(new(id, new AudioStreamingBody.CaptureOffer(Format)));
    private static async Task EmptyStream(LanProductControlSessionTests.Fixture lan, Guid id)
    {
        await Offer(lan, id);
        Require((await lan.ReadAudio()).Body is AudioStreamingBody.Accept, "The product consumer did not accept a valid source.");
        Require((await lan.ReadAudio()).Body is AudioStreamingBody.OutputReady ready && ready.Format == Format,
            "The product consumer changed the source output format.");
        await lan.SendAudio(new(id, new AudioStreamingBody.End(0, SHA256.HashData([]))));
        Require((await lan.ReadAudio()).Body is AudioStreamingBody.ContentVerified { TotalBytes: 0 }, "The empty source lost content verification.");
        Require((await lan.ReadAudio()).Body is AudioStreamingBody.PlaybackComplete { SourceFrames: 0, TrailingPaddingFrames: 0 },
            "The product consumer omitted ordered playback completion or invented audio.");
    }
    private static async Task SuccessiveStreams()
    {
        await using var f = await CaptureFixture.Create(); var devices = new ConcurrentBag<NativeDevice>();
        await using var host = Host(f, devices); await host.AttachAsync(f.Lan.Session, f.Lan.Token);
        Require(!host.ReadSnapshot().Enabled && host.ReadSnapshot().ListeningDevices == 0, "An unconfigured output advertised audio.");
        await host.EnableAsync(AudioCaptureReceiveSessionTests.Endpoint, f.Lan.Token); await Capabilities(f.Lan, true);
        for (int i = 0; i < 2; i++)
        {
            await EmptyStream(f.Lan, Guid.NewGuid());
            await Until(() => host.ReadSnapshot() is { Phase: null, ListeningDevices: 1 }, f.Lan.Token);
        }
        Require(devices.Count == 2 && devices.All(device => device.DisposeCalls == 1 && device.Client.DisposeCalls == 1 && !device.WrongThread),
            "Successive requests reused or abandoned an actual native owner.");
        await host.DisableAsync(); await Capabilities(f.Lan, false);
        Require(host.ReadSnapshot() is { Enabled: false, Stopping: false, ListeningDevices: 0, NativeReleaseConfirmed: true },
            "Disable completed before native/consumer release.");
        await f.Lan.Barrier();
    }
    private static async Task CompetingPeer()
    {
        await using var first = await CaptureFixture.Create(); await using var second = await CaptureFixture.Create();
        var shown = Signal(); var decision = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        first.Decide = (_, token) => { shown.TrySetResult(); return decision.Task.WaitAsync(token); };
        var devices = new ConcurrentBag<NativeDevice>(); await using var host = Host(first, devices);
        await host.AttachAsync(first.Lan.Session, first.Lan.Token); await host.AttachAsync(second.Lan.Session, second.Lan.Token);
        await host.EnableAsync(AudioCaptureReceiveSessionTests.Endpoint, first.Lan.Token); await Capabilities(first.Lan, true); await Capabilities(second.Lan, true);
        await Offer(first.Lan, Guid.NewGuid()); await shown.Task.WaitAsync(Limit);
        await Offer(second.Lan, Guid.NewGuid());
        Require((await second.Lan.ReadAudio()).Body is AudioStreamingBody.Stop { Reason: AudioStreamingStopReason.ReceiverDeclined },
            "Competing audio preempted the approved stream or waited without a response.");
        Require(devices.Count == 1 && devices.All(device => device.Activations == 0), "Competing or unapproved audio activated native output.");
        decision.TrySetResult(false);
        Require((await first.Lan.ReadAudio()).Body is AudioStreamingBody.Stop { Reason: AudioStreamingStopReason.ReceiverDeclined }, "The original prompt lost its decline.");
        await Until(() => host.ReadSnapshot() is { Phase: null, ListeningDevices: 2 }, first.Lan.Token);
        await first.Lan.Barrier(); await second.Lan.Barrier();
    }
    private static async Task PeerCancellation()
    {
        await using var f = await CaptureFixture.Create(); var shown = Signal();
        f.Decide = async (_, token) => { shown.TrySetResult(); await Task.Delay(Timeout.Infinite, token); return false; };
        await using var host = Host(f, new()); await host.AttachAsync(f.Lan.Session, f.Lan.Token);
        await host.EnableAsync(AudioCaptureReceiveSessionTests.Endpoint, f.Lan.Token); await Capabilities(f.Lan, true);
        var id = Guid.NewGuid(); await Offer(f.Lan, id); await shown.Task.WaitAsync(Limit);
        await f.Lan.SendAudio(new(id, new AudioStreamingBody.Stop(AudioStreamingStopReason.UserStopped)));
        await Until(() => host.ReadSnapshot() is { Enabled: true, Phase: null, ListeningDevices: 1 }, f.Lan.Token);
        await f.Lan.Barrier(); // No Stop echo or capability withdrawal may precede it.
    }
    private static async Task WithdrawnOffers()
    {
        await using var f = await CaptureFixture.Create();
        f.Decide = async (_, token) => { await Task.Delay(Timeout.Infinite, token); return false; };
        var devices = new ConcurrentBag<NativeDevice>();
        await using var host = Host(f, devices); await host.AttachAsync(f.Lan.Session, f.Lan.Token);
        await host.EnableAsync(AudioCaptureReceiveSessionTests.Endpoint, f.Lan.Token); await Capabilities(f.Lan, true);
        for (int i = 0; i < 8; i++)
        {
            var id = Guid.NewGuid(); await Offer(f.Lan, id);
            await f.Lan.SendAudio(new(id, new AudioStreamingBody.Stop(AudioStreamingStopReason.UserStopped)));
            try { await f.Lan.WithdrawnOfferBarrier(id); }
            catch (InvalidDataException error)
            { throw new InvalidDataException($"Immediate withdrawal {i}, offered stream {id}.", error); }
            await Until(() => host.ReadSnapshot() is { Enabled: true, Phase: null, ListeningDevices: 1 }, f.Lan.Token);
            await f.Lan.Barrier(); // No late/duplicate reply may survive the completed cancellation.
            Require(devices.All(device => device.Activations == 0), "An immediately withdrawn unapproved offer activated output.");
        }
        Require(f.Lan.Session.IsReady, "Withdrawn audio retired its live MAIN owner.");
    }
    private static async Task StopPreparation()
    {
        await using var f = await CaptureFixture.Create(); var devices = new ConcurrentBag<NativeDevice>();
        await using var host = Host(f, devices, device => device.Client.BlockPrepare = true);
        await host.AttachAsync(f.Lan.Session, f.Lan.Token); await host.EnableAsync(AudioCaptureReceiveSessionTests.Endpoint, f.Lan.Token); await Capabilities(f.Lan, true);
        await Offer(f.Lan, Guid.NewGuid()); await Until(() => !devices.IsEmpty, f.Lan.Token); var device = devices.Single();
        await device.Client.PrepareEntered.Task.WaitAsync(Limit);
        var stopping = host.DisableAsync();
        try
        {
            Require(!stopping.IsCompleted && host.ReadSnapshot() is { Stopping: true, NativeReleaseConfirmed: false, NativeReleaseUnconfirmed: false },
                "Product stop abandoned the actual native preparation.");
        }
        finally { device.Client.PrepareRelease.Set(); }
        await stopping.WaitAsync(Limit);
        Require((await f.Lan.ReadAudio()).Body is AudioStreamingBody.Stop { Reason: AudioStreamingStopReason.UserStopped }, "Native cancellation lost its terminal reply.");
        await Capabilities(f.Lan, false);
        Require(device.DisposeCalls == 1 && device.Client.DisposeCalls == 1 && !device.WrongThread && host.ReadSnapshot().NativeReleaseConfirmed,
            "Product stop did not wait for real same-thread native release.");
        await f.Lan.Barrier();
    }
    private static async Task RetainedNative()
    {
        await using var f = await CaptureFixture.Create(); var devices = new ConcurrentBag<NativeDevice>();
        var host = Host(f, devices, device => { device.Client.PrepareFailure = new IOException("prepare failed"); device.Client.DisposeFailure = new IOException("release uncertain"); });
        await host.AttachAsync(f.Lan.Session, f.Lan.Token); await host.EnableAsync(AudioCaptureReceiveSessionTests.Endpoint, f.Lan.Token); await Capabilities(f.Lan, true);
        await Offer(f.Lan, Guid.NewGuid());
        Require((await f.Lan.ReadAudio()).Body is AudioStreamingBody.Stop, "Uncertain native release produced positive admission.");
        await Capabilities(f.Lan, false); await Until(() => !host.ReadSnapshot().NativeReleaseConfirmed, f.Lan.Token);
        Require(host.ReadSnapshot() is { Enabled: false, ListeningDevices: 0, Phase: AudioCaptureReceivePhase.Failed, NativeReleaseUnconfirmed: true },
            "Uncertain release discarded the active operation or stayed advertised.");
        await Throws<InvalidOperationException>(() => host.EnableAsync(AudioCaptureReceiveSessionTests.Endpoint, f.Lan.Token));
        await Throws<InvalidOperationException>(() => host.DetachAsync(f.Lan.Session));
        Require(host.OwnsSession(f.Lan.Session), "Unknown native release lost the exact MAIN ownership marker.");
        await Throws<AggregateException>(() => host.DisposeAsync().AsTask());
        var retained = devices.Single(); Require(retained.DisposeCalls == 1 && retained.Client.DisposeCalls == 1 && !retained.WrongThread,
            "Failed host cleanup retried or moved the native owner.");
        await f.Lan.Barrier();
    }
    private static async Task QueuedCapabilities()
    {
        await using var f = await CaptureFixture.Create();
        using var inbox = await f.Lan.OpenAudioInbox();
        await using var held = f.Lan.HoldWriter(); await held.Entered.WaitAsync(f.Lan.Token);
        var enable = f.Lan.Session.SetCaptureReceiverEnabledAsync(true, f.Lan.Token);
        var disable = f.Lan.Session.SetCaptureReceiverEnabledAsync(false, f.Lan.Token);
        held.Release(); await held.Completion; await f.Lan.ReadWriterBarrier(); await Task.WhenAll(enable, disable);
        await Capabilities(f.Lan, false); await Capabilities(f.Lan, false); await f.Lan.Barrier();
    }
    private static async Task RearmGap()
    {
        await using var f = await CaptureFixture.Create();
        await Throws<InvalidOperationException>(() => f.Lan.Session.SetCaptureReceiverEnabledAsync(true, f.Lan.Token));
        var inbox = await f.Lan.OpenAudioInbox();
        await f.Lan.Session.SetCaptureReceiverEnabledAsync(true, f.Lan.Token); await Capabilities(f.Lan, true); inbox.Dispose();
        var id = Guid.NewGuid(); await Offer(f.Lan, id);
        Require((await f.Lan.ReadAudio()).Body is AudioStreamingBody.Stop { Reason: AudioStreamingStopReason.ReceiverDeclined },
            "An advertised consumer gap silently discarded the sender's request.");
        await f.Lan.Barrier();
        await f.Lan.Session.SetCaptureReceiverEnabledAsync(false, f.Lan.Token); await Capabilities(f.Lan, false);
    }
    private static async Task RearmGapWithdrawal()
    {
        await using var f = await CaptureFixture.Create();
        var inbox = await f.Lan.OpenAudioInbox();
        await f.Lan.Session.SetCaptureReceiverEnabledAsync(true, f.Lan.Token); await Capabilities(f.Lan, true);
        inbox.Dispose(); // Deliberately leave the advertised receiver without an offer waiter.
        var id = Guid.NewGuid();
        await Offer(f.Lan, id);
        await f.Lan.SendAudio(new(id, new AudioStreamingBody.Stop(AudioStreamingStopReason.UserStopped)));
        Require(await f.Lan.WithdrawnOfferBarrier(id) == LanProductControlSessionTests.WithdrawnOfferBarrierReply.DeclinedThenPong,
            "The deterministic unattended offer did not retain its exact decline before Pong.");
        Require(f.Lan.Session.IsReady && f.Device.Activations == 0, "A withdrawn gap offer closed MAIN or activated output.");
        await f.Lan.Session.SetCaptureReceiverEnabledAsync(false, f.Lan.Token); await Capabilities(f.Lan, false);
        await f.Lan.Barrier();
    }
    private static TaskCompletionSource Signal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
    private static async Task Until(Func<bool> condition, CancellationToken token)
    { while (!condition()) await Task.Delay(1, token); }
    private static async Task<T> Throws<T>(Func<Task> action) where T : Exception
    { try { await action(); } catch (T error) { return error; } throw new Exception($"Expected {typeof(T).Name}."); }
    private static void Require(bool condition, string reason) { if (!condition) throw new Exception(reason); }
}
