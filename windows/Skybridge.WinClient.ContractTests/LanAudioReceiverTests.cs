using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.Audio;

internal static class LanAudioReceiverTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("audio input after End invalidates the owner before the tail waiter can complete", InputAfterEnd),
        ("audio peer Stop retires the stream before an approval waiter can resume", PeerStop),
        ("audio inbox publishes the first offer before subsequent PCM", OrderedOffer),
        ("audio inbox overflow clears buffered frames and retires only that stream", Overflow),
        ("audio owner cancellation wakes reads and discards buffered frames", OwnerCancellation),
        ("canceled audio offer cannot leave an admitted inbox behind", OfferCancellation),
        ("audio offer timeout releases the pending registration", OfferTimeout),
        ("audio inbox rejects overlapping readers and honors canceled reads", SingleReader),
        ("audio retirement has a finite limit and does not evict old IDs", RetirementLimit)
    ];
    private static async Task InputAfterEnd()
    {
        foreach (bool duplicateEnd in new[] { false, true })
        {
            using var receiver = new LanAudioReceiver(() => true, CancellationToken.None);
            var id = Guid.NewGuid(); var accepting = receiver.AcceptOfferAsync(Binding(), CancellationToken.None);
            receiver.Receive(Offer(id)); using var inbox = await accepting;
            _ = await inbox.ReadAsync(CancellationToken.None);
            var end = new AudioStreamingMessage(id, new AudioStreamingBody.End(0, System.Security.Cryptography.SHA256.HashData([])));
            receiver.Receive(end); _ = await inbox.ReadAsync(CancellationToken.None);
            inbox.RequireEffectCurrent();
            Require(receiver.Receive(duplicateEnd ? end : Data(id)) == LanAudioReceiveDisposition.Retired,
                "Input after End remained live while the output owner was waiting for its tail.");
            var failure = await Throws<LanAudioStreamException>(() => { inbox.RequireEffectCurrent(); return Task.CompletedTask; });
            Require(failure.Reason == AudioStreamingStopReason.ProtocolViolation, "Input after End lost its protocol cause.");
            await Throws<LanAudioStreamException>(() => inbox.ReadAsync(CancellationToken.None));
        }
    }
    private static async Task PeerStop()
    {
        foreach (bool full in new[] { false, true })
        {
            using var receiver = new LanAudioReceiver(() => true, CancellationToken.None);
            var id = Guid.NewGuid(); var accepting = receiver.AcceptOfferAsync(Binding(), CancellationToken.None);
            receiver.Receive(Offer(id)); using var inbox = await accepting;
            if (full) for (int i = 1; i < LanAudioReceiver.MessageCapacity; i++) receiver.Receive(Data(id));
            receiver.Receive(new(id, new AudioStreamingBody.Stop(AudioStreamingStopReason.UserStopped)));
            var failure = await Throws<LanAudioStreamException>(() => { inbox.RequireCurrent(); return Task.CompletedTask; });
            Require(failure.Reason == AudioStreamingStopReason.UserStopped, "Peer Stop was lost behind queued data or overflow.");
            await Throws<LanAudioStreamException>(() => inbox.ReadAsync(CancellationToken.None));
            Require(receiver.Receive(Data(id)) == LanAudioReceiveDisposition.Retired, "Late audio revived a peer-stopped stream.");
        }
    }
    // Synthetic identity fixture; cryptographic validation belongs to handshake tests.
    private static AudioSessionIdentityBinding Binding()
    {
        const string local = "id:local-audio-fixture", peer = "id:remote-audio-fixture";
        using var keys = new ProductSessionKeys(ProductHandshakeRole.Initiator, "fixture", new byte[32], new byte[32], new byte[32]);
        var signer = ProductHandshakeProtocolIdentity.Capture(new WebRtcProductProtocolIdentityPublicKey(
            WebRtcProductSignatureAlgorithm.Ed25519, Enumerable.Repeat((byte)31, 32).ToArray()).Encode(), "fixture");
        var soa = new RemoteControlHandshakeSoa(RemoteControlHandshakeBinding.PeerId(local),
            RemoteControlHandshakeBinding.PeerId(peer), new byte[16]);
        return AudioSessionIdentityBinding.Capture(keys, local, peer, signer, signer, soa.EncodeTlv());
    }
    private static AudioStreamingMessage Offer(Guid id) => new(id,
        new AudioStreamingBody.CaptureOffer(new(48000, 2, AudioStreamingEncoding.Float32, 32, 3)));
    private static AudioStreamingMessage Data(Guid id, long offset = 0) => new(id, new AudioStreamingBody.PcmData(offset, [1, 2, 3, 4]));
    private static async Task OrderedOffer()
    {
        using var receiver = new LanAudioReceiver(() => true, CancellationToken.None);
        var id = Guid.NewGuid(); var binding = Binding();
        Require(receiver.Receive(Offer(id)) == LanAudioReceiveDisposition.Unavailable, "Offer was admitted without a waiting consumer.");
        var accepting = receiver.AcceptOfferAsync(binding, CancellationToken.None);
        await Throws<InvalidOperationException>(() => receiver.AcceptOfferAsync(binding, CancellationToken.None));
        Require(receiver.Receive(Data(id)) == LanAudioReceiveDisposition.Unavailable && !accepting.IsCompleted,
            "PCM opened an inbox without an offer.");
        receiver.Receive(Offer(id)); receiver.Receive(Data(id));
        using var inbox = await accepting;
        Require(ReferenceEquals(inbox.Binding, binding) && inbox.StreamId == id, "Offer lost its owner evidence.");
        Require((await inbox.ReadAsync(CancellationToken.None)).Body is AudioStreamingBody.CaptureOffer, "First offer was lost or reordered.");
        Require((await inbox.ReadAsync(CancellationToken.None)).Body is AudioStreamingBody.PcmData, "PCM order changed.");
    }
    private static async Task Overflow()
    {
        using var receiver = new LanAudioReceiver(() => true, CancellationToken.None);
        var id = Guid.NewGuid(); var accepting = receiver.AcceptOfferAsync(Binding(), CancellationToken.None);
        receiver.Receive(Offer(id)); using var inbox = await accepting;
        for (var i = 1; i < LanAudioReceiver.MessageCapacity; i++)
            Require(receiver.Receive(Data(id, i * 4)) == LanAudioReceiveDisposition.Queued, "Inbox filled before its declared capacity.");
        Require(receiver.Receive(Data(id, 32)) == LanAudioReceiveDisposition.QueueOverflow, "Overflow was silently dropped or accepted.");
        var failure = await Throws<LanAudioStreamException>(() => inbox.ReadAsync(CancellationToken.None));
        Require(failure.Reason == AudioStreamingStopReason.QueueOverflow, "Overflow cause was lost behind buffered data.");
        Require(receiver.Receive(Data(id, 36)) == LanAudioReceiveDisposition.Retired, "Retired stream was revived.");
        var next = receiver.AcceptOfferAsync(Binding(), CancellationToken.None); var newId = Guid.NewGuid();
        receiver.Receive(Offer(newId)); using var replacement = await next;
        inbox.Dispose(); // Closing an old handle must not close its replacement.
        Require((await replacement.ReadAsync(CancellationToken.None)).StreamId == newId, "Old inbox closed the new stream.");
    }
    private static async Task OwnerCancellation()
    {
        foreach (var buffered in new[] { false, true })
        {
            using var owner = new CancellationTokenSource();
            using var receiver = new LanAudioReceiver(() => !owner.IsCancellationRequested, owner.Token);
            var id = Guid.NewGuid(); var accepting = receiver.AcceptOfferAsync(Binding(), CancellationToken.None);
            receiver.Receive(Offer(id)); using var inbox = await accepting;
            _ = await inbox.ReadAsync(CancellationToken.None);
            Task<AudioStreamingMessage>? read = null;
            if (buffered) receiver.Receive(Data(id));
            else { read = inbox.ReadAsync(CancellationToken.None); Require(!read.IsCompleted, "Empty inbox read did not wait."); }
            owner.Cancel();
            var failure = await Throws<LanAudioStreamException>(() => read ?? inbox.ReadAsync(CancellationToken.None));
            Require(failure.Reason == AudioStreamingStopReason.SessionReplaced, "Owner cancellation lost its reason.");
            await Throws<LanAudioStreamException>(() => receiver.AcceptOfferAsync(Binding(), CancellationToken.None));
        }
        using var pendingOwner = new CancellationTokenSource();
        using var pendingReceiver = new LanAudioReceiver(() => true, pendingOwner.Token);
        var pending = pendingReceiver.AcceptOfferAsync(Binding(), CancellationToken.None);
        pendingOwner.Cancel();
        await Throws<LanAudioStreamException>(() => pending);
    }
    private static async Task OfferCancellation()
    {
        using var receiver = new LanAudioReceiver(() => true, CancellationToken.None);
        using var canceled = new CancellationTokenSource(); var id = Guid.NewGuid();
        var accepting = receiver.AcceptOfferAsync(Binding(), canceled.Token);
        canceled.Cancel();
        receiver.Receive(Offer(id)); // Exercise cancellation versus offer delivery, whichever obtains the gate first.
        await Throws<OperationCanceledException>(() => accepting);
        var late = receiver.Receive(Data(id));
        Require(late is LanAudioReceiveDisposition.Retired or LanAudioReceiveDisposition.Unavailable,
            "Canceled acceptance retained an active inbox.");
        var next = receiver.AcceptOfferAsync(Binding(), CancellationToken.None); var newId = Guid.NewGuid();
        receiver.Receive(Offer(newId)); using var inbox = await next;
        Require((await inbox.ReadAsync(CancellationToken.None)).StreamId == newId, "Canceled offer blocked its successor.");
    }
    private static async Task OfferTimeout()
    {
        using var receiver = new LanAudioReceiver(() => true, CancellationToken.None, TimeSpan.FromMilliseconds(30));
        await Throws<TimeoutException>(() => receiver.AcceptOfferAsync(Binding(), CancellationToken.None));
        using var cancel = new CancellationTokenSource();
        var next = receiver.AcceptOfferAsync(Binding(), cancel.Token);
        Require(!next.IsCompleted, "Timed-out registration retained the only slot.");
        cancel.Cancel(); await Throws<OperationCanceledException>(() => next);
    }
    private static async Task SingleReader()
    {
        using var receiver = new LanAudioReceiver(() => true, CancellationToken.None);
        var id = Guid.NewGuid(); var accepting = receiver.AcceptOfferAsync(Binding(), CancellationToken.None);
        receiver.Receive(Offer(id)); using var inbox = await accepting;
        _ = await inbox.ReadAsync(CancellationToken.None);
        using var cancel = new CancellationTokenSource();
        var read = inbox.ReadAsync(cancel.Token);
        await Throws<InvalidOperationException>(() => inbox.ReadAsync(CancellationToken.None));
        cancel.Cancel(); await Throws<OperationCanceledException>(() => read);
        receiver.Receive(Data(id));
        await Throws<OperationCanceledException>(() => inbox.ReadAsync(cancel.Token));
        Require((await inbox.ReadAsync(CancellationToken.None)).Body is AudioStreamingBody.PcmData,
            "Canceled read consumed or lost the next message.");
        var waiting = inbox.ReadAsync(CancellationToken.None); inbox.Dispose();
        var failure = await Throws<LanAudioStreamException>(() => waiting);
        Require(failure.Reason == AudioStreamingStopReason.UserStopped, "Inbox close did not wake the reader.");
    }
    private static async Task RetirementLimit()
    {
        using var receiver = new LanAudioReceiver(() => true, CancellationToken.None);
        var ids = new List<Guid>();
        for (var i = 0; i < LanAudioReceiver.RetiredStreamCapacity; i++)
        {
            var id = Guid.NewGuid(); ids.Add(id);
            var accepting = receiver.AcceptOfferAsync(Binding(), CancellationToken.None);
            receiver.Receive(Offer(id)); (await accepting).Dispose();
        }
        await Throws<InvalidOperationException>(() => receiver.AcceptOfferAsync(Binding(), CancellationToken.None));
        foreach (var id in ids) Require(receiver.Receive(Offer(id)) == LanAudioReceiveDisposition.Retired, "Old retired ID was evicted and reused.");
    }
    private static async Task<T> Throws<T>(Func<Task> action) where T : Exception
    { try { await action(); } catch (T error) { return error; } throw new Exception($"Expected {typeof(T).Name}."); }
    private static void Require(bool condition, string reason) { if (!condition) throw new Exception(reason); }
}
