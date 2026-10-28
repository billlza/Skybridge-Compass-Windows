using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.Audio;
using Skybridge.WinClient.Services.FileTransfer;

internal static class AudioOriginalFileReceiveSessionTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("file product reports actual native progress only to a negotiated consumer", NativeProgress),
        ("file product processes peer Stop while exact-output reply waits for MAIN", StopBeforeReadyDelivery),
        ("file product receives real classic TCP after MAIN approval and completes exact native frames", Complete),
        ("file product continues its admitted transfer and exact native frames after membership renewal", RenewedFile),
        ("file product does not turn transfer receipt into playback completion before native release", Tail),
        ("file product rejects foreign metadata without consuming the approved file slot", WrongMetadata),
        ("file product refuses unsolicited classic bytes without creating an artifact", Unsolicited),
        ("file product decline opens neither private storage nor native output", Declined),
        ("file product rejects capture controls on an approved original-file stream", CaptureControl),
        ("file product cancels a pending real classic receive and preserves MAIN", CancelPartial),
        ("file product account revocation stops a pending classic receive", RevokePartial),
        ("file product reports content corruption without OutputReady or playbackComplete", Corrupt),
        ("file product rejects unsupported WAVE before opening native output", Unsupported),
        ("file product rejects non-finite PCM without submitting it", NonFinite),
        ("file product native cleanup failure retains ownership and prevents playbackComplete", CleanupFailure),
        ("file capability needs a live matching listener and advertises no ordinary file approval", Capability),
        ("file capability rejects a missing authenticated file port", MissingPort),
        ("file registry closing a ticket remains safe for an already captured cancellation", CancelClosedTicket),
        ("file registry rejects a different MAIN owner and a second live ticket", ForeignOwner),
        ("file product host installs file capability then receives and releases its real stream", HostReception),
        ("file listener stop drains a partial producer and its playback owner", ListenerStop),
        .. AudioUsbFileReceiveTests.Cases
    ];
    private static readonly AudioStreamingPcmFormat Format = new(48000, 2, AudioStreamingEncoding.Float32, 32, 3);
    internal sealed class Fixture : IAsyncDisposable
    {
        internal readonly AudioOriginalFileReceiveRegistry Registry = new();
        internal readonly ConcurrentQueue<Exception> ReceiveFailures = new();
        internal readonly string Root = Path.Combine(AppContext.BaseDirectory, "file-product-" + Guid.NewGuid().ToString("N"));
        internal readonly Guid TransferId = Guid.NewGuid();
        internal AudioCaptureReceiveSessionTests.Fixture Main = null!;
        internal readonly LanProductControlListener Listener;
        internal IPEndPoint Endpoint => (IPEndPoint)Listener.RequireLiveListener().LocalEndpoint;
        internal byte[] Bytes = Wave(Pcm(17));
        internal string FileName = "music.wav";
        internal byte[] Key = [];
        internal ClassicFileMetadata Metadata => ClassicFileTransferWire.Authenticate(new ClassicFileMetadata(
            TransferId.ToString("D"), FileName, Bytes.Length, Convert.ToHexStringLower(SHA256.HashData(Bytes)),
            65536, 2, SenderDeviceId: Main.Lan.Session.PeerDeviceId), Key);
        private Fixture()
        {
            Listener = new(async (client, token) =>
            {
                try { await Registry.ReceiveAsync(client, id =>
                    id == Main.Lan.Session.PeerDeviceId ? Main.Lan.Session : throw new InvalidDataException("Unknown MAIN peer."), token); }
                catch (Exception error) { ReceiveFailures.Enqueue(error); throw; }
            }, () => true);
        }
        internal static async Task<Fixture> Create(bool enableRenewal = false, bool reportFileOutputProgress = false)
        {
            var f = new Fixture(); Directory.CreateDirectory(f.Root);
            f.Listener.Start(IPAddress.Loopback, CancellationToken.None); f.Registry.Bind(f.Listener, f.Root);
            f.Main = await AudioCaptureReceiveSessionTests.Fixture.Create(f.Registry, checked((ushort)f.Endpoint.Port), enableRenewal,
                reportFileOutputProgress: reportFileOutputProgress);
            f.Key = ClassicFileTransferWire.DeriveTransferKey(f.Main.Lan.Keys, f.TransferId.ToString("D"));
            return f;
        }
        internal async Task Offer(bool accepted = true)
        {
            Main.Run = Main.Receiver.RunAsync(Main.Caller.Token);
            await Main.Receiver.ReadyForOffer.WaitAsync(Main.Lan.Token);
            await Main.Lan.SendAudio(new(Main.StreamId, new AudioStreamingBody.FileOffer(TransferId, Bytes.Length, SHA256.HashData(Bytes))));
            if (accepted)
                Require((await Main.Read()).Body is AudioStreamingBody.Accept { ReceiveWindowBytes: 0 }, "File mode did not accept exactly zero capture credit.");
        }
        internal async Task<TcpClient> Begin(ClassicFileMetadata? metadata = null)
        {
            var client = new TcpClient();
            try
            {
                await client.ConnectAsync(Endpoint, Main.Lan.Token);
                await ClassicFileTransferFrames.WriteAsync(client.GetStream(), ClassicFileFrameType.Metadata,
                    ClassicFileTransferWire.Encode(metadata ?? Metadata), Main.Lan.Token);
                return client;
            }
            catch { client.Dispose(); throw; }
        }
        internal async Task Transfer(byte[]? bytes = null)
        {
            using var client = await Begin(); var network = client.GetStream();
            var content = bytes ?? Bytes; int index = 0;
            for (int offset = 0; offset < content.Length; offset += 65536)
                await ClassicFileTransferFrames.WriteAsync(network, ClassicFileFrameType.Chunk,
                    ClassicFileTransferWire.Encode(ClassicFileTransferWire.SealChunk(index++, content.AsSpan(offset, Math.Min(65536, content.Length - offset)), Key)), Main.Lan.Token);
            await ClassicFileTransferFrames.WriteAsync(network, ClassicFileFrameType.Complete, ReadOnlyMemory<byte>.Empty, Main.Lan.Token);
            var frame = await ClassicFileTransferFrames.ReadAsync(network, Main.Lan.Token);
            Require(frame.Type == ClassicFileFrameType.Receipt, "Missing classic receipt.");
            var receipt = ClassicFileTransferWire.Decode<ClassicFileReceipt>(frame.Payload);
            ClassicFileTransferWire.Verify(receipt, Metadata, Key);
            Require(receipt.Success && receipt.ReceivedBytes == Bytes.Length, "Transfer receipt did not bind exact source bytes.");
        }
        internal async Task Ready()
        {
            Require((await Main.Read()).Body is AudioStreamingBody.OutputReady output && output.Format == Format,
                "OutputReady did not preserve the source declaration.");
        }
        internal async Task CompletePlayback()
        {
            Require((await Main.Read()).Body is AudioStreamingBody.PlaybackComplete p &&
                p.SourceFrames == (Bytes.Length - 68) / 8 && p.TrailingPaddingFrames == 0,
                "File mode emitted capture controls or incorrect playback completion.");
            var result = await Main.Run!.WaitAsync(Main.Lan.Token);
            Require(result is AudioPlaybackReceiveReceipt.OriginalFile receipt && receipt.Format == Format &&
                receipt.FileBytes == Bytes.Length && receipt.FileSha256Hex == Metadata.FileHash &&
                receipt.Output.SourceFrames == (ulong)(Bytes.Length - 68) / 8, "File/native receipt was substituted.");
            Require(Main.Native.Submissions.SelectMany(b => b).SequenceEqual(Bytes.Skip(68)), "The output changed source PCM bytes.");
            Released(); Main.NativeReleased(); await Main.Lan.Barrier();
        }
        internal void Released() => Require(Main.Receiver.FileReleaseConfirmed && Directory.GetFiles(Root).Length == 0,
            "Private file cleanup was not confirmed.");
        public async ValueTask DisposeAsync()
        {
            var failures = new List<Exception>();
            try { Registry.Unbind(Listener); } catch (Exception e) { failures.Add(e); }
            var stopped = Listener.StopAsync();
            try { await Main.DisposeAsync(); } catch (Exception e) { failures.Add(e); }
            try { await stopped; await Listener.DisposeAsync(); } catch (Exception e) { failures.Add(e); }
            CryptographicOperations.ZeroMemory(Key);
            if (failures.Count != 0) throw new AggregateException("File fixture cleanup failed.", failures);
            Require(Directory.GetFiles(Root).Length == 0, "Fixture cannot erase evidence of a leaked artifact.");
            Directory.Delete(Root);
        }
    }

    private static async Task NativeProgress()
    {
        foreach (bool receivingRole in new[] { false, true })
        {
            await using var f = await Fixture.Create(reportFileOutputProgress: true);
            f.Bytes = Wave(Pcm(25001)); f.Main.Native.AllowRetirement = true;
            await f.Offer();
            await f.Main.Lan.Session.SetAudioReceiverCapabilitiesAsync(true, AudioOriginalFileReceiveSupport.Wave,
                f.Main.Lan.Token, reportFileOutputProgress: true);
            var identity = LanProductControlMessages.Payload<LanProductIdentity>(await f.Main.Lan.Read());
            Require(identity.Capabilities?.Contains(AudioStreamingWire.FileOutputProgressReportCapability) == true,
                "Installed reporter did not publish its actual role.");
            await f.Main.Lan.PublishPeerFileOutputProgress(receivingRole); await f.Main.Lan.Barrier();
            await f.Transfer(); await f.Ready();
            long previous = 0; int count = 0;
            while (true)
            {
                var body = (await f.Main.Read()).Body;
                if (body is AudioStreamingBody.PlaybackComplete { SourceFrames: 25001, TrailingPaddingFrames: 0 }) break;
                Require(body is AudioStreamingBody.FileOutputProgress && receivingRole, "Unexpected or unnegotiated file progress.");
                var current = ((AudioStreamingBody.FileOutputProgress)body).SourceFrames;
                Require(current > previous && current <= 25001, "File progress exceeded or regressed from the native source extent.");
                previous = current; count++;
            }
            Require(receivingRole ? count > 0 : count == 0, "Peer role did not govern native progress delivery.");
            Require(await f.Main.Run! is AudioPlaybackReceiveReceipt.OriginalFile { Output.SourceFrames: 25001 }, "Native completion receipt changed.");
            f.Released(); f.Main.NativeReleased(); await f.Main.Lan.Barrier();
        }
    }
    private static async Task StopBeforeReadyDelivery()
    {
        await using var f = await Fixture.Create(); f.Main.Native.BlockPrepare = true;
        await f.Offer();
        await using var held = f.Main.Lan.HoldWriter(); await held.Entered.WaitAsync(f.Main.Lan.Token);
        TimeoutException? releaseTimeout = null;
        try
        {
            await f.Transfer(); await f.Main.Native.PrepareEntered.Task.WaitAsync(f.Main.Lan.Token);
            f.Main.Native.PrepareRelease.Set();
            // Observe the existing writer's admission state, without introducing a
            // production test hook or assuming a delay means the frame was queued.
            var writerField = typeof(AudioCaptureReceiveSession).GetField("_writer",
                System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)
                ?? throw new InvalidOperationException("Receiver control owner is unavailable to the test.");
            await Until(() => writerField.GetValue(f.Main.Receiver) is AudioReceiverControlWriter writer && writer.PendingCount.Sending,
                f.Main.Lan.Token);
            await f.Main.Lan.SendAudio(new(f.Main.StreamId, new AudioStreamingBody.Stop(AudioStreamingStopReason.UserStopped)));
            try { await f.Main.Native.DisposeEntered.Task.WaitAsync(TimeSpan.FromSeconds(2)); }
            catch (TimeoutException error) { releaseTimeout = error; }
            Require(!f.Main.Device.WrongThread, "Stop moved native cleanup off its owner.");
        }
        finally { f.Main.Native.PrepareRelease.Set(); held.Release(); await held.Completion; }
        await f.Main.Lan.ReadWriterBarrier();
        await f.Main.Failure(); f.Released(); f.Main.NativeReleased();
        // Assert after observing the expected stream failure so fixture disposal
        // cannot obscure the original timing failure with an unobserved Stop.
        if (releaseTimeout is not null)
            throw new InvalidOperationException("Native output remained owned while OutputReady waited for MAIN after peer Stop.", releaseTimeout);
        await f.Main.Lan.Barrier();
    }
    private static async Task Complete()
    {
        await using var f = await Fixture.Create(); f.Main.Native.AllowRetirement = true; f.Bytes = Wave(Pcm(25001));
        await f.Offer(); await f.Transfer(); await f.Ready(); await f.CompletePlayback();
    }
    private static async Task RenewedFile()
    {
        await using var f = await Fixture.Create(enableRenewal: true);
        var delays = AudioCaptureReceiveSessionTests.ConfigureRenewal(f.Main);
        f.Main.Native.AllowRetirement = true; f.Bytes = Wave(Pcm(25001));
        await f.Offer(); var initial = f.Main.Receiver.RenewalSnapshot?.Evidence ?? throw new Exception("Missing file renewal owner.");
        (await delays.Next()).Release.TrySetResult();
        await AudioMembershipRenewalTests.Until(() => f.Main.Receiver.RenewalSnapshot is { State: AudioMembershipRenewalState.Waiting } state && state.Evidence.Id != initial.Id);
        await f.Transfer(); await f.Ready(); await f.CompletePlayback();
    }
    private static async Task Tail()
    {
        await using var f = await Fixture.Create(); f.Main.Native.AllowRetirement = true; f.Main.Native.BlockDispose = true;
        await f.Offer(); await f.Transfer(); await f.Ready();
        await f.Main.Native.DisposeEntered.Task.WaitAsync(f.Main.Lan.Token);
        Require(!f.Main.Run!.IsCompleted && !f.Main.Receiver.FileReleaseConfirmed && Directory.GetFiles(f.Root).Length == 1,
            "Transfer receipt or native disposal entry incorrectly completed playback.");
        var completion = f.Main.Read(); await Task.Delay(25, f.Main.Lan.Token);
        Require(!completion.IsCompleted, "PlaybackComplete preceded actual native release.");
        f.Main.Native.DisposeRelease.Set();
        Require((await completion).Body is AudioStreamingBody.PlaybackComplete, "No final playback receipt after native release.");
        await f.Main.Run; f.Released(); f.Main.NativeReleased();
    }
    private static async Task WrongMetadata()
    {
        await using var f = await Fixture.Create(); f.Main.Native.AllowRetirement = true; await f.Offer();
        using (var wrong = await f.Begin(ClassicFileTransferWire.Authenticate(f.Metadata with { FileHash = new string('a', 64) }, f.Key)))
            await Until(() => f.ReceiveFailures.Count == 1, f.Main.Lan.Token);
        Require(Directory.GetFiles(f.Root).Length == 0 && !f.Main.Run!.IsCompleted, "Invalid metadata consumed the approved slot.");
        await f.Transfer(); await f.Ready(); await f.CompletePlayback();
    }
    private static async Task Unsolicited()
    {
        await using var f = await Fixture.Create(); using var client = await f.Begin();
        await Until(() => f.ReceiveFailures.Count == 1, f.Main.Lan.Token);
        Require(Directory.GetFiles(f.Root).Length == 0 && f.Main.Device.Activations == 0, "Unsolicited transfer reached storage or output.");
        await f.Main.Lan.Barrier();
    }
    private static async Task Declined()
    {
        await using var f = await Fixture.Create(); f.Main.Decide = (_, _) => Task.FromResult(false); await f.Offer(false);
        var failure = await f.Main.Failure(); Require(failure.Reason == AudioStreamingStopReason.ReceiverDeclined, "Decline reason changed.");
        Require((await f.Main.UntilStop()).Count == 1 && f.Main.Device.Activations == 0, "Decline accepted a file or opened native output."); f.Released();
    }
    private static async Task CaptureControl()
    {
        await using var f = await Fixture.Create(); await f.Offer();
        await f.Main.Data(0, new byte[8]); var failure = await f.Main.Failure();
        Require(failure.Reason == AudioStreamingStopReason.ProtocolViolation && f.Main.Device.Activations == 0, "Capture input entered file mode.");
        await f.Main.UntilStop(); f.Released(); await f.Main.Lan.Barrier();
    }
    private static async Task CancelPartial() => await StopPartial(false);
    private static async Task RevokePartial() => await StopPartial(true);
    private static async Task StopPartial(bool revoke)
    {
        await using var f = await Fixture.Create(); await f.Offer(); using var client = await f.Begin();
        await Until(() => Directory.GetFiles(f.Root).Length == 1, f.Main.Lan.Token);
        if (revoke) f.Main.Epoch.Revoke(); else f.Main.Caller.Cancel();
        var failure = await f.Main.Failure();
        Require(failure.Reason == (revoke ? AudioStreamingStopReason.AccountRevoked : AudioStreamingStopReason.UserStopped), "Partial transfer lost stop cause.");
        f.Released(); Require(failure.FileReleaseConfirmed && failure.NativeReleaseConfirmed && f.Main.Device.Activations == 0,
            "Partial cancellation lost resource ownership."); await f.Main.UntilStop(); await f.Main.Lan.Barrier();
    }
    private static async Task Corrupt()
    {
        await using var f = await Fixture.Create(); await f.Offer();
        using var client = await f.Begin(); var changed = f.Bytes.ToArray(); changed[^1] ^= 1;
        await ClassicFileTransferFrames.WriteAsync(client.GetStream(), ClassicFileFrameType.Chunk,
            ClassicFileTransferWire.Encode(ClassicFileTransferWire.SealChunk(0, changed, f.Key)), f.Main.Lan.Token);
        await ClassicFileTransferFrames.WriteAsync(client.GetStream(), ClassicFileFrameType.Complete, ReadOnlyMemory<byte>.Empty, f.Main.Lan.Token);
        await f.Main.Failure(); Require((await f.Main.UntilStop()).Count == 1 && f.Main.Device.Activations == 0, "Bad content reached output readiness."); f.Released();
    }
    private static async Task Unsupported()
    {
        await using var f = await Fixture.Create(); f.Bytes = "not a WAVE original"u8.ToArray(); await f.Offer(); await f.Transfer();
        var failure = await f.Main.Failure(); Require(failure.Reason == AudioStreamingStopReason.UnsupportedSource && f.Main.Device.Activations == 0,
            "Unsupported container changed mode or opened output."); await f.Main.UntilStop(); f.Released();
    }
    private static async Task NonFinite()
    {
        await using var f = await Fixture.Create(); BinaryPrimitives.WriteUInt32LittleEndian(f.Bytes.AsSpan(68), 0x7f800000);
        await f.Offer(); await f.Transfer(); await f.Ready(); var failure = await f.Main.Failure();
        Require(failure.Reason == AudioStreamingStopReason.UnsupportedSource && f.Main.Native.Submissions.Count == 0,
            "Non-finite file samples reached output."); await f.Main.UntilStop(); f.Released(); f.Main.NativeReleased();
    }
    private static async Task CleanupFailure()
    {
        await using var f = await Fixture.Create(); f.Main.Native.AllowRetirement = true;
        f.Main.Native.DisposeFailure = new IOException("controlled native close failure");
        await f.Offer(); await f.Transfer(); await f.Ready(); var failure = await f.Main.Failure();
        Require(!failure.NativeReleaseConfirmed && failure.FileReleaseConfirmed && !f.Main.Receiver.ResourcesReleaseConfirmed,
            "Failed native close was treated as released.");
        Require((await f.Main.UntilStop()).Count == 1, "Native close failure emitted playback completion."); f.Released();
    }
    private static async Task Capability()
    {
        await using var f = await Fixture.Create();
        Require(f.Registry.CanReceiveFor(f.Main.Lan.Session), "Bound live exact file endpoint was unavailable.");
        using var offerScope = new CancellationTokenSource();
        var accepting = f.Main.Lan.Session.AcceptAudioOfferAsync(offerScope.Token);
        await f.Main.Lan.Session.SetAudioReceiverCapabilitiesAsync(true, true, f.Main.Lan.Token);
        var identity = LanProductControlMessages.Payload<LanProductIdentity>(await f.Main.Lan.Read());
        Require(identity.FileTransferPort == f.Endpoint.Port && identity.Capabilities is { } c &&
            c.Contains("audio_file_receive_v1") && c.Contains("audio_capture_receive_v1") &&
            !c.Contains("file_transfer") && !c.Contains("classic_approval_v1"), "File endpoint overstated its protocol capabilities.");
        f.Registry.Unbind(f.Listener); Require(!f.Registry.CanReceiveFor(f.Main.Lan.Session), "Unbound endpoint stayed eligible.");
        await f.Main.Lan.Session.SetAudioReceiverCapabilitiesAsync(false, false, f.Main.Lan.Token);
        var disabled = LanProductControlMessages.Payload<LanProductIdentity>(await f.Main.Lan.Read());
        Require(disabled.Capabilities?.Any(c => c is "audio_file_receive_v1" or "audio_capture_receive_v1") != true,
            "Disabled consumer remained advertised.");
        offerScope.Cancel(); await Throws<OperationCanceledException>(() => accepting);
    }
    private static async Task MissingPort()
    {
        await using var lan = await LanProductControlSessionTests.Fixture.ConnectForAudio(localFilePort: null, generalFiles: false); await lan.Admit();
        await Throws<InvalidOperationException>(() => lan.Session.SetAudioReceiverCapabilitiesAsync(false, true, lan.Token));
        await lan.Barrier();
    }
    private static async Task CancelClosedTicket()
    {
        await using var f = await Fixture.Create();
        var (inbox, permission, admission) = await Admission(f);
        using (inbox)
        {
            var ticket = f.Registry.Register(admission); await ticket.CloseAsync();
            ticket.Cancel(); // Same ticket reference retained by Unbind before Close won.
            Require(ticket.ReleaseConfirmed, "A closed no-producer ticket retained resources.");
            var next = f.Registry.Register(admission); await next.CloseAsync(); permission.Revoke();
        }
    }
    private static async Task ForeignOwner()
    {
        await using var f = await Fixture.Create(); await using var other = await AudioCaptureReceiveSessionTests.Fixture.Create();
        var (inbox, permission, admission) = await Admission(f);
        using (inbox)
        {
            var ticket = f.Registry.Register(admission);
            await Throws<InvalidOperationException>(() => { _ = f.Registry.Register(admission); return Task.CompletedTask; });
            using var wire = new MemoryStream();
            await Throws<InvalidDataException>(() => ticket.ReceiveAsync(other.Lan.Session, wire, f.Metadata, IPAddress.Loopback, f.Main.Lan.Token));
            Require(!ticket.HasStarted && !admission.HasClaimedTransfer, "Foreign MAIN consumed a producer slot.");
            await ticket.CloseAsync(); permission.Revoke();
        }
    }
    private static async Task HostReception()
    {
        await using var f = await Fixture.Create(); f.Main.Native.AllowRetirement = true;
        await using var host = new AudioReceiveHost((session, endpoint) =>
        {
            Require(ReferenceEquals(session, f.Main.Lan.Session) && endpoint == AudioCaptureReceiveSessionTests.Endpoint,
                "Host changed the actual session/output owner.");
            return f.Main.Receiver;
        }, f.Registry);
        await host.AttachAsync(f.Main.Lan.Session, f.Main.Lan.Token);
        await host.EnableAsync(AudioCaptureReceiveSessionTests.Endpoint, f.Main.Lan.Token);
        var identity = LanProductControlMessages.Payload<LanProductIdentity>(await f.Main.Lan.Read());
        Require(identity.Capabilities?.Contains("audio_file_receive_v1") == true && identity.FileTransferPort == f.Endpoint.Port,
            "Installed host did not publish its actual file endpoint.");
        await f.Main.Lan.SendAudio(new(f.Main.StreamId, new AudioStreamingBody.FileOffer(f.TransferId, f.Bytes.Length, SHA256.HashData(f.Bytes))));
        Require((await f.Main.Read()).Body is AudioStreamingBody.Accept { ReceiveWindowBytes: 0 }, "Host did not accept file mode.");
        await f.Transfer(); await f.Ready();
        Require((await f.Main.Read()).Body is AudioStreamingBody.PlaybackComplete { SourceFrames: 17, TrailingPaddingFrames: 0 },
            "Host changed file completion.");
        await Until(() => host.ReadSnapshot() is { Phase: null, ListeningDevices: 1 }, f.Main.Lan.Token);
        f.Released(); f.Main.NativeReleased();
        await host.DisableAsync();
        var disabled = LanProductControlMessages.Payload<LanProductIdentity>(await f.Main.Lan.Read());
        Require(disabled.Capabilities?.Contains("audio_file_receive_v1") != true && host.ReadSnapshot().NativeReleaseConfirmed,
            "Stopped host retained its file advertisement or resources.");
        await f.Main.Lan.Barrier();
    }
    private static async Task ListenerStop()
    {
        await using var f = await Fixture.Create(); await f.Offer(); using var client = await f.Begin();
        await Until(() => Directory.GetFiles(f.Root).Length == 1, f.Main.Lan.Token);
        f.Registry.Unbind(f.Listener); var stopping = f.Listener.StopAsync();
        var failure = await f.Main.Failure(); await stopping;
        Require(failure.FileReleaseConfirmed && failure.NativeReleaseConfirmed && f.Listener.ReadSnapshot().ActiveConnections == 0,
            "Listener stop abandoned a producer or its artifact.");
        f.Released(); await f.Main.UntilStop(); await f.Main.Lan.Barrier();
    }
    private static async Task<(ILanAudioStreamInbox, AudioPlaybackPermission, AudioOriginalFileAdmission)> Admission(Fixture f)
    {
        var accepting = f.Main.Lan.Session.AcceptAudioOfferAsync(f.Main.Lan.Token);
        await f.Main.Lan.SendAudio(new(f.Main.StreamId, new AudioStreamingBody.FileOffer(f.TransferId, f.Bytes.Length, SHA256.HashData(f.Bytes))));
        var inbox = await accepting; _ = await inbox.ReadAsync(f.Main.Lan.Token);
        var permission = await f.Main.Approvals.RequestAsync(inbox, f.Main.Lease(inbox), AudioCaptureReceiveSessionTests.Endpoint, f.Main.Caller.Token);
        return (inbox, permission, new(f.Main.Lan.Session, inbox, permission, AudioCaptureReceiveSessionTests.Endpoint));
    }
    internal static byte[] Pcm(int frames)
    {
        var bytes = new byte[frames * 8];
        for (int offset = 0; offset < bytes.Length; offset += 4)
            BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(offset), BitConverter.SingleToInt32Bits((offset / 4 % 23 - 11) / 16f));
        return bytes;
    }
    internal static byte[] Wave(byte[] pcm)
    {
        var bytes = new byte[68 + pcm.Length]; "RIFF"u8.CopyTo(bytes);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(4), (uint)bytes.Length - 8);
        "WAVEfmt "u8.CopyTo(bytes.AsSpan(8)); BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(16), 40);
        Format.RequireExactOutputFormat().ToWaveFormatExtensible().CopyTo(bytes, 20);
        "data"u8.CopyTo(bytes.AsSpan(60)); BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(64), (uint)pcm.Length);
        pcm.CopyTo(bytes, 68); return bytes;
    }
    private static async Task Until(Func<bool> condition, CancellationToken token)
    { while (!condition()) await Task.Delay(1, token); }
    private static async Task<T> Throws<T>(Func<Task> action) where T : Exception
    { try { await action(); } catch (T e) { return e; } throw new InvalidOperationException($"Expected {typeof(T).Name}."); }
    private static void Require(bool value, string message) { if (!value) throw new InvalidOperationException(message); }
}
