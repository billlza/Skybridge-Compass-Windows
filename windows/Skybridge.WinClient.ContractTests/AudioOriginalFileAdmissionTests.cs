using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.Audio;
using Skybridge.WinClient.Services.FileTransfer;

internal static class AudioOriginalFileAdmissionTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("original audio receives exact private file bytes and a distinct signed transfer receipt", PrivateRoundTrip),
        ("verified original audio is inspected through the same live descriptor without changing PCM", VerifiedWave),
        ("original audio binds real MAIN and classic TCP bytes to one approved artifact", TcpRoundTrip),
        ("original audio rejects wrong transfer length hash peer and address before consuming its grant", MetadataBinding),
        ("original audio rejects an invalid metadata MAC before private storage", MetadataMac),
        ("original audio permission cannot borrow another MAIN inbox or output", PermissionBinding),
        ("original audio continuation retains admitted bytes but cannot create another transfer from old consent", ContinuationAdmission),
        ("original audio rechecks revoked approval after a network read before disk effect", RevokedAfterRead),
        ("original audio rejects corrupt authenticated content and consumes only its failed attempt", BadContent),
        ("original audio receipt failure releases private storage and never returns playback input", ReceiptFailure),
        ("original audio total deadline cancels a pending real socket receive and removes its file", ReceiveDeadline),
        ("private audio reads require current permission and stay within the verified artifact", ReadBoundary),
        ("shared classic receive owns pending writes through cancellation and clears plaintext", PendingSink)
    ];
    internal static int WindowsExclusiveChecks { get; private set; }
    private static readonly byte[] Bytes = Enumerable.Range(0, 65_539).Select(i => (byte)(i * 73)).ToArray();
    private static void Require(bool value, string message) { if (!value) throw new InvalidOperationException(message); }
    private static async Task<T> Throws<T>(Func<Task> action) where T : Exception
    { try { await action(); } catch (T error) { return error; } throw new InvalidOperationException($"Expected {typeof(T).Name}."); }

    private sealed class Fixture : IAsyncDisposable
    {
        internal AudioCaptureReceiveSessionTests.Fixture Main { get; }
        internal ILanAudioStreamInbox Inbox { get; }
        internal AudioPlaybackPermission Permission { get; }
        internal AccountAudioMembershipLease Membership { get; }
        internal AudioOriginalFileAdmission Admission { get; }
        internal ClassicFileMetadata Metadata { get; }
        internal byte[] Key { get; }
        internal byte[] SourceBytes { get; }
        internal string Root { get; } = Path.Combine(AppContext.BaseDirectory, "original-audio-test-" + Guid.NewGuid().ToString("N"));
        internal string Marker => Path.Combine(Root, "existing.txt");
        private Fixture(AudioCaptureReceiveSessionTests.Fixture main, ILanAudioStreamInbox inbox,
            AudioPlaybackPermission permission, AccountAudioMembershipLease membership, Guid transfer, TimeSpan? timeout, byte[] bytes)
        {
            Main = main; Inbox = inbox; Permission = permission; Membership = membership;
            SourceBytes = bytes;
            Key = ClassicFileTransferWire.DeriveTransferKey(main.Lan.Keys, transfer.ToString("D"));
            Metadata = ClassicFileTransferWire.Authenticate(new ClassicFileMetadata(transfer.ToString("D"), "source.wav", bytes.Length,
                Convert.ToHexStringLower(SHA256.HashData(bytes)), 65536, 2, SenderDeviceId: main.Lan.Session.PeerDeviceId), Key);
            Admission = new(main.Lan.Session, inbox, permission, AudioCaptureReceiveSessionTests.Endpoint, timeout);
            Directory.CreateDirectory(Root); File.WriteAllText(Marker, "preserve");
        }
        internal static async Task<Fixture> Create(TimeSpan? timeout = null, byte[]? bytes = null)
        {
            bytes ??= Bytes;
            var main = await AudioCaptureReceiveSessionTests.Fixture.Create();
            ILanAudioStreamInbox? inbox = null;
            try
            {
                var transfer = Guid.NewGuid();
                var accepting = main.Lan.Session.AcceptAudioOfferAsync(main.Lan.Token);
                await main.Lan.SendAudio(new(main.StreamId, new AudioStreamingBody.FileOffer(transfer, bytes.Length, SHA256.HashData(bytes))));
                inbox = await accepting;
                Require((await inbox.ReadAsync(main.Lan.Token)).Body is AudioStreamingBody.FileOffer, "File offer did not reach the actual MAIN reader.");
                var membership = main.Lease(inbox);
                var permission = await main.Approvals.RequestAsync(inbox, membership, AudioCaptureReceiveSessionTests.Endpoint, main.Caller.Token);
                return new(main, inbox, permission, membership, transfer, timeout, bytes);
            }
            catch { inbox?.Dispose(); await main.DisposeAsync(); throw; }
        }
        internal async Task<Wire> Body(byte[]? bytes = null)
        {
            bytes ??= SourceBytes; var body = new Wire(); int index = 0;
            for (int offset = 0; offset < bytes.Length; offset += 65536)
                await ClassicFileTransferFrames.WriteAsync(body, ClassicFileFrameType.Chunk,
                    ClassicFileTransferWire.Encode(ClassicFileTransferWire.SealChunk(index++, bytes.AsSpan(offset, Math.Min(65536, bytes.Length - offset)), Key)), Main.Lan.Token);
            await ClassicFileTransferFrames.WriteAsync(body, ClassicFileFrameType.Complete, ReadOnlyMemory<byte>.Empty, Main.Lan.Token);
            body.InputLength = body.Length; body.Position = 0; return body;
        }
        internal Task<AudioOriginalFileArtifact> Receive(Stream wire, ClassicFileMetadata? metadata = null, IPAddress? address = null) =>
            Admission.ReceiveAsync(wire, metadata ?? Metadata, address ?? IPAddress.Loopback, Root, Main.Lan.Token);
        internal void RequirePrivateReleased()
        {
            Require(Directory.GetFiles(Root).SequenceEqual([Marker]) && File.ReadAllText(Marker) == "preserve", "Private cleanup leaked bytes or touched an existing file.");
            Require(Main.Lan.Session.IsReady && Main.Device.Activations == 0, "File receipt changed MAIN or opened audio output.");
        }
        public async ValueTask DisposeAsync()
        {
            Permission.Revoke(); Inbox.Dispose(); await Main.DisposeAsync();
            CryptographicOperations.ZeroMemory(Key); Directory.Delete(Root, true);
        }
    }
    private sealed class Wire : MemoryStream
    {
        internal long InputLength;
        internal Action? AfterRead, BeforeWrite;
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default)
        { var count = await base.ReadAsync(buffer, token); AfterRead?.Invoke(); return count; }
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken token = default)
        { BeforeWrite?.Invoke(); return base.WriteAsync(buffer, token); }
    }
    private static async Task PrivateRoundTrip()
    {
        await using var f = await Fixture.Create(); using var wire = await f.Body();
        var artifact = await f.Receive(wire);
        try
        {
            Require(artifact.Length == Bytes.Length && artifact.Sha256Hex == f.Metadata.FileHash, "Artifact lost its exact commitment.");
            var actual = (await artifact.ReadAsync(0, 65536, default)).Concat(await artifact.ReadAsync(65536, 3, default)).ToArray();
            Require(actual.SequenceEqual(Bytes), "Stored source bytes changed.");
            wire.Position = wire.InputLength;
            var frame = await ClassicFileTransferFrames.ReadAsync(wire, default);
            Require(frame.Type == ClassicFileFrameType.Receipt, "File transfer produced a different completion type.");
            var receipt = ClassicFileTransferWire.Decode<ClassicFileReceipt>(frame.Payload);
            ClassicFileTransferWire.Verify(receipt, f.Metadata, f.Key);
            Require(receipt.Success && receipt.ReceivedBytes == Bytes.Length, "Transfer receipt did not cover the verified file.");
            if (OperatingSystem.IsWindows())
            {
                var path = Directory.GetFiles(f.Root).Single(p => p != f.Marker);
                await Throws<IOException>(() => { using var other = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete); return Task.CompletedTask; });
                await Throws<IOException>(() => { File.Move(path, path + ".moved"); return Task.CompletedTask; });
                WindowsExclusiveChecks += 2;
            }
            using var duplicate = await f.Body();
            await Throws<InvalidOperationException>(() => f.Receive(duplicate));
        }
        finally { await artifact.DisposeAsync(); }
        Require(artifact.IsReleased, "File release was not confirmed."); f.RequirePrivateReleased();
    }
    private static async Task ContinuationAdmission()
    {
        await using var f = await Fixture.Create(); using var wire = await f.Body();
        var initial = f.Membership.Evidence;
        f.Main.Clock.Advance(TimeSpan.FromSeconds(1));
        var fresh = f.Main.Lease(f.Inbox).Evidence;
        f.Membership.ContinueWith(initial, fresh, default);
        f.Admission.RequireCurrent();
        await Throws<InvalidDataException>(() => Task.FromResult(new AudioOriginalFileAdmission(
            f.Main.Lan.Session, f.Inbox, f.Permission, AudioCaptureReceiveSessionTests.Endpoint)));
        await using var artifact = await f.Receive(wire);
        Require(artifact.Length == Bytes.Length && artifact.Sha256Hex == f.Metadata.FileHash,
            "Renewal changed or prevented the already admitted original-file transfer.");
        Require(f.Permission.Request.MembershipId == initial.Id && f.Membership.Evidence.Id == fresh.Id,
            "Continuation rewrote the approval's initial grant identity.");
    }
    private static async Task VerifiedWave()
    {
        using var source = new MemoryStream();
        using (var writer = new BinaryWriter(source, System.Text.Encoding.ASCII, leaveOpen: true))
        {
            writer.Write("RIFF"u8); writer.Write(44U); writer.Write("WAVEfmt "u8); writer.Write(16U);
            writer.Write((ushort)1); writer.Write((ushort)2); writer.Write(44100U); writer.Write(176400U);
            writer.Write((ushort)4); writer.Write((ushort)16); writer.Write("data"u8); writer.Write(8U);
            writer.Write(short.MinValue); writer.Write(short.MaxValue); writer.Write((short)-1); writer.Write((short)1);
        }
        var bytes = source.ToArray();
        await using var f = await Fixture.Create(bytes: bytes); using var wire = await f.Body();
        var artifact = await f.Receive(wire);
        try
        {
            var wave = await artifact.InspectWaveAsync(default);
            Require(wave.Format.SampleRate == 44100 && wave.Format.Encoding == AudioStreamingEncoding.Signed16 &&
                wave.Format.ValidBits == 16 && wave.Format.Channels == 2 && wave.Format.WaveChannelMask is null &&
                wave.PcmByteOffset == 44 && wave.PcmByteCount == 8 && wave.FrameCount == 2, "Verified WAVE declarations were changed or inferred.");
            Require((await artifact.ReadAsync(wave.PcmByteOffset, (int)wave.PcmByteCount, default)).SequenceEqual(bytes.AsSpan(44).ToArray()),
                "WAVE inspection changed stored samples.");
        }
        finally { await artifact.DisposeAsync(); }
        f.RequirePrivateReleased();
    }
    private static async Task TcpRoundTrip()
    {
        await using var f = await Fixture.Create(); using var body = await f.Body();
        using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
        using var sender = new TcpClient(); await sender.ConnectAsync((IPEndPoint)listener.LocalEndpoint);
        using var receiver = await listener.AcceptTcpClientAsync();
        var receiving = f.Receive(receiver.GetStream());
        await sender.GetStream().WriteAsync(body.ToArray(), f.Main.Lan.Token);
        var artifact = await receiving;
        try
        {
            var frame = await ClassicFileTransferFrames.ReadAsync(sender.GetStream(), f.Main.Lan.Token);
            Require(frame.Type == ClassicFileFrameType.Receipt, "Classic TCP did not return a file receipt.");
            var receipt = ClassicFileTransferWire.Decode<ClassicFileReceipt>(frame.Payload);
            ClassicFileTransferWire.Verify(receipt, f.Metadata, f.Key);
            Require(receipt.Success && artifact.Length == Bytes.Length &&
                (await artifact.ReadAsync(65530, 9, default)).SequenceEqual(Bytes.AsSpan(65530, 9).ToArray()),
                "Real TCP changed file extent or its final bytes.");
        }
        finally { await artifact.DisposeAsync(); }
        f.RequirePrivateReleased();
    }
    private static async Task MetadataBinding()
    {
        await using var f = await Fixture.Create();
        foreach (var wrong in new[] {
            f.Metadata with { TransferId = Guid.NewGuid().ToString("D") }, f.Metadata with { FileSize = Bytes.Length + 1 },
            f.Metadata with { FileHash = new string('a', 64) }, f.Metadata with { SenderDeviceId = "id:other-peer" } })
        {
            var key = ClassicFileTransferWire.DeriveTransferKey(f.Main.Lan.Keys, wrong.TransferId);
            using var wire = await f.Body();
            await Throws<InvalidDataException>(() => f.Receive(wire, ClassicFileTransferWire.Authenticate(wrong, key)));
            CryptographicOperations.ZeroMemory(key);
            Require(!f.Admission.HasClaimedTransfer && wire.Position == 0, "Mismatched metadata consumed approval or read file bytes."); f.RequirePrivateReleased();
        }
        using var route = await f.Body();
        await Throws<InvalidDataException>(() => f.Receive(route, address: IPAddress.Parse("192.0.2.1")));
        Require(!f.Admission.HasClaimedTransfer, "A foreign address consumed approval.");
        using var valid = await f.Body(); await using var artifact = await f.Receive(valid);
    }
    private static async Task MetadataMac()
    {
        await using var f = await Fixture.Create(); using var wire = await f.Body();
        await Throws<CryptographicException>(() => f.Receive(wire, f.Metadata with { MetadataAuthTag = new byte[32] }));
        Require(!f.Admission.HasClaimedTransfer && wire.Position == 0, "Invalid MAC consumed approval or read file bytes."); f.RequirePrivateReleased();
    }
    private static async Task PermissionBinding()
    {
        await using var f = await Fixture.Create(); await using var other = await Fixture.Create();
        await Throws<InvalidDataException>(() => { _ = new AudioOriginalFileAdmission(f.Main.Lan.Session, other.Inbox, f.Permission, AudioCaptureReceiveSessionTests.Endpoint); return Task.CompletedTask; });
        await Throws<InvalidDataException>(() => { _ = new AudioOriginalFileAdmission(f.Main.Lan.Session, f.Inbox, f.Permission, "other-output"); return Task.CompletedTask; });
        f.Permission.Revoke();
        using var wire = await f.Body(); await Throws<AudioPlaybackApprovalException>(() => f.Receive(wire));
        Require(!f.Admission.HasClaimedTransfer, "Revoked approval consumed file admission."); f.RequirePrivateReleased();
    }
    private static async Task RevokedAfterRead()
    {
        await using var f = await Fixture.Create(); using var wire = await f.Body();
        wire.AfterRead = f.Permission.Revoke;
        await Throws<AudioPlaybackApprovalException>(() => f.Receive(wire));
        Require(f.Admission.HasClaimedTransfer && wire.Length == wire.InputLength, "Revocation sent a success receipt."); f.RequirePrivateReleased();
    }
    private static async Task BadContent()
    {
        await using var f = await Fixture.Create(); var changed = Bytes.ToArray(); changed[42] ^= 1;
        using var wire = await f.Body(changed);
        await Throws<InvalidDataException>(() => f.Receive(wire));
        Require(f.Admission.HasClaimedTransfer && wire.Length == wire.InputLength, "Bad digest was acknowledged or reopened."); f.RequirePrivateReleased();
        using var retry = await f.Body(); await Throws<InvalidOperationException>(() => f.Receive(retry));
    }
    private static async Task ReceiptFailure()
    {
        await using var f = await Fixture.Create(); using var wire = await f.Body(); var expected = new IOException("receipt writer failed");
        wire.BeforeWrite = () => throw expected;
        Require(ReferenceEquals(await Throws<IOException>(() => f.Receive(wire)), expected), "Receipt failure was masked."); f.RequirePrivateReleased();
    }
    private static async Task ReceiveDeadline()
    {
        await using var f = await Fixture.Create(TimeSpan.FromMilliseconds(100));
        using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
        using var sender = new TcpClient(); await sender.ConnectAsync((IPEndPoint)listener.LocalEndpoint);
        using var receiver = await listener.AcceptTcpClientAsync();
        await Throws<TimeoutException>(() => f.Receive(receiver.GetStream()).WaitAsync(TimeSpan.FromSeconds(3)));
        Require(f.Admission.HasClaimedTransfer, "The real pending receive did not claim its exact grant."); f.RequirePrivateReleased();
    }
    private static async Task ReadBoundary()
    {
        await using var f = await Fixture.Create(); using var wire = await f.Body(); var artifact = await f.Receive(wire);
        try
        {
            foreach (var (offset, count) in new (long, int)[] { (-1, 1), (0, 65537), (Bytes.Length, 1), (long.MaxValue, 1), (0, 0) })
                await Throws<InvalidDataException>(() => artifact.ReadAsync(offset, count, default));
            f.Permission.Revoke(); await Throws<AudioPlaybackApprovalException>(() => artifact.ReadAsync(0, 1, default));
        }
        finally { await artifact.DisposeAsync(); }
        await Throws<ObjectDisposedException>(() => artifact.ReadAsync(0, 1, default)); f.RequirePrivateReleased();
    }
    private static async Task PendingSink()
    {
        await using var f = await Fixture.Create(); using var wire = await f.Body(); using var stop = new CancellationTokenSource();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        ReadOnlyMemory<byte> held = default;
        var receiving = ClassicFileTransferReceiver.ReceiveContentAsync(wire, f.Metadata, f.Key,
            async (bytes, _) => { held = bytes; entered.SetResult(); await release.Task; }, () => { }, stop.Token);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(2)); stop.Cancel();
        Require(!receiving.IsCompleted && held.Span.ContainsAnyExcept((byte)0), "Cancellation detached an actual pending write.");
        release.SetResult(); await Throws<OperationCanceledException>(() => receiving);
        Require(!held.Span.ContainsAnyExcept((byte)0), "Failed write retained plaintext bytes."); f.RequirePrivateReleased();
    }
}
