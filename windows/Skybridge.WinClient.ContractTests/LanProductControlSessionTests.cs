using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.FileTransfer;
using Skybridge.WinClient.Services.Audio;

internal static class LanProductControlSessionTests
{
    internal static IReadOnlyList<(string Name, Func<Task> Run)> Cases { get; } =
    [
        ("LAN AppMessage retains Apple dates and rejects ambiguous or mismatched identities", MessageContract),
        ("LAN local publication must match the exact handshake signer", LocalIdentityBinding),
        ("LAN encrypted admission gates exact file routes and retires with its connection", Admission),
        ..ConnectedFileCases,
        ("LAN audio binds role-aware exact device IDs and actual signers after admission", AudioIdentityBinding),
        ("LAN audio preserves Android and Apple account device ID spelling", AccountDeviceIdSpelling),
        ("LAN changed account ID spelling retires audio without reviving its grant", AccountDeviceIdChange),
        ("LAN audio rejects absent malformed duplicate and mismatched SOA without breaking MAIN", RejectAudioBinding),
        ("LAN audio identity evidence cannot be reacquired after cancellation or disposal", AudioOwnerLifetime),
        ("encrypted MAIN demultiplexes audio in order and keeps control traffic live", AudioDemultiplex),
        ("encrypted MAIN rejects unavailable audio without admitting or closing it", AudioUnavailable),
        ("encrypted MAIN retires overflowing audio and keeps its control reader", AudioOverflow),
        ("recognized malformed audio closes its exact encrypted MAIN owner", MalformedAudio),
        ("audio receiver replies require effect checks while Stop retains exact owner binding", AudioReplies),
        ("queued audio reply rechecks revoked permission before any wire bytes", QueuedAudioPermission),
        ("queued audio reply cannot outlive its stream or affect a replacement", QueuedAudioReplacement),
        ("queued audio reply owns its encoded metadata and cancellation releases its send slot", QueuedAudioSnapshot),
        ("audio replies reject foreign owners and wrong stream IDs before authorization", ForeignAudioReply),
        ("LAN encrypted admission rejects a different peer protocol identity", WrongIdentity)
    ];
    internal static IReadOnlyList<(string Name, Func<Task> Run)> ConnectedFileCases =>
    [
        ("connected LAN file recipient sends multi-chunk bytes with a verified receipt for either MAIN role", ConnectedFile),
        ("connected LAN file recipient retires a changed route and rejects same-peer replacement", ChangedFileRoute)
    ];
    private const string PeerId = "id:1a2b3c4d-22aa-33bb-44cc-5555deadbeef";
    private const string LocalId = "id:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    private static readonly byte[] LocalPublicKey = Enumerable.Repeat((byte)41, 1952).ToArray();
    private static readonly byte[] PublicKey = Enumerable.Repeat((byte)23, 1952).ToArray();
    private static readonly string Fingerprint = new WebRtcProductProtocolIdentityPublicKey(
        WebRtcProductSignatureAlgorithm.MlDsa65, PublicKey).AuthoritativeFingerprint;
    private static readonly ProductHandshakePeerContext Peer = new(PeerId, Fingerprint);
    private static LanProductIdentity Identity() => new(PeerId, [new(0x0101, new byte[1184])], 100,
        [new("ML-DSA-65", PublicKey)], Capabilities: ["file_transfer"], FileTransferPort: 8080);
    private static byte[] Soa(ProductHandshakeRole role) => new RemoteControlHandshakeSoa(
        RemoteControlHandshakeBinding.PeerId(role == ProductHandshakeRole.Initiator ? LocalId : PeerId),
        RemoteControlHandshakeBinding.PeerId(role == ProductHandshakeRole.Initiator ? PeerId : LocalId),
        Enumerable.Range(0, 16).Select(value => (byte)value).ToArray()).EncodeTlv();
    private static void Require(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); }
    private static void Throws<T>(Action action) where T : Exception
    {
        try { action(); } catch (T) { return; }
        throw new InvalidOperationException($"Expected {typeof(T).Name}.");
    }

    private static Task MessageContract()
    {
        Require(LanProductControlMessages.Timestamp(new DateTimeOffset(2001, 1, 1, 0, 0, 0, TimeSpan.Zero)) == 0,
            "AppMessage dates must use the Swift reference date.");
        var encoded = LanProductControlMessages.Encode(LanControlMessageKind.Identity, Identity());
        LanProductControlMessages.ValidateIdentity(LanProductControlMessages.Payload<LanProductIdentity>(
            LanProductControlMessages.Decode(encoded)), Peer);
        Throws<InvalidDataException>(() => LanProductControlMessages.Decode("{\"ping\":{\"id\":1},\"pong\":{\"id\":1}}"u8));
        Throws<JsonException>(() => LanProductControlMessages.Payload<LanProductPing>(
            LanProductControlMessages.Decode("{\"ping\":{\"id\":1,\"id\":2}}"u8)));
        Throws<InvalidDataException>(() => LanProductControlMessages.ValidateIdentity(Identity() with { DeviceId = "id:different-device" }, Peer));
        Throws<InvalidDataException>(() => LanProductControlMessages.ValidateIdentity(Identity() with { KemPublicKeys = [null!] }, Peer));
        foreach (var malformed in new[] { "SBP2"u8.ToArray(), new byte[] { 83, 66, 80, 50, 0, 0, 0, 1 } })
            Throws<InvalidDataException>(() => ProductControlTrafficPadding.Unwrap(malformed));
        Require(ProductControlTrafficPadding.Unwrap(ProductControlTrafficPadding.Wrap(encoded)).SequenceEqual(encoded),
            "SBP2 changed the authenticated payload.");
        return Task.CompletedTask;
    }

    private static async Task Admission()
    {
        await using var fixture = await Fixture.Connect();
        Require(!fixture.Session.IsReady, "TCP and keys alone must not admit file transfer.");
        Throws<InvalidOperationException>(() => fixture.Session.AuthorizeFileTransfer(fixture.Candidate, "transfer"));
        var admission = fixture.Session.CompleteAdmissionAsync(fixture.Token);
        Require((await fixture.Read()).Kind == LanControlMessageKind.Identity, "Local identity did not precede the admission ping.");
        var ping = LanProductControlMessages.Payload<LanProductPing>(await fixture.Read());
        await fixture.Send(LanControlMessageKind.Identity, Identity());
        Require(!fixture.Session.IsReady, "Identity alone admitted a transfer before peer approval committed.");
        await fixture.Send(LanControlMessageKind.Pong, ping);
        await admission;
        var key = fixture.Session.AuthorizeFileTransfer(fixture.Candidate, "transfer");
        Require(key.SequenceEqual(ClassicFileTransferWire.DeriveTransferKey(fixture.Keys, "transfer")), "The file used different session keys.");
        var metadata = ClassicFileTransferWire.Authenticate(new ClassicFileMetadata("transfer", "f", 0,
            Convert.ToHexStringLower(SHA256.HashData([])), 65536, 2, SenderDeviceId: PeerId), key);
        Require(fixture.Session.AuthorizeIncomingTransfer(metadata, IPAddress.Loopback).SequenceEqual(key),
            "The same authenticated peer could not use the reverse transfer direction.");
        Throws<InvalidDataException>(() => fixture.Session.AuthorizeIncomingTransfer(metadata, IPAddress.Parse("127.0.0.2")));
        Throws<CryptographicException>(() => fixture.Session.AuthorizeIncomingTransfer(metadata with { FileName = "tampered" }, IPAddress.Loopback));
        Throws<InvalidDataException>(() => fixture.Session.AuthorizeFileTransfer(fixture.Candidate with {
            Routes = fixture.Candidate.Routes with { FileTransfer = fixture.Candidate.Routes.FileTransfer! with { Port = 8081 } }
        }, "transfer"));
        try { await fixture.Session.CompleteAdmissionAsync(fixture.Token); throw new Exception("Admission ran twice."); }
        catch (InvalidOperationException) { }
        fixture.Remote.Close();
        Require(await fixture.Session.Completion.WaitAsync(fixture.Token) is not null && !fixture.Session.IsReady,
            "A disconnected control session retained file authority or hid its failure.");
        Throws<InvalidOperationException>(() => fixture.Session.AuthorizeFileTransfer(fixture.Candidate, "transfer"));
    }

    private static async Task ConnectedFile()
    {
        foreach (var role in new[] { ProductHandshakeRole.Initiator, ProductHandshakeRole.Responder })
        {
            await using var fixture = await Fixture.Connect(role, inboundOnly: role == ProductHandshakeRole.Responder);
            using var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = checked((ushort)((IPEndPoint)listener.LocalEndpoint).Port);
            Require(fixture.Session.CurrentFileRecipient() is null, "An unapproved MAIN became a file target.");
            await fixture.Admit(peerFilePort: port);
            var recipient = fixture.Session.CurrentFileRecipient() ?? throw new Exception("Missing approved connected peer.");
            Require(recipient.DeviceId == PeerId && recipient.Port == port && recipient.SignerFingerprint == Fingerprint,
                "File selection was not bound to the authenticated identity and its own port.");
            var root = Directory.CreateDirectory(Path.Combine(AppContext.BaseDirectory, "recipient-test-" + Guid.NewGuid().ToString("N"))).FullName;
            try
            {
                var bytes = RandomNumberGenerator.GetBytes(196_731);
                var path = Path.Combine(root, "selected.bin");
                await File.WriteAllBytesAsync(path, bytes, fixture.Token);
                var destination = Directory.CreateDirectory(Path.Combine(root, "received")).FullName;
                var id = Guid.NewGuid().ToString("D");
                var sending = ClassicFileTransferSender.SendToRecipientAsync(fixture.Session, recipient, id, path, null, fixture.Token);
                using var peer = await listener.AcceptTcpClientAsync(fixture.Token);
                var stream = peer.GetStream();
                var frame = await ClassicFileTransferFrames.ReadAsync(stream, fixture.Token);
                Require(frame.Type == ClassicFileFrameType.Metadata, "Missing initial file metadata.");
                var metadata = ClassicFileTransferWire.Decode<ClassicFileMetadata>(frame.Payload);
                var key = ClassicFileTransferWire.DeriveTransferKey(fixture.Keys, id);
                try
                {
                    ClassicFileTransferWire.Verify(metadata, key);
                    var received = await ClassicFileTransferReceiver.ReceiveAsync(stream, metadata, key, destination, null, fixture.Token);
                    var sent = await sending;
                    Require(sent.TransferId == id && sent.FileHash == Convert.ToHexStringLower(SHA256.HashData(bytes)) &&
                        sent.Bytes == bytes.Length && received.FileHash == sent.FileHash &&
                        (await File.ReadAllBytesAsync(received.SavedPath!, fixture.Token)).SequenceEqual(bytes),
                        "Receiver disk bytes or the sender's verified receipt did not match the selected source.");
                }
                finally { CryptographicOperations.ZeroMemory(key); }
            }
            finally { Directory.Delete(root, recursive: true); }
        }
    }

    private static async Task ChangedFileRoute()
    {
        await using var first = await Fixture.Connect(ProductHandshakeRole.Responder, inboundOnly: true);
        await using var second = await Fixture.Connect(ProductHandshakeRole.Responder, inboundOnly: true);
        await first.Admit();
        await second.Admit();
        var selected = first.Session.CurrentFileRecipient() ?? throw new Exception("Missing first recipient.");
        var inFlight = first.Session.RequireFileRecipient(selected);
        Throws<InvalidOperationException>(() => second.Session.AuthorizeFileTransfer(selected, "other"));
        Throws<InvalidOperationException>(() => first.Session.AuthorizeFileTransfer(selected with { Port = 1 }, "tampered"));
        await first.Send(LanControlMessageKind.Identity, Identity() with { Capabilities = [] });
        await first.Send(LanControlMessageKind.Ping, new LanProductPing(11));
        Require((await first.Read()).Kind == LanControlMessageKind.Pong, "Failed to fence the withdrawal.");
        Require(inFlight.IsCancellationRequested && first.Session.CurrentFileRecipient() is null,
            "An existing file operation survived route withdrawal.");
        await first.Send(LanControlMessageKind.Identity, Identity());
        await first.Send(LanControlMessageKind.Ping, new LanProductPing(12));
        Require((await first.Read()).Kind == LanControlMessageKind.Pong, "Failed to fence readmission.");
        Throws<InvalidOperationException>(() => first.Session.AuthorizeFileTransfer(selected, "stale"));
        var renewed = first.Session.CurrentFileRecipient() ?? throw new Exception("Missing renewed route.");
        Require(renewed.RouteGeneration != selected.RouteGeneration && renewed.Port == selected.Port,
            "A route re-added at the same port resurrected a stale user selection.");
    }

    private static Task LocalIdentityBinding()
    {
        var captured = ProductHandshakeProtocolIdentity.Capture(
            new WebRtcProductProtocolIdentityPublicKey(WebRtcProductSignatureAlgorithm.MlDsa65, PublicKey).Encode(), "test");
        LanProductControlMessages.ValidateLocalIdentity(Identity(), captured);
        foreach (var keys in new LanProtocolPublicKey[]?[] {
            null, [], [new("ML-DSA-65", new byte[1952])],
            [new("ML-DSA-65", PublicKey), new("ML-DSA-65", PublicKey)],
            [new("Ed25519", new byte[32])]
        })
            Throws<InvalidDataException>(() => LanProductControlMessages.ValidateLocalIdentity(
                Identity() with { ProtocolIdentityPublicKeys = keys }, captured));
        return Task.CompletedTask;
    }

    private static async Task WrongIdentity()
    {
        await using var fixture = await Fixture.Connect();
        var admission = fixture.Session.CompleteAdmissionAsync(fixture.Token);
        _ = await fixture.Read(); _ = await fixture.Read();
        await fixture.Send(LanControlMessageKind.Identity, Identity() with { DeviceId = "id:unrelated-device" });
        try { await admission; throw new Exception("A different identity was admitted."); }
        catch (IOException error) { Require(error.InnerException is InvalidDataException, "Identity rejection lost its cause."); }
        Require(!fixture.Session.IsReady, "Failed admission retained transfer authority.");
    }

    private static async Task AudioIdentityBinding()
    {
        foreach (var role in new[] { ProductHandshakeRole.Initiator, ProductHandshakeRole.Responder })
        {
            var extensions = Soa(role);
            await using var fixture = await Fixture.Connect(role, extensions);
            extensions.AsSpan().Fill(0); // The live owner must own its evidence, not retain caller memory.
            Throws<InvalidOperationException>(() => fixture.Session.RequireAudioIdentityBinding());
            await fixture.Admit();
            var binding = fixture.Session.RequireAudioIdentityBinding();
            Require(binding.Role == role && binding.SessionId == fixture.Keys.SessionId &&
                binding.LocalDeviceId == LocalId && binding.PeerDeviceId == PeerId,
                "Audio evidence lost the session or reversed device IDs.");
            Require(ReferenceEquals(binding.LocalProtocolIdentity, fixture.Session.LocalHandshakeIdentity) &&
                ReferenceEquals(binding.PeerProtocolIdentity, fixture.Session.PeerHandshakeIdentity) &&
                binding.LocalProtocolIdentity.MatchesPublicKey(LocalPublicKey) &&
                binding.PeerProtocolIdentity.MatchesPublicKey(PublicKey), "Audio used different handshake signers.");
            Require(binding.AttemptId == "000102030405060708090a0b0c0d0e0f", "Signed attempt ID was lost.");
        }
    }

    private static async Task RejectAudioBinding()
    {
        var valid = Soa(ProductHandshakeRole.Initiator);
        var badVersion = valid.ToArray(); badVersion[4] = 2;
        var wrongLocal = valid.ToArray(); wrongLocal[5] ^= 1;
        var wrongPeer = valid.ToArray(); wrongPeer[37] ^= 1;
        foreach (var extensions in new[] {
            Array.Empty<byte>(), valid[..^1], valid.Concat(valid).ToArray(), badVersion,
            wrongLocal, wrongPeer, Soa(ProductHandshakeRole.Responder), valid.Concat(new byte[] { 1 }).ToArray()
        })
        {
            await using var fixture = await Fixture.Connect(extensions: extensions);
            await fixture.Admit();
            Throws<InvalidDataException>(() => fixture.Session.RequireAudioIdentityBinding());
            Require(fixture.Session.IsReady, "Audio-only rejection broke ordinary MAIN admission.");
            Require(fixture.Session.AuthorizeFileTransfer(fixture.Candidate, "transfer").Length == 32,
                "Audio rejection changed the existing file-transfer contract.");
        }
    }

    private static async Task AccountDeviceIdSpelling()
    {
        foreach (var spelling in new[] { PeerId[3..], PeerId[3..].ToUpperInvariant() })
        {
            await using var fixture = await Fixture.Connect(extensions: Soa(ProductHandshakeRole.Initiator));
            await fixture.Admit(spelling);
            var binding = fixture.Session.RequireAudioIdentityBinding();
            Require(binding.PeerDeviceId == spelling && binding.LocalDeviceId == LocalId,
                "Canonical SOA identity replaced the exact account registry spelling.");
            using var inbox = await fixture.OpenAudioInbox();
            Require(inbox.Binding.PeerDeviceId == spelling, "Audio inbox lost the authenticated declaration spelling.");
        }
    }

    private static async Task AccountDeviceIdChange()
    {
        await using var fixture = await Fixture.Connect(extensions: Soa(ProductHandshakeRole.Initiator)); await fixture.Admit();
        using var inbox = await fixture.OpenAudioInbox(); var pending = inbox.ReadAsync(fixture.Token);
        await fixture.Send(LanControlMessageKind.Identity, Identity() with { DeviceId = PeerId[3..] });
        await fixture.Barrier();
        await ThrowsAsync<LanAudioStreamException>(() => pending);
        await ThrowsAsync<LanAudioStreamException>(() => fixture.Session.AcceptAudioOfferAsync(fixture.Token));
        Require(fixture.Session.IsReady, "Account spelling change incorrectly changed ordinary MAIN identity semantics.");
        await fixture.SendAudio(new(inbox.StreamId, new AudioStreamingBody.Credit(99)));
        await fixture.SendAudio(AudioOffer(Guid.NewGuid()));
        await fixture.Barrier();
        Require(fixture.Session.IsReady && fixture.Session.UnavailableAudioFrames == 1,
            "Late audio after an identity spelling change killed MAIN or re-admitted a stream.");
    }

    private static async Task AudioOwnerLifetime()
    {
        foreach (var dispose in new[] { false, true })
        {
            await using var fixture = await Fixture.Connect(extensions: Soa(ProductHandshakeRole.Initiator));
            await fixture.Admit();
            _ = fixture.Session.RequireAudioIdentityBinding();
            if (dispose) await fixture.Session.DisposeAsync();
            else fixture.Cancel();
            Throws<InvalidOperationException>(() => fixture.Session.RequireAudioIdentityBinding());
        }
    }

    private static AudioStreamingMessage AudioOffer(Guid id) => new(id,
        new AudioStreamingBody.CaptureOffer(new(48000, 2, AudioStreamingEncoding.Float32, 32, 3)));

    private static async Task AudioDemultiplex()
    {
        await using var fixture = await Fixture.Connect(extensions: Soa(ProductHandshakeRole.Initiator));
        await fixture.Admit();
        var accepting = fixture.Session.AcceptAudioOfferAsync(fixture.Token);
        var id = Guid.NewGuid(); await fixture.SendAudio(AudioOffer(id));
        using var inbox = await accepting;
        Require((await inbox.ReadAsync(fixture.Token)).Body is AudioStreamingBody.CaptureOffer, "MAIN did not queue the first offer.");
        byte[] pcm = [0, 0, 0, 128, 1, 0, 0, 128];
        await fixture.SendAudio(new(id, new AudioStreamingBody.PcmData(0, pcm)));
        await fixture.Barrier();
        var data = (AudioStreamingBody.PcmData)(await inbox.ReadAsync(fixture.Token)).Body;
        Require(data.Bytes.SequenceEqual(pcm) && data.ByteOffset == 0, "Encrypted carrier changed sample bytes or order.");
        Require(fixture.Session.IsReady && fixture.Session.UnavailableAudioFrames == 0, "Audio damaged MAIN readiness.");
        var waiting = inbox.ReadAsync(fixture.Token);
        fixture.Remote.Close(); await fixture.Session.Completion.WaitAsync(TimeSpan.FromSeconds(5));
        try { await waiting; throw new Exception("Closed MAIN kept a pending audio read."); }
        catch (LanAudioStreamException error) { Require(error.Reason == AudioStreamingStopReason.SessionReplaced, "MAIN loss lost audio failure cause."); }
    }

    private static async Task AudioUnavailable()
    {
        await using var fixture = await Fixture.Connect(); // Old no-SOA ordinary MAIN remains supported.
        await fixture.Admit();
        await fixture.SendAudio(AudioOffer(Guid.NewGuid()));
        await fixture.Barrier();
        Require(fixture.Session.IsReady && fixture.Session.UnavailableAudioFrames == 1,
            "No consumer incorrectly admitted audio or closed MAIN.");
        Throws<InvalidDataException>(() => fixture.Session.AcceptAudioOfferAsync(fixture.Token));
        Require(fixture.Session.LocalIdentity.Capabilities?.Any(value => value.StartsWith("audio_", StringComparison.Ordinal)) != true,
            "The incomplete receiver advertised audio capability.");
        Require(fixture.Session.AuthorizeFileTransfer(fixture.Candidate, "still-live").Length == 32, "Unavailable audio killed existing file authority.");
    }

    private static async Task AudioOverflow()
    {
        await using var fixture = await Fixture.Connect(extensions: Soa(ProductHandshakeRole.Initiator));
        await fixture.Admit();
        var accepting = fixture.Session.AcceptAudioOfferAsync(fixture.Token); var id = Guid.NewGuid();
        await fixture.SendAudio(AudioOffer(id)); using var inbox = await accepting;
        for (var i = 0; i < LanAudioReceiver.MessageCapacity; i++)
            await fixture.SendAudio(new(id, new AudioStreamingBody.Credit(i)));
        await fixture.Barrier();
        Require(fixture.Session.AudioQueueOverflows == 1 && fixture.Session.IsReady, "Queue overflow was hidden or killed MAIN.");
        try { await inbox.ReadAsync(fixture.Token); throw new Exception("Overflow delivered buffered audio."); }
        catch (LanAudioStreamException error) { Require(error.Reason == AudioStreamingStopReason.QueueOverflow, "Overflow cause changed."); }
        await fixture.SendAudio(new(id, new AudioStreamingBody.Credit(99)));
        await fixture.Barrier();
        Require(fixture.Session.IsReady && fixture.Session.AudioQueueOverflows == 1, "Valid late retired audio damaged MAIN.");
    }

    private static async Task MalformedAudio()
    {
        var valid = AudioStreamingLanEnvelope.Encode(AudioOffer(Guid.NewGuid()));
        var reserved = valid.ToArray(); reserved[5] = 1;
        var badPayload = valid.ToArray(); badPayload[13] = 0;
        var oversized = new byte[AudioStreamingLanEnvelope.MaximumBytes + 1]; valid.CopyTo(oversized, 0);
        foreach (var bytes in new[] { valid[..5], reserved, badPayload, oversized })
        {
            await using var fixture = await Fixture.Connect(); await fixture.Admit();
            await fixture.SendPlaintext(bytes);
            var failure = await fixture.Session.Completion.WaitAsync(TimeSpan.FromSeconds(5));
            Require(failure is InvalidDataException && !fixture.Session.IsReady, "Malformed recognized audio fell through or left MAIN alive.");
            Require(fixture.Session.UnavailableAudioFrames == 0, "Malformed audio was classified as unavailable instead of failing.");
        }
    }

    private static async Task AudioReplies()
    {
        await using var fixture = await Fixture.Connect(extensions: Soa(ProductHandshakeRole.Initiator)); await fixture.Admit();
        using var inbox = await fixture.OpenAudioInbox(); var calls = 0;
        AudioStreamingBody[] replies = [new AudioStreamingBody.Accept(4096), new AudioStreamingBody.Credit(32),
            new AudioStreamingBody.ContentVerified(32, new byte[32]),
            new AudioStreamingBody.OutputReady(new(48000, 2, AudioStreamingEncoding.Float32, 32, 3)),
            new AudioStreamingBody.PlaybackComplete(4, 0)];
        foreach (var body in replies)
        {
            var message = new AudioStreamingMessage(inbox.StreamId, body);
            await fixture.Session.SendAudioReplyAsync(inbox, message, () => calls++, fixture.Token);
            Require(AudioStreamingWire.Encode(await fixture.ReadAudio()).SequenceEqual(AudioStreamingWire.Encode(message)),
                "Authorized reply changed its stream or payload on the encrypted carrier.");
        }
        Require(calls == replies.Length, "A positive reply omitted its actual writer-admission effect check.");
        Throws<ArgumentNullException>(() => fixture.Session.SendAudioReplyAsync(inbox, new(inbox.StreamId, replies[0]), null!, fixture.Token));
        foreach (var body in new AudioStreamingBody[] { new AudioStreamingBody.Stop(AudioStreamingStopReason.UserStopped),
            new AudioStreamingBody.PcmData(0, [1]), new AudioStreamingBody.End(0, new byte[32]),
            AudioOffer(inbox.StreamId).Body, new AudioStreamingBody.FileOffer(Guid.NewGuid(), 1, new byte[32]) })
            Throws<InvalidDataException>(() => fixture.Session.SendAudioReplyAsync(inbox, new(inbox.StreamId, body), () => calls++, fixture.Token));
        await fixture.Session.SendAudioStopAsync(inbox, AudioStreamingStopReason.ReceiverDeclined, fixture.Token);
        Require((await fixture.ReadAudio()).Body is AudioStreamingBody.Stop { Reason: AudioStreamingStopReason.ReceiverDeclined } &&
            calls == replies.Length, "Stop required playback permission or used an unbound message.");
    }

    private static async Task QueuedAudioPermission()
    {
        await using var fixture = await Fixture.Connect(extensions: Soa(ProductHandshakeRole.Initiator)); await fixture.Admit();
        using var inbox = await fixture.OpenAudioInbox(); var allowed = true; var calls = 0;
        await using var held = fixture.HoldWriter(); await held.Entered.WaitAsync(fixture.Token);
        var sending = fixture.Session.SendAudioReplyAsync(inbox, new(inbox.StreamId, new AudioStreamingBody.Accept(4096)), () =>
        {
            calls++;
            if (!allowed) throw new UnauthorizedAccessException("Fixture playback permission revoked.");
        }, fixture.Token);
        Require(!sending.IsCompleted && calls == 0, "Audio permission was checked outside writer admission.");
        allowed = false; held.Release(); await held.Completion;
        await ThrowsAsync<UnauthorizedAccessException>(() => sending);
        Require(calls == 1 && fixture.Session.IsReady, "Permission refusal was retried or closed MAIN.");
        await fixture.ReadWriterBarrier();
        await fixture.Session.SendAudioStopAsync(inbox, AudioStreamingStopReason.PermissionRevoked, fixture.Token);
        Require((await fixture.ReadAudio()).Body is AudioStreamingBody.Stop { Reason: AudioStreamingStopReason.PermissionRevoked },
            "Revoked positive reply wrote bytes before the permitted Stop.");
    }

    private static async Task QueuedAudioReplacement()
    {
        await using var fixture = await Fixture.Connect(extensions: Soa(ProductHandshakeRole.Initiator)); await fixture.Admit();
        using var old = await fixture.OpenAudioInbox(); var oldCalls = 0; var newCalls = 0;
        await using var held = fixture.HoldWriter(); await held.Entered.WaitAsync(fixture.Token);
        var previous = fixture.Session.SendAudioReplyAsync(old, new(old.StreamId, new AudioStreamingBody.Credit(1)), () => oldCalls++, fixture.Token);
        await ThrowsAsync<InvalidOperationException>(() => fixture.Session.SendAudioStopAsync(old, AudioStreamingStopReason.UserStopped, fixture.Token));
        old.Dispose();
        using var replacement = await fixture.OpenAudioInbox();
        var next = fixture.Session.SendAudioReplyAsync(replacement, new(replacement.StreamId, new AudioStreamingBody.Credit(2)), () => newCalls++, fixture.Token);
        held.Release(); await held.Completion;
        await ThrowsAsync<LanAudioStreamException>(() => previous); await next;
        Require(oldCalls == 0 && newCalls == 1, "Retired send reached authorization or old cleanup revoked its replacement.");
        await fixture.ReadWriterBarrier();
        var actual = await fixture.ReadAudio();
        Require(actual.StreamId == replacement.StreamId && actual.Body is AudioStreamingBody.Credit { RetiredBytes: 2 },
            "A retired stream wrote a reply before its replacement.");
    }

    private static async Task QueuedAudioSnapshot()
    {
        await using var fixture = await Fixture.Connect(extensions: Soa(ProductHandshakeRole.Initiator)); await fixture.Admit();
        using var inbox = await fixture.OpenAudioInbox(); var calls = 0;
        await using var held = fixture.HoldWriter(); await held.Entered.WaitAsync(fixture.Token);
        using var cancel = new CancellationTokenSource();
        var canceled = fixture.Session.SendAudioReplyAsync(inbox, new(inbox.StreamId, new AudioStreamingBody.Accept(4096)), () => calls++, cancel.Token);
        cancel.Cancel(); await ThrowsAsync<OperationCanceledException>(() => canceled);
        Require(calls == 0, "Canceled queued audio reached its effect check.");
        var hash = Enumerable.Range(0, 32).Select(value => (byte)value).ToArray(); var expected = hash.ToArray();
        var sending = fixture.Session.SendAudioReplyAsync(inbox, new(inbox.StreamId, new AudioStreamingBody.ContentVerified(123, hash)), () => calls++, fixture.Token);
        hash.AsSpan().Clear(); held.Release(); await held.Completion; await sending;
        await fixture.ReadWriterBarrier(); var actual = await fixture.ReadAudio();
        Require(actual.Body is AudioStreamingBody.ContentVerified verified && verified.TotalBytes == 123 && verified.Sha256.SequenceEqual(expected) &&
            calls == 1 && fixture.Session.IsReady, "Queued send retained mutable descriptor bytes or canceled send retained the slot.");
    }

    private static async Task ForeignAudioReply()
    {
        await using var first = await Fixture.Connect(extensions: Soa(ProductHandshakeRole.Initiator)); await first.Admit();
        await using var second = await Fixture.Connect(extensions: Soa(ProductHandshakeRole.Initiator)); await second.Admit();
        using var inbox = await first.OpenAudioInbox(); var calls = 0;
        await ThrowsAsync<InvalidDataException>(() => second.Session.SendAudioReplyAsync(inbox,
            new(inbox.StreamId, new AudioStreamingBody.Credit(0)), () => calls++, second.Token));
        await ThrowsAsync<InvalidDataException>(() => second.Session.SendAudioStopAsync(inbox, AudioStreamingStopReason.UserStopped, second.Token));
        await ThrowsAsync<InvalidDataException>(() => first.Session.SendAudioReplyAsync(inbox,
            new(Guid.NewGuid(), new AudioStreamingBody.Credit(0)), () => calls++, first.Token));
        Require(calls == 0, "Wrong owner or stream reached its permission callback.");
        await first.Barrier(); await second.Barrier();
    }

    private static async Task ThrowsAsync<T>(Func<Task> action) where T : Exception
    { try { await action(); } catch (T) { return; } throw new Exception($"Expected {typeof(T).Name}."); }

    internal sealed class Fixture : IAsyncDisposable
    {
        private readonly CancellationTokenSource _deadline = new(TimeSpan.FromSeconds(10));
        private readonly WebRtcAppSecureSessionKeys _remoteKeys;
        internal ProductSessionKeys Keys { get; }
        internal TcpProductControlTransport Remote { get; }
        internal TcpProductControlTransport Local { get; }
        internal LanProductControlSession Session { get; }
        internal CancellationToken Token => _deadline.Token;
        internal DiscoveryBrowserPeerCandidate Candidate { get; }
        private Fixture(TcpClient local, TcpClient remote, ProductHandshakeRole role, byte[] extensions, ushort? localFilePort, bool generalFiles, bool inboundOnly)
        {
            Keys = new(role, "fixture", new byte[32],
                Enumerable.Repeat((byte)1, 32).ToArray(), Enumerable.Repeat((byte)2, 32).ToArray());
            Remote = new(remote, 1024 * 1024, 1024 * 1024);
            var control = new DiscoveryPeerEndpoint(SkyBridgeProtocolConstants.TcpControlDnsSdService,
                "fixture.local", 9000, "fixture._skybridge._tcp.local", "resolved-dns-sd-endpoint");
            Candidate = new(new(CoreDiscoveryServiceKind.FileTransfer, PeerId, "Fixture", CorePeerPlatform.Apple,
                "macOS", Fingerprint, "file_transfer", "1", PeerCapabilities.Apple()), "", "") {
                Routes = new(control, new(SkyBridgeProtocolConstants.FileTransferDnsSdService, "fixture.local", 8080,
                    "fixture._skybridge-xfer._tcp.local", "resolved-dns-sd-endpoint"), null)
            };
            var signingIdentity = ProductHandshakeProtocolIdentity.Capture(
                new WebRtcProductProtocolIdentityPublicKey(WebRtcProductSignatureAlgorithm.MlDsa65, PublicKey).Encode(), "fixture");
            var localSigner = ProductHandshakeProtocolIdentity.Capture(
                new WebRtcProductProtocolIdentityPublicKey(WebRtcProductSignatureAlgorithm.MlDsa65, LocalPublicKey).Encode(), "local fixture");
            Local = new(local, 1024 * 1024, 1024 * 1024);
            Session = new(Local, Keys, Peer,
                Identity() with { DeviceId = LocalId, ProtocolIdentityPublicKeys = [new("ML-DSA-65", LocalPublicKey)],
                    FileTransferPort = localFilePort, Capabilities = generalFiles ? ["file_transfer"] : [] },
                inboundOnly ? null : control, IPAddress.Loopback, Token, localSigner, signingIdentity, extensions);
            Require(Session.LocalHandshakeIdentity.Fingerprint == localSigner.Fingerprint &&
                Session.PeerHandshakeIdentity.Fingerprint == Fingerprint, "MAIN discarded its exact signing identities.");
            using var reversed = new ProductSessionKeys(role == ProductHandshakeRole.Initiator ? ProductHandshakeRole.Responder : ProductHandshakeRole.Initiator,
                Keys.SessionId, Keys.TranscriptHash, Keys.ReceiveKey, Keys.SendKey);
            _remoteKeys = WebRtcProductHandshakeSessionKeys.ToWebRtcKeys(reversed);
        }
        internal static Task<Fixture> ConnectForAudio(ushort? localFilePort = 8080, bool generalFiles = true) =>
            Connect(extensions: Soa(ProductHandshakeRole.Initiator), localFilePort: localFilePort, generalFiles: generalFiles);
        internal static async Task<Fixture> Connect(ProductHandshakeRole role = ProductHandshakeRole.Initiator, byte[]? extensions = null, ushort? localFilePort = 8080, bool generalFiles = true, bool inboundOnly = false)
        {
            using var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var local = new TcpClient();
            await local.ConnectAsync((IPEndPoint)listener.LocalEndpoint);
            var remote = await listener.AcceptTcpClientAsync();
            return new(local, remote, role, extensions ?? Array.Empty<byte>(), localFilePort, generalFiles, inboundOnly);
        }
        internal void Cancel() => _deadline.Cancel();
        internal async Task Admit(string? peerSpelling = null, ushort peerFilePort = 8080)
        {
            var admission = Session.CompleteAdmissionAsync(Token);
            Require((await Read()).Kind == LanControlMessageKind.Identity, "Missing local identity.");
            var ping = LanProductControlMessages.Payload<LanProductPing>(await Read());
            await Send(LanControlMessageKind.Identity, Identity() with { DeviceId = peerSpelling ?? PeerId, FileTransferPort = peerFilePort });
            await Send(LanControlMessageKind.Pong, ping);
            await admission;
        }
        internal async Task<LanControlMessage> Read() => LanProductControlMessages.Decode(
            WebRtcControlChannelCodec.DecryptAppleLegacyAppPayload(ProductControlTrafficPadding.Unwrap((await Remote.ReadAsync(Token)).ToArray()), _remoteKeys));
        internal async Task<AudioStreamingMessage> ReadAudio() => AudioStreamingLanEnvelope.DecodeIfPresent(
            WebRtcControlChannelCodec.DecryptAppleLegacyAppPayload(ProductControlTrafficPadding.Unwrap((await Remote.ReadAsync(Token)).ToArray()), _remoteKeys))
            ?? throw new Exception("Expected an encrypted SBE1 audio reply.");
        internal async Task<ILanAudioStreamInbox> OpenAudioInbox()
        {
            var accepting = Session.AcceptAudioOfferAsync(Token); var id = Guid.NewGuid();
            await SendAudio(AudioOffer(id)); var inbox = await accepting;
            Require((await inbox.ReadAsync(Token)).Body is AudioStreamingBody.CaptureOffer, "The inbox did not begin with its offer.");
            return inbox;
        }
        internal TcpProductControlTransportTests.HeldWriter HoldWriter()
        {
            using var localKeys = WebRtcProductHandshakeSessionKeys.ToWebRtcKeys(Keys);
            var frame = ProductControlTrafficPadding.Wrap(WebRtcControlChannelCodec.EncryptAppleLegacyAppPayload(
                LanProductControlMessages.Encode(LanControlMessageKind.Ping, new LanProductPing(0xBB66)), localKeys));
            return new(Local, Token, frame);
        }
        internal async Task ReadWriterBarrier()
        {
            var message = await Read();
            Require(message.Kind == LanControlMessageKind.Ping && LanProductControlMessages.Payload<LanProductPing>(message).Id == 0xBB66,
                "The writer barrier did not precede queued audio.");
        }
        internal Task Send<T>(LanControlMessageKind kind, T payload) => Remote.SendAsync(ProductControlTrafficPadding.Wrap(
            WebRtcControlChannelCodec.EncryptAppleLegacyAppPayload(LanProductControlMessages.Encode(kind, payload), _remoteKeys)), Token);
        internal Task SendPlaintext(byte[] plaintext) => Remote.SendAsync(ProductControlTrafficPadding.Wrap(
            WebRtcControlChannelCodec.EncryptAppleLegacyAppPayload(plaintext, _remoteKeys)), Token);
        internal Task SendAudio(AudioStreamingMessage message) => SendPlaintext(AudioStreamingLanEnvelope.Encode(message));
        internal async Task Barrier()
        {
            var ping = new LanProductPing(0xAA55);
            await Send(LanControlMessageKind.Ping, ping);
            var message = await Read();
            Require(message.Kind == LanControlMessageKind.Pong && LanProductControlMessages.Payload<LanProductPing>(message).Id == ping.Id,
                "MAIN did not process ordered control traffic after audio.");
        }
        public async ValueTask DisposeAsync()
        {
            await Session.DisposeAsync(); await Remote.DisposeAsync();
            _remoteKeys.Dispose(); Keys.Dispose(); _deadline.Dispose();
        }
    }
}
