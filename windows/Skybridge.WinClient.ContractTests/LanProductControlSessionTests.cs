using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.FileTransfer;
using Skybridge.WinClient.Services.Audio;
using Skybridge.WinClient.Services.Connection;

internal static class LanProductControlSessionTests
{
    internal static IReadOnlyList<(string Name, Func<Task> Run)> Cases { get; } =
    [
        ("LAN AppMessage retains Apple dates and rejects ambiguous or mismatched identities", MessageContract),
        ("LAN local publication must match the exact handshake signer", LocalIdentityBinding),
        ("LAN encrypted admission gates exact file routes and retires with its connection", Admission),
        ("LAN audio binds role-aware exact device IDs and actual signers after admission", AudioIdentityBinding),
        ("LAN audio preserves Android and Apple account device ID spelling", AccountDeviceIdSpelling),
        ("LAN changed account ID spelling retires audio without reviving its grant", AccountDeviceIdChange),
        ("LAN audio rejects absent malformed duplicate and mismatched SOA without breaking MAIN", RejectAudioBinding),
        ("LAN audio identity evidence cannot be reacquired after cancellation or disposal", AudioOwnerLifetime),
        ("Control session erases keys even when its carrier release fails", CarrierReleaseFailure),
        ("encrypted MAIN demultiplexes audio in order and keeps control traffic live", AudioDemultiplex),
        ("encrypted MAIN rejects unavailable audio without admitting or closing it", AudioUnavailable),
        ("encrypted MAIN retires overflowing audio and keeps its control reader", AudioOverflow),
        ("recognized malformed audio closes its exact encrypted MAIN owner", MalformedAudio),
        ("audio receiver replies require effect checks while Stop retains exact owner binding", AudioReplies),
        ("queued audio reply rechecks revoked permission before any wire bytes", QueuedAudioPermission),
        ("queued audio reply cannot outlive its stream or affect a replacement", QueuedAudioReplacement),
        ("queued audio reply owns its encoded metadata and cancellation releases its send slot", QueuedAudioSnapshot),
        ("audio replies reject foreign owners and wrong stream IDs before authorization", ForeignAudioReply),
        ("withdrawal barrier rejects a decline for a different stream", () => RejectWithdrawalReply("foreign-stream")),
        ("withdrawal barrier rejects another terminal reason", () => RejectWithdrawalReply("other-reason")),
        ("withdrawal barrier rejects a positive admission reply", () => RejectWithdrawalReply("admission")),
        ("withdrawal barrier rejects duplicate declines", () => RejectWithdrawalReply("duplicate")),
        ("withdrawal barrier rejects a mismatched Pong", () => RejectWithdrawalReply("wrong-pong")),
        ("LAN encrypted admission rejects a different peer protocol identity", WrongIdentity),
        ("USB MAIN preserves exact cable account and audio binding without network file authority", UsbCarrierBinding),
        ("USB MAIN account revocation ends readiness audio authority and subsequent control effects", UsbAccountRevocation)
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

    private static AudioAccountScope UsbScope() => new(SessionAuthority.ForSupabaseProject("https://audio-account-test.supabase.co"), "audio-user", "audio-user");
    private static UsbPeerInspection UsbInspection(string udid = "00008132-1111111111111111")
    {
        // Controlled advertisement port for these already-constructed session
        // keys. Native mux/ML-DSA/Finished validation is a separate Windows case.
        var now = DateTimeOffset.UtcNow; var request = UsbPeerDiscoveryWire.Request(now);
        var response = new UsbPeerDiscoveryResponse(request, new(PeerId[3..], "ML-DSA-65",
            System.Collections.Immutable.ImmutableArray.CreateRange(PublicKey), Fingerprint), "USB fixture", "ios", [1]);
        response = response with { Signature = System.Collections.Immutable.ImmutableArray.CreateRange(SHA256.HashData(UsbPeerDiscoveryWire.SigningData(response))) };
        return UsbPeerInspection.Verify(udid, response, request, now, (_, bytes, signature) =>
        { Require(signature.AsSpan().SequenceEqual(SHA256.HashData(bytes)), "Controlled discovery signature changed."); });
    }
    private static async Task UsbCarrierBinding()
    {
        var selected = UsbInspection(); var scope = UsbScope();
        await using var fixture = await Fixture.Connect(extensions: Soa(ProductHandshakeRole.Initiator), localFilePort: null,
            generalFiles: false, carrier: new ProductControlCarrier.Usb(UsbControlRoute.From(selected), scope));
        await fixture.Admit(); fixture.Session.RequireUsbRoute(selected, scope);
        Require(fixture.Session.Carrier is ProductControlCarrier.Usb && fixture.Session.LocalFileTransferPort is null,
            "USB was represented as a network file listener.");
        Throws<InvalidOperationException>(() => _ = fixture.Session.RemoteAddress);
        Throws<InvalidDataException>(() => fixture.Session.RequireUsbRoute(UsbInspection("00008132-2222222222222222"), scope));
        Throws<InvalidDataException>(() => fixture.Session.RequireUsbRoute(selected, scope with { Subject = "other" }));
        Throws<InvalidDataException>(() => fixture.Session.AuthorizeFileTransfer(fixture.Candidate, "file"));
        var metadata = new ClassicFileMetadata("file", "f", 0, new string('a',64), 65536, 2, SenderDeviceId: PeerId);
        Throws<InvalidDataException>(() => fixture.Session.AuthorizeIncomingTransfer(metadata, IPAddress.Loopback));
        Require(!new AudioOriginalFileReceiveRegistry().CanReceiveFor(fixture.Session), "USB MAIN alone advertised file reception.");
        using var inbox = await fixture.OpenAudioInbox();
        Require(inbox.Binding.PeerProtocolIdentity.Fingerprint == Fingerprint && inbox.Binding.SessionId == fixture.Session.SessionId,
            "USB audio did not inherit its actual MAIN identity and keys.");
        await fixture.SendAudio(new(inbox.StreamId, new AudioStreamingBody.PcmData(0, [1,2,3,4])));
        Require((await inbox.ReadAsync(fixture.Token)).Body is AudioStreamingBody.PcmData { ByteOffset: 0 }, "USB framing did not preserve ordered encrypted audio.");
        await fixture.Barrier();
    }
    private static async Task UsbAccountRevocation()
    {
        var selected = UsbInspection(); var scope = UsbScope(); var epoch = new AccountAudioAuthorization(scope);
        await using var fixture = await Fixture.Connect(extensions: Soa(ProductHandshakeRole.Initiator), localFilePort: null,
            generalFiles: false, carrier: new ProductControlCarrier.Usb(UsbControlRoute.From(selected), scope), isAuthorityCurrent: () => epoch.IsCurrent);
        await fixture.Admit(); using var inbox = await fixture.OpenAudioInbox();
        epoch.Revoke();
        Require(!fixture.Session.IsReady, "Revoked USB account retained session readiness.");
        Throws<InvalidOperationException>(() => fixture.Session.RequireAudioIdentityBinding());
        await fixture.Send(LanControlMessageKind.Ping, new LanProductPing(77));
        Require(await fixture.Session.Completion.WaitAsync(fixture.Token) is not null, "Revoked control traffic did not retire the exact session.");
        Throws<LanAudioStreamException>(() => inbox.RequireCurrent());
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

    private static async Task RejectWithdrawalReply(string variant)
    {
        await using var fixture = await Fixture.ConnectForAudio(); await fixture.Admit();
        var id = Guid.NewGuid();
        AudioStreamingMessage decline = new(id, new AudioStreamingBody.Stop(AudioStreamingStopReason.ReceiverDeclined));
        var messages = variant switch
        {
            "foreign-stream" => new[] { new AudioStreamingMessage(Guid.NewGuid(), decline.Body) },
            "other-reason" => [new AudioStreamingMessage(id, new AudioStreamingBody.Stop(AudioStreamingStopReason.UserStopped))],
            "admission" => [new AudioStreamingMessage(id, new AudioStreamingBody.Accept(4096))],
            "duplicate" => [decline, decline],
            "wrong-pong" => Array.Empty<AudioStreamingMessage>(),
            _ => throw new ArgumentException("Unknown withdrawal-barrier counterexample.", nameof(variant))
        };
        foreach (var message in messages) await fixture.InjectLocalReplyForTest(AudioStreamingLanEnvelope.Encode(message));
        if (variant == "wrong-pong")
            await fixture.InjectLocalReplyForTest(LanProductControlMessages.Encode(LanControlMessageKind.Pong, new LanProductPing(0)));
        await ThrowsAsync<InvalidDataException>(() => fixture.WithdrawnOfferBarrier(id));
    }

    internal enum WithdrawnOfferBarrierReply { PongOnly, DeclinedThenPong }

    private static async Task ThrowsAsync<T>(Func<Task> action) where T : Exception
    { try { await action(); } catch (T) { return; } throw new Exception($"Expected {typeof(T).Name}."); }

    private static async Task CarrierReleaseFailure()
    {
        var failure = new IOException("Injected stream cleanup failure.");
        await using var fixture = await Fixture.Connect(releaseFailure: failure);
        await fixture.Admit();
        // Capture the actual owner's arrays before retirement, rather than checking
        // only that a public API refuses further calls with still-live keys.
        var flags = System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic;
        var keys = typeof(LanProductControlSession).GetField("_keys", flags)?.GetValue(fixture.Session) as ProductSessionKeys
            ?? throw new InvalidOperationException("Session key owner is unavailable to the erasure test.");
        var appKeys = typeof(LanProductControlSession).GetField("_appKeys", flags)?.GetValue(fixture.Session) as WebRtcAppSecureSessionKeys
            ?? throw new InvalidOperationException("App key owner is unavailable to the erasure test.");
        var secretViews = new[] { keys.SendKey, keys.ReceiveKey, appKeys.SendKey, appKeys.ReceiveKey };
        Require(secretViews.All(bytes => bytes.Span.ContainsAnyExcept((byte)0)), "Fixture has no nonzero secrets to erase.");
        foreach (var attempt in Enumerable.Range(0, 2))
        {
            try { await fixture.Session.DisposeAsync(); throw new InvalidOperationException("Cleanup failure was hidden."); }
            catch (IOException error) { Require(ReferenceEquals(error, failure), "Session lost its carrier cleanup cause."); }
        }
        Require(secretViews.All(bytes => !bytes.Span.ContainsAnyExcept((byte)0)) &&
            fixture.Session.Completion.IsCompleted && !fixture.Session.IsReady, "Failed disposal retained keys or live session workers.");
        Throws<ObjectDisposedException>(() => keys.Clone());
    }

    internal sealed class Fixture : IAsyncDisposable
    {
        private readonly CancellationTokenSource _deadline = new(TimeSpan.FromSeconds(10));
        private readonly WebRtcAppSecureSessionKeys _remoteKeys;
        private readonly Exception? _releaseFailure;
        private long _barrierSequence = 0xAA55;
        internal ProductSessionKeys Keys { get; }
        internal ProductControlStreamTransport Remote { get; }
        internal ProductControlStreamTransport Local { get; }
        internal LanProductControlSession Session { get; }
        internal CancellationToken Token => _deadline.Token;
        internal DiscoveryBrowserPeerCandidate Candidate { get; }
        private Fixture(TcpClient local, TcpClient remote, ProductHandshakeRole role, byte[] extensions, ushort? localFilePort,
            bool generalFiles, Exception? releaseFailure, ProductControlCarrier? carrier, Func<bool>? isAuthorityCurrent)
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
            _releaseFailure = releaseFailure;
            Local = releaseFailure is null ? new(local, 1024 * 1024, 1024 * 1024) :
                new(new ProductControlStreamOwnershipTests.ObservedStream(local.GetStream(), local)
                    { DisposeFailure = releaseFailure }, 1024 * 1024, 1024 * 1024);
            Session = new(Local, Keys, Peer,
                Identity() with { DeviceId = LocalId, ProtocolIdentityPublicKeys = [new("ML-DSA-65", LocalPublicKey)],
                    FileTransferPort = localFilePort, Capabilities = generalFiles ? ["file_transfer"] : [] },
                carrier ?? new ProductControlCarrier.Network(IPAddress.Loopback, control), Token, localSigner, signingIdentity,
                extensions, isAuthorityCurrent ?? (static () => true));
            Require(Session.LocalHandshakeIdentity.Fingerprint == localSigner.Fingerprint &&
                Session.PeerHandshakeIdentity.Fingerprint == Fingerprint, "MAIN discarded its exact signing identities.");
            using var reversed = new ProductSessionKeys(role == ProductHandshakeRole.Initiator ? ProductHandshakeRole.Responder : ProductHandshakeRole.Initiator,
                Keys.SessionId, Keys.TranscriptHash, Keys.ReceiveKey, Keys.SendKey);
            _remoteKeys = WebRtcProductHandshakeSessionKeys.ToWebRtcKeys(reversed);
        }
        internal static Task<Fixture> ConnectForAudio(ushort? localFilePort = 8080, bool generalFiles = true) =>
            Connect(extensions: Soa(ProductHandshakeRole.Initiator), localFilePort: localFilePort, generalFiles: generalFiles);
        internal static async Task<Fixture> Connect(ProductHandshakeRole role = ProductHandshakeRole.Initiator, byte[]? extensions = null,
            ushort? localFilePort = 8080, bool generalFiles = true, Exception? releaseFailure = null,
            ProductControlCarrier? carrier = null, Func<bool>? isAuthorityCurrent = null)
        {
            using var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var local = new TcpClient();
            await local.ConnectAsync((IPEndPoint)listener.LocalEndpoint);
            var remote = await listener.AcceptTcpClientAsync();
            return new(local, remote, role, extensions ?? Array.Empty<byte>(), localFilePort, generalFiles, releaseFailure, carrier, isAuthorityCurrent);
        }
        internal void Cancel() => _deadline.Cancel();
        internal async Task Admit(string? peerSpelling = null)
        {
            var admission = Session.CompleteAdmissionAsync(Token);
            Require((await Read()).Kind == LanControlMessageKind.Identity, "Missing local identity.");
            var ping = LanProductControlMessages.Payload<LanProductPing>(await Read());
            await Send(LanControlMessageKind.Identity, Identity() with { DeviceId = peerSpelling ?? PeerId });
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
        // Synthetic server replies exercise the test reader's negative boundaries;
        // no product sender or authorization path uses this fixture-only injection.
        internal Task InjectLocalReplyForTest(byte[] plaintext)
        {
            using var localKeys = WebRtcProductHandshakeSessionKeys.ToWebRtcKeys(Keys);
            var frame = ProductControlTrafficPadding.Wrap(WebRtcControlChannelCodec.EncryptAppleLegacyAppPayload(plaintext, localKeys));
            return Local.SendAsync(frame, Token);
        }
        private LanProductPing NextBarrierPing() => new(checked((ulong)Interlocked.Increment(ref _barrierSequence)));
        private async Task<byte[]> ReadBarrierPlaintext() => WebRtcControlChannelCodec.DecryptAppleLegacyAppPayload(
            ProductControlTrafficPadding.Unwrap((await Remote.ReadAsync(Token)).ToArray()), _remoteKeys);
        internal async Task Barrier()
        {
            var ping = NextBarrierPing();
            await Send(LanControlMessageKind.Ping, ping);
            RequireBarrierPong(await ReadBarrierPlaintext(), ping);
        }
        internal async Task<WithdrawnOfferBarrierReply> WithdrawnOfferBarrier(Guid offeredStream)
        {
            if (offeredStream == Guid.Empty) throw new ArgumentException("The withdrawn offer must have its actual stream ID.", nameof(offeredStream));
            var ping = NextBarrierPing();
            await Send(LanControlMessageKind.Ping, ping);
            var plaintext = await ReadBarrierPlaintext();
            var result = WithdrawnOfferBarrierReply.PongOnly;
            if (AudioStreamingLanEnvelope.DecodeIfPresent(plaintext) is { } reply)
            {
                // An unaccepted offer may already have been declined by the
                // sole MAIN reader before it reads the peer's cancellation.
                // Only that exact single negative reply may precede this Pong.
                if (reply.StreamId != offeredStream || reply.Body is not AudioStreamingBody.Stop { Reason: AudioStreamingStopReason.ReceiverDeclined })
                    throw new InvalidDataException($"Withdrawal barrier received an unexpected reply for {reply.StreamId}: {reply.Body}.");
                result = WithdrawnOfferBarrierReply.DeclinedThenPong;
                plaintext = await ReadBarrierPlaintext();
            }
            RequireBarrierPong(plaintext, ping); // Rejects a second audio reply of any kind.
            return result;
        }
        private static void RequireBarrierPong(byte[] plaintext, LanProductPing ping)
        {
            if (AudioStreamingLanEnvelope.DecodeIfPresent(plaintext) is { } audio)
            {
                var detail = audio.Body is AudioStreamingBody.Stop stop ? stop.Reason.ToString() : audio.Body.GetType().Name;
                throw new InvalidDataException($"MAIN barrier expected Pong but received audio {audio.Body.GetType().Name} for {audio.StreamId}: {detail}.");
            }
            var message = LanProductControlMessages.Decode(plaintext);
            if (message.Kind != LanControlMessageKind.Pong || LanProductControlMessages.Payload<LanProductPing>(message).Id != ping.Id)
                throw new InvalidDataException("MAIN did not return the exact ordered control Pong after audio.");
        }
        public async ValueTask DisposeAsync()
        {
            try { await Session.DisposeAsync(); }
            catch (Exception error) when (ReferenceEquals(error, _releaseFailure)) { /* Asserted by CarrierReleaseFailure. */ }
            await Remote.DisposeAsync();
            _remoteKeys.Dispose(); Keys.Dispose(); _deadline.Dispose();
        }
    }
}
