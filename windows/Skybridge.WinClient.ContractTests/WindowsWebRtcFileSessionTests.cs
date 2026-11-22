using System.Security.Cryptography;
using System.Text.Json;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.FileTransfer;
using Skybridge.WinClient.Services.RemoteControl;

internal static class WindowsWebRtcFileSessionTests
{
    internal static IReadOnlyList<(string Name, Func<Task> Run)> Cases => OperatingSystem.IsWindows()
        ? [.. PortableCases, ("first LAN file connection compares both operators, verifies signed KEM refresh and saves acknowledged bytes", LanFileFirstPairTests.Run),
            ("passive file-only LAN receives ordinary bytes on its announced port and verifies the saved receipt", LanProductControlResponderTests.NativePassiveFileReadback),
            ("native first pairing writes only mutual consent to DPAPI and reconnects both signed devices after reopening", NativeRememberAndReconnect)]
        : PortableCases;
    private static IReadOnlyList<(string Name, Func<Task> Run)> PortableCases =>
    [
        ("ordinary WebRTC files require approval and a disk-backed exact receipt in both directions", BothDirections),
        ("WebRTC file receiver decline creates no artifact and does not close the session", Decline),
        ("WebRTC SAS rejects mismatch, stale transcript, signer change and silent capability downgrade", PairingBoundaries),
        ("WebRTC native fragments reassemble across headers and reject oversized prefixes", Framing),
    ];

    private sealed class Wire : IWebRtcProductControlPlane
    {
        internal Wire? Other;
        internal int Messages;
        public bool IsConnected { get; set; } = true;
        public event Action<byte[]>? MessageReceived;
        public Task SendAsync(ReadOnlyMemory<byte> bytes, CancellationToken token = default)
        {
            token.ThrowIfCancellationRequested();
            if (!IsConnected || Other is null) throw new IOException("Test link closed.");
            if (bytes.Length > 8192) throw new IOException("SCTP chunk exceeded the shipping helper's IPC limit.");
            Interlocked.Increment(ref Messages);
            Other.MessageReceived?.Invoke(bytes.ToArray());
            return Task.CompletedTask;
        }
        internal void Inject(byte[] chunk) => MessageReceived?.Invoke(chunk);
    }

    private static RemoteControlPairingMaterial Peer(string id, string name, byte marker) =>
        RemoteControlPairingMaterial.Create(id, name, Enumerable.Repeat(marker, 1952).ToArray(), new byte[1184]);

    private static LiveWebRtcProductControlContext Context(IWebRtcProductControlPlane plane, RemoteControlPairingMaterial peer, string role) =>
        new(plane, peer.DeviceId, peer.ProtocolPublicKeyFingerprint, role, "mac-product-control-v1", "skybridge",
            "fixture", "local", "remote", "test-pair", 0, new string('c', 64), 1000,
            WebRtcProductControlSecureSessionState.Established, SessionIncarnation: WebRtcProductSessionIncarnation.Create());

    private static Task BothDirections() => Transfer(accept: true);
    private static Task Decline() => Transfer(accept: false);

    internal static Task TransferOverHelpers(IWebRtcProductControlPlane left, IWebRtcProductControlPlane right) =>
        Transfer(true, left, right);

    private static async Task Transfer(bool accept, IWebRtcProductControlPlane? nativeA = null, IWebRtcProductControlPlane? nativeB = null)
    {
        var root = Directory.CreateDirectory(Path.Combine(AppContext.BaseDirectory, "sbwc-file-" + Guid.NewGuid().ToString("N"))).FullName;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var token = timeout.Token;
        try
        {
            var rawA = new Wire(); var rawB = new Wire(); rawA.Other = rawB; rawB.Other = rawA;
            var a = new WebRtcProductFramedPlane(nativeA ?? rawA); var b = new WebRtcProductFramedPlane(nativeB ?? rawB);
            var (alice, bob, keyA, keyB, ownerA, ownerB) = await CreateOwnersAsync(a, b, token);
            using var ka = keyA; using var kb = keyB;
            var dirA = Directory.CreateDirectory(Path.Combine(root, "one")).FullName;
            var dirB = Directory.CreateDirectory(Path.Combine(root, "two")).FullName;
            var approve = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            bool delay = true;
            WindowsWebRtcReceiveOptions Receive(string path, string expectedSender) =>
                new(() => path, async (metadata, destination, ct) =>
                {
                    Require(metadata.SenderDeviceId == expectedSender && destination == path, "Unbound receiver or wrong destination.");
                    if (delay)
                    {
                        approve.TrySetResult();
                        await release.Task.WaitAsync(ct);
                    }
                    return accept;
                }, _ => { }, (_,_,_) => { });
            int remembered = 0;
            string? leftCode = null, rightCode = null;
            var userReady = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var compare = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var leftPolicy = new WebRtcPairingPolicy(false, false, (_, code, _) =>
            {
                leftCode = code; return Task.FromResult(WebRtcComparison.Remember);
            }, (peer, _) => { Require(peer.HasSameAuthority(bob), "Wrong remembered peer."); Interlocked.Increment(ref remembered); });
            var rightPolicy = new WebRtcPairingPolicy(false, false, async (_, code, ct) =>
            {
                rightCode = code; userReady.TrySetResult(); await compare.Task.WaitAsync(ct); return WebRtcComparison.AllowOnce;
            }, (_, _) => throw new Exception("Allow once wrote persistent trust."));
            await using var left = new WindowsWebRtcFileSession(ownerA, ka, alice, bob, leftPolicy, Receive(dirA, bob.DeviceId));
            await using var right = new WindowsWebRtcFileSession(ownerB, kb, bob, alice, rightPolicy, Receive(dirB, alice.DeviceId));
            var loopA = left.RunAsync(token); var loopB = right.RunAsync(token);
            try
            {
                byte[] bytes = RandomNumberGenerator.GetBytes(196_731);
                var source = Path.Combine(root, "ordinary.bin");
                await File.WriteAllBytesAsync(source, bytes, token);
                var id = Guid.NewGuid().ToString("D");
                var sending = left.SendFileAsync(id, source, null, token);
                await userReady.Task.WaitAsync(token);
                Require(!sending.IsCompleted && !left.PairingApproved.IsCompleted && !right.PairingApproved.IsCompleted &&
                    !approve.Task.IsCompleted && Volatile.Read(ref remembered) == 0, "Pairing or file authorization preceded both comparisons.");
                compare.SetResult();
                await Task.WhenAll(left.PairingApproved, right.PairingApproved).WaitAsync(token);
                Require(leftCode is { Length: 6 } && leftCode == rightCode && Volatile.Read(ref remembered) == 1,
                    "The signed session did not produce mutual identical codes and exactly one opt-in.");
                await approve.Task.WaitAsync(token);
                Require(Directory.GetFileSystemEntries(dirB).Length == 0 && !sending.IsCompleted, "A file was accepted before local approval.");
                delay = false; release.SetResult();
                if (!accept)
                {
                    try { await sending; throw new Exception("A declined transfer succeeded."); }
                    catch (IOException) { }
                    Require(Directory.GetFileSystemEntries(dirB).Length == 0 && !loopB.IsCompleted, "Decline created a file or terminated the owner.");
                    return;
                }
                var receipt = await sending;
                var hash = Convert.ToHexStringLower(SHA256.HashData(bytes));
                Require(receipt.TransferId == id && receipt.Bytes == bytes.Length && receipt.FileHash == hash &&
                    (await File.ReadAllBytesAsync(Path.Combine(dirB, "ordinary.bin"), token)).SequenceEqual(bytes), "First direction failed disk readback or receipt verification.");
                var reverse = await right.SendFileAsync(Guid.NewGuid().ToString("D"), Path.Combine(dirB, "ordinary.bin"), null, token);
                Require(reverse.FileHash == hash && reverse.Bytes == bytes.Length &&
                    (await File.ReadAllBytesAsync(Path.Combine(dirA, "ordinary.bin"), token)).SequenceEqual(bytes), "Reverse direction failed disk readback or receipt verification.");
                Require(nativeA is not null || (rawA.Messages > 30 && rawB.Messages > 30), "The multi-chunk transfer never crossed the helper fragment boundary.");
            }
            finally
            {
                timeout.Cancel();
                try { await Task.WhenAll(loopA, loopB); } catch (OperationCanceledException) { }
            }
        }
        finally { Directory.Delete(root, true); }
    }

    private static async Task<(RemoteControlPairingMaterial, RemoteControlPairingMaterial, WebRtcAppSecureSessionKeys,
        WebRtcAppSecureSessionKeys, LiveWebRtcProductControlContext, LiveWebRtcProductControlContext)> CreateOwnersAsync(
        IWebRtcProductControlPlane a, IWebRtcProductControlPlane b, CancellationToken token)
    {
        const string one = "id:11111111-1111-1111-1111-111111111111", two = "id:22222222-2222-2222-2222-222222222222";
        if (!OperatingSystem.IsWindows())
        {
            var forward = RandomNumberGenerator.GetBytes(32); var backwards = RandomNumberGenerator.GetBytes(32);
            var transcript = RandomNumberGenerator.GetBytes(32);
            var first = Peer(one, "One", 11); var second = Peer(two, "Two", 22);
            return (first, second, new(WebRtcAppSecureRole.Initiator, "test-secure-room", transcript, forward, backwards),
                new(WebRtcAppSecureRole.Responder, "test-secure-room", transcript, backwards, forward),
                Context(a, second, "offer"), Context(b, first, "answer"));
        }

        if (!MLDsa.IsSupported || !MLKem.IsSupported) throw new PlatformNotSupportedException("Native Windows ML-DSA and ML-KEM are required.");
        using var signingA = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        using var signingB = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        using var kemA = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
        using var kemB = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
        var alice = RemoteControlPairingMaterial.Create(one, "One", signingA.ExportMLDsaPublicKey(), kemA.ExportEncapsulationKey());
        var bob = RemoteControlPairingMaterial.Create(two, "Two", signingB.ExportMLDsaPublicKey(), kemB.ExportEncapsulationKey());
        var skA = signingA.ExportMLDsaPrivateKey(); var skB = signingB.ExportMLDsaPrivateKey(); var dkB = kemB.ExportDecapsulationKey();
        try
        {
            using var cryptoA = new WebRtcProductPqcHandshakeCryptoProvider(new WebRtcProductPqcHandshakeCryptoProviderOptions(
                skA, bob.MlKem768PublicKey, initiatorSuiteWireId: WebRtcProductHandshakeCodec.SuiteMlKem768Mldsa65ForwardSecure));
            using var cryptoB = new WebRtcProductPqcHandshakeCryptoProvider(new WebRtcProductPqcHandshakeCryptoProviderOptions(
                skB, ReadOnlyMemory<byte>.Empty, dkB));
            var storeA = new WebRtcProductSecureSessionStore(); var storeB = new WebRtcProductSecureSessionStore();
            try
            {
                var wait = new WebRtcProductHandshakeDriver(cryptoB, storeB).StartResponderAsync(Context(b, alice, "answer") with
                    { SecureSessionState = WebRtcProductControlSecureSessionState.TransportOnly, SessionIncarnation = null }, token);
                var start = new WebRtcProductHandshakeDriver(cryptoA, storeA).StartInitiatorAsync(Context(a, bob, "offer") with
                    { SecureSessionState = WebRtcProductControlSecureSessionState.TransportOnly, SessionIncarnation = null }, token);
                var owners = await Task.WhenAll(start, wait);
                return (alice, bob, storeA.RequireEstablishedKeys(owners[0]), storeB.RequireEstablishedKeys(owners[1]), owners[0], owners[1]);
            }
            finally { storeA.ClearAllForGlobalShutdown(); storeB.ClearAllForGlobalShutdown(); }
        }
        finally { CryptographicOperations.ZeroMemory(skA); CryptographicOperations.ZeroMemory(skB); CryptographicOperations.ZeroMemory(dkB); }
    }

    private static async Task NativeRememberAndReconnect()
    {
        var root = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "webrtc-first-pair-" + Guid.NewGuid().ToString("N"))).FullName;
        string? lastTranscript = null;
        try
        {
            using (var left = await RemoteControlIdentityStore.LoadOrCreateAsync(Path.Combine(root, "one"), "One"))
            using (var right = await RemoteControlIdentityStore.LoadOrCreateAsync(Path.Combine(root, "two"), "Two"))
            {
                await Session(left, right, reject: true, remembered: false);
                await Session(left, right, reject: false, remembered: false);
            }
            using var reopenedA = await RemoteControlIdentityStore.LoadOrCreateAsync(Path.Combine(root, "one"), "One");
            using var reopenedB = await RemoteControlIdentityStore.LoadOrCreateAsync(Path.Combine(root, "two"), "Two");
            await Session(reopenedB, reopenedA, reject: false, remembered: true);
        }
        finally { Directory.Delete(root, true); }

        async Task Session(RemoteControlIdentityStore left, RemoteControlIdentityStore right, bool reject, bool remembered)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            var token = deadline.Token;
            var a = left.PublicMaterial; var b = right.PublicMaterial;
            WebRtcPairingPolicy Policy(RemoteControlIdentityStore store, RemoteControlPairingMaterial other, bool decline)
            {
                var known = store.FindWebRtcIdentity(other.DeviceId, other.ProtocolPublicKeyFingerprint);
                Require((known.Compared is not null) == remembered && known.PreviouslyTrusted is null, "The scoped authority did not survive correctly.");
                return new(remembered, false, (_, code, _) =>
                {
                    Require(!remembered && code.Length == 6, "Unexpected comparison on a remembered connection.");
                    return Task.FromResult(decline ? WebRtcComparison.Reject : WebRtcComparison.Remember);
                }, store.RememberComparedWebRtcPeer);
            }
            var rawA = new Wire(); var rawB = new Wire(); rawA.Other = rawB; rawB.Other = rawA;
            var laneA = new WebRtcProductFramedPlane(rawA); var laneB = new WebRtcProductFramedPlane(rawB);
            using var ca = left.CreateWebRtcInitiator(b); using var cb = right.CreateCryptoProvider();
            var sa = new WebRtcProductSecureSessionStore(); var sb = new WebRtcProductSecureSessionStore();
            try
            {
                var responding = new WebRtcProductHandshakeDriver(cb, sb).StartResponderAsync(Context(laneB, a, "answer") with
                    { SecureSessionState = WebRtcProductControlSecureSessionState.TransportOnly, SessionIncarnation = null }, token);
                var initiating = new WebRtcProductHandshakeDriver(ca, sa).StartInitiatorAsync(Context(laneA, b, "offer") with
                    { SecureSessionState = WebRtcProductControlSecureSessionState.TransportOnly, SessionIncarnation = null }, token);
                var owners = await Task.WhenAll(initiating, responding);
                using var ka = sa.RequireEstablishedKeys(owners[0]); using var kb = sb.RequireEstablishedKeys(owners[1]);
                string transcript = Convert.ToHexString(ka.TranscriptHash.Span);
                Require(lastTranscript != transcript && ka.TranscriptHash.Span.SequenceEqual(kb.TranscriptHash.Span),
                    "Each pairing must bind the new, mutually signed handshake.");
                lastTranscript = transcript;
                await using var first = new WindowsWebRtcFileSession(owners[0], ka, a, b, Policy(left, b, false));
                await using var second = new WindowsWebRtcFileSession(owners[1], kb, b, a, Policy(right, a, reject));
                var loops = Task.WhenAll(first.RunAsync(token), second.RunAsync(token));
                try
                {
                    if (reject)
                    {
                        try { await Task.WhenAll(first.PairingApproved, second.PairingApproved).WaitAsync(token); }
                        catch (Exception e) when (e is WebRtcPairingDeclinedException or OperationCanceledException) { }
                        Require(!token.IsCancellationRequested && !first.PairingApproved.IsCompletedSuccessfully &&
                            !second.PairingApproved.IsCompletedSuccessfully, "A rejected pair became usable or stalled.");
                    }
                    else await Task.WhenAll(first.PairingApproved, second.PairingApproved).WaitAsync(token);
                    Require((left.FindWebRtcIdentity(b.DeviceId, b.ProtocolPublicKeyFingerprint).Compared is not null) == !reject &&
                        (right.FindWebRtcIdentity(a.DeviceId, a.ProtocolPublicKeyFingerprint).Compared is not null) == !reject &&
                        left.TrustedPeers.Count == 0 && right.TrustedPeers.Count == 0,
                        "Mutual decisions did not match both actual scoped stores.");
                }
                finally
                {
                    deadline.Cancel();
                    try { await loops; } catch (OperationCanceledException) { } catch (WebRtcPairingDeclinedException) when (reject) { }
                }
            }
            finally { sa.ClearAllForGlobalShutdown(); sb.ClearAllForGlobalShutdown(); }
        }
    }

    private static async Task PairingBoundaries()
    {
        byte[] transcript = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        var hash = Convert.ToHexStringLower(transcript);
        var peer = Peer("id:valid-peer", "Peer", 6);
        var identity = new LanProductIdentity(peer.DeviceId, [new(0x0101, peer.MlKem768PublicKey.ToArray())], 0,
            [new("ML-DSA-65", peer.ProtocolPublicKey.ToArray())], Capabilities: [WindowsWebRtcPairing.Capability]);
        var sent = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int writes = 0;
        var opt = new WebRtcPairingPolicy(false, false, (_, _, _) => Task.FromResult(WebRtcComparison.Remember), (_, _) => writes++);
        using var bound = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        Task Send(byte[] _, CancellationToken ct) { ct.ThrowIfCancellationRequested(); sent.TrySetResult(); return Task.CompletedTask; }
        static JsonElement Vote(string hash, bool yes) => JsonSerializer.SerializeToElement(new {
            pairingSASDecision = new { version = 1, transcriptHashHex = hash, accepted = yes } });
        static void Reject(Action attempt) { try { attempt(); } catch (Exception e) when (e is InvalidDataException or WebRtcPairingDeclinedException) { return; } throw new Exception("Invalid vote/identity accepted."); }
        static async Task Declined(Task attempt) { try { await attempt; } catch (Exception e) when (e is InvalidDataException or WebRtcPairingDeclinedException) { return; } throw new Exception("Pairing succeeded."); }
        Require(WindowsWebRtcPairing.VerificationCode(transcript) == "879057", "Cross-platform transcript SAS differs.");
        var comparison = new WindowsWebRtcPairing(peer, transcript, opt);
        comparison.ReceiveIdentity(identity);
        var running = comparison.RunAsync(Send, bound.Token);
        await sent.Task.WaitAsync(bound.Token);
        Reject(() => comparison.ReceiveVote(Vote(new string('f', 64), true), 180));
        Reject(() => comparison.ReceiveVote(Vote(hash, false), 180));
        await Declined(running);
        Require(writes == 0, "A remote mismatch after local acceptance wrote trust.");
        var mismatch = new WindowsWebRtcPairing(peer, transcript, opt with { Compare = (_,_,_) => Task.FromResult(WebRtcComparison.Reject) });
        mismatch.ReceiveIdentity(identity); mismatch.ReceiveVote(Vote(hash, true), 180);
        await Declined(mismatch.RunAsync(Send, bound.Token));
        Require(writes == 0, "Local mismatch with a remote accept wrote trust.");
        var reconnect = new WindowsWebRtcPairing(peer, transcript, opt with {
            Remembered = true, Compare = (_, _, _) => throw new Exception("Remembered signed peer unexpectedly prompted.") });
        reconnect.ReceiveIdentity(identity);
        var resumed = reconnect.RunAsync(Send, bound.Token);
        Require(!reconnect.Approved.IsCompleted, "Remembered peer skipped fresh remote approval.");
        reconnect.ReceiveVote(Vote(hash, true), 180);
        await resumed;
        Require(writes == 0 && (await reconnect.Approved).HasSameProtocolIdentity(peer), "Fresh reconnect lost its signed owner.");
        var changed = new WindowsWebRtcPairing(peer, transcript, opt);
        Reject(() => changed.ReceiveIdentity(identity with { ProtocolIdentityPublicKeys = [new("ML-DSA-65", new byte[1952])] }));
        var downgraded = new WindowsWebRtcPairing(peer, transcript, opt with { Remembered = true, LegacyTrusted = true });
        downgraded.ReceiveIdentity(identity with { Capabilities = [] });
        await Declined(downgraded.RunAsync(Send, bound.Token));
    }

    private static Task Framing()
    {
        var wire = new Wire(); var plane = new WebRtcProductFramedPlane(wire);
        wire.Inject([0,0]); wire.Inject([0,3,1,2]); wire.Inject([3,0,0,0,1,4]);
        var data = new List<byte[]>(); plane.MessageReceived += data.Add;
        Require(data.Count == 2 && data[0].SequenceEqual(new byte[]{1,2,3}) && data[1].SequenceEqual(new byte[]{4}), "Framing lost the initial handoff or message boundary.");
        try { wire.Inject([255,255,255,255]); throw new Exception("Oversized payload accepted."); }
        catch (InvalidDataException) { }
        Require(!plane.IsConnected, "The invalid stream remained usable.");
        return Task.CompletedTask;
    }
    private static void Require(bool value, string message) { if (!value) throw new InvalidOperationException(message); }
}
