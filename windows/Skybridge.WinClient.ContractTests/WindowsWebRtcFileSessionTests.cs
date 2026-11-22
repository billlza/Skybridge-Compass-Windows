using System.Security.Cryptography;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.FileTransfer;
using Skybridge.WinClient.Services.RemoteControl;

internal static class WindowsWebRtcFileSessionTests
{
    internal static IReadOnlyList<(string Name, Func<Task> Run)> Cases =>
    [
        ("ordinary WebRTC files require approval and a disk-backed exact receipt in both directions", BothDirections),
        ("WebRTC file receiver decline creates no artifact and does not close the session", Decline),
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
            await using var left = new WindowsWebRtcFileSession(ownerA, ka, alice, bob, Receive(dirA, bob.DeviceId));
            await using var right = new WindowsWebRtcFileSession(ownerB, kb, bob, alice, Receive(dirB, alice.DeviceId));
            var loopA = left.RunAsync(token); var loopB = right.RunAsync(token);
            try
            {
                byte[] bytes = RandomNumberGenerator.GetBytes(196_731);
                var source = Path.Combine(root, "ordinary.bin");
                await File.WriteAllBytesAsync(source, bytes, token);
                var id = Guid.NewGuid().ToString("D");
                var sending = left.SendFileAsync(id, source, null, token);
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
