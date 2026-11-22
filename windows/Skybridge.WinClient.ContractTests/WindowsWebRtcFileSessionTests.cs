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
            var alice = Peer("id:11111111-1111-1111-1111-111111111111", "One", 11);
            var bob = Peer("id:22222222-2222-2222-2222-222222222222", "Two", 22);
            var rawA = new Wire(); var rawB = new Wire(); rawA.Other = rawB; rawB.Other = rawA;
            var a = new WebRtcProductFramedPlane(nativeA ?? rawA); var b = new WebRtcProductFramedPlane(nativeB ?? rawB);
            var forward = RandomNumberGenerator.GetBytes(32); var backwards = RandomNumberGenerator.GetBytes(32);
            var transcript = RandomNumberGenerator.GetBytes(32);
            using var ka = new WebRtcAppSecureSessionKeys(WebRtcAppSecureRole.Initiator, "crypto-room", transcript, forward, backwards);
            using var kb = new WebRtcAppSecureSessionKeys(WebRtcAppSecureRole.Responder, "crypto-room", transcript, backwards, forward);
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
            await using var left = new WindowsWebRtcFileSession(Context(a, bob, "offer"), ka, alice, bob, Receive(dirA, bob.DeviceId));
            await using var right = new WindowsWebRtcFileSession(Context(b, alice, "answer"), kb, bob, alice, Receive(dirB, alice.DeviceId));
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
