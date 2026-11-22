using System.Net;
using System.Collections.Immutable;
using System.Security.Cryptography;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.FileTransfer;
using Skybridge.WinClient.Services.RemoteControl;

internal static class LanFileFirstPairTests
{
    private sealed class Operator : ILanPibApprovalPresenter
    {
        internal bool Accept;
        internal TaskCompletionSource<string> Digits = NewDigits();
        internal static TaskCompletionSource<string> NewDigits() => new(TaskCreationOptions.RunContinuationsAsynchronously);
        public bool StageCandidate => true;
        public Task<bool> ShowAsync(LanPibApprovalRequest request, CancellationToken token)
        {
            request.RequireCurrent(); token.ThrowIfCancellationRequested(); Digits.TrySetResult(request.SasCode);
            return Task.FromResult(Accept);
        }
    }

    internal static async Task Run()
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 19041)) throw new PlatformNotSupportedException("Native Windows identity and ordinary file reception are required.");
        var directory = Directory.CreateTempSubdirectory("windows-lan-file-first-pair-");
        try
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45));
            var ct = deadline.Token;
            var sourceDir = Directory.CreateDirectory(Path.Combine(directory.FullName, "sender"));
            var dest = Directory.CreateDirectory(Path.Combine(directory.FullName, "received"));
            await using var caller = new WindowsDeviceWorkspace(sourceDir.FullName, "Sender");
            var left = await caller.GetConnectionIdentityAsync(ct);
            var receiverDir = Directory.CreateDirectory(Path.Combine(directory.FullName, "receiver"));
            using var right = await RemoteControlIdentityStore.LoadOrCreateAsync(receiverDir.FullName, "Receiver", ct);
            void Require(bool ok, string why) { if (!ok) throw new InvalidOperationException(why); }
            Require(left.FileTransferPeers.Count == 0 && right.FileTransferPeers.Count == 0, "The initial identities already had trust.");
            var approval = new Operator();
            var pib = right.CreatePibResponder(approval, ct.ThrowIfCancellationRequested, filesOnly: true);
            var skr = right.CreateKemRefreshResponder(ct.ThrowIfCancellationRequested, QPeriaptPeerPlatform.LocalVersion(), filesOnly: true);
            var ready = new TaskCompletionSource<LanProductControlSession>(TaskCreationOptions.RunContinuationsAsynchronously);
            int offers = 0;
            var saved = new TaskCompletionSource<ClassicFileTransferResult>(TaskCreationOptions.RunContinuationsAsynchronously);
            await using var file = new ClassicFileTransferListener(id =>
            {
                var session = ready.Task.IsCompletedSuccessfully ? ready.Task.Result : throw new IOException("Missing admitted MAIN.");
                Require(RemoteControlHandshakeBinding.CanonicalDeviceId(id) == session.PeerDeviceId, "File socket changed sender.");
                return session;
            }, dest.FullName, (_, _, _) => { offers++; return Task.FromResult(true); }, new Progress<ClassicFileTransferProgress>(),
                (_, result, failure) => { if (failure != null) saved.TrySetException(failure); else if (result != null) saved.TrySetResult(result); },
                ct, IPAddress.Loopback, ct.ThrowIfCancellationRequested);
            var receiverPort = file.Port;
            var senderDownloads = Directory.CreateDirectory(Path.Combine(directory.FullName, "return-files"));
            await using var reverseFiles = new ClassicFileTransferListener(caller.RequireIncomingControlSession, senderDownloads.FullName,
                (_, _, _) => Task.FromResult(true), new Progress<ClassicFileTransferProgress>(), (_, _, _) => { },
                ct, IPAddress.Loopback, ct.ThrowIfCancellationRequested);
            var senderPort = reverseFiles.Port;
            var host = right.PublicMaterial;
            await using var main = new LanProductControlListener(async (client, token) =>
            {
                var accepted = await LanProductControlResponder.AcceptWithBootstrapAsync(client,
                    new("Receiver account", "receiver-account", host.DeviceId, host.DeviceName), host,
                    () => right.FileTransferPeers, right.CreateCryptoProvider, receiverPort, token, skr, pib, advertiseGeneralFiles: true);
                if (accepted is not LanIncomingControlResult.Main admitted) return;
                await using var session = admitted.Session;
                ready.TrySetResult(session);
                await session.Completion;
            }, () => !ct.IsCancellationRequested);
            main.Start(IPAddress.Loopback, ct);
            var port = checked((ushort)((IPEndPoint)main.RequireLiveListener().LocalEndpoint).Port);
            var address = IPAddress.Loopback.ToString();
            var selected = new DiscoveryBrowserPeerCandidate(new(CoreDiscoveryServiceKind.FileTransfer, host.DeviceId, host.DeviceName,
                CorePeerPlatform.Windows, "Windows", host.ProtocolPublicKeyFingerprint, "file_transfer", "1", PeerCapabilities.Windows()), "", "")
            {
                Routes = new(new(SkyBridgeProtocolConstants.TcpControlDnsSdService, address, port, "Receiver._skybridge._tcp.local","resolved-dns-sd-endpoint"),
                    new(SkyBridgeProtocolConstants.FileTransferDnsSdService, address, file.Port, "Receiver._skybridge-xfer._tcp.local","resolved-dns-sd-endpoint"), null)
            };
            var account = new RemoteControlViewerAccount("Sender account", "sender-account");
            int comparisons = 0;
            async Task<bool> Compare(string name, string code, CancellationToken token)
            {
                Require(name == host.DeviceName && code == await approval.Digits.Task.WaitAsync(token), "The screens did not show the same transaction.");
                Require(left.FileTransferPeers.Count == 0 && right.FileTransferPeers.Count == 0, "A preview or local match prematurely committed a peer.");
                comparisons++; return true;
            }
            async Task MustFail(Func<Task> attempt)
            {
                try { await attempt(); }
                catch (Exception e) when (e is IOException or InvalidDataException or CryptographicException) { return; }
                throw new InvalidOperationException("An unapproved peer established a file session.");
            }
            using var alternate = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
            await using (var changedAck = new LanProductControlListener(async (client, token) =>
            {
                await using var wire = new TcpProductControlTransport(client, LanBootstrapWire.MaximumBytes, LanBootstrapWire.MaximumBytes);
                var bytes = await wire.ReadAsync(token);
                if (LanBootstrapWire.ReadDiscriminator(bytes.Span) == "protocolIdentityBindingRequest")
                {
                    var pending = LanPibWire.DecodeRequest(bytes.Span);
                    var pendingCandidate = pib.CreateCandidate(pending, token);
                    await wire.SendAsync(LanPibWire.EncodeCandidate(pendingCandidate), token);
                    return;
                }
                var c = LanPibWire.DecodeConfirm(bytes.Span);
                var ack = new LanPibFinalAck(3, c.TransactionId, c.RequesterDeviceId, c.ResponderDeviceId,
                    c.RequesterProtocolIdentityFingerprint, c.ResponderProtocolIdentityFingerprint, c.RequestNonce, c.ConfirmationNonce,
                    c.RequestHashHex, c.CandidateHashHex, LanPibCanonical.ConfirmHash(c), c.SasTranscriptHashHex, true,
                    LanProductControlMessages.Timestamp(DateTimeOffset.UtcNow), c.ExpiresAt, []);
                ack = ack with { ResponderSignature = alternate.SignData(LanPibCanonical.FinalAckPreimage(ack)).ToImmutableArray() };
                await wire.SendAsync(LanPibWire.EncodeFinalAck(ack), token);
            }, () => true))
            {
                changedAck.Start(IPAddress.Loopback, ct);
                var route = selected.Routes.Control! with { Port = checked((ushort)((IPEndPoint)changedAck.RequireLiveListener().LocalEndpoint).Port) };
                await MustFail(() => left.PrepareLanFilePeerAsync(host.DeviceId, host.ProtocolPublicKeyFingerprint, route,
                    (_, _, _) => Task.FromResult(true), ct.ThrowIfCancellationRequested, ct));
                Require(left.FileTransferPeers.Count == 0 && right.FileTransferPeers.Count == 0, "A changed final ACK signer created trust.");
            }
            approval.Digits = Operator.NewDigits();
            await MustFail(() => caller.ConnectControlAsync(selected, account, senderPort, ct, Compare, ct.ThrowIfCancellationRequested));
            Require(left.FileTransferPeers.Count == 0 && right.FileTransferPeers.Count == 0 && !ready.Task.IsCompleted,
                "A receiving operator's refusal granted trust or opened MAIN.");
            approval.Accept = true; approval.Digits = Operator.NewDigits();
            var impersonator = selected with { Peer = selected.Peer with { PublicKeyFingerprint = new string('c',64) } };
            await MustFail(() => caller.ConnectControlAsync(impersonator, account, senderPort, ct, Compare, ct.ThrowIfCancellationRequested));
            Require(left.FileTransferPeers.Count == 0 && right.FileTransferPeers.Count == 0, "A signer substitution created trust.");
            approval.Digits = Operator.NewDigits();
            var outgoing = await caller.ConnectControlAsync(selected, account, senderPort, ct, Compare, ct.ThrowIfCancellationRequested);
            var incoming = await ready.Task.WaitAsync(ct);
            Require(comparisons == 2 && left.FileTransferPeers.Single().ProtocolPublicKeyFingerprint == host.ProtocolPublicKeyFingerprint &&
                right.FileTransferPeers.Single().ProtocolPublicKeyFingerprint == left.PublicMaterial.ProtocolPublicKeyFingerprint &&
                left.TrustedPeers.Count == 0 && right.TrustedPeers.Count == 0 && incoming.LocalIdentity.Capabilities is ["file_transfer"],
                "First pairing did not create only mutually approved file authorities.");
            await using (var changedKem = new LanProductControlListener(async (client, token) =>
            {
                await using var wire = new TcpProductControlTransport(client, LanBootstrapWire.MaximumBytes, LanBootstrapWire.MaximumBytes);
                var request = SignedLanKemRefreshWire.DecodeRequest((await wire.ReadAsync(token)).Span);
                var response = skr.Respond(request, token);
                response = response with { Signature = alternate.SignData(SignedLanKemRefreshCanonical.ResponsePreimage(response)).ToImmutableArray() };
                await wire.SendAsync(SignedLanKemRefreshWire.EncodeResponse(response), token);
            }, () => true))
            {
                changedKem.Start(IPAddress.Loopback, ct);
                var route = selected.Routes.Control! with { Port = checked((ushort)((IPEndPoint)changedKem.RequireLiveListener().LocalEndpoint).Port) };
                await MustFail(() => left.PrepareLanFilePeerAsync(host.DeviceId, host.ProtocolPublicKeyFingerprint, route,
                    (_, _, _) => throw new Exception("Existing signer should use signed KEM refresh."), ct.ThrowIfCancellationRequested, ct));
            }
            outgoing.RequireFileTransferRoute(selected);
            var target = outgoing.CurrentFileRecipient() ?? throw new InvalidOperationException("The ordinary file page has no recipient.");
            var bytes = RandomNumberGenerator.GetBytes(151_121);
            var path = Path.Combine(sourceDir.FullName, "first-ordinary.bin");
            await File.WriteAllBytesAsync(path, bytes, ct);
            var receipt = await ClassicFileTransferSender.SendToRecipientAsync(outgoing, target, Guid.NewGuid().ToString("D"), path, null, ct);
            var persisted = await saved.Task.WaitAsync(ct);
            Require(offers == 1 && receipt.Bytes == bytes.Length && receipt.FileHash == Convert.ToHexStringLower(SHA256.HashData(bytes)) &&
                persisted.FileHash == receipt.FileHash && (await File.ReadAllBytesAsync(Path.Combine(dest.FullName,"first-ordinary.bin"), ct)).SequenceEqual(bytes),
                "An ordinary first transfer did not receive consent, exact bytes and its authenticated receipt.");
            var backTarget = incoming.CurrentFileRecipient() ?? throw new InvalidOperationException("The responder did not find the returning file route.");
            var back = await ClassicFileTransferSender.SendToRecipientAsync(incoming, backTarget, Guid.NewGuid().ToString("D"),
                Path.Combine(dest.FullName, "first-ordinary.bin"), null, ct);
            Require(back.Bytes == bytes.Length && back.FileHash == receipt.FileHash &&
                (await File.ReadAllBytesAsync(Path.Combine(senderDownloads.FullName, "first-ordinary.bin"), ct)).SequenceEqual(bytes),
                "The reverse first-session file lost its signed owner, disk bytes or receipt.");
            await caller.DisconnectControlSessionsAsync();
            await main.StopAsync();
        }
        finally { directory.Delete(true); }
    }
}
