using System.Net;
using System.Runtime.Versioning;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.Audio;
using Skybridge.WinClient.Services.Connection;
using Skybridge.WinClient.Services.FileTransfer;
using Skybridge.WinClient.Services.RemoteControl;

[SupportedOSPlatform("windows10.0.19041")]
internal static class UsbControlWorkspaceTests
{
    internal static IEnumerable<(string, Func<Task>)> Cases =>
    [
        ("Windows USB MAIN runs native forward-secret PQC Finished and encrypted identity admission", () => NativeMain(false)),
        ("Windows USB MAIN automatically selects the matching native Q policy and exact identity", () => NativeMain(true)),
        ("Windows USB MAIN cannot publish after account revocation while handshake is pending", RevokedHandshake),
        ("Windows USB MAIN offline access binds the exact prior device pair without bearer authentication", () => NativeOfflineMain(false)),
        ("Windows USB MAIN rejects a discovery alias without the exact encrypted account identity", () => NativeOfflineMain(true))
    ];
    private sealed class Approval : ILanPibApprovalPresenter
    {
        public Task<bool> ShowAsync(LanPibApprovalRequest request, CancellationToken token)
        { token.ThrowIfCancellationRequested(); request.RequireCurrent(); return Task.FromResult(true); }
    }
    private static AccountDeviceAuthentication Authentication() => AccountDeviceAuthentication.FromVerifiedSession(
        AccountAudioAuthorizationTests.Token().AccessToken ?? throw new InvalidDataException("Missing controlled account token."),
        SessionAuthority.ForSupabaseProject("https://audio-account-test.supabase.co"), "audio-user");
    private static UsbMuxConnector Connector(NativeUsbDiscoveryFixture peer) => new(token => UsbMuxConnector.ConnectSocket(peer.Endpoint, token));
    private static async Task NativeMain(bool policyBound)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        var directory = Directory.CreateTempSubdirectory("skybridge-usb-main-");
        try
        {
            await using var peer = new NativeUsbDiscoveryFixture(pairingApproval: new Approval(), policyBoundMain: policyBound);
            var connector = Connector(peer); using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(40));
            var selected = await new UsbPeerDiscoveryClient(connector).InspectAsync(NativeUsbDiscoveryFixture.Serial, limit.Token);
            var authentication = Authentication(); var account = new AccountAudioAuthorization(AudioAccountScope.From(authentication));
            await using (var workspace = new WindowsDeviceWorkspace(directory.FullName, "USB requester"))
            {
                await workspace.PairUsbPeerAsync(selected, authentication, account, new Approval(), limit.Token, connector);
                string path = Path.Combine(directory.FullName,"remote-control-identity.bin"); var before = await File.ReadAllBytesAsync(path, limit.Token);
                var session = await workspace.ConnectUsbControlAsync(selected, authentication, account, new("USB account","fixture"), limit.Token, connector);
                var suite = await peer.MainEstablished.Task.WaitAsync(limit.Token);
                Require(suite == (policyBound ? WebRtcProductHandshakeCodec.SuiteQPeriaptPolicyBound :
                    WebRtcProductHandshakeCodec.SuiteMlKem768Mldsa65ForwardSecure) && session.IsReady &&
                    session.Carrier is ProductControlCarrier.Usb && session.PeerHandshakeIdentity.Fingerprint == selected.Response.Identity.Fingerprint,
                    "Native USB MAIN lost its route, actual signer, Finished checks or forward-secret PQC suite.");
                session.RequireUsbRoute(selected, account.Scope);
                Require(ReferenceEquals(session, workspace.RequireIncomingControlSession(session.PeerDeviceId)), "The workspace did not retain the exact session owner.");
                var reused = await workspace.ConnectUsbControlAsync(selected, authentication, account, new("USB account","fixture"), limit.Token, connector);
                Require(ReferenceEquals(session,reused) && peer.MainAttempts == 1 && peer.KeyRefreshReplies == 1,
                    "A matching live USB session was recreated or refreshed unnecessarily.");
                var visible = workspace.ReadConnectedUsbPeers().Single();
                Require(visible.Route == UsbControlRoute.From(selected) && !visible.AudioReceiverInstalled,
                    "The UI lost its exact USB route or implied an audio consumer that was not installed.");
                var binding = session.RequireAudioIdentityBinding();
                Require(binding.PeerProtocolIdentity.Fingerprint == selected.Response.Identity.Fingerprint &&
                    binding.Role == ProductHandshakeRole.Initiator && binding.AttemptId.Length == 32,
                    "USB audio identity did not derive from actual native MAIN evidence.");
                await Reject<InvalidOperationException>(() => Task.Run(() => _ = session.RemoteAddress));
                var metadata = new ClassicFileMetadata("transfer","f",0,new string('a',64),65536,2,SenderDeviceId:session.PeerDeviceId);
                await Reject<InvalidDataException>(() => Task.Run(() => session.AuthorizeIncomingTransfer(metadata,IPAddress.Loopback)));
                Require(session.LocalFileTransferPort is null && workspace.OriginalAudioFiles.CanReceiveFor(session) &&
                    workspace.OriginalAudioFiles.UsbReceiverFor(session) is { } registration && registration.IsCurrentFor(session),
                    "USB connection did not install its exact return owner independently of a TCP listener.");
                var after = await File.ReadAllBytesAsync(path,limit.Token);
                Require(before.AsSpan().SequenceEqual(after), "USB handshake persisted temporary KEM or replaced trust.");
                account.Revoke(); Require(!session.IsReady, "Revoked account retained USB readiness.");
                Require(workspace.ReadConnectedUsbPeers().Count == 0, "Revoked USB session still appeared connected.");
                await workspace.DisconnectControlSessionsAsync();
                await peer.MainEnded.Task.WaitAsync(limit.Token);
            }
            using var restored = await RemoteControlIdentityStore.LoadExistingAsync(directory.FullName,"USB requester");
            Require(restored.TrustedMaterials.Single().IsProtocolIdentityOnly, "USB MAIN changed durable identity-only trust.");
        }
        finally { Directory.Delete(directory.FullName,recursive:true); }
    }
    private static async Task NativeOfflineMain(bool wrongDeclaration)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        var directory = Directory.CreateTempSubdirectory("skybridge-usb-offline-");
        try
        {
            await using var peer = new NativeUsbDiscoveryFixture(pairingApproval: new Approval());
            var connector = Connector(peer); using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(50));
            var selected = await new UsbPeerDiscoveryClient(connector).InspectAsync(NativeUsbDiscoveryFixture.Serial, limit.Token);
            var authentication = Authentication(); var scope = AudioAccountScope.From(authentication);
            await using (var enrolling = new WindowsDeviceWorkspace(directory.FullName, "USB requester"))
                await enrolling.PairUsbPeerAsync(selected, authentication, new(scope), new Approval(), limit.Token, connector);
            AudioCheckpointIdentity local;
            using (var identity = await RemoteControlIdentityStore.LoadExistingAsync(directory.FullName, "USB requester"))
            {
                var material = identity.PublicMaterial;
                local = AudioCheckpointIdentity.From(AudioDeviceIdentity.FromRegistryBinding(new CurrentPathProtocolIdentityBinding(
                    material.DeviceId, CurrentPathProtocolSigningAlgorithm.MLDsa65, material.ProtocolPublicKey.ToArray())));
            }
            var remote = AudioCheckpointIdentity.From(AudioDeviceIdentity.FromRegistryBinding(new CurrentPathProtocolIdentityBinding(
                (wrongDeclaration ? "" : "id:") + selected.Response.Identity.DeviceID,
                CurrentPathProtocolSigningAlgorithm.MLDsa65, selected.Response.Identity.PublicKey.ToArray())));
            var clock = new AudioAccountMembershipTests.Clock();
            var login = Guid.NewGuid();
            // Controlled prior account publication. Native MAIN and DPAPI identity
            // are real; protected journal recovery has its own cross-process suite.
            var checkpoint = new AudioMembershipCheckpoint(1, login, Guid.NewGuid(), scope, local, remote,
                clock.Now, new(clock.Now.WallMilliseconds + 60_000, clock.Now.ContinuousMilliseconds + 60_000),
                new AudioMembershipCheckpointTests.Continuity().Create());
            AccountAudioAuthorization Offline(params AudioMembershipCheckpoint[] values) =>
                new(scope, recovery: new(login, scope, "USB account", "fixture", values, clock.Read), offline: true);
            string path = Path.Combine(directory.FullName, "remote-control-identity.bin");
            var before = await File.ReadAllBytesAsync(path, limit.Token);
            await using var workspace = new WindowsDeviceWorkspace(directory.FullName, "USB requester");
            await using var audio = new AudioReceiveHost((_, _) =>
                throw new InvalidOperationException("Connecting USB must not enable or play audio."), workspace.OriginalAudioFiles);
            workspace.ConfigureAudioReception(audio);
            int responses = peer.Responses;
            await Reject<InvalidOperationException>(() => workspace.ConnectUsbControlAsync(selected, null, new(scope),
                new("USB account", "fixture"), limit.Token, connector));
            await Reject<InvalidOperationException>(() => workspace.ConnectUsbControlAsync(selected, null, new(scope, offline: true),
                new("USB account", "fixture"), limit.Token, connector));
            Require(peer.Responses == responses, "Missing online authentication or offline grant opened a USB transaction.");
            foreach (var invalid in new[] { checkpoint with { Local = local with { Fingerprint = new string('0', 64) } },
                checkpoint with { Peer = remote with { Fingerprint = new string('0', 64) } } })
                await Reject<AudioMembershipException>(() => workspace.ConnectUsbControlAsync(selected, null, Offline(invalid),
                    new("USB account", "fixture"), limit.Token, connector));
            Require(peer.KeyRefreshReplies == 0 && peer.MainAttempts == 0, "A changed saved device identity reached SKR or MAIN.");
            var longer = checkpoint with { EvidenceId = Guid.NewGuid(), Peer = remote with { DeviceId = "id:another-offline-peer" },
                Expires = new(clock.Now.WallMilliseconds + 120_000, clock.Now.ContinuousMilliseconds + 120_000) };
            var offline = Offline(checkpoint, longer);
            await Reject<InvalidOperationException>(() => workspace.PairUsbPeerAsync(selected, authentication, offline,
                new Approval(), limit.Token, connector));
            if (wrongDeclaration)
            {
                peer.ExpectClientHandshakeAbort = true;
                var error = await Reject<AudioMembershipException>(() => workspace.ConnectUsbControlAsync(selected, null, offline,
                    new("USB account", "fixture"), limit.Token, connector));
                await peer.MainEnded.Task.WaitAsync(limit.Token);
                Require(error.Reason == AudioMembershipFailure.IdentityChanged && peer.MainAttempts == 1 && peer.KeyRefreshReplies == 1 &&
                    workspace.ReadConnectedUsbPeers().Count == 0 &&
                    audio.ReadSnapshot().ConnectedDevices == 0, "A discovery alias published MAIN or installed audio authority.");
                await Reject<InvalidDataException>(() => Task.Run(() => workspace.RequireIncomingControlSession("id:" + selected.Response.Identity.DeviceID)));
                return;
            }
            var session = await workspace.ConnectUsbControlAsync(selected, null, offline, new("USB account", "fixture"), limit.Token, connector);
            await peer.MainEstablished.Task.WaitAsync(limit.Token);
            Require(session.IsReady && workspace.ReadConnectedUsbPeers().Single().AudioReceiverInstalled &&
                peer.MainAttempts == 1 && peer.KeyRefreshReplies == 1, "Finite offline authority did not establish its exact native USB session.");
            var binding = session.RequireAudioIdentityBinding();
            Require(checkpoint.Peer.Matches(AudioDeviceIdentity.From(binding.PeerDeviceId, binding.PeerProtocolIdentity)),
                "Offline MAIN used a discovery alias instead of the actual encrypted identity declaration.");
            var reused = await workspace.ConnectUsbControlAsync(selected, null, offline, new("USB account", "fixture"), limit.Token, connector);
            Require(ReferenceEquals(session, reused) && peer.MainAttempts == 1, "Offline route reuse replaced its exact admitted identity.");
            clock.Advance(60_000);
            Require(offline.IsCurrent && !session.IsReady && workspace.ReadConnectedUsbPeers().Count == 0,
                "Another peer's longer grant kept the expired USB route usable or visible.");
            var after = await File.ReadAllBytesAsync(path, limit.Token);
            Require(before.AsSpan().SequenceEqual(after),
                "Offline connection changed durable device trust.");
            await workspace.DisconnectControlSessionsAsync();
            await peer.MainEnded.Task.WaitAsync(limit.Token);
            clock.Advance(-60_000);
            await Reject<AudioMembershipException>(() => workspace.ConnectUsbControlAsync(selected, null, offline,
                new("USB account", "fixture"), limit.Token, connector));
            Require(peer.MainAttempts == 1 && peer.KeyRefreshReplies == 1, "Clock recovery revived expired USB authority.");
        }
        finally { Directory.Delete(directory.FullName, recursive: true); }
    }
    private static async Task RevokedHandshake()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        var directory = Directory.CreateTempSubdirectory("skybridge-usb-main-revoked-");
        try
        {
            await using var peer = new NativeUsbDiscoveryFixture(pairingApproval: new Approval());
            using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(40)); var connector = Connector(peer);
            var selected = await new UsbPeerDiscoveryClient(connector).InspectAsync(NativeUsbDiscoveryFixture.Serial,limit.Token);
            var authentication = Authentication(); var account = new AccountAudioAuthorization(AudioAccountScope.From(authentication));
            await using var workspace = new WindowsDeviceWorkspace(directory.FullName,"USB requester");
            await workspace.PairUsbPeerAsync(selected,authentication,account,new Approval(),limit.Token,connector);
            var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            peer.BeforeMainReply = async token => { entered.TrySetResult(); await release.Task.WaitAsync(token); };
            var connecting = workspace.ConnectUsbControlAsync(selected,authentication,account,new("USB account","fixture"),limit.Token,connector);
            await entered.Task.WaitAsync(limit.Token);
            try { peer.ExpectClientHandshakeAbort = true; account.Revoke(); Require(!connecting.IsCompleted,"The pending handshake was detached."); }
            finally { release.TrySetResult(); }
            await Reject<InvalidOperationException>(() => connecting);
            await peer.MainEnded.Task.WaitAsync(limit.Token);
            await Reject<InvalidDataException>(() => Task.Run(() => workspace.RequireIncomingControlSession("id:"+selected.Response.Identity.DeviceID)));
            Require(!peer.MainEstablished.Task.IsCompleted && peer.MainFailure is not null,
                "The revoked client admitted MAIN or lost the actual peer transport-abort evidence.");
        }
        finally { Directory.Delete(directory.FullName,recursive:true); }
    }
    private static void Require(bool value,string reason) { if(!value)throw new InvalidOperationException(reason); }
    private static async Task<T> Reject<T>(Func<Task> call) where T:Exception
    { try { await call(); } catch(T error) { return error; } throw new InvalidOperationException($"Expected {typeof(T).Name}."); }
}
