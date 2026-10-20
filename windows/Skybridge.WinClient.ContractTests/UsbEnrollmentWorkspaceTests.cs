using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.Audio;
using Skybridge.WinClient.Services.Connection;
using Skybridge.WinClient.Services.RemoteControl;
using System.Runtime.Versioning;

[SupportedOSPlatform("windows10.0.19041")]
internal static class UsbEnrollmentWorkspaceTests
{
    internal static IEnumerable<(string, Func<Task>)> Cases =>
    [
        ("Windows USB enrollment traverses native mux discovery PIB and DPAPI reload", NativeRoundTrip),
        ("Windows USB enrollment rejects changed cable identity and offline new trust", NativeAdmission),
        ("Windows USB enrollment shutdown drains approval and revocation prevents commit", NativeCancellation),
        ("Windows USB key refresh verifies native signatures without persisting temporary KEM keys", NativeKeyRefresh),
        ("Windows USB key refresh cannot create trust or accept a changed cable identity", NativeKeyRefreshAdmission)
    ];
    private sealed class Approval(Func<LanPibApprovalRequest, CancellationToken, Task<bool>> show) : ILanPibApprovalPresenter
    { public Task<bool> ShowAsync(LanPibApprovalRequest request, CancellationToken token) => show(request, token); }
    private static readonly Approval Accept = new((request, _) => { request.RequireCurrent(); return Task.FromResult(true); });
    // Controlled account publication only. Native USB, ML-DSA and DPAPI are real;
    // these tests do not establish live account-server authentication.
    private static AccountDeviceAuthentication Authentication() => AccountDeviceAuthentication.FromVerifiedSession(
        AccountAudioAuthorizationTests.Token().AccessToken ?? throw new InvalidDataException("Missing account fixture token."),
        SessionAuthority.ForSupabaseProject("https://audio-account-test.supabase.co"), "audio-user");
    private static UsbMuxConnector Connector(NativeUsbDiscoveryFixture peer) =>
        new(token => UsbMuxConnector.ConnectSocket(peer.Endpoint, token));

    private static async Task NativeRoundTrip()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        var directory = Directory.CreateTempSubdirectory("skybridge-usb-workspace-");
        try
        {
            await using var peer = new NativeUsbDiscoveryFixture(pairingApproval: Accept);
            var connector = Connector(peer);
            using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var selected = await new UsbPeerDiscoveryClient(connector).InspectAsync(NativeUsbDiscoveryFixture.Serial, limit.Token);
            var authentication = Authentication();
            var epoch = new AccountAudioAuthorization(AudioAccountScope.From(authentication));
            await using (var workspace = new WindowsDeviceWorkspace(directory.FullName, "USB test"))
            {
                await workspace.PairUsbPeerAsync(selected, authentication, epoch, Accept, limit.Token, connector);
                Require(peer.Responses == 2 && peer.PairingCommits == 1, "Enrollment omitted fresh discovery or final confirmation.");
            }
            using var identity = await RemoteControlIdentityStore.LoadExistingAsync(directory.FullName, "USB test");
            Require(identity.TrustedMaterials.Single().IsProtocolIdentityOnly &&
                identity.TrustedMaterials[0].ProtocolPublicKey.Span.SequenceEqual(selected.Response.Identity.PublicKey.AsSpan()),
                "Workspace enrollment did not retain the exact identity-only pin through DPAPI reload.");
        }
        finally { Directory.Delete(directory.FullName, recursive: true); }
    }

    private static async Task NativeAdmission()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        var directory = Directory.CreateTempSubdirectory("skybridge-usb-admission-");
        try
        {
            await using var peer = new NativeUsbDiscoveryFixture(pairingApproval: Accept);
            await using var replacement = new NativeUsbDiscoveryFixture(pairingApproval: Accept);
            using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            var selected = await new UsbPeerDiscoveryClient(Connector(peer)).InspectAsync(NativeUsbDiscoveryFixture.Serial, limit.Token);
            var authentication = Authentication();
            await using var workspace = new WindowsDeviceWorkspace(directory.FullName, "USB test");
            await Reject<InvalidOperationException>(() => workspace.PairUsbPeerAsync(selected, authentication,
                new(AudioAccountScope.From(authentication), offline: true), Accept, limit.Token, Connector(peer)));
            Require(peer.Responses == 1, "Offline audio recovery initiated new general-purpose trust.");
            await Reject<InvalidDataException>(() => workspace.PairUsbPeerAsync(selected, authentication,
                new(AudioAccountScope.From(authentication)), Accept, limit.Token, Connector(replacement)));
            Require(replacement.Responses == 1 && replacement.PairingCommits == 0 &&
                !Directory.EnumerateFiles(directory.FullName, "*", SearchOption.AllDirectories).Any(),
                "A changed cable identity reached local identity creation or peer approval.");
        }
        finally { Directory.Delete(directory.FullName, recursive: true); }
    }

    private static async Task NativeCancellation()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        foreach (bool shutdown in new[] { false, true })
        {
            var directory = Directory.CreateTempSubdirectory("skybridge-usb-cancel-");
            try
            {
                await using var peer = new NativeUsbDiscoveryFixture(pairingApproval: Accept);
                var connector = Connector(peer);
                using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(25));
                var selected = await new UsbPeerDiscoveryClient(connector).InspectAsync(NativeUsbDiscoveryFixture.Serial, limit.Token);
                var authentication = Authentication();
                var epoch = new AccountAudioAuthorization(AudioAccountScope.From(authentication));
                var shown = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                var canceled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                var approval = new Approval(async (_, token) =>
                {
                    using var registration = token.Register(() => canceled.TrySetResult());
                    shown.TrySetResult();
                    return await release.Task; // Intentionally noncooperative: the workspace must retain it.
                });
                await using var workspace = new WindowsDeviceWorkspace(directory.FullName, "USB test");
                var operation = workspace.PairUsbPeerAsync(selected, authentication, epoch, approval, limit.Token, connector);
                await shown.Task.WaitAsync(limit.Token);
                Task? close = null;
                try
                {
                    await Reject<InvalidOperationException>(() => workspace.PairUsbPeerAsync(selected, authentication, epoch, Accept, limit.Token, connector));
                    if (shutdown)
                    {
                        close = workspace.DisposeAsync().AsTask();
                        await canceled.Task.WaitAsync(limit.Token);
                        Require(!close.IsCompleted && !operation.IsCompleted, "Shutdown abandoned the approval owner.");
                    }
                    else epoch.Revoke();
                }
                finally { release.TrySetResult(true); }
                if (shutdown) await Reject<OperationCanceledException>(() => operation);
                else await Reject<InvalidOperationException>(() => operation);
                if (close is not null) await close.WaitAsync(limit.Token);
                else await workspace.DisposeAsync();
                using var identity = await RemoteControlIdentityStore.LoadExistingAsync(directory.FullName, "USB test");
                Require(identity.TrustedMaterials.Count == 0 && peer.PairingCommits == 0 && peer.Responses == 2,
                    "Cancellation or account revocation still confirmed or committed the pending trust.");
            }
            finally { Directory.Delete(directory.FullName, recursive: true); }
        }
    }

    private static async Task NativeKeyRefresh()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        var directory = Directory.CreateTempSubdirectory("skybridge-usb-key-refresh-");
        try
        {
            await using var peer = new NativeUsbDiscoveryFixture(pairingApproval: Accept);
            var connector = Connector(peer);
            using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var selected = await new UsbPeerDiscoveryClient(connector).InspectAsync(NativeUsbDiscoveryFixture.Serial, limit.Token);
            var authentication = Authentication(); var epoch = new AccountAudioAuthorization(AudioAccountScope.From(authentication));
            await using (var workspace = new WindowsDeviceWorkspace(directory.FullName, "USB test"))
            {
                await workspace.PairUsbPeerAsync(selected, authentication, epoch, Accept, limit.Token, connector);
                var identityPath = Path.Combine(directory.FullName,"remote-control-identity.bin");
                byte[] before = await File.ReadAllBytesAsync(identityPath, limit.Token);
                var lease = await workspace.RefreshUsbPeerKeysAsync(selected, authentication, epoch, limit.Token, connector);
                Require(peer.KeyRefreshReplies == 1 && peer.Responses == 3 &&
                    lease.EndpointDigest == selected.EndpointDigest && lease.PeerDeviceId == "id:" + selected.Response.Identity.DeviceID,
                    "Key refresh did not traverse fresh native discovery and exact framed reply binding.");
                Require(lease.ClaimKeys(lease.PeerDeviceId, lease.Fingerprint, lease.EndpointDigest).Single().SuiteWireId == 257,
                    "The fixture's absent Q implementation was advertised as available.");
                byte[] after = await File.ReadAllBytesAsync(identityPath, limit.Token);
                Require(before.AsSpan().SequenceEqual(after),
                    "Temporary refreshed KEM material rewrote persistent pairing authority.");
                using var caller = new CancellationTokenSource(TimeSpan.FromSeconds(15));
                var cancelable = await workspace.RefreshUsbPeerKeysAsync(selected, authentication, epoch, caller.Token, connector);
                caller.Cancel();
                await Reject<OperationCanceledException>(() => Task.Run(cancelable.RequireCurrent));
                epoch.Revoke(); await Reject<InvalidOperationException>(() => Task.Run(lease.RequireCurrent));
                await Reject<InvalidOperationException>(() => workspace.RefreshUsbPeerKeysAsync(selected, authentication, epoch, limit.Token, connector));
                Require(peer.Responses == 4, "Revoked account initiated another USB refresh.");
            }
            using var restored = await RemoteControlIdentityStore.LoadExistingAsync(directory.FullName,"USB test");
            Require(restored.TrustedMaterials.Single().IsProtocolIdentityOnly, "Refreshed key outlived its lease in DPAPI storage.");
        }
        finally { Directory.Delete(directory.FullName, recursive: true); }
    }

    private static async Task NativeKeyRefreshAdmission()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        var directory = Directory.CreateTempSubdirectory("skybridge-usb-key-admission-");
        try
        {
            await using var peer = new NativeUsbDiscoveryFixture(pairingApproval: Accept);
            await using var replacement = new NativeUsbDiscoveryFixture(pairingApproval: Accept);
            var connector = Connector(peer);
            using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var selected = await new UsbPeerDiscoveryClient(connector).InspectAsync(NativeUsbDiscoveryFixture.Serial, limit.Token);
            var authentication = Authentication(); var epoch = new AccountAudioAuthorization(AudioAccountScope.From(authentication));
            await using var workspace = new WindowsDeviceWorkspace(directory.FullName,"USB test");
            await Reject<FileNotFoundException>(() => workspace.RefreshUsbPeerKeysAsync(selected, authentication, epoch, limit.Token, connector));
            Require(!Directory.EnumerateFiles(directory.FullName,"*",SearchOption.AllDirectories).Any(), "Refresh created a replacement local identity.");
            await workspace.PairUsbPeerAsync(selected, authentication, epoch, Accept, limit.Token, connector);
            await Reject<InvalidDataException>(() => workspace.RefreshUsbPeerKeysAsync(selected, authentication, epoch, limit.Token, Connector(replacement)));
            Require(peer.KeyRefreshReplies == 0 && replacement.KeyRefreshReplies == 0, "Changed cable identity reached SKR.");
        }
        finally { Directory.Delete(directory.FullName, recursive: true); }
    }

    private static void Require(bool value, string message) { if (!value) throw new InvalidOperationException(message); }
    private static async Task Reject<T>(Func<Task> operation) where T : Exception
    { try { await operation(); } catch (T) { return; } throw new InvalidOperationException($"Expected {typeof(T).Name}."); }
}
