using System.Security.Cryptography;
using System.Text.Json;
using System.Diagnostics;
using System.Reflection;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.Audio;
using Skybridge.WinClient.ViewModels;
using static AudioAccountMembershipTests;

internal static partial class AudioObservationJournalTests
{
    private static (string Name, Func<Task> Run)[] OfflineRecoveryCases =>
    [
        ("offline audio startup restores only finite audio authority and original lease timestamps", OfflineStartup),
        ("offline audio binds both actual device keys and rejects unknown peers without network fallback", OfflineIdentities),
        ("offline audio original expiry and observed clock regression are terminal", OfflineExpiry),
        ("offline audio restored leases require current logon continuity and canonical account revision", OfflineHeadAndContinuity),
        ("offline audio startup refuses uncertain operations and continuity failure", OfflineStartupBarriers),
        ("offline audio unavailable renewal preserves deadlines and fresh online verification promotes exact owner", OfflineRenewal),
        ("offline audio TLS rejection and signout retire existing restored authority", OfflineHardFailure),
        ("offline audio missing identity never creates replacement device state", OfflineMissingIdentity),
        ("offline audio cancellation during recovery publishes no lease or canonical mutation", OfflineCancellation),
        ("offline audio expired credentials cannot authenticate but can retain a prior finite grant", OfflineExpiredCredential),
        ("offline audio new process restores canonical membership through the product coordinator and provider", OfflineProcess)
    ];

    private static async Task<AccountSessionResult> StartOffline(Fixture f)
    {
        f.Client.UserFailure = TemporaryCredentialFailure();
        f.Client.RefreshFailure = TemporaryCredentialFailure();
        f.Owner = f.NewOwner();
        return await f.Owner.HydrateFromStoreAsync();
    }

    private static async Task OfflineStartup()
    {
        await using var f = await Fixture.Create(); var before = f.Read();
        f.Clock.Advance(8000);
        var result = await StartOffline(f); var stored = f.Storage.Load();
        var receiver = f.Owner.ReadAudioReceiverAccount();
        Require(!result.Success && result.OfflineAudio?.Status == AudioAccountRecoveryStatus.Available &&
            !f.Owner.IsSignedIn && receiver is { OfflineExpiresAt: not null } && receiver.Authorization.IsOffline &&
            receiver.DisplayName == "Audio fixture" && await f.Owner.GetDeviceAuthenticationAsync(default) is null,
            "Offline startup published ordinary account access or failed to expose finite audio reception.");
        var original = before.Checkpoints.Single(c => c.Peer.Matches(Peer(f.Binding)));
        f.Client.UserRequest = (_, _) => throw new Exception("Offline lease tried to verify the account online.");
        f.Client.BeforeRefresh = () => throw new Exception("Offline lease tried to refresh credentials.");
        var lease = await f.Provider.LeaseAsync(new Inbox(f.Binding), default);
        Require(lease.Evidence.Id == original.EvidenceId && lease.Evidence.Issued == original.Issued &&
            lease.Evidence.Expires == original.Expires && f.HttpCalls == 0 &&
            f.Storage.Load().Version == stored.Version && f.Read().Checkpoints.SequenceEqual(before.Checkpoints),
            "Recovery issued a new grant, extended expiry, performed HTTP or rewrote the canonical record.");
        lease.RequireCurrent();
    }

    private static async Task OfflineIdentities()
    {
        await using var f = await Fixture.Create(); await StartOffline(f);
        var snapshot = f.Epoch.Recovery ?? throw new Exception("Missing recovery set.");
        snapshot.RequireLocalIdentity(Local(f.Binding));
        await Throws<AudioMembershipException>(() => Task.Run(() => snapshot.RequireLocalIdentity(Local(Binding(mlDsa: true)))));
        foreach (var binding in new[] { Binding(peer: 17), Binding(mlDsa: true) })
            await Throws<AudioMembershipException>(() => f.Provider.LeaseAsync(new Inbox(binding), default));
        var valid = await f.Provider.LeaseAsync(new Inbox(f.Binding), default); valid.RequireCurrent();
        Require(f.HttpCalls == 0 && f.Epoch.IsCurrent, "An unknown identity caused HTTP fallback or revoked unrelated saved authority.");
    }

    private static async Task OfflineExpiry()
    {
        foreach (bool rollback in new[] { false, true })
        {
            await using var f = await Fixture.Create(); await StartOffline(f);
            var epoch = f.Epoch; var initial = f.Clock.Now;
            var lease = await f.Provider.LeaseAsync(new Inbox(f.Binding), default);
            f.Clock.Now = rollback ? initial with { ContinuousMilliseconds = initial.ContinuousMilliseconds - 1 }
                : lease.Evidence.Expires;
            await Throws<InvalidOperationException>(() => Task.Run(lease.RequireCurrent));
            Require(!epoch.IsCurrent && f.Owner.ReadAudioReceiverAccount() is null,
                "Expired or clock-regressed recovery remained visible as available.");
            f.Clock.Now = initial;
            Require(!epoch.IsCurrent, "Clock recovery revived an expired startup publication.");
            await Throws<InvalidOperationException>(() => f.Provider.LeaseAsync(new Inbox(f.Binding), default));
            Require(f.HttpCalls == 0, "Expired offline authority attempted implicit online enrollment.");
        }
    }

    private static async Task OfflineHeadAndContinuity()
    {
        foreach (bool changedHead in new[] { false, true })
        {
            await using var f = await Fixture.Create(); await StartOffline(f); var epoch = f.Epoch;
            if (changedHead)
            {
                var current = f.Storage.Load();
                Require(f.Storage.Save(current.Session!, current.Version!, SessionStoreSaveMode.NewLogin).Succeeded,
                    "Fixture account replacement failed.");
                await Throws<AudioJournalStorageException>(() => f.Provider.LeaseAsync(new Inbox(f.Binding), default));
                Require(!epoch.IsCurrent, "Changed canonical login retained the old publication.");
            }
            else
            {
                f.Continuity.BeforeRequire = () => throw new CryptographicException("Synthetic logon changed.");
                var error = await Throws<AudioMembershipException>(() => f.Provider.LeaseAsync(new Inbox(f.Binding), default));
                Require(error.InnerException is CryptographicException, "Recovery hid a native continuity failure.");
            }
            Require(f.HttpCalls == 0, "Unproven recovery fell back to network issuance.");
        }
    }

    private static async Task OfflineStartupBarriers()
    {
        foreach (string kind in new[] { "credential", "registry", "continuity", "expired", "none" })
        {
            await using var f = await Fixture.Create(checkpoints: kind != "none");
            if (kind == "credential")
            {
                var head = f.Storage.Load();
                Require(((ISessionVerificationStore)f.Storage).BeginVerification(head.Version!, head.LoginId!.Value,
                    Guid.NewGuid(), false).Succeeded, "Fixture pending credential did not persist.");
            }
            if (kind == "registry") _ = await f.Journal.BeginAsync(f.Epoch, Local(f.Binding), AccountDeviceRegistryRequest.List, null, default);
            if (kind == "continuity") f.Continuity.BeforeRequire = () => throw new CryptographicException("Synthetic logon changed.");
            if (kind == "expired") f.Clock.Advance(AudioAccountMembershipEvidence.MaximumLifetimeMilliseconds);
            var result = await StartOffline(f);
            Require(!result.Success && result.OfflineAudio?.Status != AudioAccountRecoveryStatus.Available &&
                f.Owner.ReadAudioReceiverAccount() is null && f.Owner.ReadAudioAuthorization() is null,
                "Unsettled, expired, unsealed or absent evidence enabled offline audio.");
            if (kind is "credential" or "registry")
                Require(f.Storage.Load().AudioState is null, "New startup verification retained uncertain old grants.");
        }
    }

    private static async Task OfflineRenewal()
    {
        await using var f = await Fixture.Create(); await StartOffline(f); var epoch = f.Epoch;
        using var inbox = new Inbox(f.Binding);
        var lease = await f.Provider.LeaseAsync(inbox, default); var original = lease.Evidence;
        f.Clock.Advance(1000);
        await Throws<AudioMembershipRequestUnavailableException>(() => f.Provider.RenewAsync(inbox, lease, default));
        lease.RequireCurrent();
        Require(ReferenceEquals(original, lease.Evidence) && f.HttpCalls == 0 && epoch.IsOffline,
            "Temporary renewal failure extended or replaced the finite grant.");
        f.Client.UserFailure = null; f.Client.RefreshFailure = null;
        var renewed = await f.Provider.RenewAsync(inbox, lease, default);
        Require(ReferenceEquals(renewed, lease) && ReferenceEquals(epoch, f.Epoch) && !epoch.IsOffline && f.Owner.IsSignedIn &&
            f.Owner.ReadAudioReceiverAccount()?.OfflineExpiresAt is null && f.HttpCalls == 1 && lease.Evidence.Id != original.Id &&
            lease.Evidence.Expires.WallMilliseconds > original.Expires.WallMilliseconds,
            "Online verification replaced the live owner or renewed evidence without a fresh registry GET.");
        lease.RequireCurrent();
    }

    private static async Task OfflineHardFailure()
    {
        foreach (bool signout in new[] { false, true })
        {
            await using var f = await Fixture.Create(); await StartOffline(f); var epoch = f.Epoch;
            using var inbox = new Inbox(f.Binding);
            var lease = await f.Provider.LeaseAsync(inbox, default);
            if (signout) Require((await f.Owner.SignOutAsync()).Success, "Fixture signout failed.");
            else
            {
                f.Client.UserFailure = TemporaryCredentialFailure(tls: true);
                await Throws<AccountDeviceAuthenticationException>(() => f.Provider.RenewAsync(inbox, lease, default));
            }
            Require(!epoch.IsCurrent && f.Owner.ReadAudioReceiverAccount() is null && f.Storage.Load().AudioState is null,
                "Hard credential failure or signout retained offline authority.");
            await Throws<InvalidOperationException>(() => Task.Run(lease.RequireCurrent));
        }
    }

    private static async Task OfflineMissingIdentity()
    {
        foreach (bool directoryPresent in new[] { false, true })
        {
            var directory = Path.Combine(Path.GetTempPath(), "skybridge-missing-audio-identity-" + Guid.NewGuid().ToString("N"));
            var lockPath = Path.Combine(directory, ".remote-control-identity.lock");
            if (directoryPresent) { Directory.CreateDirectory(directory); File.WriteAllText(lockPath, "Fixture lease"); }
            try
            {
                await Skybridge.WinClient.Services.RemoteControl.RemoteControlIdentityStore.LoadExistingAsync(directory, "Fixture", protector: new PlainProtector());
                throw new Exception("Offline identity loader created a replacement identity.");
            }
            catch (Exception error) when (error is DirectoryNotFoundException or FileNotFoundException)
            {
                Require(Directory.Exists(directory) == directoryPresent, "Offline identity failure created local device state.");
                if (directoryPresent)
                    Require(Directory.GetFiles(directory).SequenceEqual([lockPath]) && File.ReadAllText(lockPath) == "Fixture lease",
                        "Offline identity load replaced a missing key or changed the lock file.");
            }
            finally { if (Directory.Exists(directory)) Directory.Delete(directory, true); }
        }
    }

    private static async Task OfflineCancellation()
    {
        await using var f = await Fixture.Create(); await StartOffline(f); var head = f.Storage.Load();
        using var canceled = new CancellationTokenSource();
        f.Continuity.BeforeRequire = canceled.Cancel;
        await Throws<OperationCanceledException>(() => f.Provider.LeaseAsync(new Inbox(f.Binding), canceled.Token));
        Require(f.HttpCalls == 0 && f.Storage.Load().Version == head.Version, "Canceled recovery changed authorization state.");
        f.Continuity.BeforeRequire = null;
        (await f.Provider.LeaseAsync(new Inbox(f.Binding), default)).RequireCurrent();
    }

    private static async Task OfflineExpiredCredential()
    {
        await using var f = await Fixture.Create(); var head = f.Storage.Load(); var checkpoints = f.Read().Checkpoints;
        // Fixture simulates an originally verified credential whose expiry has
        // elapsed. It is never passed as a successful live authentication result.
        var expired = AccountAudioAuthorizationTests.Token(minutes: -1);
        Require(f.Storage.Save(head.Session! with { AccessToken = expired.AccessToken }, head.Version!,
            SessionStoreSaveMode.ContinueLogin).Succeeded, "Expired credential fixture did not persist.");
        var result = await StartOffline(f);
        Require(result.OfflineAudio?.Status == AudioAccountRecoveryStatus.Available && f.Client.RefreshCalls == 1 &&
            await f.Owner.GetDeviceAuthenticationAsync(default) is null, "Expired credentials authenticated a normal request.");
        var lease = await f.Provider.LeaseAsync(new Inbox(f.Binding), default);
        Require(lease.Evidence.Expires == checkpoints.Single(c => c.Peer.Matches(Peer(f.Binding))).Expires && f.HttpCalls == 0,
            "Expired credentials minted a new playback interval.");
    }

    private static async Task OfflineProcess()
    {
        await using var f = await Fixture.Create(); var before = f.Read();
        string executable = Environment.ProcessPath ?? throw new Exception("Missing process executable.");
        var start = new ProcessStartInfo(executable) { UseShellExecute = false, RedirectStandardOutput = true,
            RedirectStandardError = true, CreateNoWindow = true };
        if (Path.GetFileNameWithoutExtension(executable).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            start.ArgumentList.Add(Assembly.GetExecutingAssembly().Location);
        start.ArgumentList.Add("--audio-offline-reader"); start.ArgumentList.Add(f.DirectoryPath);
        using var child = Process.Start(start) ?? throw new Exception("Offline reader did not start.");
        var stdout = child.StandardOutput.ReadToEndAsync(); var stderr = child.StandardError.ReadToEndAsync();
        var limit = TimeSpan.FromSeconds(20);
        try
        {
            await child.WaitForExitAsync().WaitAsync(limit); ProcessTerminationBarrier.Require(child, limit);
            string output = await stdout.WaitAsync(limit), error = await stderr.WaitAsync(limit);
            Require(child.ExitCode == 0 && output.Trim() == "OFFLINE_AUDIO_RESTORED" && error.Length == 0,
                "Separate recovery process failed: " + error);
            var after = f.Storage.Load();
            Require(after.LoginId == before.LoginId && after.PendingVerificationId is null &&
                AudioAccountJournalState.Read(after.AudioState!.Value).Checkpoints.SequenceEqual(before.Checkpoints),
                "Separate recovery process changed the original authorization.");
            Console.WriteLine($"AUDIO_OFFLINE_PROCESS parent={Environment.ProcessId} reader={child.Id} protection={(OperatingSystem.IsWindows() ? "CurrentUser-DPAPI+same-logon" : "host-fixtures-only")}");
        }
        finally
        {
            if (!child.HasExited) child.Kill(entireProcessTree: true);
            ProcessTerminationBarrier.Require(child, limit);
        }
    }

    internal static async Task ReadOfflineChild(string directory)
    {
        var clock = new Clock(); clock.Advance(8000); var continuity = new Continuity();
        var auth = new AccountAudioAuthorizationTests.Client { UserFailure = TemporaryCredentialFailure(), RefreshFailure = TemporaryCredentialFailure() };
        ISessionProtector protector = OperatingSystem.IsWindows() ? new DpapiSessionProtector() : new PlainProtector();
        var store = new SessionStore(directory, protector);
        var original = AudioAccountJournalState.Read(store.Load().AudioState ?? throw new Exception("Missing saved audio state."));
        var owner = new AccountSessionCoordinator(auth, store, clock.Read, continuity);
        var startup = await owner.HydrateFromStoreAsync();
        Require(startup.OfflineAudio?.Status == AudioAccountRecoveryStatus.Available && !owner.IsSignedIn,
            "Separate process did not restore limited audio authority.");
        using var http = new HttpClient(new Handler((_, _) => throw new Exception("Recovery unexpectedly sent HTTP.")));
        await using var provider = new AudioAccountMembershipProvider(http, owner.ReadAudioAuthorization,
            owner.GetAudioAuthenticationAsync, clock.Read, continuity: continuity);
        using var inbox = new Inbox(Binding());
        var lease = await provider.LeaseAsync(inbox, default);
        var checkpoint = original.Checkpoints.Single(c => c.Peer.Matches(Peer(inbox.Binding)));
        Require(lease.Evidence.Id == checkpoint.EvidenceId && lease.Evidence.Issued == checkpoint.Issued &&
            lease.Evidence.Expires == checkpoint.Expires, "New process renewed a saved authorization.");
        lease.RequireCurrent(); Console.WriteLine("OFFLINE_AUDIO_RESTORED");
    }
}
