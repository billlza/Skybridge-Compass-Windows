using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.Audio;
using Skybridge.WinClient.ViewModels;
using static AudioAccountMembershipTests;

internal static partial class AudioObservationJournalTests
{
    private static AuthClientFailure TemporaryCredentialFailure(bool tls = false) =>
        new(AuthFailureKind.Network, "fixture-credential-route") {
            Cause = new HttpRequestException(tls ? HttpRequestError.SecureConnectionError : HttpRequestError.ConnectionError, "Synthetic credential failure.")
        };

    private static async Task CredentialRefresh()
    {
        await using var f = await Fixture.Create(minutes: 4, keepNearExpiry: true);
        var before = f.Read(); var epoch = f.Epoch; Guid? pending = null;
        f.Client.RefreshedToken = AccountAudioAuthorizationTests.Token();
        f.Client.BeforeRefresh = () => {
            pending = f.Storage.Load().PendingVerificationId;
            Require(pending is not null && f.Read().Checkpoints.SequenceEqual(before.Checkpoints), "Refresh started without its durable barrier.");
        };
        f.Client.UserRequest = (_, subject) => {
            var current = f.Storage.Load();
            Require(current.PendingVerificationId == pending && current.Session!.AccessToken == f.Client.RefreshedToken.AccessToken &&
                current.LoginId == before.LoginId && f.Read().Checkpoints.SequenceEqual(before.Checkpoints),
                "Token rotation dropped its barrier, changed login or renewed audio evidence.");
            return Task.FromResult(AuthClientResult<AuthUser>.Success(new AuthUser { Id = subject }));
        };
        await f.Owner.GetAudioAuthenticationAsync(epoch, default);
        Require(f.Storage.Load().PendingVerificationId is null && ReferenceEquals(f.Epoch, epoch) &&
            f.Read().Checkpoints.SequenceEqual(before.Checkpoints), "Successful verification changed finite authority or left its own marker.");
    }

    private static async Task CredentialHydration()
    {
        await using var f = await Fixture.Create(); var before = f.Read(); int refreshes = f.Client.RefreshCalls, observed = 0;
        f.Owner = new(f.Client, f.Storage);
        f.Client.UserRequest = (_, subject) => {
            Require(f.Storage.Load().PendingVerificationId is not null && f.Owner.ReadAudioAuthorization() is null,
                "Startup verified the account without a barrier or published authority early.");
            observed++;
            return Task.FromResult(AuthClientResult<AuthUser>.Success(new AuthUser { Id = subject }));
        };
        Require((await f.Owner.HydrateFromStoreAsync()).Success && observed == 1 && f.Client.RefreshCalls == refreshes &&
            f.Storage.Load().PendingVerificationId is null && f.Read().Checkpoints.SequenceEqual(before.Checkpoints),
            "Startup failed to settle its live-user check without renewal.");
    }

    private static async Task CredentialPreparationFailure()
    {
        foreach (int fault in new[] { 1, 2 })
        {
            await using var f = await Fixture.Create(minutes: 4, keepNearExpiry: true);
            var before = f.Read(); int refreshes = f.Client.RefreshCalls; f.Committer.NextFault = fault;
            var result = await f.Owner.HydrateFromStoreAsync(); var after = f.Storage.Load();
            Require(!result.Success && result.VerificationFailure is { Stage: "preparation", Storage.Status: SessionStoreWriteStatus.IoFailure } &&
                f.Client.RefreshCalls == refreshes && (after.PendingVerificationId is not null) == (fault == 2) &&
                f.Read().Checkpoints.SequenceEqual(before.Checkpoints) && f.Owner.ReadAudioAuthorization() is null,
                "Failed preparation sent authentication, hid uncertainty or retained a runtime publication.");
        }
    }

    private static async Task CredentialNegativeFailure()
    {
        foreach (int mode in new[] { 0, 1, 2 })
        {
            bool failSettlement = mode == 2;
            await using var f = await Fixture.Create(minutes: 4, keepNearExpiry: true); var before = f.Read();
            f.Client.RefreshFailure = AuthClientFailure.Create(AuthFailureKind.Unauthorized, "fixture-refresh-rejected");
            f.Client.BeforeRefresh = () => {
                f.Committer.NextFault = mode == 1 ? 2 : 1;
                if (failSettlement) f.Committer.BeforeCommit = () => f.Committer.NextFault = 1;
            };
            var result = await f.Owner.HydrateFromStoreAsync(); var stored = f.Storage.Load();
            Require(!result.Success && f.Owner.ReadAudioAuthorization() is null, "Failed negative cleanup reported success or retained runtime authority.");
            if (mode == 1)
            {
                Require(stored.Status == SessionStoreLoadStatus.Cleared && stored.PendingVerificationId is null &&
                    result.VerificationFailure is { Storage.Status: SessionStoreWriteStatus.Conflict, PreviousErrorCode: "IoFailure" },
                    "Post-clear failure was mistaken for an unchanged record or lost its primary failure.");
                continue;
            }
            Require(stored.LoginId == before.LoginId, "A failed pre-commit clear changed account ownership.");
            if (failSettlement)
                Require(stored.PendingVerificationId is not null && f.Read().Checkpoints.SequenceEqual(before.Checkpoints) &&
                    result.VerificationFailure is { Stage: "completion", PreviousFailureKind: AccountSessionFailureKind.SessionPersistenceFailed },
                    "A failed negative completion lost its barrier or original clear failure.");
            else Require(stored.PendingVerificationId is null && stored.AudioState is null, "Settled rejection retained offline authority.");
        }
    }

    private static async Task CredentialTemporaryFailure()
    {
        foreach (bool tls in new[] { false, true })
        {
            await using var f = await Fixture.Create(minutes: 4, keepNearExpiry: true); var before = f.Read();
            f.Client.RefreshFailure = TemporaryCredentialFailure(tls);
            var result = await f.Owner.HydrateFromStoreAsync(); var after = f.Storage.Load();
            Require(!result.Success && result.AuthenticationFailure?.Cause is HttpRequestException && after.PendingVerificationId is null &&
                (tls ? after.AudioState is null : AudioAccountJournalState.Read(after.AudioState!.Value).Checkpoints.SequenceEqual(before.Checkpoints)),
                "Credential failure renewed evidence, lost its cause or treated TLS as an offline fallback.");
        }
    }

    private static async Task CredentialScopeChange()
    {
        await using var f = await Fixture.Create(minutes: 4, keepNearExpiry: true); var old = f.Epoch; var before = f.Read();
        f.Client.RefreshedToken = AccountAudioAuthorizationTests.Token(app: new { tenant_id = "new-credential-tenant" });
        f.Client.UserRequest = (_, _) => {
            var stored = f.Storage.Load();
            Require(!old.IsCurrent && stored.PendingVerificationId is not null && stored.AudioState is not null,
                "Observed scope change was not covered before the later user check.");
            var failure = TemporaryCredentialFailure();
            return Task.FromResult(AuthClientResult<AuthUser>.Failed(failure.Kind, failure.Code, failure.Cause));
        };
        var result = await f.Owner.HydrateFromStoreAsync(); var after = f.Storage.Load();
        Require(!result.Success && after.LoginId == before.LoginId && after.PendingVerificationId is null && after.AudioState is null,
            "Temporary verification error restored the previous tenant's authority.");
    }

    private static async Task CredentialExceptions()
    {
        await using var f = await Fixture.Create(minutes: 4, keepNearExpiry: true);
        var failure = new InvalidOperationException("Synthetic unexpected authentication failure.");
        f.Client.BeforeRefresh = () => { f.Committer.NextFault = 1; throw failure; };
        var error = await Throws<AggregateException>(() => f.Owner.HydrateFromStoreAsync());
        Require(error.InnerExceptions.Count == 2 && ReferenceEquals(error.InnerExceptions[0], failure) &&
            error.InnerExceptions[1] is AccountVerificationStorageException && f.Storage.Load().PendingVerificationId is not null &&
            f.Owner.ReadAudioAuthorization() is null, "Completion masked its primary exception or cleared its uncertain barrier.");
    }

    private static async Task CredentialCompletionFailure()
    {
        foreach (int fault in new[] { 1, 2 })
        {
            await using var f = await Fixture.Create(minutes: 4, keepNearExpiry: true); var before = f.Read(); int commits = 0;
            f.Client.RefreshedToken = AccountAudioAuthorizationTests.Token();
            f.Committer.BeforeCommit = () => { if (++commits == 4) f.Committer.NextFault = fault; };
            var result = await f.Owner.HydrateFromStoreAsync(); var after = f.Storage.Load();
            Require(commits == 4 && !result.Success && result.VerificationFailure is { Stage: "completion" } &&
                f.Owner.ReadAudioAuthorization() is null && (after.PendingVerificationId is not null) == (fault == 1) &&
                f.Read().Checkpoints.SequenceEqual(before.Checkpoints), "Uncertain final verification published authority or retried its commit.");
        }
    }

    private static async Task CredentialStaleOwner()
    {
        await using var f = await Fixture.Create(); SessionStoreWriteResult? replacement = null;
        f.Client.UserRequest = (_, subject) => {
            var current = f.Storage.Load();
            replacement = f.Storage.Save(current.Session!, current.Version!, SessionStoreSaveMode.NewLogin);
            Require(replacement.Succeeded, "Synthetic replacement did not commit.");
            return Task.FromResult(AuthClientResult<AuthUser>.Success(new AuthUser { Id = subject }));
        };
        var result = await f.Owner.HydrateFromStoreAsync(); var after = f.Storage.Load();
        Require(!result.Success && result.ErrorCode == nameof(SessionStoreWriteStatus.Conflict) && replacement is not null &&
            after.Version == replacement.Version && after.PendingVerificationId is null && after.AudioState is null,
            "Stale verification settled into another account owner.");
    }

    private static async Task CredentialInterrupted()
    {
        await using var f = await Fixture.Create(); var original = f.Storage.Load(); var prior = Guid.NewGuid();
        Require(((ISessionVerificationStore)f.Storage).BeginVerification(original.Version!, original.LoginId!.Value, prior, false).Succeeded,
            "Unsettled verification fixture did not commit.");
        f.Owner = new(f.Client, f.Storage);
        f.Client.UserRequest = (_, _) => {
            var current = f.Storage.Load();
            Require(current.PendingVerificationId is not null && current.PendingVerificationId != prior && current.AudioState is null &&
                current.LoginId == original.LoginId, "A new live check inherited uncertain old audio or reset the account.");
            var failure = TemporaryCredentialFailure();
            return Task.FromResult(AuthClientResult<AuthUser>.Failed(failure.Kind, failure.Code, failure.Cause));
        };
        var result = await f.Owner.HydrateFromStoreAsync(); var after = f.Storage.Load();
        Require(!result.Success && after.PendingVerificationId is null && after.AudioState is null && after.LoginId == original.LoginId,
            "Interrupted verification recovered old grants during a temporary outage.");
    }

    private static async Task CredentialStorageOwnership()
    {
        await using var f = await Fixture.Create(); var original = f.Storage.Load(); var store = (ISessionVerificationStore)f.Storage;
        var id = Guid.NewGuid(); var prepared = store.BeginVerification(original.Version!, original.LoginId!.Value, id, false);
        Require(prepared.Succeeded, "Credential owner did not prepare.");
        var rotated = f.Storage.Save(original.Session! with { DisplayName = "Synthetic rotation" }, prepared.Version!, SessionStoreSaveMode.ContinueLogin);
        Require(rotated.Succeeded && f.Storage.Load().PendingVerificationId == id, "Credential save dropped verification ownership.");
        var audio = ((ISessionAudioStateStore)f.Storage).WriteAudioState(original.AudioState!.Value, rotated.Version!, original.LoginId.Value);
        Require(audio.Succeeded && f.Storage.Load().PendingVerificationId == id, "Audio mutation dropped verification ownership.");
        Require(store.CompleteVerification(audio.Version!, original.LoginId.Value, Guid.NewGuid(), false).Status == SessionStoreWriteStatus.Conflict &&
            store.CompleteVerification(prepared.Version!, original.LoginId.Value, id, false).Status == SessionStoreWriteStatus.Conflict &&
            f.Storage.Load().Version == audio.Version, "Wrong or stale completion mutated a newer account state.");
        Require(store.BeginVerification(audio.Version!, original.LoginId.Value, Guid.NewGuid(), false).Status == SessionStoreWriteStatus.InvalidRecord,
            "Another observation took over uncertain authority without retirement.");
        var complete = store.CompleteVerification(audio.Version!, original.LoginId.Value, id, false);
        Require(complete.Succeeded && f.Storage.Load().PendingVerificationId is null &&
            f.Storage.Load().AudioState!.Value.GetRawText() == original.AudioState.Value.GetRawText(), "Exact completion changed original audio evidence.");
    }

    private static async Task CredentialStorageSchema()
    {
        await using var f = await Fixture.Create(); var original = f.Storage.Load(); string path = Path.Combine(f.DirectoryPath, "session.bin");
        ISessionProtector protector = OperatingSystem.IsWindows() ? new DpapiSessionProtector() : new PlainProtector();
        byte[] clear = protector.Unprotect(File.ReadAllBytes(path)); JsonObject source;
        try { source = JsonNode.Parse(clear)!.AsObject(); }
        finally { CryptographicOperations.ZeroMemory(clear); }
        void Write(JsonObject value)
        {
            byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(value);
            try { File.WriteAllBytes(path, protector.Protect(bytes)); }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
        var old = source.DeepClone().AsObject(); old["schemaVersion"] = 3; old.Remove("pendingVerificationId"); Write(old);
        var migrated = f.Storage.Load();
        Require(migrated.Succeeded && migrated.LoginId == original.LoginId && migrated.PendingVerificationId is null &&
            migrated.AudioState!.Value.GetRawText() == original.AudioState!.Value.GetRawText(), "Schema-three reading invented or changed authority.");
        var id = Guid.NewGuid();
        Require(((ISessionVerificationStore)f.Storage).BeginVerification(migrated.Version!, migrated.LoginId!.Value, id, false).Succeeded &&
            f.Storage.Load().PendingVerificationId == id, "Schema-three owner did not migrate into a pending verification.");
        foreach (bool older in new[] { true, false })
        {
            var invalid = source.DeepClone().AsObject(); invalid["schemaVersion"] = older ? 3 : 4;
            invalid["pendingVerificationId"] = (older ? Guid.NewGuid() : Guid.Empty).ToString(); Write(invalid);
            var bytes = File.ReadAllBytes(path);
            Require(f.Storage.Load().Status == SessionStoreLoadStatus.InvalidSession && File.ReadAllBytes(path).SequenceEqual(bytes),
                "An undeclared or empty verification marker was admitted or rewritten.");
        }
    }
}
