using System.Text;
using System.Text.Json;
using System.Net;
using System.Net.Http;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.Audio;
using Skybridge.WinClient.ViewModels;

internal static class AccountAudioAuthorizationTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("audio account publication rotates on same-account sign-in and cannot revive an old epoch", SignInRotation),
        ("audio account epoch survives verified same-scope token refresh", RefreshContinuity),
        ("audio account tenant change invalidates the captured refresh requester", TenantChange),
        ("audio account changed scope retires playback before pending user verification", ChangedScopeDuringVerification),
        ("audio account observed scope change survives cancellation of the refresh requester", CanceledChangedScopeVerification),
        ("audio account ambiguous refreshed scope retires playback before pending user verification", InvalidScopeDuringVerification),
        ("audio account unchanged scope remains finite during pending user verification", SameScopeDuringVerification),
        ("audio account changed refresh scope cannot fall back after transient user verification failure", ChangedScopeVerificationFailure),
        ("audio account changed refresh scope retires playback before credential persistence", ChangedScopeBeforePersistence),
        ("audio account transient refresh failure preserves only existing authorization", TransientRefresh),
        ("audio auth request retains exact transport causes and allowlists temporary failures", RequestFailureClassification),
        ("audio credential adapter preserves request failure detail without extending account authority", RenewalCredentialBoundary),
        ("audio account hard refresh rejection revokes even when disk cleanup fails", RejectedRefresh),
        ("audio logout revokes before failed local cleanup and refresh cannot recreate it", FailedSignOut),
        ("audio account failed replacement cannot revive restored UI state", FailedReplacement),
        ("audio rotated-session persistence failure revokes before server cleanup", FailedRefreshCommit),
        ("audio account prepublication verification failure preserves the unchanged account", FailedVerification),
        ("audio account rejects ambiguous protected tenant metadata with a visible cause", InvalidTenant),
        ("audio account scope binds authority subject and protected tenant separately", ExactScope)
    ];
    private static readonly SessionAuthority Authority = SessionAuthority.ForSupabaseProject("https://audio-account-test.supabase.co");

    // The Auth API and session store are controlled ports; these are lifecycle tests, not live login proof.
    internal static AuthToken Token(string subject = "audio-user", int minutes = 60, object? app = null)
    {
        static string B(object value) => Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(value)))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return new AuthToken { AccessToken = B(new { alg = "EdDSA", typ = "JWT" }) + "." + B(new {
            iss = Authority.Issuer, sub = subject, aud = "authenticated", role = "authenticated",
            exp = DateTimeOffset.UtcNow.AddMinutes(minutes).ToUnixTimeSeconds(), app_metadata = app ?? new { tenant_id = "tenant-a" }
        }) + ".dGVzdA", RefreshToken = "fixture-refresh", User = new AuthUser { Id = subject } };
    }
    private static async Task<(AccountSessionCoordinator Owner, Client Auth, Store Storage)> SignedIn(int minutes = 60)
    {
        var auth = new Client(); var storage = new Store(); var owner = new AccountSessionCoordinator(auth, storage);
        Require((await owner.ApplyAuthAsync(Token(minutes: minutes))).Success, "Fixture account publication failed.");
        return (owner, auth, storage);
    }
    private static async Task SignInRotation()
    {
        var (owner, _, _) = await SignedIn(); var first = owner.RequireAudioAuthorization();
        var captured = await owner.GetDeviceAuthenticationAsync(default);
        Require(ReferenceEquals(captured?.AudioAuthorization, first), "Device request did not capture its exact publication.");
        Require((await owner.ApplyAuthAsync(Token())).Success, "Same-account sign-in failed.");
        var second = owner.RequireAudioAuthorization();
        Require(ReferenceEquals(captured?.AudioAuthorization, first) &&
            ReferenceEquals((await owner.GetDeviceAuthenticationAsync(default))?.AudioAuthorization, second),
            "Same-account login rebound an old immutable request snapshot.");
        Require(!first.IsCurrent && second.IsCurrent && !ReferenceEquals(first, second), "Same-account sign-in retained the old publication.");
        await Throws<InvalidOperationException>(() => owner.GetAudioAuthenticationAsync(first, default));
        await owner.SignOutAsync(); Require(!second.IsCurrent, "Sign-out left its audio epoch current.");
        Require((await owner.ApplyAuthAsync(Token())).Success, "Re-sign-in failed.");
        await Throws<InvalidOperationException>(() => owner.GetAudioAuthenticationAsync(second, default));
    }
    private static async Task RefreshContinuity()
    {
        var (owner, auth, _) = await SignedIn(minutes: 4); var epoch = owner.RequireAudioAuthorization();
        var snapshot = await owner.GetAudioAuthenticationAsync(epoch, default);
        Require(ReferenceEquals(snapshot.AudioAuthorization, epoch), "Normal refresh lost the captured publication.");
        Require(auth.RefreshCalls == 1 && ReferenceEquals(epoch, owner.RequireAudioAuthorization()) && epoch.IsCurrent,
            "Ordinary token rotation replaced the account publication.");
        epoch.RequireAuthentication(snapshot);
        Require(epoch.Scope.Subject == "audio-user" && epoch.Scope.TenantId == "tenant-a" && epoch.Scope.Authority == Authority,
            "Account scope lost a protected field.");
    }
    private static async Task TenantChange()
    {
        var (owner, auth, _) = await SignedIn(minutes: 4); var epoch = owner.RequireAudioAuthorization();
        auth.RefreshedToken = Token(app: new { tenant_id = "tenant-b" });
        await Throws<InvalidOperationException>(() => owner.GetAudioAuthenticationAsync(epoch, default));
        var replacement = owner.RequireAudioAuthorization();
        Require(!epoch.IsCurrent && replacement.Scope.TenantId == "tenant-b" && replacement.IsCurrent,
            "Changed tenant retained old device authorization.");
    }
    private static Task ChangedScopeDuringVerification() => PendingVerification(
        new { tenant_id = "tenant-b" }, expectedCurrent: false, invalidScope: false);
    private static Task CanceledChangedScopeVerification() => PendingVerification(
        new { tenant_id = "tenant-b" }, expectedCurrent: false, invalidScope: false, cancelRequester: true);
    private static Task InvalidScopeDuringVerification() => PendingVerification(
        new { tenant_id = "tenant-a", org_id = "tenant-b" }, expectedCurrent: false, invalidScope: true);
    private static Task SameScopeDuringVerification() => PendingVerification(
        new { tenant_id = "tenant-a" }, expectedCurrent: true, invalidScope: false);
    private static async Task PendingVerification(object protectedMetadata, bool expectedCurrent, bool invalidScope,
        bool cancelRequester = false)
    {
        var (owner, auth, _) = await SignedIn(minutes: 4);
        var epoch = owner.RequireAudioAuthorization();
        auth.RefreshedToken = Token(app: protectedMetadata);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<AuthClientResult<AuthUser>>(TaskCreationOptions.RunContinuationsAsynchronously);
        auth.UserRequest = (_, _) => { entered.TrySetResult(); return release.Task; };
        using var cancellation = new CancellationTokenSource();
        var request = owner.GetAudioAuthenticationAsync(epoch, cancellation.Token);
        bool duringVerification;
        bool publicationDuringVerification;
        try
        {
            await Task.WhenAny(entered.Task, request).WaitAsync(TimeSpan.FromSeconds(5));
            Require(entered.Task.IsCompletedSuccessfully, "Refresh did not reach the controlled user lookup.");
            Require(!request.IsCompleted, "User lookup was not pending at the observation boundary.");
            duringVerification = epoch.IsCurrent;
            publicationDuringVerification = ReferenceEquals(owner.ReadAudioAuthorization(), epoch);
            if (cancelRequester) cancellation.Cancel();
        }
        finally
        {
            release.TrySetResult(AuthClientResult<AuthUser>.Success(new AuthUser { Id = "audio-user" }));
        }
        if (cancelRequester)
            await Throws<OperationCanceledException>(() => request);
        else if (invalidScope)
            await Throws<InvalidDataException>(() => request);
        else if (!expectedCurrent)
            await Throws<InvalidOperationException>(() => request);
        else
            Require(ReferenceEquals((await request).AudioAuthorization, epoch), "Unchanged scope replaced its live publication.");
        Require(duringVerification == expectedCurrent && publicationDuringVerification == expectedCurrent,
            "The refreshed scope was not reflected in playback authority while user verification was pending.");
        if (!expectedCurrent && !invalidScope)
        {
            var replacement = owner.RequireAudioAuthorization();
            Require(replacement.IsCurrent && replacement.Scope.TenantId == "tenant-b" && !ReferenceEquals(replacement, epoch),
                "Fresh verified scope did not create a distinct publication.");
        }
    }
    private static async Task ChangedScopeVerificationFailure()
    {
        var (owner, auth, storage) = await SignedIn(minutes: 4);
        var epoch = owner.RequireAudioAuthorization();
        auth.RefreshedToken = Token(app: new { tenant_id = "tenant-b" });
        auth.UserFailure = AuthClientFailure.Create(AuthFailureKind.Network, "fixture-network-unavailable") with {
            Cause = new HttpRequestException(HttpRequestError.ConnectionError, "Fixture connection loss.")
        };
        await Throws<InvalidOperationException>(() => owner.GetAudioAuthenticationAsync(epoch, default));
        Require(!epoch.IsCurrent && owner.ReadAudioAuthorization() is null && owner.IsSignedIn,
            "A failed user lookup concealed the already-observed account scope change.");
        Require(storage.Value?.AccessToken == auth.RefreshedToken.AccessToken,
            "The server-rotated credential was lost while revoking the old playback scope.");
        auth.UserFailure = null;
        _ = await owner.GetDeviceAuthenticationAsync(default);
        Require(owner.RequireAudioAuthorization().Scope.TenantId == "tenant-b" && !epoch.IsCurrent,
            "A later verified retry revived the predecessor or could not publish the confirmed scope.");
    }
    private static async Task ChangedScopeBeforePersistence()
    {
        var (owner, auth, storage) = await SignedIn(minutes: 4);
        var epoch = owner.RequireAudioAuthorization();
        auth.RefreshedToken = Token(app: new { tenant_id = "tenant-b" });
        bool? liveAtCommit = null;
        storage.BeforeSave = () => liveAtCommit = epoch.IsCurrent;
        storage.FailSaveAt = storage.SaveCalls + 1;
        await Throws<AccountDeviceAuthenticationException>(() => owner.GetAudioAuthenticationAsync(epoch, default));
        Require(liveAtCommit == false && !epoch.IsCurrent,
            "The known scope contradiction did not revoke playback before credential I/O.");
    }
    private static async Task TransientRefresh()
    {
        var (owner, auth, _) = await SignedIn(minutes: 4); var epoch = owner.RequireAudioAuthorization();
        auth.RefreshFailure = AuthClientFailure.Create(AuthFailureKind.Network, "fixture-network-unavailable");
        await Throws<AccountDeviceAuthenticationException>(() => owner.GetAudioAuthenticationAsync(epoch, default));
        Require(epoch.IsCurrent && ReferenceEquals(owner.RequireAudioAuthorization(), epoch), "Transport loss falsely revoked the account publication.");
        auth.RefreshFailure = null;
        _ = await owner.GetAudioAuthenticationAsync(epoch, default);
        Require(ReferenceEquals(owner.RequireAudioAuthorization(), epoch), "Recovery silently replaced the still-current account publication.");
    }
    private static async Task RejectedRefresh()
    {
        var (owner, auth, storage) = await SignedIn(minutes: 4); var epoch = owner.RequireAudioAuthorization();
        storage.FailClear = true;
        auth.RefreshFailure = AuthClientFailure.Create(AuthFailureKind.Unauthorized, "session_expired");
        await Throws<AccountDeviceAuthenticationException>(() => owner.GetAudioAuthenticationAsync(epoch, default));
        Require(!epoch.IsCurrent && owner.IsSignedIn, "Disk cleanup failure either resurrected audio or falsified existing UI state.");
        await Throws<InvalidOperationException>(() => Task.FromResult(owner.RequireAudioAuthorization()));
        auth.RefreshFailure = null; _ = await owner.GetDeviceAuthenticationAsync(default);
        await Throws<InvalidOperationException>(() => Task.FromResult(owner.RequireAudioAuthorization()));
    }
    private static async Task RequestFailureClassification()
    {
        foreach (var kind in Enum.GetValues<HttpRequestError>())
        {
            var cause = new HttpRequestException(kind, "Fixture request failure.");
            using var http = new HttpClient(new FailureHandler(_ => throw cause));
            var client = new SupabaseAuthClient(http, "https://audio-account-test.supabase.co", "fixture-public-key");
            var result = await client.RefreshAsync("fixture-refresh");
            bool expected = kind is HttpRequestError.NameResolutionError or HttpRequestError.ConnectionError or HttpRequestError.ResponseEnded;
            Require(ReferenceEquals(result.Failure?.Cause, cause) && result.Failure.StatusCode is null &&
                AudioMembershipRequestFailure.IsTemporary(result.Failure) == expected,
                "Auth transport detail was lost or a TLS/protocol/unknown error became retryable.");
        }
        foreach (var status in new[] { HttpStatusCode.BadRequest, HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden,
            HttpStatusCode.RequestTimeout, HttpStatusCode.TooManyRequests, HttpStatusCode.InternalServerError,
            HttpStatusCode.BadGateway, HttpStatusCode.ServiceUnavailable, HttpStatusCode.GatewayTimeout, HttpStatusCode.NotImplemented })
        {
            using var http = new HttpClient(new FailureHandler(_ => Task.FromResult(new HttpResponseMessage(status) { Content = new StringContent("{}") })));
            var client = new SupabaseAuthClient(http, "https://audio-account-test.supabase.co", "fixture-public-key");
            var result = await client.RefreshAsync("fixture-refresh");
            bool expected = (int)status is 408 or 429 or 500 or 502 or 503 or 504;
            Require(result.Failure?.StatusCode == status && AudioMembershipRequestFailure.IsTemporary(result.Failure) == expected,
                "Auth HTTP detail was lost or an auth/unknown status became retryable.");
        }
        Require(!AudioMembershipRequestFailure.IsTemporary(AuthClientFailure.Create(AuthFailureKind.Network, "unknown")),
            "An unqualified network label became retryable.");
        Require(!AudioMembershipRequestFailure.IsTemporary(AuthClientFailure.Create(AuthFailureKind.Timeout, "unknown")),
            "An unqualified timeout label became retryable.");
        foreach (var kind in new[] { HttpRequestError.ResponseEnded, HttpRequestError.InvalidResponse, HttpRequestError.Unknown })
        {
            var cause = new HttpIOException(kind, "Fixture body failure.");
            using var http = new HttpClient(new FailureHandler(_ => throw cause));
            var result = await new SupabaseAuthClient(http, "https://audio-account-test.supabase.co", "fixture-public-key").RefreshAsync("fixture-refresh");
            Require(ReferenceEquals(result.Failure?.Cause, cause) &&
                AudioMembershipRequestFailure.IsTemporary(result.Failure) == (kind == HttpRequestError.ResponseEnded),
                "Auth response truncation was confused with invalid or unknown response data.");
        }
    }
    private static async Task RenewalCredentialBoundary()
    {
        foreach (bool temporary in new[] { true, false })
        {
            var (owner, auth, _) = await SignedIn(minutes: 4); var epoch = owner.RequireAudioAuthorization();
            var cause = new HttpRequestException(temporary ? HttpRequestError.ConnectionError : HttpRequestError.SecureConnectionError,
                "Fixture refresh failure.");
            auth.RefreshFailure = new(AuthFailureKind.Network, "fixture-refresh-failed") { Cause = cause };
            Exception observed;
            try { await owner.GetAudioAuthenticationAsync(epoch, default); throw new Exception("Expected credential failure."); }
            catch (AudioMembershipRequestUnavailableException error) when (temporary) { observed = error.InnerException ?? throw new Exception("Missing request cause."); }
            catch (AccountDeviceAuthenticationException error) when (!temporary) { observed = error; }
            Require(observed is AccountDeviceAuthenticationException detail &&
                ReferenceEquals(detail.AuthenticationFailure?.Cause, cause) && ReferenceEquals(detail.InnerException, cause),
                "The audio adapter discarded the exact authentication failure.");
            Require(epoch.IsCurrent && ReferenceEquals(epoch, owner.RequireAudioAuthorization()),
                "A failed credential request replaced or extended account authority.");
        }
    }
    private sealed class FailureHandler(Func<CancellationToken, Task<HttpResponseMessage>> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => respond(cancellationToken);
    }
    private static async Task FailedSignOut()
    {
        var (owner, auth, storage) = await SignedIn(minutes: 4); var epoch = owner.RequireAudioAuthorization();
        storage.FailClear = true; var result = await owner.SignOutAsync();
        Require(!result.Success && owner.IsSignedIn && !epoch.IsCurrent && auth.SignOutCalls == 0,
            "Failed disk cleanup did not preserve account truth while revoking audio.");
        Require((await owner.GetDeviceAuthenticationAsync(default))?.AudioAuthorization is null,
            "A device request recreated audio authority after failed logout.");
        await Throws<InvalidOperationException>(() => Task.FromResult(owner.RequireAudioAuthorization()));
        Require((await owner.ApplyAuthAsync(Token())).Success && owner.RequireAudioAuthorization().IsCurrent,
            "Explicit verified sign-in could not create a fresh publication.");
    }
    private static async Task FailedReplacement()
    {
        var (owner, auth, storage) = await SignedIn(); var epoch = owner.RequireAudioAuthorization();
        storage.FailSaveAt = storage.SaveCalls + 1;
        auth.BeforeSignOut = () => Require(!epoch.IsCurrent, "Failed replacement reached server cleanup with old audio still live.");
        var result = await owner.ApplyAuthAsync(Token(subject: "replacement-user"));
        Require(!result.Success && owner.IsSignedIn && !epoch.IsCurrent, "Restoring old UI state revived an old audio grant.");
        var snapshot = await owner.GetDeviceAuthenticationAsync(default);
        Require(snapshot?.Subject == "audio-user", "Failed replacement changed the retained account.");
        await Throws<InvalidOperationException>(() => Task.FromResult(owner.RequireAudioAuthorization()));
    }
    private static async Task FailedRefreshCommit()
    {
        var (owner, auth, storage) = await SignedIn(minutes: 4); var epoch = owner.RequireAudioAuthorization();
        storage.FailSaveAt = storage.SaveCalls + 2; storage.FailClear = true;
        auth.BeforeSignOut = () => Require(!epoch.IsCurrent, "Rotated-session cleanup retained old audio authority.");
        await Throws<AccountDeviceAuthenticationException>(() => owner.GetAudioAuthenticationAsync(epoch, default));
        Require(!epoch.IsCurrent && auth.SignOutCalls == 1, "Refresh rollback skipped audio revocation or server cleanup.");
        _ = await owner.GetDeviceAuthenticationAsync(default);
        await Throws<InvalidOperationException>(() => Task.FromResult(owner.RequireAudioAuthorization()));
    }
    private static async Task FailedVerification()
    {
        var (owner, auth, _) = await SignedIn(); var epoch = owner.RequireAudioAuthorization();
        auth.UserFailure = AuthClientFailure.Create(AuthFailureKind.Unauthorized, "fixture-user-rejected");
        Require(!(await owner.ApplyAuthAsync(Token(subject: "other-user"))).Success, "Unverified replacement was accepted.");
        Require(epoch.IsCurrent && ReferenceEquals(epoch, owner.RequireAudioAuthorization()), "A failed prepublication login changed the existing account epoch.");
    }
    private static async Task InvalidTenant()
    {
        var (owner, _, _) = await SignedIn(); var epoch = owner.RequireAudioAuthorization();
        Require((await owner.ApplyAuthAsync(Token(app: new { tenant_id = "a", org_id = "b" }))).Success,
            "Audio scope validation changed ordinary verified sign-in semantics.");
        var failure = await Throws<InvalidOperationException>(() => Task.FromResult(owner.RequireAudioAuthorization()));
        Require(!epoch.IsCurrent && failure.InnerException is InvalidDataException,
            "Unsupported audio scope was silently accepted or its cause was hidden.");
    }
    private static async Task ExactScope()
    {
        var (owner, _, _) = await SignedIn(); var epoch = owner.RequireAudioAuthorization();
        var otherTenant = AccountDeviceAuthentication.FromVerifiedSession(Token(app: new { tenant_id = "tenant-b" }).AccessToken!, Authority, "audio-user");
        await Throws<InvalidDataException>(() => { epoch.RequireAuthentication(otherTenant); return Task.CompletedTask; });
        var otherSubject = AccountDeviceAuthentication.FromVerifiedSession(Token(subject: "other-user").AccessToken!, Authority, "other-user");
        await Throws<InvalidDataException>(() => { epoch.RequireAuthentication(otherSubject); return Task.CompletedTask; });
    }
    internal sealed class Client : ISupabaseAuthClient
    {
        public SessionAuthority SessionAuthority => Authority;
        internal AuthToken RefreshedToken = Token();
        internal AuthClientFailure? RefreshFailure, UserFailure;
        internal int RefreshCalls, SignOutCalls;
        internal Action? BeforeSignOut;
        internal Action? BeforeRefresh;
        internal Func<string, string?, Task<AuthClientResult<AuthUser>>>? UserRequest;
        public Task<AuthClientResult<AuthToken>> SignInWithPasswordAsync(string email, string password) => throw new NotSupportedException();
        public Task<AuthClientResult<AuthToken>> RefreshAsync(string refreshToken)
        {
            RefreshCalls++;
            BeforeRefresh?.Invoke();
            return Task.FromResult(RefreshFailure is { } failure ? AuthClientResult<AuthToken>.Failed(failure.Kind, failure.Code, failure.Cause, failure.StatusCode) : AuthClientResult<AuthToken>.Success(RefreshedToken));
        }
        public Task<AuthClientResult<AuthUser>> GetUserAsync(string token, string? userId = null) => UserRequest?.Invoke(token, userId) ?? Task.FromResult(
            UserFailure is { } failure ? AuthClientResult<AuthUser>.Failed(failure.Kind, failure.Code, failure.Cause, failure.StatusCode) :
                AuthClientResult<AuthUser>.Success(new AuthUser { Id = userId, UserMetadata = new AuthUserMetadata { DisplayName = "Audio fixture" } }));
        public Task<AuthClientResult<AuthSignOutReceipt>> SignOutAsync(string token)
        { SignOutCalls++; BeforeSignOut?.Invoke(); return Task.FromResult(AuthClientResult<AuthSignOutReceipt>.Success(new(true))); }
    }
    private sealed class Store : TestSessionState { }
    private static async Task<T> Throws<T>(Func<Task> action) where T : Exception
    { try { await action(); } catch (T error) { return error; } throw new Exception($"Expected {typeof(T).Name}."); }
    private static void Require(bool condition, string reason) { if (!condition) throw new Exception(reason); }
}
