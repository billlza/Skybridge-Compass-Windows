using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.ViewModels;

internal static class AccountDeviceTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases = [
        ("account devices use identity-bound signaling and GET version headers",RequestShapeAsync),
        ("account devices enroll once only for a missing registry identity",EnrollmentAsync),
        ("account devices preserve rejected and malformed responses",FailureBoundariesAsync),
        ("account devices distinguish exact signing identities and reject forged caller flags",IdentityRowsAsync),
        ("account devices protected tenant claims ignore editable metadata",TenantClaimsAsync),
        ("account devices expire snapshots and discard a switched account response",LifecycleAsync),
        ("account devices cannot retain online state after transport failure",NetworkFailureAsync),
        ("account device presentation preserves unknown model codes",ModelsAsync),
        ("account request snapshots serialize refresh and preserve verified authority",RefreshAuthenticationAsync),
        ("account request transient refresh failure keeps rotated credentials and retries verification",TransientAuthenticationAsync),
        ("existing account automatically registers the exact current identity",UnapprovedAccountAsync),
        ("strict presence admission still registers a missing caller and preserves revocation",StrictPresenceEnrollmentAsync),
        ("removal sends the exact target and rejects an unconfirmed response",RemovalWireAsync),
        ("self removal stops synchronization and stale confirmations cannot change another account",RemovalLifecycleAsync)
    ];
    private static readonly SessionAuthority Authority = SessionAuthority.ForSupabaseProject("https://account-test.supabase.co");
    private static readonly CurrentPathProtocolIdentityBinding Binding = new("WINDOWS-DEVICE-ACCOUNT-0001", CurrentPathProtocolSigningAlgorithm.Ed25519, new byte[32]);
    private static readonly AccountDeviceMetadata Metadata = new("Test Windows", "Test model", "Windows 10.0.26200", ["192.168.0.104"]);
    private static string Token(string subject = "account-user", object? app = null, object? user = null, int minutes = 60)
    {
        string B(object v) => Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(v)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return B(new { alg = "EdDSA", typ = "JWT" }) + "." + B(new { iss = Authority.Issuer, sub = subject, aud = "authenticated", role = "authenticated", exp = DateTimeOffset.UtcNow.AddMinutes(minutes).ToUnixTimeSeconds(), app_metadata = app, user_metadata = user }) + ".dGVzdA";
    }
    private static AccountDeviceAuthentication Auth(string subject = "account-user") => AccountDeviceAuthentication.FromVerifiedSession(Token(subject), Authority, subject);
    private static JsonObject Row(string? fingerprint = null, bool caller = true) => new() { ["deviceId"] = Binding.DeviceId, ["deviceName"] = "Test Windows", ["status"] = "active", ["protocolSigningAlgorithm"] = "Ed25519", ["protocolPublicKeyFingerprint"] = fingerprint ?? Binding.ProtocolPublicKeyFingerprint, ["platform"] = "windows", ["deviceModel"] = "Test model", ["osVersion"] = "Windows 10.0.26200", ["appVersion"] = "1.0.2", ["lastSeenAt"] = 1700000000000L, ["online"] = true, ["isCaller"] = caller };
    private static JsonObject Snapshot(params JsonNode[] rows) => new() { ["generatedAt"] = 1700000000000L, ["callerDeviceId"] = Binding.DeviceId, ["truncated"] = false, ["devices"] = new JsonArray(rows) };
    private const string Presence = "{\"online\":true,\"ttlMs\":90000,\"expiresAt\":1700000090000,\"persisted\":true,\"persistReason\":\"written\"}";
    private static HttpResponseMessage Reply(string json, HttpStatusCode status = HttpStatusCode.OK) => new(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
    private static void Check(bool ok, string message) { if (!ok) throw new InvalidOperationException(message); }
    private static async Task Throws<T>(Func<Task> run) where T : Exception { try { await run(); } catch (T) { return; } throw new InvalidOperationException("Expected " + typeof(T).Name); }
    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    { protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) => send(request, ct); }
    private static async Task RequestShapeAsync()
    {
        var paths = new List<string>(); var auth = Auth();
        using var http = new HttpClient(new Handler(async (request, ct) =>
        {
            Check(request.RequestUri?.Host == "api.nebula-technologies.net", "Canonical signaling host required");
            Check(request.Headers.Authorization?.Parameter == auth.AccessToken, "Exact bearer must authorize the request");
            Check(request.Headers.GetValues("X-SkyBridge-Tenant-Id").Single() == auth.Subject, "Tenant and bearer must be captured together");
            Check(request.Headers.GetValues("X-SkyBridge-Client-Version").Single() == "1.0.2", "GET must carry client version");
            Check(request.Headers.GetValues("X-SkyBridge-Protocol-Version").Single() == "1", "GET must carry protocol version");
            string path = request.RequestUri!.AbsolutePath; paths.Add(path);
            if (path.EndsWith("register"))
            {
                using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(ct));
                Check(body.RootElement.GetProperty("deviceId").GetString() == Binding.DeviceId, "Presence uses real binding");
                Check(body.RootElement.GetProperty("deviceModel").GetString() == Metadata.DeviceModel, "Presence reports model separately from name");
                return Reply(Presence);
            }
            Check(request.Method == HttpMethod.Get && request.Content is null, "List must be a GET without a body");
            Check(request.RequestUri.Query.Contains(Binding.ProtocolPublicKeyFingerprint, StringComparison.Ordinal), "Full signing fingerprint must be in query");
            return Reply(Snapshot(Row()).ToJsonString());
        }));
        var result = await new AccountDeviceRosterClient(http).RefreshAsync(auth, Binding, Metadata, default);
        Check(result.Devices.Single().IsCaller && paths.SequenceEqual(new[] { "/api/presence/register", "/api/devices/list" }), "Presence/list path did not execute");
    }
    private static async Task EnrollmentAsync()
    {
        foreach (bool frozen in new[] { false, true })
        {
            int lists = 0, registers = 0, presences = 0;
            using var http = new HttpClient(new Handler((request, ct) =>
            {
                string path = request.RequestUri!.AbsolutePath;
                if (path == "/api/presence/register") { presences++; return Task.FromResult(Reply(Presence)); }
                if (path == "/api/devices/list") return Task.FromResult(++lists == 1 ? Reply("{\"error\":\"" + (frozen ? "device_frozen" : "device_not_registered") + "\"}", HttpStatusCode.Forbidden) : Reply(Snapshot(Row()).ToJsonString()));
                registers++;
                return Task.FromResult(Reply(JsonSerializer.Serialize(new { registered = true, device = new { tenant_id = "account-user", user_id = "account-user", device_id = Binding.DeviceId, protocol_signing_algorithm = "Ed25519", protocol_public_key_fingerprint = Binding.ProtocolPublicKeyFingerprint, status = "active" } })));
            }));
            var client = new AccountDeviceRosterClient(http);
            if (frozen) { await Throws<CurrentPathSignalServerException>(() => client.RefreshAsync(Auth(), Binding, Metadata, default)); Check(registers == 0, "Frozen device must never self-activate"); }
            else { await client.RefreshAsync(Auth(), Binding, Metadata, default); Check(registers == 1 && lists == 2 && presences == 2, "Enrollment must be bounded to one attempt and refresh metadata"); }
        }
    }
    private static async Task FailureBoundariesAsync()
    {
        foreach (var status in new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden, HttpStatusCode.ServiceUnavailable, HttpStatusCode.TooManyRequests })
        {
            using var http = new HttpClient(new Handler((r, c) => Task.FromResult(Reply("{\"error\":\"forbidden\"}", status))));
            await Throws<CurrentPathSignalServerException>(() => new AccountDeviceRosterClient(http).RefreshAsync(Auth(), Binding, Metadata, default));
        }
        foreach (string bad in new[] { "[]", "{}", "{\"devices\":[]}", Snapshot(new JsonObject()).ToJsonString(), Snapshot(Row(), Row()).ToJsonString(), Snapshot(Row()).ToJsonString().Replace("\"online\":true", "\"online\":\"true\"") })
        {
            using var http = new HttpClient(new Handler((r, c) => Task.FromResult(Reply(r.RequestUri!.AbsolutePath.EndsWith("register") ? Presence : bad))));
            await Throws<InvalidDataException>(() => new AccountDeviceRosterClient(http).RefreshAsync(Auth(), Binding, Metadata, default));
        }
        using var canceled = new CancellationTokenSource(); canceled.Cancel();
        using var delayed = new HttpClient(new Handler(async (r, c) => { await Task.Delay(5000, c); return Reply(Presence); }));
        await Throws<OperationCanceledException>(() => new AccountDeviceRosterClient(delayed).RefreshAsync(Auth(), Binding, Metadata, canceled.Token));
    }
    private static async Task IdentityRowsAsync()
    {
        var other = Row(new string('a', 64), false); other["deviceName"] = "Prior signing identity"; other["online"] = false;
        var body = Snapshot(Row(), other);
        using var http = new HttpClient(new Handler((r, c) => Task.FromResult(Reply(r.RequestUri!.AbsolutePath.EndsWith("register") ? Presence : body.ToJsonString()))));
        var result = await new AccountDeviceRosterClient(http).RefreshAsync(Auth(), Binding, Metadata, default);
        Check(result.Devices.Select(d => d.Identity).Distinct().Count() == 2, "Same device ID must not merge different keys");
        other["isCaller"] = true;
        await Throws<InvalidDataException>(() => new AccountDeviceRosterClient(http).RefreshAsync(Auth(), Binding, Metadata, default));
    }
    private static async Task TenantClaimsAsync()
    {
        var token = Token(user: new { tenant_id = "attacker" }); var auth = AccountDeviceAuthentication.FromVerifiedSession(token, Authority, "account-user");
        Check(auth.TenantId == "account-user" && !auth.ToString().Contains(token, StringComparison.Ordinal), "Editable metadata or logging exposed authority");
        var tenant = AccountDeviceAuthentication.FromVerifiedSession(Token(app: new { tenant_id = "tenant-a", org_id = "tenant-a" }), Authority, "account-user");
        Check(tenant.TenantId == "tenant-a", "Protected tenant must be retained");
        await Throws<InvalidDataException>(() => Task.FromResult(AccountDeviceAuthentication.FromVerifiedSession(Token(app: new { tenant_id = "a", org_id = "b" }), Authority, "account-user")));
        await Throws<InvalidDataException>(() => Task.FromResult(AccountDeviceAuthentication.FromVerifiedSession(Token(), Authority, "other-user")));
    }
    private sealed class Clock : TimeProvider
    { internal long Seconds = 100; public override long TimestampFrequency => 1; public override long GetTimestamp() => Seconds; }
    private sealed class Client(Func<CancellationToken, Task<AccountDeviceRosterSnapshot>> refresh) : IAccountDeviceRosterClient
    {
        internal Func<CancellationToken, Task>? Remove;
        public void ResetRegistration() { }
        public Task RemoveAsync(AccountDeviceAuthentication a, CurrentPathProtocolIdentityBinding b, AccountDeviceEntry t, CancellationToken c)
            => Remove is null ? Task.FromException(new InvalidOperationException("No removal fixture")) : Remove(c);
        public Task<AccountDeviceRosterSnapshot> RefreshAsync(AccountDeviceAuthentication a, CurrentPathProtocolIdentityBinding b, AccountDeviceMetadata m, CancellationToken c) => refresh(c);
    }
    private static AccountDeviceRosterSnapshot One() => new(1700000000000L, Binding.DeviceId, false, [new(Binding.DeviceId, "Windows", "active", "Ed25519", Binding.ProtocolPublicKeyFingerprint, "windows", "Test model", "Windows 11", "1.0.2", 1700000000000L, true, true)]);
    private static AccountDevicesCoordinator Coordinator(IAccountDeviceRosterClient client, Clock clock) => new(client, c => Task.FromResult<AccountDeviceAuthentication?>(Auth()), c => Task.FromResult(Binding), c => Task.FromResult(Metadata), k => k == "AccountDevicesSummary" ? "{0}/{1}" : k, clock);
    private static async Task LifecycleAsync()
    {
        var clock = new Clock(); await using (var engine = Coordinator(new Client(c => Task.FromResult(One())), clock))
        {
            engine.SetAccount(Auth().Scope); await engine.RefreshOnceAsync(default);
            Check(engine.Devices.Single().State.Contains("Online", StringComparison.Ordinal), "Successful snapshot must show live state");
            clock.Seconds += 90; engine.ExpireSnapshot();
            Check(engine.Devices.Single().State.Contains("Offline", StringComparison.Ordinal) && engine.Status == "AccountDevicesExpired", "TTL must expire without a new response");
        }
        var waiting = new TaskCompletionSource<AccountDeviceRosterSnapshot>(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var late = Coordinator(new Client(c => waiting.Task), new Clock()); late.SetAccount(Auth().Scope);
        var operation = late.RefreshOnceAsync(default); late.SetAccount(Auth("other-account").Scope); waiting.SetResult(One()); await operation;
        Check(late.Devices.Count == 0, "Late response from prior account was published");
    }
    private static async Task NetworkFailureAsync()
    {
        int count = 0; await using var engine = Coordinator(new Client(c => ++count == 1 ? Task.FromResult(One()) : throw new HttpRequestException("offline")), new Clock());
        engine.SetAccount(Auth().Scope); await engine.RefreshOnceAsync(default); await engine.RefreshOnceAsync(default);
        Check(engine.Status == "AccountDevicesNetworkError" && engine.Devices.All(d => d.State.Contains("Offline", StringComparison.Ordinal)), "Network failure must not retain online claims");
    }
    private sealed class Store : TestSessionState { }
    private sealed class AuthenticationClient(Store store) : ISupabaseAuthClient
    {
        internal int RefreshCount, UserChecks;
        internal bool RejectNextUserAfterRotation;
        public SessionAuthority SessionAuthority => Authority;
        public Task<AuthClientResult<AuthToken>> SignInWithPasswordAsync(string email, string password) => throw new NotSupportedException();
        public async Task<AuthClientResult<AuthToken>> RefreshAsync(string refreshToken)
        {
            Check(refreshToken == "refresh-1", "Only the currently persisted token may rotate");
            RefreshCount++; await Task.Yield();
            return AuthClientResult<AuthToken>.Success(new AuthToken { AccessToken = Token(), RefreshToken = "refresh-2", User = new AuthUser { Id = "account-user" } });
        }
        public Task<AuthClientResult<AuthUser>> GetUserAsync(string accessToken, string? userId = null)
        {
            UserChecks++;
            if (RefreshCount > 0) Check(store.Value?.RefreshToken == "refresh-2", "A rotated refresh token must commit before the next fallible network call");
            if(RefreshCount > 0 && RejectNextUserAfterRotation)
            {
                RejectNextUserAfterRotation = false;
                return Task.FromResult(AuthClientResult<AuthUser>.Failed(AuthFailureKind.Network,"temporary-network-loss"));
            }
            return Task.FromResult(AuthClientResult<AuthUser>.Success(new AuthUser { Id = userId, UserMetadata = new AuthUserMetadata { DisplayName = "Test" } }));
        }
        public Task<AuthClientResult<AuthSignOutReceipt>> SignOutAsync(string token) => Task.FromResult(AuthClientResult<AuthSignOutReceipt>.Success(new(true)));
    }
    private static async Task RefreshAuthenticationAsync()
    {
        var store = new Store(); var auth = new AuthenticationClient(store); var owner = new AccountSessionCoordinator(auth, store);
        Check((await owner.ApplyAuthAsync(new AuthToken { AccessToken = Token(minutes: 4), RefreshToken = "refresh-1", User = new AuthUser { Id = "account-user" } })).Success, "Initial server-verified sign-in failed");
        var snapshots = await Task.WhenAll(owner.GetDeviceAuthenticationAsync(default), owner.GetDeviceAuthenticationAsync(default));
        Check(auth.RefreshCount == 1 && auth.UserChecks == 2, "Concurrent reads must refresh once, then reuse the verified session");
        Check(snapshots.All(s => s?.Subject == "account-user" && s.Authority == Authority && s.TenantId == "account-user"), "Request snapshot lost its verified subject or authority");
        await owner.SignOutAsync();
        Check(await owner.GetDeviceAuthenticationAsync(default) is null, "Signed-out requests must not reuse a bearer token");
    }

    private static async Task TransientAuthenticationAsync()
    {
        var store = new Store(); var auth = new AuthenticationClient(store); var owner = new AccountSessionCoordinator(auth,store);
        Check((await owner.ApplyAuthAsync(new AuthToken {AccessToken=Token(minutes:4),RefreshToken="refresh-1",User=new AuthUser{Id="account-user"}})).Success,"Initial verified account required");
        auth.RejectNextUserAfterRotation=true;
        await Throws<AccountDeviceAuthenticationException>(()=>owner.GetDeviceAuthenticationAsync(default));
        Check(owner.AccountDeviceScope==Auth().Scope && store.Value?.RefreshToken=="refresh-2","Transient failure must preserve the scope and already-rotated token without issuing a request snapshot");
        var recovered=await owner.GetDeviceAuthenticationAsync(default);
        Check(recovered?.Subject=="account-user" && auth.RefreshCount==1 && auth.UserChecks==3,"Retry must reverify the rotated token without consuming its parent again");
    }
    private static async Task UnapprovedAccountAsync()
    {
        var peer=Row(new string('b',64),false);peer["deviceId"]="WINDOWS-SIBLING-ACCOUNT-0002";
        int registrations=0;
        using var http=new HttpClient(new Handler((r,c)=>Task.FromResult(Reply(r.RequestUri!.AbsolutePath switch {
            "/api/presence/register"=>Presence,
            "/api/devices/list"=> registrations==0 ? Snapshot(peer.DeepClone()).ToJsonString() : Snapshot(peer.DeepClone(),Row()).ToJsonString(),
            "/api/devices/register-current"=> RegisterReceipt(),
            _ => throw new InvalidOperationException("Unexpected account endpoint")
        }))));
        string RegisterReceipt() { registrations++; return JsonSerializer.Serialize(new { registered=true, device=new {
            tenant_id=Auth().TenantId,user_id=Auth().Subject,device_id=Binding.DeviceId,status="active",
            protocol_signing_algorithm="Ed25519",protocol_public_key_fingerprint=Binding.ProtocolPublicKeyFingerprint }}); }
        var result=await new AccountDeviceRosterClient(http).RefreshAsync(Auth(),Binding,Metadata,default);
        Check(registrations==1 && result.Devices.Count==2 && result.Devices.Any(d=>d.IsCaller),"An existing account must register its exact missing caller");
        await using var engine=Coordinator(new Client(c=>Task.FromResult(result)),new Clock());engine.SetAccount(Auth().Scope);await engine.RefreshOnceAsync(default);
        Check(engine.Phase=="ready" && engine.Status=="AccountDevicesCurrent","Confirmed registration must be reflected in the roster");
    }

    private static async Task StrictPresenceEnrollmentAsync()
    {
        foreach (bool revoked in new[] { false, true })
        {
            int presences = 0, registrations = 0;
            using var http = new HttpClient(new Handler((request, ct) =>
            {
                switch (request.RequestUri!.AbsolutePath)
                {
                    case "/api/presence/register":
                        presences++;
                        return Task.FromResult(presences == 1
                            ? Reply(JsonSerializer.Serialize(new { error = revoked ? "device_revoked" : "device_not_registered" }), HttpStatusCode.Forbidden)
                            : Reply(Presence));
                    case "/api/devices/list":
                        return Task.FromResult(Reply(registrations == 0 ? Snapshot().ToJsonString() : Snapshot(Row()).ToJsonString()));
                    case "/api/devices/register-current":
                        registrations++;
                        return Task.FromResult(Reply(JsonSerializer.Serialize(new { registered = true, device = new {
                            tenant_id = Auth().TenantId, user_id = Auth().Subject, device_id = Binding.DeviceId, status = "active",
                            protocol_signing_algorithm = "Ed25519", protocol_public_key_fingerprint = Binding.ProtocolPublicKeyFingerprint } })));
                    default: throw new InvalidOperationException("Unexpected account endpoint");
                }
            }));
            var client = new AccountDeviceRosterClient(http);
            if (revoked)
            {
                await Throws<CurrentPathSignalServerException>(() => client.RefreshAsync(Auth(), Binding, Metadata, default));
                Check(registrations == 0, "A revoked caller must never register itself");
            }
            else
            {
                var result = await client.RefreshAsync(Auth(), Binding, Metadata, default);
                Check(registrations == 1 && presences == 2 && result.Devices.Single().IsCaller,
                    "A missing identity must recover strict presence admission through confirmed registration");
            }
        }
    }

    private static Task ModelsAsync()
    {
        Check(AccountDevicePresentation.Model("MacBookPro18,2", "macos", k => k).Contains("MacBook Pro", StringComparison.Ordinal), "Use shared hardware catalogue");
        Check(AccountDevicePresentation.Model("Unknown-Future-Model", "windows", k => k) == "Unknown-Future-Model", "Unknown firmware identifier must remain exact");
        Check(AccountDevicePresentation.Model(null, "windows", k => k) == "AccountDeviceModelUnknown", "Missing model must not be inferred from device name");
        return Task.CompletedTask;
    }

    private static async Task RemovalWireAsync()
    {
        var target=One().Devices[0] with { DeviceId="WINDOWS-PEER-ACCOUNT-0002", Fingerprint=new string('b',64), IsCaller=false };
        foreach (bool wrong in new[]{false,true}) {
            using var http=new HttpClient(new Handler(async (request,ct)=> {
                Check(request.RequestUri!.AbsolutePath=="/api/devices/remove","Use the common removal endpoint");
                Check(request.Headers.Authorization?.Scheme=="Bearer","Removal must be authenticated");
                var body=JsonNode.Parse(await request.Content!.ReadAsStringAsync(ct))!;
                Check(body["deviceId"]!.GetValue<string>()==Binding.DeviceId,"Preserve caller identity");
                Check(body["target"]!["protocolPublicKeyFingerprint"]!.GetValue<string>()==target.Fingerprint,"Preserve selected signing identity");
                return Reply(JsonSerializer.Serialize(new {removed=true,target=new {deviceId=wrong?"foreign-target":target.DeviceId,
                    protocolSigningAlgorithm=target.Algorithm,protocolPublicKeyFingerprint=target.Fingerprint,status="revoked"}}));
            }));
            var client=new AccountDeviceRosterClient(http);
            if(wrong) await Throws<InvalidDataException>(()=>client.RemoveAsync(Auth(),Binding,target,default));
            else await client.RemoveAsync(Auth(),Binding,target,default);
        }
    }

    private static async Task RemovalLifecycleAsync()
    {
        int requests=0,removals=0;
        var client=new Client(c=>{requests++;return Task.FromResult(One());}) { Remove=c=>{removals++;return Task.CompletedTask;} };
        await using var engine=Coordinator(client,new Clock());engine.SetAccount(Auth().Scope);await engine.RefreshOnceAsync(default);
        string identity=engine.Devices[0].Identity;
        await engine.RemoveAsync(identity,"retired-account");Check(removals==0,"An old confirmation cannot act in a new account");
        await engine.RemoveAsync(identity,Auth().Scope);Check(removals==1 && engine.Phase=="revoked","Self removal requires a confirmed receipt");
        await engine.RefreshOnceAsync(default);Check(requests==1 && !engine.CanRefresh,"A removed caller must stop synchronization");
    }
}
