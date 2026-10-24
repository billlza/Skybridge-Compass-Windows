using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.RemoteControl;

internal static class AccountPresenceRouteTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("presence omits MAIN port when reception is disabled", Disabled),
        ("presence publishes only the exact listening address and QR port", Live),
        ("presence refreshes the listener after registration", RegistrationReplacement),
        ("presence withdraws a stopped listener and publishes its replacement", StopAndRestart),
        ("presence rejects another identity before HTTP", DifferentIdentity),
        ("presence rechecks the captured owner after journal preparation", RetiredDuringPreparation),
        ("presence rejects address or port mutation after capture", EndpointMutation),
        ("presence revalidates its listener after asynchronous HTTP credential preparation", RetiredDuringAuthentication),
        ("presence route lookup failure does not become an empty successful report", LookupFailure),
        ("presence cancellation during route lookup sends no request", CancelLookup),
        ("presence endpoint copies cannot mutate the QR publication", DefensiveCopy)
    ];

    private static readonly RemoteControlPairingMaterial Identity = RemoteControlPairingMaterial.CreateProtocolIdentity(
        "id:bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "Test Windows", Enumerable.Repeat((byte)0x33, 1952).ToArray());
    private static readonly CurrentPathProtocolIdentityBinding Binding = new(Identity.DeviceId,
        CurrentPathProtocolSigningAlgorithm.MLDsa65, Identity.ProtocolPublicKey, Identity.ProtocolPublicKeyFingerprint);
    private static readonly AccountDeviceMetadata Metadata = new("Test Windows", "Model", "Windows test",
        ["192.168.1.60", "10.0.0.5"]);
    private const string Presence = "{\"online\":true,\"ttlMs\":90000,\"expiresAt\":1700000090000,\"persisted\":true,\"persistReason\":\"written\"}";

    private static AccountDeviceAuthentication Auth()
    {
        var authority = SessionAuthority.ForSupabaseProject("https://account-test.supabase.co");
        static string B(object value) => Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(value))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        string token = B(new { alg = "EdDSA", typ = "JWT" }) + "." + B(new
        {
            iss = authority.Issuer, sub = "account-user", aud = "authenticated", role = "authenticated",
            exp = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds()
        }) + ".dGVzdA";
        return AccountDeviceAuthentication.FromVerifiedSession(token, authority, "account-user");
    }

    private static void Require(bool value, string message) { if (!value) throw new InvalidOperationException(message); }
    private static async Task<T> Throws<T>(Func<Task> action) where T : Exception
    {
        try { await action(); } catch (T error) { return error; }
        throw new InvalidOperationException($"Expected {typeof(T).Name}.");
    }
    private static HttpResponseMessage Reply(string body, HttpStatusCode status = HttpStatusCode.OK) =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) => send(request, token);
    }
    private sealed class Fixture : IDisposable
    {
        internal IPEndPoint Endpoint = new(IPAddress.Parse("192.168.1.60"), 51164);
        internal object Owner = new();
        internal bool Listening = true, RegisterFirst;
        internal int Requests, Captures, Lists, Registrations;
        internal readonly List<JsonElement> Presences = [];
        internal readonly HttpClient Http;
        internal Action? OnRegister;
        internal Fixture() => Http = new(new Handler(Respond));
        internal Task<LanConnectionInfoPublication?> Capture(CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); Captures++;
            if (!Listening) return Task.FromResult<LanConnectionInfoPublication?>(null);
            object owner = Owner;
            return Task.FromResult<LanConnectionInfoPublication?>(new(Identity, () =>
            {
                if (!Listening || !ReferenceEquals(owner, Owner)) throw new InvalidOperationException("MAIN owner retired.");
                return Endpoint;
            }));
        }
        internal AccountDeviceRosterClient Client(IAccountDeviceRegistryObserver? observer = null,
            Func<CancellationToken, Task<LanConnectionInfoPublication?>>? capture = null) => new(Http, observer, capture ?? Capture);
        internal Task<AccountDeviceRosterSnapshot> Refresh(AccountDeviceRosterClient client, CancellationToken token = default) =>
            client.RefreshAsync(Auth(), Binding, Metadata, token);
        private async Task<HttpResponseMessage> Respond(HttpRequestMessage request, CancellationToken token)
        {
            Requests++;
            string path = request.RequestUri!.AbsolutePath;
            if (path == "/api/presence/register")
            {
                using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(token));
                Presences.Add(body.RootElement.Clone());
                return RegisterFirst && Registrations == 0
                    ? Reply("{\"error\":\"device_not_registered\"}", HttpStatusCode.Forbidden) : Reply(Presence);
            }
            if (path == "/api/devices/register-current")
            {
                Registrations++; OnRegister?.Invoke();
                return Reply(JsonSerializer.Serialize(new { registered = true, device = new
                {
                    tenant_id = "account-user", user_id = "account-user", device_id = Binding.DeviceId,
                    protocol_signing_algorithm = Binding.ProtocolSigningAlgorithmWireName,
                    protocol_public_key_fingerprint = Binding.ProtocolPublicKeyFingerprint, status = "active"
                } }));
            }
            Require(path == "/api/devices/list", "Unexpected signaling request."); Lists++;
            if (RegisterFirst && Registrations == 0) return Reply("{\"error\":\"device_not_registered\"}", HttpStatusCode.Forbidden);
            return Reply(JsonSerializer.Serialize(new
            {
                generatedAt = 1700000000000L, callerDeviceId = Binding.DeviceId, truncated = false,
                devices = new[] { new { deviceId = Binding.DeviceId, deviceName = Identity.DeviceName, status = "active",
                    protocolSigningAlgorithm = Binding.ProtocolSigningAlgorithmWireName,
                    protocolPublicKeyFingerprint = Binding.ProtocolPublicKeyFingerprint, online = true, isCaller = true } }
            }));
        }
        public void Dispose() => Http.Dispose();
    }
    private static void RequireRoute(JsonElement body, IPEndPoint expected)
    {
        Require(body.GetProperty("lanControlPort").GetInt32() == expected.Port, "Stale or incorrect MAIN port.");
        Require(body.GetProperty("lanAddresses").EnumerateArray().Select(a => a.GetString()).SequenceEqual([expected.Address.ToString()]),
            "MAIN port was assigned to another local interface.");
        Require(body.GetProperty("deviceId").GetString() == Binding.DeviceId &&
            body.GetProperty("protocolSigningAlgorithm").GetString() == Binding.ProtocolSigningAlgorithmWireName &&
            body.GetProperty("protocolPublicKeyFingerprint").GetString() == Binding.ProtocolPublicKeyFingerprint,
            "Presence changed the registered protocol identity.");
    }
    private static async Task Disabled()
    {
        using var f = new Fixture { Listening = false }; await f.Refresh(f.Client());
        var body = f.Presences.Single();
        Require(!body.TryGetProperty("lanControlPort", out _) && body.GetProperty("lanAddresses").GetArrayLength() == 2,
            "Disabled reception published a port or erased ordinary device metadata.");
    }
    private static async Task Live()
    {
        using var f = new Fixture(); await f.Refresh(f.Client()); RequireRoute(f.Presences.Single(), f.Endpoint);
        var publication = await f.Capture(default) ?? throw new InvalidOperationException("Missing live publication.");
        Require(publication.ReadCurrentText().Contains("/51164/", StringComparison.Ordinal), "QR and presence selected different listeners.");
    }
    private static async Task RegistrationReplacement()
    {
        using var f = new Fixture { RegisterFirst = true };
        var original = new IPEndPoint(f.Endpoint.Address, f.Endpoint.Port);
        f.OnRegister = () => { f.Owner = new(); f.Endpoint = new(IPAddress.Parse("10.0.0.5"), 51173); };
        await f.Refresh(f.Client());
        Require(f.Captures == 2 && f.Presences.Count == 2 && f.Registrations == 1, "Registration reused an earlier route capture.");
        RequireRoute(f.Presences[0], original); RequireRoute(f.Presences[1], f.Endpoint);
    }
    private static async Task StopAndRestart()
    {
        using var f = new Fixture(); var client = f.Client(); await f.Refresh(client);
        f.Listening = false; await f.Refresh(client);
        Require(!f.Presences[1].TryGetProperty("lanControlPort", out _), "Stopped listener retained its port.");
        f.Listening = true; f.Owner = new(); f.Endpoint = new(IPAddress.Parse("10.0.0.5"), 51174);
        await f.Refresh(client); RequireRoute(f.Presences[2], f.Endpoint);
        Require(f.Captures == 3, "A later heartbeat reused a cached publication.");
    }
    private static async Task DifferentIdentity()
    {
        using var f = new Fixture(); var publication = await f.Capture(default);
        var wrong = new[]
        {
            new CurrentPathProtocolIdentityBinding("WINDOWS-PRESENCE-OTHER-0001", CurrentPathProtocolSigningAlgorithm.MLDsa65, Identity.ProtocolPublicKey),
            new CurrentPathProtocolIdentityBinding(Identity.DeviceId, CurrentPathProtocolSigningAlgorithm.Ed25519, new byte[32]),
            new CurrentPathProtocolIdentityBinding(Identity.DeviceId, CurrentPathProtocolSigningAlgorithm.MLDsa65, Enumerable.Repeat((byte)0x44, 1952).ToArray())
        };
        var client = new CurrentPathSignalServerClient(f.Http, new CurrentPathSignalServerClientOptions());
        foreach (var binding in wrong)
            await Throws<InvalidDataException>(() => client.PublishAccountPresenceAsync(binding, Metadata, default, publication));
        Require(f.Requests == 0, "An identity mismatch reached HTTP.");
    }
    private sealed class PreparationObserver(Action prepare) : IAccountDeviceRegistryObserver
    {
        internal int Completed;
        public ValueTask<IAccountDeviceRegistryObservation?> BeginAsync(AccountDeviceAuthentication authentication,
            CurrentPathProtocolIdentityBinding binding, AccountDeviceRegistryRequest request, CancellationToken token,
            AccountDeviceEntry? removalTarget = null)
        {
            Require(request == AccountDeviceRegistryRequest.Presence, "Unexpected observation after a rejected publication.");
            prepare(); return ValueTask.FromResult<IAccountDeviceRegistryObservation?>(new Observation(this));
        }
        private sealed class Observation(PreparationObserver owner) : IAccountDeviceRegistryObservation
        {
            public void Listed(AccountDeviceRosterSnapshot snapshot) => throw new InvalidOperationException("Unexpected list.");
            public void Removed(AccountDeviceEntry target) => throw new InvalidOperationException("Unexpected removal.");
            public void Rejected(CurrentPathSignalServerException error) => throw new InvalidOperationException("Unexpected HTTP rejection.");
            public ValueTask CompleteAsync(Exception? failure)
            {
                Require(failure is InvalidOperationException, "Publication failure was reported as successful.");
                owner.Completed++; return ValueTask.CompletedTask;
            }
        }
    }
    private static async Task RetiredDuringPreparation()
    {
        foreach (bool replace in new[] { false, true })
        {
            using var f = new Fixture();
            var observer = new PreparationObserver(() => { if (replace) f.Owner = new(); else f.Listening = false; });
            await Throws<InvalidOperationException>(() => f.Refresh(f.Client(observer)));
            Require(f.Requests == 0 && observer.Completed == 1, "Retired owner reached HTTP or lost its observation completion.");
        }
    }
    private static async Task EndpointMutation()
    {
        foreach (bool changeAddress in new[] { false, true })
        {
            using var f = new Fixture();
            var observer = new PreparationObserver(() =>
            { if (changeAddress) f.Endpoint.Address = IPAddress.Parse("192.168.1.61"); else f.Endpoint.Port++; });
            await Throws<InvalidOperationException>(() => f.Refresh(f.Client(observer)));
            Require(f.Requests == 0, "A mutable endpoint changed an already captured presence report.");
        }
    }
    private static async Task LookupFailure()
    {
        using var f = new Fixture(); var expected = new IOException("Native network enumeration failed.");
        var actual = await Throws<IOException>(() => f.Refresh(f.Client(capture: _ => Task.FromException<LanConnectionInfoPublication?>(expected))));
        Require(ReferenceEquals(actual, expected) && f.Requests == 0, "Lookup failure was hidden or reached HTTP.");
    }
    private static async Task RetiredDuringAuthentication()
    {
        using var f = new Fixture(); var publication = await f.Capture(default);
        var client = new CurrentPathSignalServerClient(f.Http, new CurrentPathSignalServerClientOptions(
            tenantIdProvider: _ => Task.FromResult("account-user"),
            bearerTokenProvider: async _ => { await Task.Yield(); f.Owner = new(); return Auth().AccessToken; }));
        await Throws<InvalidOperationException>(() => client.PublishAccountPresenceAsync(Binding, Metadata, default, publication));
        Require(f.Requests == 0, "Credential preparation admitted a retired listening endpoint.");
    }
    private static async Task CancelLookup()
    {
        using var f = new Fixture(); using var stop = new CancellationTokenSource();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        async Task<LanConnectionInfoPublication?> Capture(CancellationToken token)
        { entered.SetResult(); await Task.Delay(Timeout.Infinite, token); throw new InvalidOperationException("Canceled lookup resumed."); }
        var run = f.Refresh(f.Client(capture: Capture), stop.Token);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(3)); stop.Cancel();
        await Throws<OperationCanceledException>(() => run.WaitAsync(TimeSpan.FromSeconds(3)));
        Require(f.Requests == 0, "Canceled lookup sent a request.");
    }
    private static async Task DefensiveCopy()
    {
        using var f = new Fixture(); var publication = await f.Capture(default) ?? throw new InvalidOperationException("Missing live publication.");
        var endpoint = publication.ReadCurrentEndpoint(Binding); endpoint.Port++;
        Require(publication.ReadCurrentEndpoint(Binding).Port == 51164 && publication.ReadCurrentText().Contains("/51164/", StringComparison.Ordinal),
            "Presence caller mutated the shared QR route.");
    }
}
