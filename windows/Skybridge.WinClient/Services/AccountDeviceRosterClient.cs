using System.Net;
using System.Net.Http;
using System.Text.Json;

namespace Skybridge.WinClient.Services;

internal sealed record AccountDeviceEntry(string DeviceId, string DeviceName, string Status,
    string Algorithm, string Fingerprint, string? Platform, string? Model, string? OsVersion,
    string? AppVersion, long? LastSeenAt, bool Online, bool IsCaller)
{
    internal string Identity => DeviceId + "/" + Algorithm + "/" + Fingerprint;
}
internal sealed record AccountDeviceRosterSnapshot(long GeneratedAt, string CallerDeviceId, bool Truncated,
    IReadOnlyList<AccountDeviceEntry> Devices);
internal sealed record AccountDeviceMetadata(string DeviceName, string? DeviceModel, string OsVersion, string[] LanAddresses);
internal interface IAccountDeviceRosterClient
{
    Task<AccountDeviceRosterSnapshot> RefreshAsync(AccountDeviceAuthentication auth, CurrentPathProtocolIdentityBinding binding,
        AccountDeviceMetadata metadata, CancellationToken cancellationToken);
    Task RemoveAsync(AccountDeviceAuthentication auth, CurrentPathProtocolIdentityBinding binding,
        AccountDeviceEntry target, CancellationToken cancellationToken);
    void ResetRegistration();
}
internal interface IAccountDeviceRegistryObserver
{
    ValueTask<IAccountDeviceRegistryObservation?> BeginAsync(AccountDeviceAuthentication authentication,
        CurrentPathProtocolIdentityBinding binding, AccountDeviceRegistryRequest request, CancellationToken cancellationToken,
        AccountDeviceEntry? removalTarget = null);
}
internal enum AccountDeviceRegistryRequest { Presence, List, Registration, Removal }
internal sealed class AccountDeviceRegistryObservationException(string stage, Exception cause)
    : InvalidOperationException($"Registry observation {stage} failed.", cause)
{
    internal string Stage { get; } = stage;
}
internal interface IAccountDeviceRegistryObservation
{
    void Listed(AccountDeviceRosterSnapshot snapshot);
    void Removed(AccountDeviceEntry target);
    void Rejected(CurrentPathSignalServerException error);
    // Runs once after the underlying request AND its result callback have settled.
    // Deliberately has no UI cancellation token: cancellation cannot erase an
    // observed denial or abandon its durable completion. null means success;
    // every other outcome retains the actual request/callback exception.
    ValueTask CompleteAsync(Exception? failure);
}

// Use the same bounded signaling HTTP path as all other current-path requests.
// No direct table query: the service overlays only exact registered identities
// with live presence and authorizes the tenant/user from the verified bearer.
internal sealed class AccountDeviceRosterClient(HttpClient httpClient, IAccountDeviceRegistryObserver? observer = null,
    Func<CancellationToken, Task<LanConnectionInfoPublication?>>? readLanConnectionInfo = null) : IAccountDeviceRosterClient
{
    private string? _registrationScope;
    private int _registrationAttempts;
    private Exception? _registrationFailure;
    public void ResetRegistration() { _registrationAttempts = 0; _registrationFailure = null; }
    public async Task<AccountDeviceRosterSnapshot> RefreshAsync(AccountDeviceAuthentication auth,
        CurrentPathProtocolIdentityBinding binding, AccountDeviceMetadata metadata, CancellationToken cancellationToken)
    {
        var client = new CurrentPathSignalServerClient(httpClient, new CurrentPathSignalServerClientOptions(
            bearerTokenProvider: _ => Task.FromResult(auth.AccessToken), tenantIdProvider: _ => Task.FromResult(auth.TenantId),
            clientVersion: "1.0.2"));
        async Task<AccountDeviceRosterSnapshot> ListAsync()
        {
            // Each GET has its own observation interval. Publish its validated result before
            // cancellation/UI checks or a registration retry can discard this snapshot.
            return await ObserveAsync(auth, binding, AccountDeviceRegistryRequest.List,
                () => client.ListAccountDevicesAsync(binding, cancellationToken),
                (observation, result) => observation.Listed(result), cancellationToken).ConfigureAwait(false);
        }
        async Task PresenceAsync()
        {
            // Read again for each presence request, including after registration. A listener
            // can stop or acquire another endpoint while that earlier request is in flight.
            var publication = readLanConnectionInfo is null ? null : await readLanConnectionInfo(cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            await ObserveAsync(auth, binding, AccountDeviceRegistryRequest.Presence,
                () => client.PublishAccountPresenceAsync(binding, metadata, cancellationToken, publication), null, cancellationToken).ConfigureAwait(false);
        }
        string scope = auth.Scope + "/" + binding.DeviceId + "/" + binding.ProtocolPublicKeyFingerprint;
        if (_registrationScope != scope) { _registrationScope = scope; ResetRegistration(); }
        async Task RegisterAsync()
        {
            if (_registrationFailure is not null && (_registrationAttempts >= 3 || !Retryable(_registrationFailure)))
                throw _registrationFailure;
            _registrationAttempts++;
            try
            {
                await ObserveAsync(auth, binding, AccountDeviceRegistryRequest.Registration,
                    () => client.RegisterAccountDeviceAsync(auth, binding, metadata.DeviceName, cancellationToken),
                    null, cancellationToken).ConfigureAwait(false);
                _registrationFailure = null;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception error) { _registrationFailure = error; throw; }
        }
        CurrentPathSignalServerException? initialAdmissionFailure = null;
        try { await PresenceAsync().ConfigureAwait(false); }
        catch (CurrentPathSignalServerException error) when (AccountDeviceWire.ErrorCode(error) is "device_not_registered" or "device_not_active")
        {
            initialAdmissionFailure = error;
        }
        AccountDeviceRosterSnapshot snapshot;
        bool enrollmentAttempted = false;
        try { snapshot = await ListAsync().ConfigureAwait(false); }
        catch (CurrentPathSignalServerException error) when (AccountDeviceWire.ErrorCode(error) is "device_not_registered" or "device_not_active")
        {
            enrollmentAttempted = true;
            await RegisterAsync().ConfigureAwait(false);
            await PresenceAsync().ConfigureAwait(false);
            snapshot = await ListAsync().ConfigureAwait(false);
        }
        var caller = snapshot.Devices.SingleOrDefault(d => d.IsCaller);
        if (!enrollmentAttempted && !snapshot.Truncated && (caller is null || caller.Status == "pending")
            && !snapshot.Devices.Any(d => d.DeviceId == binding.DeviceId && !d.IsCaller))
        {
            enrollmentAttempted = true;
            await RegisterAsync().ConfigureAwait(false);
            await PresenceAsync().ConfigureAwait(false);
            snapshot = await ListAsync().ConfigureAwait(false);
        }
        if (initialAdmissionFailure is not null && !enrollmentAttempted) throw initialAdmissionFailure;
        return snapshot;
    }

    private static bool Retryable(Exception error) => error is HttpRequestException or TaskCanceledException
        || error is CurrentPathSignalServerException rejected && ((int)rejected.StatusCode == 429 || (int)rejected.StatusCode >= 500);

    public async Task RemoveAsync(AccountDeviceAuthentication auth, CurrentPathProtocolIdentityBinding binding,
        AccountDeviceEntry target, CancellationToken cancellationToken)
    {
        var client = new CurrentPathSignalServerClient(httpClient, new CurrentPathSignalServerClientOptions(
            bearerTokenProvider: _ => Task.FromResult(auth.AccessToken), tenantIdProvider: _ => Task.FromResult(auth.TenantId), clientVersion: "1.0.2"));
        await ObserveAsync(auth, binding, AccountDeviceRegistryRequest.Removal,
            () => client.RemoveAccountDeviceAsync(binding, target, cancellationToken),
            observation => observation.Removed(target), cancellationToken, target).ConfigureAwait(false);
    }

    private Task ObserveAsync(AccountDeviceAuthentication auth, CurrentPathProtocolIdentityBinding binding,
        AccountDeviceRegistryRequest request, Func<Task> send, Action<IAccountDeviceRegistryObservation>? accepted,
        CancellationToken cancellationToken, AccountDeviceEntry? removalTarget = null) => ObserveAsync(auth, binding, request,
            async () => { await send().ConfigureAwait(false); return true; },
            (observation, _) => accepted?.Invoke(observation), cancellationToken, removalTarget);

    private async Task<T> ObserveAsync<T>(AccountDeviceAuthentication auth, CurrentPathProtocolIdentityBinding binding,
        AccountDeviceRegistryRequest request, Func<Task<T>> send, Action<IAccountDeviceRegistryObservation, T> accepted,
        CancellationToken cancellationToken, AccountDeviceEntry? removalTarget = null)
    {
        cancellationToken.ThrowIfCancellationRequested();
        // Preparation precedes the HTTP call. If it fails, no request has been
        // sent and there is no returned observation for this owner to complete.
        IAccountDeviceRegistryObservation? observation;
        try
        {
            observation = observer is null ? null : await observer.BeginAsync(auth, binding, request, cancellationToken, removalTarget).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception error) { throw new AccountDeviceRegistryObservationException("preparation", error); }
        Exception? failure = null;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            T result;
            try { result = await send().ConfigureAwait(false); }
            catch (CurrentPathSignalServerException rejected) when (observation is not null)
            {
                try { observation.Rejected(rejected); }
                catch (Exception notificationFailure)
                {
                    throw new AggregateException("Registry request and rejection observation failed.", rejected,
                        new AccountDeviceRegistryObservationException("rejection", notificationFailure));
                }
                throw;
            }
            if (observation is not null)
            {
                try { accepted(observation, result); }
                catch (Exception notificationFailure)
                { throw new AccountDeviceRegistryObservationException("result", notificationFailure); }
            }
            return result;
        }
        catch (Exception error) { failure = error; throw; }
        finally
        {
            if (observation is not null)
            {
                try { await observation.CompleteAsync(failure).ConfigureAwait(false); }
                catch (Exception completionFailure)
                {
                    var context = new AccountDeviceRegistryObservationException("completion", completionFailure);
                    if (failure is null) throw context;
                    throw new AggregateException("Registry request and observation completion failed.", failure, context);
                }
            }
        }
    }
}

public sealed partial class CurrentPathSignalServerClient
{
    internal async Task RemoveAccountDeviceAsync(CurrentPathProtocolIdentityBinding binding, AccountDeviceEntry target, CancellationToken ct)
    {
        var response = await PerformJsonRequestAsync<JsonElement>("/api/devices/remove", HttpMethod.Post, new {
            deviceId = binding.DeviceId, protocolSigningAlgorithm = binding.ProtocolSigningAlgorithmWireName,
            protocolPublicKeyFingerprint = binding.ProtocolPublicKeyFingerprint,
            clientVersion = _options.ClientVersion, protocolVersion = _options.ProtocolVersion,
            target = new { deviceId = target.DeviceId, protocolSigningAlgorithm = target.Algorithm,
                protocolPublicKeyFingerprint = target.Fingerprint }
        }, true, AccountVersionHeaders, ct).ConfigureAwait(false);
        AccountDeviceWire.RequireUniqueFields(response);
        var removed = AccountDeviceWire.Member(response,"target");
        if (!AccountDeviceWire.Boolean(response,"removed") || AccountDeviceWire.Text(removed,"status") != "revoked"
            || AccountDeviceWire.Text(removed,"deviceId") != target.DeviceId
            || AccountDeviceWire.Text(removed,"protocolSigningAlgorithm") != target.Algorithm
            || AccountDeviceWire.Text(removed,"protocolPublicKeyFingerprint") != target.Fingerprint)
            throw new InvalidDataException("Device removal was not confirmed for the selected identity.");
    }
    private IReadOnlyDictionary<string, string> AccountVersionHeaders => new Dictionary<string, string>
    {
        ["X-SkyBridge-Client-Version"] = _options.ClientVersion,
        ["X-SkyBridge-Protocol-Version"] = _options.ProtocolVersion
    };
    internal async Task PublishAccountPresenceAsync(CurrentPathProtocolIdentityBinding binding, AccountDeviceMetadata metadata, CancellationToken ct,
        LanConnectionInfoPublication? publication = null)
    {
        ct.ThrowIfCancellationRequested();
        var payload = new Dictionary<string, object?>
        {
            ["deviceId"] = binding.DeviceId,
            ["protocolSigningAlgorithm"] = binding.ProtocolSigningAlgorithmWireName,
            ["protocolPublicKeyFingerprint"] = binding.ProtocolPublicKeyFingerprint,
            ["clientVersion"] = _options.ClientVersion,
            ["protocolVersion"] = _options.ProtocolVersion,
            ["deviceName"] = metadata.DeviceName,
            ["platform"] = "windows",
            ["deviceModel"] = metadata.DeviceModel,
            ["osVersion"] = metadata.OsVersion,
            ["lanAddresses"] = metadata.LanAddresses,
            ["capabilities"] = new[] { "file_transfer", "remote_desktop" }
        };
        if (publication is not null)
        {
            var endpoint = publication.ReadCurrentEndpoint(binding);
            // Windows MAIN binds one selected interface, not every local address.
            payload["lanAddresses"] = new[] { endpoint.Address.ToString() };
            payload["lanControlPort"] = endpoint.Port;
        }
        var response = await PerformJsonRequestAsync<JsonElement>("/api/presence/register", HttpMethod.Post,
            payload, true, AccountVersionHeaders, ct,
            publication is null ? null : () => { _ = publication.ReadCurrentEndpoint(binding); }).ConfigureAwait(false);
        if (!AccountDeviceWire.Boolean(response, "online") || AccountDeviceWire.Integer(response, "ttlMs") != 90_000
            || AccountDeviceWire.Integer(response, "expiresAt") <= 0)
            throw new InvalidDataException("Presence response is invalid.");
        bool persisted = AccountDeviceWire.Boolean(response, "persisted");
        string reason = AccountDeviceWire.Text(response, "persistReason");
        if (!persisted && reason is not ("throttled" or "device_not_active"))
            throw new CurrentPathSignalServerException(reason == "registry_not_configured" ? reason : "registry_unavailable", HttpStatusCode.ServiceUnavailable);
    }

    internal async Task RegisterAccountDeviceAsync(AccountDeviceAuthentication auth, CurrentPathProtocolIdentityBinding binding, string name, CancellationToken ct)
    {
        var response = await PerformJsonRequestAsync<JsonElement>("/api/devices/register-current", HttpMethod.Post, new
        {
            deviceId = binding.DeviceId,
            protocolSigningAlgorithm = binding.ProtocolSigningAlgorithmWireName,
            protocolPublicKeyFingerprint = binding.ProtocolPublicKeyFingerprint,
            deviceName = name,
            clientVersion = _options.ClientVersion,
            protocolVersion = _options.ProtocolVersion
        }, true, AccountVersionHeaders, ct).ConfigureAwait(false);
        var row = AccountDeviceWire.Member(response, "device");
        if (!AccountDeviceWire.Boolean(response, "registered") || AccountDeviceWire.Text(row, "tenant_id") != auth.TenantId
            || AccountDeviceWire.Text(row, "user_id") != auth.Subject || AccountDeviceWire.Text(row, "device_id") != binding.DeviceId
            || AccountDeviceWire.Text(row, "protocol_signing_algorithm") != binding.ProtocolSigningAlgorithmWireName
            || AccountDeviceWire.Text(row, "protocol_public_key_fingerprint") != binding.ProtocolPublicKeyFingerprint
            || AccountDeviceWire.Text(row, "status") != "active")
            throw new InvalidDataException("Device enrollment changed the authenticated account or protocol identity.");
    }

    internal async Task<AccountDeviceRosterSnapshot> ListAccountDevicesAsync(CurrentPathProtocolIdentityBinding binding, CancellationToken ct)
    {
        string path = "/api/devices/list?deviceId=" + Uri.EscapeDataString(binding.DeviceId)
            + "&protocolSigningAlgorithm=" + Uri.EscapeDataString(binding.ProtocolSigningAlgorithmWireName)
            + "&protocolPublicKeyFingerprint=" + Uri.EscapeDataString(binding.ProtocolPublicKeyFingerprint);
        var response = await PerformJsonRequestAsync<JsonElement>(path, HttpMethod.Get, null, true, AccountVersionHeaders, ct).ConfigureAwait(false);
        AccountDeviceWire.RequireUniqueFields(response);
        long generated = AccountDeviceWire.Integer(response, "generatedAt");
        if (generated <= 0 || generated > 253402300799999L || AccountDeviceWire.Text(response, "callerDeviceId") != binding.DeviceId)
            throw new InvalidDataException("Account device snapshot caller or timestamp is invalid.");
        bool truncated = AccountDeviceWire.Boolean(response, "truncated");
        var rows = AccountDeviceWire.Member(response, "devices");
        if (rows.ValueKind != JsonValueKind.Array || rows.GetArrayLength() > 200) throw new InvalidDataException("Account device list is not a bounded array.");
        var devices = new List<AccountDeviceEntry>(); var identities = new HashSet<string>(StringComparer.Ordinal);
        foreach (var row in rows.EnumerateArray())
        {
            string id = AccountDeviceWire.Text(row, "deviceId");
            if (CurrentPathProtocolIdentityBinding.NormalizeDeviceId(id) != id)
                throw new InvalidDataException("Registered device ID must use its exact wire spelling.");
            string algorithm = AccountDeviceWire.Text(row, "protocolSigningAlgorithm");
            if (CurrentPathProtocolSigningAlgorithms.ToWireName(CurrentPathProtocolSigningAlgorithms.ParseWireName(algorithm)) != algorithm)
                throw new InvalidDataException("Registered signing algorithm must use its exact wire spelling.");
            string fingerprint = AccountDeviceWire.Text(row, "protocolPublicKeyFingerprint");
            if (!CurrentPathProtocolIdentityBinding.IsLowerHex(fingerprint, 64)) throw new InvalidDataException("Invalid registered identity fingerprint.");
            bool caller = AccountDeviceWire.Boolean(row, "isCaller");
            bool exact = id == binding.DeviceId && algorithm == binding.ProtocolSigningAlgorithmWireName && fingerprint == binding.ProtocolPublicKeyFingerprint;
            if (caller != exact) throw new InvalidDataException("Caller flag does not match the complete device identity.");
            string state = AccountDeviceWire.Text(row, "status");
            if (state is not ("active" or "pending" or "frozen")) throw new InvalidDataException("Unexpected registry status.");
            var device = new AccountDeviceEntry(id, AccountDeviceWire.OptionalText(row, "deviceName") ?? id, state, algorithm, fingerprint,
                AccountDeviceWire.OptionalText(row, "platform"), AccountDeviceWire.OptionalText(row, "deviceModel"),
                AccountDeviceWire.OptionalText(row, "osVersion"), AccountDeviceWire.OptionalText(row, "appVersion"),
                AccountDeviceWire.OptionalInteger(row, "lastSeenAt"), AccountDeviceWire.Boolean(row, "online"), caller);
            if (!identities.Add(device.Identity)) throw new InvalidDataException("Duplicate registered identity row.");
            devices.Add(device);
        }
        return new(generated, binding.DeviceId, truncated, devices.AsReadOnly());
    }
}

internal static class AccountDeviceWire
{
    internal static void RequireUniqueFields(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            var fields = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in value.EnumerateObject())
            {
                if (!fields.Add(property.Name)) throw new InvalidDataException("Duplicate account device response field.");
                RequireUniqueFields(property.Value);
            }
        }
        else if (value.ValueKind == JsonValueKind.Array)
            foreach (var element in value.EnumerateArray()) RequireUniqueFields(element);
    }
    internal static JsonElement Member(JsonElement row, string name) => row.ValueKind == JsonValueKind.Object && row.TryGetProperty(name, out var v)
        ? v : throw new InvalidDataException("Missing account device field: " + name);
    internal static string Text(JsonElement row, string name) => OptionalText(row, name) ?? throw new InvalidDataException("Missing account device text: " + name);
    internal static string? OptionalText(JsonElement row, string name)
    {
        if (row.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Account device row must be an object.");
        if (!row.TryGetProperty(name, out var v) || v.ValueKind == JsonValueKind.Null) return null;
        if (v.ValueKind != JsonValueKind.String) throw new InvalidDataException("Invalid account device text: " + name);
        string value = v.GetString() ?? throw new InvalidDataException("Null account device text.");
        if (value.Length == 0 || value.Length > 256 || value.Any(char.IsControl)) throw new InvalidDataException("Invalid account device text: " + name);
        return value;
    }
    internal static long Integer(JsonElement row, string name) => (Member(row, name).ValueKind == JsonValueKind.Number && Member(row, name).TryGetInt64(out long v)) ? v : throw new InvalidDataException("Invalid account device integer: " + name);
    internal static long? OptionalInteger(JsonElement row, string name)
    {
        if (row.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Account device row must be an object.");
        if (!row.TryGetProperty(name, out var v) || v.ValueKind == JsonValueKind.Null) return null;
        if (v.ValueKind != JsonValueKind.Number || !v.TryGetInt64(out long value) || value <= 0 || value > 253402300799999L) throw new InvalidDataException("Invalid device timestamp.");
        return value;
    }
    internal static bool Boolean(JsonElement row, string name) => Member(row, name).ValueKind switch
    { JsonValueKind.True => true, JsonValueKind.False => false, _ => throw new InvalidDataException("Invalid account device flag: " + name) };
    internal static string? ErrorCode(CurrentPathSignalServerException error)
    {
        if (error.SanitizedBody is "registry_not_configured" or "registry_unavailable") return error.SanitizedBody;
        try
        {
            using var json = JsonDocument.Parse(error.SanitizedBody);
            foreach (string key in new[] { "code", "error" }) if (json.RootElement.TryGetProperty(key, out var code) && code.ValueKind == JsonValueKind.String) return code.GetString();
        }
        catch (JsonException) { /* A redacted non-JSON error has no trusted code. */ }
        return null;
    }
}
