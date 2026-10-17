using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace Skybridge.WinClient.Services;

// Immutable public wire values. Parsing/canonicalization does not authenticate a
// requester, establish MAIN, grant account membership, or authorize playback.
internal sealed record LanKemRefreshRequest(string RequesterDeviceId, string TargetDeviceId,
    ImmutableArray<int> RequestedSuiteWireIds, string PolicyHashHex, ImmutableArray<byte> Nonce, double SentAt,
    int Version = 1, string? RequesterProtocolIdentityFingerprint = null, string? TargetProtocolIdentityFingerprint = null,
    bool PolicyRequirePQC = true, bool PolicyAllowClassicFallback = false, string RouteScope = "lan",
    string? BonjourEndpointDigest = null, string? Platform = null, string? OsVersion = null, string? QPeriaptAuthProfile = null);

internal sealed record LanKemRefreshPublicKey(int SuiteWireId, ImmutableArray<byte> PublicKey);
internal sealed record LanSignedKemRefresh(string DeviceId, string ProtocolSigningAlgorithm,
    ImmutableArray<byte> ProtocolIdentityPublicKey, string ProtocolIdentityFingerprint,
    ImmutableArray<LanKemRefreshPublicKey> KemPublicKeys, string KeyId, long Generation,
    double SentAt, double ExpiresAt, ImmutableArray<byte> RequestNonce, ImmutableArray<byte> Signature,
    int Version = 1, ImmutableArray<string> Aliases = default, string? RequestHashHex = null,
    bool PolicyRequirePQC = true, bool PolicyAllowClassicFallback = false, string RouteScope = "lan",
    string? BonjourEndpointDigest = null, string? Platform = null, string? OsVersion = null,
    ImmutableArray<int>? PermittedSuiteWireIds = null, string? QPeriaptAuthProfile = null);

internal static class SignedLanKemRefreshWire
{
    internal const int MaximumBytes = LanBootstrapWire.MaximumBytes;
    internal static LanKemRefreshRequest DecodeRequest(ReadOnlySpan<byte> bytes)
    {
        var result = LanBootstrapWire.Decode<LanKemRefreshRequest>(bytes, "kemRefreshRequest");
        SignedLanKemRefreshCanonical.RequireRequestShape(result); return result;
    }
    internal static LanSignedKemRefresh DecodeResponse(ReadOnlySpan<byte> bytes)
    {
        var result = LanBootstrapWire.Decode<LanSignedKemRefresh>(bytes, "signedKEMRefresh");
        SignedLanKemRefreshCanonical.RequireResponseShape(result, requireSignature: true); return result;
    }
    internal static byte[] EncodeRequest(LanKemRefreshRequest value)
    { SignedLanKemRefreshCanonical.RequireRequestShape(value); return LanBootstrapWire.Encode("kemRefreshRequest", value); }
    internal static byte[] EncodeResponse(LanSignedKemRefresh value)
    {
        SignedLanKemRefreshCanonical.RequireResponseShape(value, requireSignature: true);
        return LanBootstrapWire.Encode("signedKEMRefresh", value.Aliases.IsDefault ? value with { Aliases = [] } : value);
    }

    // Unsigned diagnostics only. These codes never grant authority or select fallback.
    internal static byte[] EncodeFailure(LanKemRefreshRequest request, string code) => LanBootstrapWire.Encode("kemRefreshFailure", new
    {
        version = 1, requesterDeviceId = request.RequesterDeviceId, targetDeviceId = request.TargetDeviceId,
        stage = "kem_refresh", reasonCode = code, reason = code, requestHashHex = SignedLanKemRefreshCanonical.RequestHash(request),
        sentAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0 - 978307200.0
    });


}

internal static class SignedLanKemRefreshCanonical
{
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private static readonly Regex QProfile = new(@"\Aq-periapt-abi2-policy-v1/[0-9a-f]{64}/[0-9a-f]{64}/(0|[1-9][0-9]{0,19})/[0-9a-f]{64}\z",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    internal static long Milliseconds(double referenceSeconds) => LanBootstrapCanonical.Milliseconds(referenceSeconds);
    internal static string Hash(ReadOnlySpan<byte> bytes) => LanBootstrapCanonical.Hash(bytes);
    internal static string PolicyHash(int version, bool requirePqc = true, bool allowClassic = false, string scope = "lan")
    {
        RequireVersion(version);
        return Hash(Lines([("domain", $"SkyBridge-SKR-{version}-Policy"), ("version", Number(version)),
            ("policyRequirePQC", Bit(requirePqc)), ("policyAllowClassicFallback", Bit(allowClassic)), ("routeScope", Trim(scope).ToLowerInvariant())]));
    }
    internal static string RequestHash(LanKemRefreshRequest value) => Hash(RequestPreimage(value));
    internal static byte[] RequestPreimage(LanKemRefreshRequest v)
    {
        RequireRequestShape(v);
        var fields = new List<(string, string)> {
            ("domain", $"SkyBridge-SKR-{v.Version}-Request"), ("version", Number(v.Version)),
            ("requesterDeviceId", Token(v.RequesterDeviceId)), ("targetDeviceId", Token(v.TargetDeviceId)),
            ("requesterProtocolIdentityFingerprint", Hex(v.RequesterProtocolIdentityFingerprint!)),
            ("targetProtocolIdentityFingerprint", v.TargetProtocolIdentityFingerprint is null ? "" : Hex(v.TargetProtocolIdentityFingerprint)),
            ("requestedSuiteWireIds", Suites(v.RequestedSuiteWireIds)), ("policyRequirePQC", Bit(v.PolicyRequirePQC)),
            ("policyAllowClassicFallback", Bit(v.PolicyAllowClassicFallback)), ("policyHashHex", Hex(v.PolicyHashHex)),
            ("routeScope", Trim(v.RouteScope).ToLowerInvariant()), ("bonjourEndpointDigest", OptionalToken(v.BonjourEndpointDigest)),
            ("nonce", Convert.ToBase64String(v.Nonce.AsSpan())), ("sentAtMs", Number(Milliseconds(v.SentAt))) };
        if (v.Version == 3) fields.AddRange([("platform", Token(v.Platform!)), ("osVersion", Token(v.OsVersion!)),
            ("qPeriaptAuthProfile", OptionalToken(v.QPeriaptAuthProfile))]);
        return Lines(fields);
    }
    internal static byte[] ResponsePreimage(LanSignedKemRefresh v)
    {
        RequireResponseShape(v, requireSignature: false);
        var fields = new List<(string, string)> {
            ("domain", $"SkyBridge-SKR-{v.Version}-SignedKEMRefresh"), ("version", Number(v.Version)),
            ("deviceId", Token(v.DeviceId)), ("aliases", string.Join(',', Aliases(v).Select(Token).Order(StringComparer.Ordinal))),
            ("protocolSigningAlgorithm", Trim(v.ProtocolSigningAlgorithm)), ("protocolIdentityPublicKeyHash", Hash(v.ProtocolIdentityPublicKey.AsSpan())),
            ("protocolIdentityFingerprint", Hex(v.ProtocolIdentityFingerprint)),
            ("suiteNames", string.Join(',', v.KemPublicKeys.Select(k => SuiteName(k.SuiteWireId)).Order(StringComparer.Ordinal))),
            ("suiteWireIds", Suites(v.KemPublicKeys.Select(k => k.SuiteWireId))), ("kemPublicKeyHash", KemHash(v.KemPublicKeys)),
            ("keyId", Token(v.KeyId)), ("generation", Number(v.Generation)), ("sentAtMs", Number(Milliseconds(v.SentAt))),
            ("expiresAtMs", Number(Milliseconds(v.ExpiresAt))), ("requestNonce", Convert.ToBase64String(v.RequestNonce.AsSpan())),
            ("requestHashHex", Hex(v.RequestHashHex!)), ("policyRequirePQC", Bit(v.PolicyRequirePQC)),
            ("policyAllowClassicFallback", Bit(v.PolicyAllowClassicFallback)), ("routeScope", Trim(v.RouteScope).ToLowerInvariant()),
            ("bonjourEndpointDigest", OptionalToken(v.BonjourEndpointDigest)) };
        if (v.Version >= 2) fields.AddRange([("platform", Token(v.Platform!)), ("osVersion", Token(v.OsVersion!))]);
        if (v.Version == 3) fields.AddRange([("permittedSuiteWireIds", Suites(v.PermittedSuiteWireIds!.Value)),
            ("qPeriaptAuthProfile", OptionalToken(v.QPeriaptAuthProfile))]);
        return Lines(fields);
    }
    internal static string KemHash(ImmutableArray<LanKemRefreshPublicKey> keys)
    {
        if (keys.IsDefault || keys.Any(k => k is null) || keys.Select(k => k.SuiteWireId).Distinct().Count() != keys.Length)
            throw new InvalidDataException("Invalid SKR KEM collection.");
        using var bytes = new MemoryStream(); bytes.Write("SkyBridge-SKR-1-KEMPublicKeys\n"u8);
        Span<byte> header = stackalloc byte[6];
        foreach (var key in keys.OrderBy(k => k.SuiteWireId))
        {
            RequireKey(key);
            BinaryPrimitives.WriteUInt16LittleEndian(header, checked((ushort)key.SuiteWireId));
            BinaryPrimitives.WriteUInt32LittleEndian(header[2..], checked((uint)key.PublicKey.Length));
            bytes.Write(header); bytes.Write(key.PublicKey.AsSpan());
        }
        return Hash(bytes.ToArray());
    }
    internal static void RequireRequestShape(LanKemRefreshRequest v)
    {
        ArgumentNullException.ThrowIfNull(v); RequireVersion(v.Version);
        _ = Token(v.RequesterDeviceId); _ = Token(v.TargetDeviceId); _ = Hex(v.RequesterProtocolIdentityFingerprint!);
        if (v.TargetProtocolIdentityFingerprint is not null) _ = Hex(v.TargetProtocolIdentityFingerprint);
        RequirePolicy(v.PolicyRequirePQC, v.PolicyAllowClassicFallback, v.RouteScope);
        if (Hex(v.PolicyHashHex) != PolicyHash(v.Version, v.PolicyRequirePQC, v.PolicyAllowClassicFallback, v.RouteScope))
            throw new InvalidDataException("SKR policy hash mismatch.");
        RequireNonce(v.Nonce); _ = Milliseconds(v.SentAt);
        RequireSuites(v.RequestedSuiteWireIds, v.Version, allowEmpty: false, sorted: false);
        if (v.BonjourEndpointDigest is not null) _ = Hex(v.BonjourEndpointDigest);
        if (v.Version == 3) RequireCapabilities(v.RequestedSuiteWireIds, v.Platform, v.OsVersion, v.QPeriaptAuthProfile, false);
        else if (v.Platform is not null || v.OsVersion is not null || v.QPeriaptAuthProfile is not null)
            throw new InvalidDataException("Legacy SKR request contains unsigned negotiation fields.");
    }
    internal static void RequireRequestFreshness(LanKemRefreshRequest v, long nowMilliseconds)
    {
        RequireRequestShape(v); var sent = Milliseconds(v.SentAt);
        if ((decimal)sent - nowMilliseconds > 30_000 || (decimal)nowMilliseconds - sent > 120_000)
            throw new InvalidDataException("SKR request is stale or too far in the future.");
    }
    internal static void RequireResponseShape(LanSignedKemRefresh v, bool requireSignature)
    {
        ArgumentNullException.ThrowIfNull(v); RequireVersion(v.Version); _ = Token(v.DeviceId); _ = Token(v.KeyId);
        RequirePolicy(v.PolicyRequirePQC, v.PolicyAllowClassicFallback, v.RouteScope);
        var aliases = Aliases(v);
        if (aliases.Length > 32 || aliases.Select(Token).Distinct(StringComparer.Ordinal).Count() != aliases.Length)
            throw new InvalidDataException("Duplicate or excessive SKR aliases.");
        var algorithm = Trim(v.ProtocolSigningAlgorithm) switch { "ML-DSA-65" => WebRtcProductSignatureAlgorithm.MlDsa65,
            "Ed25519" => WebRtcProductSignatureAlgorithm.Ed25519, _ => throw new InvalidDataException("Unsupported SKR signer.") };
        if (v.ProtocolIdentityPublicKey.IsDefault || new WebRtcProductProtocolIdentityPublicKey(algorithm,
                v.ProtocolIdentityPublicKey.ToArray()).AuthoritativeFingerprint != Hex(v.ProtocolIdentityFingerprint))
            throw new InvalidDataException("SKR signer fingerprint does not match its public key.");
        if (v.Generation < 0) throw new InvalidDataException("Negative SKR generation.");
        var sent = Milliseconds(v.SentAt); var expiry = Milliseconds(v.ExpiresAt);
        if (expiry <= sent || v.Version >= 2 && (decimal)expiry - sent > 300_000)
            throw new InvalidDataException("Invalid SKR validity interval.");
        RequireNonce(v.RequestNonce); _ = Hex(v.RequestHashHex!);
        if (v.BonjourEndpointDigest is not null) _ = Hex(v.BonjourEndpointDigest);
        if (v.KemPublicKeys.IsDefault || v.KemPublicKeys.Any(k => k is null)) throw new InvalidDataException("Missing SKR key collection.");
        RequireSuites(v.KemPublicKeys.Select(k => k.SuiteWireId).ToImmutableArray(), v.Version, v.Version == 3, false);
        foreach (var key in v.KemPublicKeys) RequireKey(key);
        if (v.Version == 3)
        {
            if (v.PermittedSuiteWireIds is not { } permitted) throw new InvalidDataException("Missing SKR permitted suites.");
            RequireCapabilities(permitted, v.Platform, v.OsVersion, v.QPeriaptAuthProfile, true);
            if (permitted.Contains(0x0012) && algorithm != WebRtcProductSignatureAlgorithm.MlDsa65)
                throw new InvalidDataException("Q capability requires an ML-DSA signer.");
        }
        else
        {
            if (v.PermittedSuiteWireIds is not null || v.QPeriaptAuthProfile is not null) throw new InvalidDataException("Legacy response contains unsigned negotiation fields.");
            if (v.Version == 2)
            {
                RequireAppPlatform(v.Platform, v.OsVersion);
                if (algorithm != WebRtcProductSignatureAlgorithm.MlDsa65) throw new InvalidDataException("Q refresh requires ML-DSA.");
            }
            else if (v.Platform is not null || v.OsVersion is not null) throw new InvalidDataException("Legacy response contains unsigned platform fields.");
        }
        if (v.Signature.IsDefault || v.Signature.Length > 8192 || requireSignature && v.Signature.IsEmpty)
            throw new InvalidDataException("Invalid SKR signature length.");
    }

    // Structural binding only. A caller must still verify the response signature and
    // restrict signed aliases to its existing pairing authority before using keys.
    internal static void RequireResponseBindings(LanKemRefreshRequest request, LanSignedKemRefresh response,
        string expectedFingerprint, long nowMilliseconds, long? minimumGeneration = null)
    {
        RequireRequestFreshness(request, nowMilliseconds); RequireResponseShape(response, true);
        if (request.Version != response.Version || Hex(request.TargetProtocolIdentityFingerprint!) != Hex(expectedFingerprint) ||
            Hex(response.ProtocolIdentityFingerprint) != Hex(expectedFingerprint) ||
            Hex(response.RequestHashHex!) != RequestHash(request) || !request.Nonce.AsSpan().SequenceEqual(response.RequestNonce.AsSpan()) ||
            OptionalToken(request.BonjourEndpointDigest) != OptionalToken(response.BonjourEndpointDigest) ||
            !Aliases(response).Select(Token).Append(Token(response.DeviceId)).Contains(Token(request.TargetDeviceId), StringComparer.Ordinal) ||
            minimumGeneration is { } generation && response.Generation < generation)
            throw new InvalidDataException("SKR response binding changed.");
        var sent = Milliseconds(response.SentAt); var expiry = Milliseconds(response.ExpiresAt);
        if ((decimal)sent - nowMilliseconds > 30_000 || expiry <= nowMilliseconds) throw new InvalidDataException("SKR response expired or is in the future.");
        var keys = response.KemPublicKeys.Select(k => k.SuiteWireId).Order().ToArray();
        if (keys.Any(k => !request.RequestedSuiteWireIds.Contains(k))) throw new InvalidDataException("SKR returned an unrequested key.");
        if (response.Version == 3 && !keys.SequenceEqual(Intersection(request.RequestedSuiteWireIds,
            response.PermittedSuiteWireIds!.Value, request.QPeriaptAuthProfile, response.QPeriaptAuthProfile).Order()))
            throw new InvalidDataException("SKR response omits or adds a key outside the complete permitted intersection.");
    }
    internal static ImmutableArray<int> Intersection(ImmutableArray<int> requested, ImmutableArray<int> permitted,
        string? requesterProfile, string? responderProfile) => new[] { 0x0012, 0x0001, 0x0101 }
            .Where(id => requested.Contains(id) && permitted.Contains(id) && (id != 0x0012 ||
                requesterProfile is not null && requesterProfile == responderProfile)).ToImmutableArray();
    internal static void RequireCapabilities(ImmutableArray<int> suites, string? platform, string? osVersion, string? profile, bool sorted)
    {
        RequireSuites(suites, 3, allowEmpty: sorted, sorted);
        RequireMetadata(platform); RequireMetadata(osVersion);
        if (suites.Contains(0x0012))
        {
            RequireAppPlatform(platform, osVersion);
            var match = profile is null ? null : QProfile.Match(profile);
            if (match?.Success != true || !ulong.TryParse(match.Groups[1].Value, NumberStyles.None, CultureInfo.InvariantCulture, out _))
                throw new InvalidDataException("Invalid Q policy profile.");
        }
        else if (profile is not null) throw new InvalidDataException("Q profile supplied without Q capability.");
    }
    private static void RequireAppPlatform(string? platform, string? osVersion)
    {
        string? Family(string value) => Trim(value).ToLowerInvariant() switch {
            "macos" or "mac os" => "macos", "ios" or "ipados" => "ios", "android" => "android",
            "ubuntu" => "ubuntu", "windows" => "windows", _ => null };
        // v2 signs trimmed tokens; v3 additionally checks canonical metadata in
        // RequireCapabilities. Normalize spacing only for platform eligibility.
        var family = Family(Token(platform ?? throw new InvalidDataException("Missing Q platform.")));
        var version = Regex.Replace(Token(osVersion ?? throw new InvalidDataException("Missing Q OS version.")),
            @"[ \t\r\n\f\v]+", " ", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
        if (family is null) throw new InvalidDataException("Unknown Q app platform.");
        if (char.IsAsciiDigit(version[0]))
        {
            if (family == "android") throw new InvalidDataException("Android Q metadata requires the explicit API level.");
            version = family + " " + version;
        }
        var words = version.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var versionFamily = words.Length >= 2 && words[0].Equals("mac", StringComparison.OrdinalIgnoreCase) &&
            words[1].Equals("os", StringComparison.OrdinalIgnoreCase) ? "macos" : Family(words[0]);
        if (versionFamily != family || !QPeriaptPeerPlatform.IsEligible(version)) throw new InvalidDataException("Q app platform/version mismatch.");
    }
    private static void RequireMetadata(string? value)
    {
        if (value is null || value.Length is < 1 or > 256 || value != Trim(value) || value.Any(c => c < 0x20 || c is (char)0x7f or '='))
            throw new InvalidDataException("Invalid SKR platform metadata.");
        _ = Utf8.GetByteCount(value);
    }
    private static void RequireSuites(ImmutableArray<int> suites, int version, bool allowEmpty, bool sorted)
    {
        if (suites.IsDefault || !allowEmpty && suites.IsEmpty || suites.Length > 3 || suites.Distinct().Count() != suites.Length ||
            suites.Any(id => version switch { 1 => id is not (1 or 257), 2 => id != 18, 3 => id is not (1 or 18 or 257), _ => true }) ||
            sorted && !suites.SequenceEqual(suites.Order())) throw new InvalidDataException("Invalid SKR suite set.");
    }
    internal static void RequireKey(LanKemRefreshPublicKey key)
    {
        var expected = key.SuiteWireId switch { 1 or 18 => 1216, 257 => 1184, _ => throw new InvalidDataException("Unsupported SKR key suite.") };
        if (key.PublicKey.IsDefault || key.PublicKey.Length != expected) throw new InvalidDataException("Invalid SKR public key length.");
    }
    private static void RequirePolicy(bool requirePqc, bool allowClassic, string scope)
    { if (!requirePqc || allowClassic || Trim(scope).ToLowerInvariant() != "lan") throw new InvalidDataException("SKR requires strict PQC on LAN."); }
    private static void RequireVersion(int version)
    { if (version is not (1 or 2 or 3)) throw new InvalidDataException("Unsupported SKR version."); }
    private static void RequireNonce(ImmutableArray<byte> value)
    { if (value.IsDefault || value.Length is < 16 or > 128) throw new InvalidDataException("Invalid SKR nonce length."); }
    private static ImmutableArray<string> Aliases(LanSignedKemRefresh v) => v.Aliases.IsDefault ? [] : v.Aliases;
    private static string Hex(string value)
    {
        ArgumentNullException.ThrowIfNull(value); var normalized = Trim(value).ToLowerInvariant();
        if (normalized.Length != 64 || normalized.Any(c => !char.IsAsciiHexDigit(c))) throw new InvalidDataException("Invalid SKR hash/fingerprint.");
        return normalized;
    }
    private static string Token(string value)
    {
        ArgumentNullException.ThrowIfNull(value); var normalized = Trim(value);
        if (normalized.Length is < 1 or > 256 || normalized.IndexOfAny(['\r', '\n', '=']) >= 0) throw new InvalidDataException("Invalid SKR canonical token.");
        _ = Utf8.GetByteCount(normalized); return normalized;
    }
    private static string OptionalToken(string? value) => value is null ? "" : Token(value);
    // Kotlin Char.isWhitespace combines Java whitespace and Unicode space chars.
    // The common signed platform/identity fields are ASCII; this also preserves its
    // explicit trim behavior without culture-sensitive .NET comparisons.
    private static string Trim(string value) => LanBootstrapCanonical.Trim(value);
    private static string SuiteName(int id) => id switch { 1 => "X-Wing", 18 => "Q-Periapt-ABI2-PolicyBound", 257 => "ML-KEM-768", _ => throw new InvalidDataException("Unsupported SKR suite.") };
    private static string Suites(IEnumerable<int> suites) => string.Join(',', suites.Order().Select(id => "0x" + id.ToString("X4", CultureInfo.InvariantCulture)));
    private static string Number(long value) => value.ToString(CultureInfo.InvariantCulture);
    private static string Bit(bool value) => value ? "1" : "0";
    private static byte[] Lines(IEnumerable<(string Name, string Value)> fields) => Utf8.GetBytes(string.Join('\n', fields.Select(p => p.Name + "=" + p.Value)));
}
