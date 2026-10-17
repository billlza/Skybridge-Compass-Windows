using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Globalization;
using System.Text;

namespace Skybridge.WinClient.Services;

internal sealed record LanPibRequest(int Version, string TransactionId, string RequesterDeviceId, string TargetDeviceId,
    ImmutableArray<string> RequestedProtocolSigningAlgorithms, string RequesterProtocolSigningAlgorithm,
    ImmutableArray<byte> RequesterProtocolIdentityPublicKey, string RequesterProtocolIdentityFingerprint,
    ImmutableArray<byte> RequesterSignature, ImmutableArray<byte> Nonce, double SentAt,
    bool PolicyRequirePQC = true, bool PolicyAllowClassicFallback = false, string RouteScope = "lan", string? BonjourEndpointDigest = null);
internal sealed record LanPibCandidate(int Version, string TransactionId, string DeviceId, string ProtocolSigningAlgorithm,
    ImmutableArray<byte> ProtocolIdentityPublicKey, string ProtocolIdentityFingerprint, double SentAt, double ExpiresAt,
    ImmutableArray<byte> RequestNonce, string RequestHashHex, ImmutableArray<byte> Signature,
    ImmutableArray<string> Aliases = default, string? DeviceName = null,
    bool PolicyRequirePQC = true, bool PolicyAllowClassicFallback = false, string RouteScope = "lan", string? BonjourEndpointDigest = null);
internal sealed record LanPibConfirm(int Version, string TransactionId, string RequesterDeviceId, string ResponderDeviceId,
    string RequesterProtocolIdentityFingerprint, string ResponderProtocolIdentityFingerprint,
    ImmutableArray<byte> RequestNonce, string RequestHashHex, string CandidateHashHex, string SasTranscriptHashHex,
    ImmutableArray<byte> ConfirmationNonce, double SentAt, double ExpiresAt, ImmutableArray<byte> RequesterSignature,
    bool PolicyRequirePQC = true, bool PolicyAllowClassicFallback = false, string RouteScope = "lan");
internal sealed record LanPibFinalAck(int Version, string TransactionId, string RequesterDeviceId, string ResponderDeviceId,
    string RequesterProtocolIdentityFingerprint, string ResponderProtocolIdentityFingerprint,
    ImmutableArray<byte> RequestNonce, ImmutableArray<byte> ConfirmationNonce, string RequestHashHex, string CandidateHashHex,
    string ConfirmHashHex, string SasTranscriptHashHex, bool Accepted, double SentAt, double ExpiresAt,
    ImmutableArray<byte> ResponderSignature, bool PolicyRequirePQC = true, bool PolicyAllowClassicFallback = false, string RouteScope = "lan");

internal static class LanPibWire
{
    internal static LanPibRequest DecodeRequest(ReadOnlySpan<byte> bytes)
    { var value = LanBootstrapWire.Decode<LanPibRequest>(bytes, "protocolIdentityBindingRequest"); LanPibValidation.RequireRequestShape(value); return value; }
    internal static LanPibCandidate DecodeCandidate(ReadOnlySpan<byte> bytes)
    { var value = LanBootstrapWire.Decode<LanPibCandidate>(bytes, "signedProtocolIdentityBinding"); LanPibValidation.RequireCandidateShape(value); return value; }
    internal static LanPibConfirm DecodeConfirm(ReadOnlySpan<byte> bytes)
    { var value = LanBootstrapWire.Decode<LanPibConfirm>(bytes, "protocolIdentityBindingConfirm"); LanPibValidation.RequireConfirmShape(value); return value; }
    internal static LanPibFinalAck DecodeFinalAck(ReadOnlySpan<byte> bytes)
    { var value = LanBootstrapWire.Decode<LanPibFinalAck>(bytes, "signedProtocolIdentityBindingFinalAck"); LanPibValidation.RequireFinalAckShape(value); return value; }
    internal static byte[] EncodeRequest(LanPibRequest value)
    { LanPibValidation.RequireRequestShape(value); return LanBootstrapWire.Encode("protocolIdentityBindingRequest", value); }
    internal static byte[] EncodeCandidate(LanPibCandidate value)
    { LanPibValidation.RequireCandidateShape(value); return LanBootstrapWire.Encode("signedProtocolIdentityBinding", value.Aliases.IsDefault ? value with { Aliases = [] } : value); }
    internal static byte[] EncodeConfirm(LanPibConfirm value)
    { LanPibValidation.RequireConfirmShape(value); return LanBootstrapWire.Encode("protocolIdentityBindingConfirm", value); }
    internal static byte[] EncodeFinalAck(LanPibFinalAck value)
    { LanPibValidation.RequireFinalAckShape(value); return LanBootstrapWire.Encode("signedProtocolIdentityBindingFinalAck", value); }
}

/// <summary>Bounded canonical encoding, not identity or signature verification.
/// The reference canonical goldens contain placeholder fingerprints/signatures:
/// they may be encoded here but must fail the independent network admission checks.</summary>
internal static class LanPibCanonical
{
    private static readonly UTF8Encoding Utf8 = new(false, true);
    internal static string Hash(ReadOnlySpan<byte> bytes) => LanBootstrapCanonical.Hash(bytes);
    internal static long Milliseconds(double seconds) => LanBootstrapCanonical.Milliseconds(seconds);
    internal static string RequestHash(LanPibRequest value) => Hash(RequestPreimage(value));
    internal static string CandidateHash(LanPibCandidate value) => HashJoined(CandidatePreimage(value), Signature(value.Signature));
    internal static string ConfirmHash(LanPibConfirm value) => HashJoined(ConfirmPreimage(value), Signature(value.RequesterSignature));
    internal static string SasTranscriptHash(LanPibRequest request, LanPibCandidate candidate) => HashJoined(
        "SkyBridge-PIB-1-SAS\n"u8.ToArray(), RequestPreimage(request), Signature(request.RequesterSignature),
        CandidatePreimage(candidate), Signature(candidate.Signature));
    internal static string SasCode(LanPibRequest request, LanPibCandidate candidate) =>
        (BinaryPrimitives.ReadUInt32BigEndian(Convert.FromHexString(SasTranscriptHash(request, candidate))) % 1_000_000)
            .ToString("D6", CultureInfo.InvariantCulture);

    internal static byte[] RequestPreimage(LanPibRequest v)
    {
        ArgumentNullException.ThrowIfNull(v); Version(v.Version, 3);
        var algorithms = Algorithms(v.RequestedProtocolSigningAlgorithms);
        return Lines([
            ("domain", "SkyBridge-PIB-1-Request"), ("version", "3"), ("transactionId", Transaction(v.TransactionId)),
            ("requesterDeviceId", Token(v.RequesterDeviceId)), ("targetDeviceId", Token(v.TargetDeviceId)),
            ("requestedProtocolSigningAlgorithms", string.Join(',', algorithms.Order(StringComparer.Ordinal))),
            ("requesterProtocolSigningAlgorithm", Token(v.RequesterProtocolSigningAlgorithm, 64)),
            ("requesterProtocolIdentityPublicKeyHash", Hash(Key(v.RequesterProtocolIdentityPublicKey))),
            ("requesterProtocolIdentityFingerprint", Hex(v.RequesterProtocolIdentityFingerprint)),
            ("policyRequirePQC", Bit(v.PolicyRequirePQC)), ("policyAllowClassicFallback", Bit(v.PolicyAllowClassicFallback)),
            ("routeScope", Token(v.RouteScope).ToLowerInvariant()), ("bonjourEndpointDigest", Optional(v.BonjourEndpointDigest, 128)),
            ("nonce", Nonce(v.Nonce)), ("sentAtMs", Time(v.SentAt))]);
    }
    internal static byte[] CandidatePreimage(LanPibCandidate v)
    {
        ArgumentNullException.ThrowIfNull(v); Version(v.Version, 2);
        var aliases = Aliases(v);
        return Lines([
            ("domain", "SkyBridge-PIB-1-SignedProtocolIdentityBinding"), ("version", "2"), ("transactionId", Transaction(v.TransactionId)),
            ("deviceId", Token(v.DeviceId)), ("aliases", string.Join(',', aliases.Select(x => Token(x)).Order(StringComparer.Ordinal).Distinct(StringComparer.Ordinal))),
            ("protocolSigningAlgorithm", Token(v.ProtocolSigningAlgorithm, 64)), ("protocolIdentityPublicKeyHash", Hash(Key(v.ProtocolIdentityPublicKey))),
            ("protocolIdentityFingerprint", Hex(v.ProtocolIdentityFingerprint)), ("deviceName", Optional(v.DeviceName)),
            ("sentAtMs", Time(v.SentAt)), ("expiresAtMs", Time(v.ExpiresAt)), ("requestNonce", Nonce(v.RequestNonce)),
            ("requestHashHex", Hex(v.RequestHashHex)), ("policyRequirePQC", Bit(v.PolicyRequirePQC)),
            ("policyAllowClassicFallback", Bit(v.PolicyAllowClassicFallback)), ("routeScope", Token(v.RouteScope).ToLowerInvariant()),
            ("bonjourEndpointDigest", Optional(v.BonjourEndpointDigest, 128))]);
    }
    internal static byte[] ConfirmPreimage(LanPibConfirm v)
    {
        ArgumentNullException.ThrowIfNull(v); Version(v.Version, 3);
        return Lines([
            ("domain", "SkyBridge-PIB-1-V3-Confirm"), ("version", "3"), ("transactionId", Transaction(v.TransactionId)),
            ("requesterDeviceId", Token(v.RequesterDeviceId)), ("responderDeviceId", Token(v.ResponderDeviceId)),
            ("requesterProtocolIdentityFingerprint", Hex(v.RequesterProtocolIdentityFingerprint)),
            ("responderProtocolIdentityFingerprint", Hex(v.ResponderProtocolIdentityFingerprint)), ("requestNonce", Nonce(v.RequestNonce)),
            ("requestHashHex", Hex(v.RequestHashHex)), ("candidateHashHex", Hex(v.CandidateHashHex)), ("sasTranscriptHashHex", Hex(v.SasTranscriptHashHex)),
            ("confirmationNonce", Nonce(v.ConfirmationNonce)), ("sentAtMs", Time(v.SentAt)), ("expiresAtMs", Time(v.ExpiresAt)),
            ("policyRequirePQC", Bit(v.PolicyRequirePQC)), ("policyAllowClassicFallback", Bit(v.PolicyAllowClassicFallback)),
            ("routeScope", Token(v.RouteScope).ToLowerInvariant())]);
    }
    internal static byte[] FinalAckPreimage(LanPibFinalAck v)
    {
        ArgumentNullException.ThrowIfNull(v); Version(v.Version, 3);
        return Lines([
            ("domain", "SkyBridge-PIB-1-V3-SignedFinalAck"), ("version", "3"), ("transactionId", Transaction(v.TransactionId)),
            ("requesterDeviceId", Token(v.RequesterDeviceId)), ("responderDeviceId", Token(v.ResponderDeviceId)),
            ("requesterProtocolIdentityFingerprint", Hex(v.RequesterProtocolIdentityFingerprint)),
            ("responderProtocolIdentityFingerprint", Hex(v.ResponderProtocolIdentityFingerprint)), ("requestNonce", Nonce(v.RequestNonce)),
            ("confirmationNonce", Nonce(v.ConfirmationNonce)), ("requestHashHex", Hex(v.RequestHashHex)), ("candidateHashHex", Hex(v.CandidateHashHex)),
            ("confirmHashHex", Hex(v.ConfirmHashHex)), ("sasTranscriptHashHex", Hex(v.SasTranscriptHashHex)), ("accepted", Bit(v.Accepted)),
            ("sentAtMs", Time(v.SentAt)), ("expiresAtMs", Time(v.ExpiresAt)), ("policyRequirePQC", Bit(v.PolicyRequirePQC)),
            ("policyAllowClassicFallback", Bit(v.PolicyAllowClassicFallback)), ("routeScope", Token(v.RouteScope).ToLowerInvariant())]);
    }

    internal static string Transaction(string value)
    {
        var text = Trim(value);
        if (!Guid.TryParseExact(text, "D", out var id)) throw new InvalidDataException("PIB transaction must be a hyphenated UUID.");
        return id.ToString("D");
    }
    internal static string Hex(string value)
    {
        var normalized = Trim(value).ToLowerInvariant();
        if (normalized.Length != 64 || normalized.Any(c => !char.IsAsciiHexDigit(c))) throw new InvalidDataException("Invalid PIB digest or fingerprint.");
        return normalized;
    }
    internal static string Token(string value, int maximum = 256)
    {
        var normalized = Trim(value);
        if (normalized.Length is < 1 || normalized.Length > maximum || normalized.Any(c => c is '\r' or '\n' or '='))
            throw new InvalidDataException("Invalid PIB canonical token.");
        _ = Utf8.GetByteCount(normalized); return normalized;
    }
    internal static string Optional(string? value, int maximum = 256) => value is null || Trim(value).Length == 0 ? "" : Token(value, maximum);
    internal static ImmutableArray<string> Aliases(LanPibCandidate value)
    {
        var aliases = value.Aliases.IsDefault ? ImmutableArray<string>.Empty : value.Aliases;
        if (aliases.Length > 32) throw new InvalidDataException("Too many PIB aliases.");
        foreach (var alias in aliases) _ = ListToken(alias);
        return aliases;
    }
    internal static ImmutableArray<string> Algorithms(ImmutableArray<string> values)
    {
        if (values.IsDefault || values.Length is < 1 or > 4) throw new InvalidDataException("Invalid PIB algorithm offer.");
        var result = values.Select(a => ListToken(a, 64)).ToImmutableArray();
        if (result.Distinct(StringComparer.Ordinal).Count() != result.Length) throw new InvalidDataException("Duplicate PIB algorithm offer.");
        return result;
    }
    private static string ListToken(string value, int maximum = 256)
    {
        var token = Token(value, maximum);
        if (token.Contains(',')) throw new InvalidDataException("PIB list members cannot contain the canonical delimiter.");
        return token;
    }
    internal static byte[] Signature(ImmutableArray<byte> bytes)
    {
        if (bytes.IsDefaultOrEmpty || bytes.Length > 8192) throw new InvalidDataException("Invalid PIB signature size.");
        return bytes.ToArray();
    }
    private static ReadOnlySpan<byte> Key(ImmutableArray<byte> value)
    {
        if (value.IsDefaultOrEmpty || value.Length > 4096) throw new InvalidDataException("Invalid PIB public key size.");
        return value.AsSpan();
    }
    private static string Nonce(ImmutableArray<byte> value)
    {
        if (value.IsDefault || value.Length is < 16 or > 128) throw new InvalidDataException("Invalid PIB nonce size.");
        return Convert.ToBase64String(value.AsSpan());
    }
    private static string Time(double value) => Milliseconds(value).ToString(CultureInfo.InvariantCulture);
    private static string Bit(bool value) => value ? "1" : "0";
    private static void Version(int actual, int required)
    { if (actual != required) throw new InvalidDataException("Unsupported PIB message version."); }
    private static byte[] Lines(IEnumerable<(string Name, string Value)> fields) => Utf8.GetBytes(string.Join('\n', fields.Select(p => p.Name + "=" + p.Value)));
    private static string HashJoined(params byte[][] values)
    {
        using var bytes = new MemoryStream(); foreach (var value in values) bytes.Write(value); return Hash(bytes.ToArray());
    }
    private static string Trim(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return LanBootstrapCanonical.Trim(value);
    }

}

/// <summary>Structural policy, time and transcript checks only. Callers must also
/// verify each required signature and await explicit local SAS approval before a
/// durable trust commit. A final ACK is publishable only after that commit succeeds.</summary>
internal static class LanPibValidation
{
    internal static void RequireRequestShape(LanPibRequest value)
    {
        _ = LanPibCanonical.RequestPreimage(value);
        Device(value.RequesterDeviceId); Device(value.TargetDeviceId);
        Policy(value.PolicyRequirePQC, value.PolicyAllowClassicFallback, value.RouteScope);
        _ = SigningIdentity(value.RequesterProtocolSigningAlgorithm, value.RequesterProtocolIdentityPublicKey, value.RequesterProtocolIdentityFingerprint);
        _ = LanPibCanonical.Signature(value.RequesterSignature);
        if (value.BonjourEndpointDigest is not null) _ = LanPibCanonical.Hex(value.BonjourEndpointDigest);
    }
    internal static void RequireCandidateShape(LanPibCandidate value)
    {
        _ = LanPibCanonical.CandidatePreimage(value); Device(value.DeviceId);
        Policy(value.PolicyRequirePQC, value.PolicyAllowClassicFallback, value.RouteScope);
        _ = SigningIdentity(value.ProtocolSigningAlgorithm, value.ProtocolIdentityPublicKey, value.ProtocolIdentityFingerprint);
        _ = LanPibCanonical.Signature(value.Signature);
        var aliases = LanPibCanonical.Aliases(value);
        foreach (var alias in aliases) Device(alias);
        if (aliases.Distinct(StringComparer.Ordinal).Count() != aliases.Length) throw new InvalidDataException("Duplicate PIB candidate aliases.");
        Interval(value.SentAt, value.ExpiresAt);
        if (value.BonjourEndpointDigest is not null) _ = LanPibCanonical.Hex(value.BonjourEndpointDigest);
    }
    internal static void RequireConfirmShape(LanPibConfirm value)
    {
        _ = LanPibCanonical.ConfirmPreimage(value); Device(value.RequesterDeviceId); Device(value.ResponderDeviceId);
        Policy(value.PolicyRequirePQC, value.PolicyAllowClassicFallback, value.RouteScope);
        _ = LanPibCanonical.Signature(value.RequesterSignature); Interval(value.SentAt, value.ExpiresAt);
    }
    internal static void RequireFinalAckShape(LanPibFinalAck value)
    {
        _ = LanPibCanonical.FinalAckPreimage(value); Device(value.RequesterDeviceId); Device(value.ResponderDeviceId);
        Policy(value.PolicyRequirePQC, value.PolicyAllowClassicFallback, value.RouteScope);
        _ = LanPibCanonical.Signature(value.ResponderSignature); Interval(value.SentAt, value.ExpiresAt);
    }
    internal static WebRtcProductProtocolIdentityPublicKey SigningIdentity(string algorithm, ImmutableArray<byte> key, string fingerprint)
    {
        var kind = LanPibCanonical.Token(algorithm, 64) switch
        {
            "ML-DSA-65" => WebRtcProductSignatureAlgorithm.MlDsa65,
            "Ed25519" => WebRtcProductSignatureAlgorithm.Ed25519,
            _ => throw new InvalidDataException("Unsupported PIB signing identity algorithm.")
        };
        if (key.IsDefaultOrEmpty) throw new InvalidDataException("PIB signing identity is absent.");
        var identity = new WebRtcProductProtocolIdentityPublicKey(kind, key.ToArray());
        if (identity.AuthoritativeFingerprint != LanPibCanonical.Hex(fingerprint))
            throw new InvalidDataException("PIB protocol fingerprint does not match the claimed signing public key.");
        return identity;
    }
    internal static void RequireRequestFreshness(LanPibRequest value, long nowMilliseconds)
    {
        RequireRequestShape(value);
        var sent = LanPibCanonical.Milliseconds(value.SentAt);
        if ((decimal)sent - nowMilliseconds > 30_000 || (decimal)nowMilliseconds - sent > 120_000)
            throw new InvalidDataException("PIB initial request is stale or too far in the future.");
    }
    internal static void RequireCandidateBindings(LanPibRequest request, LanPibCandidate candidate, string expectedPin, long nowMilliseconds)
    {
        RequireRequestFreshness(request, nowMilliseconds);
        CandidateTranscript(request, candidate, expectedPin);
        Live(candidate.SentAt, candidate.ExpiresAt, nowMilliseconds);
    }
    internal static void RequireConfirmBindings(LanPibRequest request, LanPibCandidate candidate, LanPibConfirm confirm, long nowMilliseconds)
    {
        // The initial request was admitted once. SAS confirmation can occur after
        // its 120s freshness limit while the five-minute candidate is still valid.
        CandidateTranscript(request, candidate, candidate.ProtocolIdentityFingerprint);
        RequireConfirmShape(confirm);
        Live(candidate.SentAt, candidate.ExpiresAt, nowMilliseconds);
        Live(confirm.SentAt, confirm.ExpiresAt, nowMilliseconds);
        if (LanPibCanonical.Transaction(confirm.TransactionId) != LanPibCanonical.Transaction(request.TransactionId) ||
            confirm.RequesterDeviceId != request.RequesterDeviceId || confirm.ResponderDeviceId != candidate.DeviceId ||
            LanPibCanonical.Hex(confirm.RequesterProtocolIdentityFingerprint) != LanPibCanonical.Hex(request.RequesterProtocolIdentityFingerprint) ||
            LanPibCanonical.Hex(confirm.ResponderProtocolIdentityFingerprint) != LanPibCanonical.Hex(candidate.ProtocolIdentityFingerprint) ||
            !confirm.RequestNonce.AsSpan().SequenceEqual(request.Nonce.AsSpan()) ||
            LanPibCanonical.Hex(confirm.RequestHashHex) != LanPibCanonical.RequestHash(request) ||
            LanPibCanonical.Hex(confirm.CandidateHashHex) != LanPibCanonical.CandidateHash(candidate) ||
            LanPibCanonical.Hex(confirm.SasTranscriptHashHex) != LanPibCanonical.SasTranscriptHash(request, candidate) ||
            confirm.ExpiresAt > candidate.ExpiresAt)
            throw new InvalidDataException("PIB confirmation changed its admitted candidate or transcript binding.");
    }
    internal static void RequireFinalAckBindings(LanPibRequest request, LanPibCandidate candidate, LanPibConfirm confirm,
        LanPibFinalAck ack, long nowMilliseconds)
    {
        RequireConfirmBindings(request, candidate, confirm, nowMilliseconds); RequireFinalAckShape(ack);
        Live(ack.SentAt, ack.ExpiresAt, nowMilliseconds);
        if (!ack.Accepted || LanPibCanonical.Transaction(ack.TransactionId) != LanPibCanonical.Transaction(confirm.TransactionId) ||
            ack.RequesterDeviceId != request.RequesterDeviceId || ack.ResponderDeviceId != candidate.DeviceId ||
            LanPibCanonical.Hex(ack.RequesterProtocolIdentityFingerprint) != LanPibCanonical.Hex(confirm.RequesterProtocolIdentityFingerprint) ||
            LanPibCanonical.Hex(ack.ResponderProtocolIdentityFingerprint) != LanPibCanonical.Hex(candidate.ProtocolIdentityFingerprint) ||
            !ack.RequestNonce.AsSpan().SequenceEqual(request.Nonce.AsSpan()) ||
            !ack.ConfirmationNonce.AsSpan().SequenceEqual(confirm.ConfirmationNonce.AsSpan()) ||
            LanPibCanonical.Hex(ack.RequestHashHex) != LanPibCanonical.RequestHash(request) ||
            LanPibCanonical.Hex(ack.CandidateHashHex) != LanPibCanonical.CandidateHash(candidate) ||
            LanPibCanonical.Hex(ack.ConfirmHashHex) != LanPibCanonical.ConfirmHash(confirm) ||
            LanPibCanonical.Hex(ack.SasTranscriptHashHex) != LanPibCanonical.SasTranscriptHash(request, candidate) ||
            ack.ExpiresAt > Math.Min(candidate.ExpiresAt, confirm.ExpiresAt))
            throw new InvalidDataException("PIB final acknowledgement is rejected or differs from its bounded confirmation.");
    }
    private static void CandidateTranscript(LanPibRequest request, LanPibCandidate candidate, string expectedPin)
    {
        RequireRequestShape(request); RequireCandidateShape(candidate);
        if (LanPibCanonical.Transaction(request.TransactionId) != LanPibCanonical.Transaction(candidate.TransactionId) ||
            !LanPibCanonical.Algorithms(request.RequestedProtocolSigningAlgorithms).Contains(LanPibCanonical.Token(candidate.ProtocolSigningAlgorithm, 64), StringComparer.Ordinal) ||
            LanPibCanonical.Hex(candidate.ProtocolIdentityFingerprint) != LanPibCanonical.Hex(expectedPin) ||
            !candidate.RequestNonce.AsSpan().SequenceEqual(request.Nonce.AsSpan()) ||
            LanPibCanonical.Hex(candidate.RequestHashHex) != LanPibCanonical.RequestHash(request) ||
            LanPibCanonical.Optional(candidate.BonjourEndpointDigest, 128) != LanPibCanonical.Optional(request.BonjourEndpointDigest, 128) ||
            !LanPibCanonical.Aliases(candidate).Append(candidate.DeviceId).Contains(request.TargetDeviceId, StringComparer.Ordinal))
            throw new InvalidDataException("PIB candidate differs from its request, target or expected signing pin.");
    }
    private static void Device(string value)
    {
        if (LanPibCanonical.Token(value) != value || value.Any(c => char.IsControl(c)))
            throw new InvalidDataException("PIB device identifiers must be canonical bounded tokens.");
    }
    private static void Policy(bool pqc, bool classic, string route)
    {
        if (!pqc || classic || LanPibCanonical.Token(route).ToLowerInvariant() != "lan")
            throw new InvalidDataException("PIB requires the strict LAN PQC policy.");
    }
    private static void Interval(double sent, double expires)
    {
        var start = LanPibCanonical.Milliseconds(sent); var end = LanPibCanonical.Milliseconds(expires);
        if (end <= start || (decimal)end - start > 300_000 || expires - sent > 300.0)
            throw new InvalidDataException("PIB validity must be positive and at most five minutes.");
    }
    private static void Live(double sent, double expires, long now)
    {
        Interval(sent, expires);
        if ((decimal)LanPibCanonical.Milliseconds(sent) - now > 30_000 || LanPibCanonical.Milliseconds(expires) <= now)
            throw new InvalidDataException("PIB transaction is expired or too far in the future.");
    }
}
