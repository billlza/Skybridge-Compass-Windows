using System.Collections.Immutable;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Skybridge.WinClient.Services;
using Canonical = Skybridge.WinClient.Services.SignedLanKemRefreshCanonical;
using Wire = Skybridge.WinClient.Services.SignedLanKemRefreshWire;

internal static class SignedLanKemRefreshTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("SKR v1 matches the independent Apple canonical text and hashes", LegacyGolden),
        ("SKR v2 matches the shared Apple Android public vector", () => Golden(2, null)),
        ("SKR v3 all_common public vector preserves full Q intersection", () => Golden(3, "all_common")),
        ("SKR v3 native_common public vector preserves native intersection", () => Golden(3, "native_common")),
        ("SKR v3 ml_only public vector preserves ML-KEM selection", () => Golden(3, "ml_only")),
        ("SKR v3 q_profile_mismatch public vector excludes only Q", () => Golden(3, "q_profile_mismatch")),
        ("SKR v3 strict_q_no_common public vector preserves signed empty intersection", () => Golden(3, "strict_q_no_common")),
        ("SKR v3 empty_permitted public vector remains bound and signed", () => Golden(3, "empty_permitted")),
        ("SKR dates floor negative fractions and reject Int64 overflow", TimestampBoundaries),
        ("SKR JSON rejects ambiguity unknown fields missing data and invalid byte encodings", StrictWire),
        ("SKR requests enforce freshness policy and version-specific fields", RequestRejections),
        ("SKR responses preserve exact nonce hash target and generation bindings", ResponseRejections),
        ("SKR generation stays exact beyond Double integer precision", ExactGeneration),
        ("SKR Q profiles preserve UInt64 and declared platform boundaries", ProfileBoundaries),
        ("SKR canonical sorting is ordinal and independent of process culture", CultureAndOrdering),
        ("SKR rejects duplicate aliases and invalid or incomplete key sets", KeySetRejections),
        ("SKR decoded public bytes remain immutable across source-buffer reuse", ByteOwnership),
        ("SKR empty optional alias collection round-trips explicitly", EmptyAliases)
    ];
    internal static int NativeSignaturesChecked { get; private set; }
    private static void Require(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); }
    private static void Reject(Action action)
    {
        try { action(); }
        catch (Exception error) when (error is InvalidDataException or JsonException or ArgumentException or EncoderFallbackException or DecoderFallbackException) { return; }
        throw new InvalidOperationException("Malformed SKR input was accepted.");
    }
    private static byte[] Envelope(string name, JsonElement value) => Encoding.UTF8.GetBytes("{\"" + name + "\":" + value.GetRawText() + "}");
    private static (LanKemRefreshRequest Request, LanSignedKemRefresh Response, JsonElement Vector) Load(int version, string? name)
    {
        using var doc = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", $"skr{version}-golden.json")));
        var v = version == 2 ? doc.RootElement : doc.RootElement.GetProperty("vectors").EnumerateArray()
            .Single(x => x.GetProperty("name").GetString() == name);
        return (Wire.DecodeRequest(Envelope("kemRefreshRequest", v.GetProperty("request"))),
            Wire.DecodeResponse(Envelope("signedKEMRefresh", v.GetProperty("response"))), v.Clone());
    }
    private static Task Golden(int version, string? name)
    {
        var (request, response, vector) = Load(version, name);
        Require(Canonical.RequestHash(request) == vector.GetProperty("requestHashHex").GetString(), "Request canonical hash differs from Apple vector.");
        var preimage = Canonical.ResponsePreimage(response);
        Require(Canonical.Hash(preimage) == vector.GetProperty("responseHashHex").GetString(), "Response canonical hash differs from Apple vector.");
        Require(preimage[^1] != (byte)'\n' && !preimage.AsSpan().StartsWith(new byte[] { 0xef, 0xbb, 0xbf }), "Canonical framing changed.");
        Canonical.RequireResponseBindings(request, response, response.ProtocolIdentityFingerprint, Canonical.Milliseconds(request.SentAt));
        if (version == 3)
        {
            var common = Canonical.Intersection(request.RequestedSuiteWireIds, response.PermittedSuiteWireIds!.Value,
                request.QPeriaptAuthProfile, response.QPeriaptAuthProfile);
            var expected = vector.GetProperty("selectedSuiteWireId");
            Require(expected.ValueKind == JsonValueKind.Null ? common.IsEmpty : common[0] == expected.GetInt32(), "Negotiation preference differs.");
        }
        if (OperatingSystem.IsWindows() && !MLDsa.IsSupported) throw new PlatformNotSupportedException("Native SKR ML-DSA verification is required on Windows.");
        if (MLDsa.IsSupported)
        {
            using var verifier = MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm.MLDsa65, response.ProtocolIdentityPublicKey.AsSpan());
            Require(verifier.VerifyData(preimage, response.Signature.AsSpan()), "Independent ML-DSA signature did not verify.");
            var tampered = preimage.ToArray(); tampered[^1] ^= 1;
            Require(!verifier.VerifyData(tampered, response.Signature.AsSpan()), "Tampered SKR bytes verified.");
            NativeSignaturesChecked++;
        }
        var roundtrip = Wire.DecodeResponse(Wire.EncodeResponse(response));
        Require(Canonical.Hash(Canonical.ResponsePreimage(roundtrip)) == Canonical.Hash(preimage), "JSON response roundtrip changed signed bytes.");
        Require(Canonical.RequestHash(Wire.DecodeRequest(Wire.EncodeRequest(request))) == Canonical.RequestHash(request), "Request roundtrip changed bytes.");
        return Task.CompletedTask;
    }
    private static (LanKemRefreshRequest Request, LanSignedKemRefresh Response) Legacy()
    {
        var nonce = Enumerable.Range(0, 24).Select(i => (byte)i).ToImmutableArray();
        var request = new LanKemRefreshRequest("id:android-1", "id:mac-1", [257, 1], Canonical.PolicyHash(1), nonce, 721692800.125,
            RequesterProtocolIdentityFingerprint: new string('a', 64), TargetProtocolIdentityFingerprint: new string('b', 64), BonjourEndpointDigest: new string('c', 64));
        var response = new LanSignedKemRefresh("id:mac-1", "Ed25519", Enumerable.Repeat((byte)0x11, 32).ToImmutableArray(),
            "6d2b9f7fa7f28ec0553190b584e04b31b946d0767464c9028284bdb721e4d884",
            [new(257, Enumerable.Repeat((byte)0x66, 1184).ToImmutableArray()), new(1, Enumerable.Repeat((byte)0x55, 1216).ToImmutableArray())],
            "skr-key-1", 1700000000125, 721692800.25, 721693100.25, nonce, Enumerable.Repeat((byte)0x77, 64).ToImmutableArray(),
            Aliases: ["id:mac-1", "bonjour:mac@local."], RequestHashHex: Canonical.RequestHash(request), RouteScope: " LAN ", BonjourEndpointDigest: new string('c', 64));
        return (request, response);
    }
    private static Task LegacyGolden()
    {
        var (request, response) = Legacy();
        Require(Canonical.PolicyHash(1) == "82dc84c640da0ab35b7711b86cfa38215c840b6f437f2d31a30a961ed17aae5e", "Policy golden differs.");
        Require(Canonical.RequestHash(request) == "ef160c364bf085b77e1d14799283550343cf8844767951d819a87d04f8660428", "Request golden differs.");
        var bytes = Canonical.ResponsePreimage(response);
        Require(Canonical.Hash(bytes) == "e5cf02c00119fa5bc7d19335a726fed99807de83dc963fad1be144b8d310b99f", "Response golden differs.");
        Require(Encoding.UTF8.GetString(bytes).Contains("suiteNames=ML-KEM-768,X-Wing\nsuiteWireIds=0x0001,0x0101", StringComparison.Ordinal), "Name ordering was incorrectly tied to suite IDs.");
        // The legacy fixture contains placeholder signature bytes; no verification claim.
        return Task.CompletedTask;
    }
    private static Task TimestampBoundaries()
    {
        Require(Canonical.Milliseconds(-978307200.0005) == -1, "Negative fractions truncated instead of flooring.");
        Require(Canonical.Milliseconds(721692800.125) == 1700000000125, "Reference epoch changed.");
        foreach (var bad in new[] { double.NaN, double.PositiveInfinity, double.NegativeInfinity, double.MaxValue, double.MinValue,
            9223372036854775808.0 / 1000.0 - 978307200.0 }) Reject(() => Canonical.Milliseconds(bad));
        return Task.CompletedTask;
    }
    private static Task StrictWire()
    {
        var (request, _, _) = Load(2, null); var good = Encoding.UTF8.GetString(Wire.EncodeRequest(request));
        foreach (var bad in new[] {
            good.Replace("\"version\":2", "\"version\":2,\"version\":2", StringComparison.Ordinal),
            good.Replace("\"version\":2", "\"version\":2,\"surprise\":1", StringComparison.Ordinal),
            good[..^1] + ",\"heartbeat\":{}}", "{\"kemRefreshRequest\":{}}", "{\"kemRefreshRequest\":null}",
            good.Replace("\"nonce\":\"", "\"nonce\":\" ", StringComparison.Ordinal),
            good.Replace("\"requesterDeviceId\":", "\"requesterDeviceId\":null,\"other\":", StringComparison.Ordinal) })
            Reject(() => Wire.DecodeRequest(Encoding.UTF8.GetBytes(bad)));
        var invalidUtf8 = Encoding.UTF8.GetBytes(good); invalidUtf8[5] = 0xff; Reject(() => Wire.DecodeRequest(invalidUtf8));
        Reject(() => Wire.DecodeRequest(new byte[Wire.MaximumBytes + 1]));
        return Task.CompletedTask;
    }
    private static Task RequestRejections()
    {
        var (request, _, _) = Load(2, null); var now = Canonical.Milliseconds(request.SentAt);
        foreach (var bad in new[] { request with { Version = 4 }, request with { PolicyRequirePQC = false }, request with { PolicyAllowClassicFallback = true },
            request with { PolicyHashHex = new string('f', 64) }, request with { RequestedSuiteWireIds = [18, 18] }, request with { RequestedSuiteWireIds = [1] },
            request with { Nonce = [] }, request with { RequesterDeviceId = "bad=field" }, request with { Platform = "Android" } })
            Reject(() => Canonical.RequireRequestFreshness(bad, now));
        Canonical.RequireRequestFreshness(request, now + 120000); Canonical.RequireRequestFreshness(request, now - 30000);
        Reject(() => Canonical.RequireRequestFreshness(request, now + 120001)); Reject(() => Canonical.RequireRequestFreshness(request, now - 30001));
        return Task.CompletedTask;
    }
    private static Task ResponseRejections()
    {
        var (request, response, _) = Load(3, "all_common"); var now = Canonical.Milliseconds(request.SentAt);
        foreach (var bad in new[] { response with { RequestNonce = response.RequestNonce.SetItem(0, (byte)(response.RequestNonce[0] ^ 1)) },
            response with { RequestHashHex = new string('a', 64) }, response with { BonjourEndpointDigest = new string('e', 64) },
            response with { DeviceId = "wrong-device", Aliases = [] }, response with { Generation = -1 }, response with { ExpiresAt = request.SentAt },
            response with { Signature = [] }, response with { ProtocolIdentityFingerprint = new string('f', 64) } })
            Reject(() => Canonical.RequireResponseBindings(request, bad, response.ProtocolIdentityFingerprint, now));
        Reject(() => Canonical.RequireResponseBindings(request, response, new string('f', 64), now));
        Reject(() => Canonical.RequireResponseBindings(request, response, response.ProtocolIdentityFingerprint, now, response.Generation + 1));
        return Task.CompletedTask;
    }
    private static Task ExactGeneration()
    {
        var (_, response, _) = Load(2, null);
        foreach (var generation in new[] { 9007199254740993L, long.MaxValue })
        {
            var value = Wire.DecodeResponse(Wire.EncodeResponse(response with { Generation = generation }));
            Require(value.Generation == generation && Encoding.UTF8.GetString(Canonical.ResponsePreimage(value))
                .Contains("generation=" + generation.ToString(CultureInfo.InvariantCulture) + "\n", StringComparison.Ordinal), "Generation lost integer precision.");
        }
        var json = Encoding.UTF8.GetString(Wire.EncodeResponse(response));
        Reject(() => Wire.DecodeResponse(Encoding.UTF8.GetBytes(json.Replace("\"generation\":7", "\"generation\":9223372036854775808", StringComparison.Ordinal))));
        return Task.CompletedTask;
    }
    private static Task ProfileBoundaries()
    {
        var (request, response, _) = Load(3, "all_common");
        var max = request.QPeriaptAuthProfile!.Replace("/7/", "/18446744073709551615/", StringComparison.Ordinal);
        Canonical.RequireRequestShape(request with { QPeriaptAuthProfile = max });
        foreach (var profile in new[] { max.Replace("18446744073709551615", "18446744073709551616", StringComparison.Ordinal),
            request.QPeriaptAuthProfile.Replace("/7/", "/07/", StringComparison.Ordinal) })
            Reject(() => Canonical.RequireRequestShape(request with { QPeriaptAuthProfile = profile }));
        Reject(() => Canonical.RequireRequestShape(request with { Platform = "Windows" }));
        Reject(() => Canonical.RequireRequestShape(request with { OsVersion = "16" }));
        Reject(() => Canonical.RequireRequestShape(request with { Platform = " Android " }));
        var (_, v2, _) = Load(2, null);
        Canonical.RequireResponseShape(v2 with { Platform = " macOS ", OsVersion = "macOS\t26.5" }, true);
        return Task.CompletedTask;
    }
    private static Task CultureAndOrdering()
    {
        var (request, response) = Legacy(); var expected = Canonical.ResponsePreimage(response); var saved = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("tr-TR");
            Require(Canonical.ResponsePreimage(response with { Aliases = response.Aliases.Reverse().ToImmutableArray(),
                KemPublicKeys = response.KemPublicKeys.Reverse().ToImmutableArray() }).SequenceEqual(expected), "Culture or input order changed canonical bytes.");
            var digestCase = request with { BonjourEndpointDigest = new string('A', 64) };
            Require(Encoding.UTF8.GetString(Canonical.RequestPreimage(digestCase)).Contains("bonjourEndpointDigest=" + new string('A', 64), StringComparison.Ordinal), "Endpoint digest was incorrectly lowercased.");
        }
        finally { CultureInfo.CurrentCulture = saved; }
        return Task.CompletedTask;
    }
    private static Task KeySetRejections()
    {
        var (request, response, _) = Load(3, "all_common");
        Reject(() => Canonical.ResponsePreimage(response with { Aliases = ["peer", " peer "] }));
        Reject(() => Canonical.ResponsePreimage(response with { KemPublicKeys = [response.KemPublicKeys[0], response.KemPublicKeys[0]] }));
        Reject(() => Canonical.ResponsePreimage(response with { KemPublicKeys = [response.KemPublicKeys[0] with { PublicKey = [] }] }));
        Reject(() => Canonical.ResponsePreimage(response with { PermittedSuiteWireIds = [257, 18, 1] }));
        Reject(() => Canonical.RequireResponseBindings(request, response with { KemPublicKeys = response.KemPublicKeys.RemoveAt(0) },
            response.ProtocolIdentityFingerprint, Canonical.Milliseconds(request.SentAt)));
        return Task.CompletedTask;
    }
    private static Task ByteOwnership()
    {
        var (_, response, _) = Load(2, null); var wire = Wire.EncodeResponse(response); var decoded = Wire.DecodeResponse(wire);
        var expected = Canonical.Hash(Canonical.ResponsePreimage(decoded)); wire.AsSpan().Fill(0);
        var exported = decoded.ProtocolIdentityPublicKey.ToArray(); exported.AsSpan().Fill(0);
        Require(Canonical.Hash(Canonical.ResponsePreimage(decoded)) == expected, "Decoded signing material retained a mutable source/export alias.");
        return Task.CompletedTask;
    }
    private static Task EmptyAliases()
    {
        var (_, response, _) = Load(2, null); var decoded = Wire.DecodeResponse(Wire.EncodeResponse(response with { Aliases = default }));
        Require(!decoded.Aliases.IsDefault && decoded.Aliases.IsEmpty, "Optional empty aliases could not be encoded.");
        return Task.CompletedTask;
    }
}
