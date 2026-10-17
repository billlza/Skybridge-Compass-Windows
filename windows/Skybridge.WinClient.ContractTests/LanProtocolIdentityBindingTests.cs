using System.Collections.Immutable;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Skybridge.WinClient.Services;
using Canonical = Skybridge.WinClient.Services.LanPibCanonical;
using Validate = Skybridge.WinClient.Services.LanPibValidation;
using Wire = Skybridge.WinClient.Services.LanPibWire;

internal static class LanProtocolIdentityBindingTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("PIB canonical request candidate confirm ACK and SAS match independent Apple golden", Golden),
        ("PIB golden placeholder identities remain invalid at network admission", GoldenNotAuthority),
        ("PIB four explicit envelope types roundtrip immutable public data", WireRoundTrips),
        ("PIB wire rejects duplicate missing unknown null and malformed encodings", StrictWire),
        ("PIB candidate version remains two while the other transaction messages use three", VersionBoundaries),
        ("PIB initial request freshness has exact age and future bounds", RequestFreshness),
        ("PIB candidate binds target pin nonce original request hash and endpoint digest", CandidateBindings),
        ("PIB confirmation preserves exact IDs signatures nonces and both transcript hashes", ConfirmBindings),
        ("PIB valid SAS confirmation after 120 seconds remains within the five-minute transaction", LateConfirmation),
        ("PIB final ACK cannot extend either parent deadline or revive an expired transaction", AckDeadlines),
        ("PIB parent deadlines preserve fractional ordering within a signed millisecond", FractionalParentDeadlines),
        ("PIB final ACK preserves acceptance signer bindings and the complete confirmation", AckBindings),
        ("PIB canonical encoding is culture independent and signatures affect the correct hashes", CanonicalHashBoundaries),
        ("PIB canonical list fields reject ambiguous comma-delimited members", UnambiguousLists),
        ("PIB shape rejects policy changes malformed identities dates and oversized data", InvalidShapes)
    ];
    private sealed record Transcript(LanPibRequest Request, LanPibCandidate Candidate, LanPibConfirm Confirm, LanPibFinalAck Ack);
    private static ImmutableArray<byte> Bytes(byte value, int count) => Enumerable.Repeat(value, count).ToImmutableArray();
    private static void Require(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); }
    private static void Reject(Action action)
    {
        try { action(); }
        catch (Exception e) when (e is InvalidDataException or JsonException or ArgumentException or WebRtcProductHandshakeCodecException or EncoderFallbackException or DecoderFallbackException) { return; }
        throw new InvalidOperationException("Invalid PIB input or transcript was admitted.");
    }
    private static Transcript GoldenTranscript()
    {
        const string transaction = "00112233-4455-6677-8899-AABBCCDDEEFF";
        const double sent = 721692800.0;
        var request = new LanPibRequest(3, transaction, "id:ios-golden", "id:mac-golden", ["Ed25519"], "Ed25519",
            Bytes(0x22, 32), new string('a', 64), Bytes(0x11, 64), Enumerable.Range(0, 24).Select(i => (byte)i).ToImmutableArray(), sent,
            BonjourEndpointDigest: new string('c', 64));
        var candidate = new LanPibCandidate(2, transaction, request.TargetDeviceId, "Ed25519", Bytes(0x44, 32), new string('b', 64),
            sent, sent + 300, request.Nonce, Canonical.RequestHash(request), Bytes(0x33, 64),
            ["id:mac-golden", "bonjour:mac-golden@local."], "Golden Mac", BonjourEndpointDigest: request.BonjourEndpointDigest);
        return Complete(request, candidate, sent, sent + 300);
    }
    private static Transcript Complete(LanPibRequest request, LanPibCandidate candidate, double confirmSent, double confirmExpiry)
    {
        var confirm = new LanPibConfirm(3, request.TransactionId, request.RequesterDeviceId, candidate.DeviceId,
            request.RequesterProtocolIdentityFingerprint, candidate.ProtocolIdentityFingerprint, request.Nonce, Canonical.RequestHash(request),
            Canonical.CandidateHash(candidate), Canonical.SasTranscriptHash(request, candidate), Bytes(0x55, 24), confirmSent, confirmExpiry, Bytes(0x66, 64));
        var ack = new LanPibFinalAck(3, request.TransactionId, request.RequesterDeviceId, candidate.DeviceId,
            request.RequesterProtocolIdentityFingerprint, candidate.ProtocolIdentityFingerprint, request.Nonce, confirm.ConfirmationNonce,
            confirm.RequestHashHex, confirm.CandidateHashHex, Canonical.ConfirmHash(confirm), confirm.SasTranscriptHashHex,
            true, confirmSent, Math.Min(candidate.ExpiresAt, confirmExpiry), Bytes(0x77, 64));
        return new(request, candidate, confirm, ack);
    }
    private static string Fingerprint(string algorithm, ImmutableArray<byte> key) => new WebRtcProductProtocolIdentityPublicKey(
        algorithm == "Ed25519" ? WebRtcProductSignatureAlgorithm.Ed25519 : WebRtcProductSignatureAlgorithm.MlDsa65, key.ToArray()).AuthoritativeFingerprint;
    private static Transcript ValidShape()
    {
        var golden = GoldenTranscript(); var request = golden.Request with
        { RequesterProtocolIdentityFingerprint = Fingerprint("Ed25519", golden.Request.RequesterProtocolIdentityPublicKey) };
        var candidate = golden.Candidate with { ProtocolIdentityFingerprint = Fingerprint("Ed25519", golden.Candidate.ProtocolIdentityPublicKey), RequestHashHex = Canonical.RequestHash(request) };
        // Placeholder signatures remain intentionally unverified. Tests below concern
        // canonical fields and bindings; they do not establish possession or grant trust.
        return Complete(request, candidate, request.SentAt, candidate.ExpiresAt);
    }
    private static long Now(Transcript t, double elapsed = 0) => Canonical.Milliseconds(t.Request.SentAt + elapsed);
    private static Task Golden()
    {
        var t = GoldenTranscript();
        Require(Canonical.RequestHash(t.Request) == "0b57a8713f6eba3c41061d38c1b33dcfa11750885976f0d5828916d3ac8f01ad", "Request golden differs.");
        Require(Canonical.CandidateHash(t.Candidate) == "4cbf643a7041361d658f6ba4d7960ec42a962e76275e38098de6a09ebf581e1a", "Candidate golden differs.");
        Require(Canonical.SasTranscriptHash(t.Request, t.Candidate) == "724f79895460bfcb6e7136e637998b22285dca087573ed257678293c95ecd950" &&
            Canonical.SasCode(t.Request, t.Candidate) == "811081", "PIB SAS domain, signature concatenation or UInt32BE fold differs.");
        Require(Canonical.ConfirmHash(t.Confirm) == "78a1f5b29b7535479de0ea576fb778624b5bab359483e3024bbb61acf223566a", "Confirm golden differs.");
        Require(Canonical.Hash(Canonical.FinalAckPreimage(t.Ack)) == "f6edad1347d9b1bd805e326491ca5a4fe52870dbfed233af6fc56ee38a89f760", "Final ACK golden differs.");
        foreach (var bytes in new[] { Canonical.RequestPreimage(t.Request), Canonical.CandidatePreimage(t.Candidate), Canonical.ConfirmPreimage(t.Confirm), Canonical.FinalAckPreimage(t.Ack) })
            Require(bytes[^1] != (byte)'\n' && !bytes.AsSpan().StartsWith(new byte[] { 0xef, 0xbb, 0xbf }), "Canonical text has trailing LF or BOM.");
        return Task.CompletedTask;
    }
    private static Task GoldenNotAuthority()
    {
        var t = GoldenTranscript(); Reject(() => Validate.RequireRequestShape(t.Request)); Reject(() => Wire.EncodeRequest(t.Request));
        Reject(() => Validate.RequireCandidateShape(t.Candidate)); Reject(() => Wire.EncodeCandidate(t.Candidate));
        return Task.CompletedTask;
    }
    private static Task WireRoundTrips()
    {
        var t = ValidShape(); var requestBytes = Wire.EncodeRequest(t.Request); var request = Wire.DecodeRequest(requestBytes);
        var candidate = Wire.DecodeCandidate(Wire.EncodeCandidate(t.Candidate)); var confirm = Wire.DecodeConfirm(Wire.EncodeConfirm(t.Confirm));
        var ack = Wire.DecodeFinalAck(Wire.EncodeFinalAck(t.Ack));
        requestBytes.AsSpan().Fill(0);
        Require(Canonical.RequestHash(request) == Canonical.RequestHash(t.Request), "Source-buffer reuse changed immutable request.");
        Require(Canonical.CandidateHash(candidate) == Canonical.CandidateHash(t.Candidate) && Canonical.ConfirmHash(confirm) == Canonical.ConfirmHash(t.Confirm) &&
            Canonical.FinalAckPreimage(ack).SequenceEqual(Canonical.FinalAckPreimage(t.Ack)), "A wire roundtrip changed signed bytes.");
        Validate.RequireCandidateBindings(request, candidate, candidate.ProtocolIdentityFingerprint, Now(t));
        Validate.RequireFinalAckBindings(request, candidate, confirm, ack, Now(t));
        var empty = t.Candidate with { Aliases = default };
        Require(Wire.DecodeCandidate(Wire.EncodeCandidate(empty)).Aliases.IsEmpty, "Optional aliases did not remain explicit empty state.");
        return Task.CompletedTask;
    }
    private static Task StrictWire()
    {
        var t = ValidShape(); var json = Encoding.UTF8.GetString(Wire.EncodeRequest(t.Request));
        foreach (var bad in new[] {
            json.Replace("\"version\":3", "\"version\":3,\"version\":3", StringComparison.Ordinal),
            json.Replace("\"version\":3", "\"version\":3,\"surprise\":true", StringComparison.Ordinal),
            json.Replace("\"version\":3,", "", StringComparison.Ordinal), json.Replace("\"requesterSignature\":\"", "\"requesterSignature\":\" ", StringComparison.Ordinal),
            "{\"protocolIdentityBindingRequest\":null}", "{\"protocolIdentityBindingRequest\":{}}", json[..^1] + ",\"kemRefreshRequest\":{}}" })
            Reject(() => Wire.DecodeRequest(Encoding.UTF8.GetBytes(bad)));
        var corrupt = Encoding.UTF8.GetBytes(json); corrupt[5] = 0xff; Reject(() => Wire.DecodeRequest(corrupt));
        Reject(() => Wire.DecodeRequest(new byte[LanBootstrapWire.MaximumBytes + 1]));
        Reject(() => Wire.DecodeFinalAck(Wire.EncodeConfirm(t.Confirm))); return Task.CompletedTask;
    }
    private static Task VersionBoundaries()
    {
        var t = ValidShape(); Reject(() => Wire.EncodeRequest(t.Request with { Version = 2 })); Reject(() => Wire.EncodeCandidate(t.Candidate with { Version = 3 }));
        Reject(() => Wire.EncodeConfirm(t.Confirm with { Version = 2 })); Reject(() => Wire.EncodeFinalAck(t.Ack with { Version = 2 })); return Task.CompletedTask;
    }
    private static Task RequestFreshness()
    {
        var t = ValidShape(); Validate.RequireRequestFreshness(t.Request, Now(t, 120)); Reject(() => Validate.RequireRequestFreshness(t.Request, Now(t, 120) + 1));
        Validate.RequireRequestFreshness(t.Request, Now(t, -30)); Reject(() => Validate.RequireRequestFreshness(t.Request, Now(t, -30) - 1)); return Task.CompletedTask;
    }
    private static Task CandidateBindings()
    {
        var t = ValidShape();
        foreach (var bad in new[] { t.Candidate with { TransactionId = Guid.NewGuid().ToString("D") }, t.Candidate with { DeviceId = "another-target", Aliases = [] },
            t.Candidate with { RequestNonce = Bytes(1, 24) }, t.Candidate with { RequestHashHex = new string('a', 64) },
            t.Candidate with { BonjourEndpointDigest = new string('d', 64) }, t.Candidate with { ExpiresAt = t.Request.SentAt } })
            Reject(() => Validate.RequireCandidateBindings(t.Request, bad, t.Candidate.ProtocolIdentityFingerprint, Now(t)));
        Reject(() => Validate.RequireCandidateBindings(t.Request, t.Candidate, new string('a', 64), Now(t)));
        var onlyMl = t.Request with { RequestedProtocolSigningAlgorithms = ["ML-DSA-65"] };
        Reject(() => Validate.RequireCandidateBindings(onlyMl, t.Candidate, t.Candidate.ProtocolIdentityFingerprint, Now(t)));
        return Task.CompletedTask;
    }
    private static Task ConfirmBindings()
    {
        var t = ValidShape();
        foreach (var bad in new[] { t.Confirm with { RequesterDeviceId = t.Request.RequesterDeviceId.ToUpperInvariant() },
            t.Confirm with { ResponderDeviceId = t.Candidate.DeviceId.ToUpperInvariant() }, t.Confirm with { RequestNonce = Bytes(1, 24) },
            t.Confirm with { RequestHashHex = new string('f', 64) }, t.Confirm with { CandidateHashHex = new string('f', 64) },
            t.Confirm with { SasTranscriptHashHex = new string('f', 64) }, t.Confirm with { RequesterProtocolIdentityFingerprint = new string('f', 64) } })
            Reject(() => Validate.RequireConfirmBindings(t.Request, t.Candidate, bad, Now(t)));
        var changedRequestSignature = t.Request with { RequesterSignature = Bytes(2, 64) };
        Reject(() => Validate.RequireConfirmBindings(changedRequestSignature, t.Candidate, t.Confirm, Now(t)));
        var changedCandidateSignature = t.Candidate with { Signature = Bytes(3, 64) };
        Reject(() => Validate.RequireConfirmBindings(t.Request, changedCandidateSignature, t.Confirm, Now(t)));
        return Task.CompletedTask;
    }
    private static Task LateConfirmation()
    {
        var t = ValidShape(); t = Complete(t.Request, t.Candidate, t.Request.SentAt + 180, t.Candidate.ExpiresAt);
        Reject(() => Validate.RequireRequestFreshness(t.Request, Now(t, 180)));
        Validate.RequireConfirmBindings(t.Request, t.Candidate, t.Confirm, Now(t, 180));
        Validate.RequireFinalAckBindings(t.Request, t.Candidate, t.Confirm, t.Ack, Now(t, 180)); return Task.CompletedTask;
    }
    private static Task AckDeadlines()
    {
        var original = ValidShape(); var t = Complete(original.Request, original.Candidate, original.Request.SentAt + 290, original.Candidate.ExpiresAt);
        var extended = t.Ack with { ExpiresAt = t.Request.SentAt + 590 };
        Validate.RequireFinalAckShape(extended); // Its own interval is valid; both parents still constrain it.
        Reject(() => Validate.RequireFinalAckBindings(t.Request, t.Candidate, t.Confirm, extended, Now(t, 295)));
        Reject(() => Validate.RequireFinalAckBindings(t.Request, t.Candidate, t.Confirm, extended, Now(t, 310)));
        Validate.RequireFinalAckBindings(t.Request, t.Candidate, t.Confirm, t.Ack, Now(t, 299.999));
        Reject(() => Validate.RequireFinalAckBindings(t.Request, t.Candidate, t.Confirm, t.Ack, Now(t, 300)));
        t = Complete(original.Request, original.Candidate, original.Request.SentAt + 180, original.Request.SentAt + 200);
        Reject(() => Validate.RequireFinalAckBindings(t.Request, t.Candidate, t.Confirm, t.Ack with { ExpiresAt = t.Request.SentAt + 201 }, Now(t, 180)));
        Reject(() => Validate.RequireConfirmBindings(t.Request, t.Candidate, t.Confirm with { ExpiresAt = t.Candidate.ExpiresAt + 1 }, Now(t, 180)));
        return Task.CompletedTask;
    }
    private static Task FractionalParentDeadlines()
    {
        var original = ValidShape(); var t = Complete(original.Request, original.Candidate, original.Request.SentAt + 180, original.Request.SentAt + 200.25);
        var extended = t.Ack with { ExpiresAt = double.BitIncrement(t.Confirm.ExpiresAt) };
        Require(Canonical.Milliseconds(extended.ExpiresAt) == Canonical.Milliseconds(t.Confirm.ExpiresAt), "Fixture must share one canonical millisecond.");
        Reject(() => Validate.RequireFinalAckBindings(t.Request, t.Candidate, t.Confirm, extended, Now(t, 180)));
        var candidate = t.Candidate with { ExpiresAt = t.Confirm.ExpiresAt };
        t = Complete(t.Request, candidate, t.Confirm.SentAt, double.BitIncrement(candidate.ExpiresAt));
        Reject(() => Validate.RequireConfirmBindings(t.Request, t.Candidate, t.Confirm, Now(t, 180)));
        return Task.CompletedTask;
    }
    private static Task AckBindings()
    {
        var t = ValidShape();
        foreach (var bad in new[] { t.Ack with { Accepted = false }, t.Ack with { ConfirmHashHex = new string('f', 64) },
            t.Ack with { ConfirmationNonce = Bytes(1, 24) }, t.Ack with { ResponderDeviceId = "another-peer" },
            t.Ack with { RequestNonce = Bytes(1, 24) }, t.Ack with { RequesterProtocolIdentityFingerprint = new string('f', 64) },
            t.Ack with { CandidateHashHex = new string('f', 64) }, t.Ack with { SasTranscriptHashHex = new string('f', 64) } })
            Reject(() => Validate.RequireFinalAckBindings(t.Request, t.Candidate, t.Confirm, bad, Now(t)));
        return Task.CompletedTask;
    }
    private static Task CanonicalHashBoundaries()
    {
        var t = ValidShape(); var saved = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("tr-TR");
            Require(Canonical.RequestHash(t.Request) == Canonical.RequestHash(t.Request with { TransactionId = t.Request.TransactionId.ToLowerInvariant() }), "UUID normalization is culture-sensitive.");
            Require(Canonical.RequestHash(t.Request) == Canonical.RequestHash(t.Request with { RequesterSignature = Bytes(9, 64) }), "Request hash included requester signature.");
            Require(Canonical.CandidateHash(t.Candidate) != Canonical.CandidateHash(t.Candidate with { Signature = Bytes(9, 64) }) &&
                Canonical.ConfirmHash(t.Confirm) != Canonical.ConfirmHash(t.Confirm with { RequesterSignature = Bytes(9, 64) }), "Signed transcript hashes omitted raw signature.");
            Require(Canonical.RequestHash(t.Request) != Canonical.RequestHash(t.Request with { BonjourEndpointDigest = t.Request.BonjourEndpointDigest!.ToUpperInvariant() }), "Endpoint digest case was erased from canonical text.");
        }
        finally { CultureInfo.CurrentCulture = saved; }
        return Task.CompletedTask;
    }
    private static Task InvalidShapes()
    {
        var t = ValidShape();
        foreach (var bad in new[] { t.Request with { Nonce = [] }, t.Request with { RequesterSignature = [] }, t.Request with { RequesterSignature = Bytes(1, 8193) },
            t.Request with { RequesterDeviceId = "bad\nidentity" }, t.Request with { RequesterDeviceId = " spaced " },
            t.Request with { PolicyAllowClassicFallback = true }, t.Request with { PolicyRequirePQC = false }, t.Request with { RouteScope = "wan" },
            t.Request with { RequestedProtocolSigningAlgorithms = ["Ed25519", "Ed25519"] }, t.Request with { TransactionId = "1-2-3-4-5" },
            t.Request with { SentAt = double.NaN }, t.Request with { SentAt = double.MaxValue },
            t.Request with { RequesterProtocolIdentityPublicKey = Bytes(1, 48), RequesterProtocolSigningAlgorithm = "ML-DSA-65" } }) Reject(() => Wire.EncodeRequest(bad));
        Reject(() => Wire.EncodeCandidate(t.Candidate with { Aliases = ["duplicate", "duplicate"] }));
        Reject(() => Wire.EncodeCandidate(t.Candidate with { ExpiresAt = t.Candidate.SentAt + 301 }));
        var fractionalExpiry = double.BitIncrement(t.Candidate.SentAt + 300);
        Require(Canonical.Milliseconds(fractionalExpiry) == Canonical.Milliseconds(t.Candidate.ExpiresAt),
            "The duration counterexample must share the canonical deadline millisecond.");
        Reject(() => Wire.EncodeCandidate(t.Candidate with { ExpiresAt = fractionalExpiry }));
        Reject(() => Wire.EncodeConfirm(t.Confirm with { ConfirmationNonce = Bytes(1, 129) }));
        Reject(() => Wire.EncodeFinalAck(t.Ack with { ResponderSignature = default })); return Task.CompletedTask;
    }

    private static Task UnambiguousLists()
    {
        var t = ValidShape();
        // Without a delimiter restriction, [a,b; c] and [a; b,c] share the
        // same canonical text. These are unsupported inputs, not aliases.
        foreach (var aliases in new ImmutableArray<string>[] { ["a,b", "c"], ["a", "b,c"] })
        {
            var candidate = t.Candidate with { Aliases = aliases };
            Reject(() => Canonical.CandidatePreimage(candidate));
            Reject(() => Wire.EncodeCandidate(candidate));
        }
        foreach (var algorithms in new ImmutableArray<string>[] { ["Ed25519,ML-DSA-65"], ["Ed25519", "ML-DSA-65,other"] })
        {
            var request = t.Request with { RequestedProtocolSigningAlgorithms = algorithms };
            Reject(() => Canonical.RequestPreimage(request));
            Reject(() => Wire.EncodeRequest(request));
        }
        return Task.CompletedTask;
    }

    internal static int NativeSignaturesVerified { get; private set; }
    internal static void NativeMldsaRoundTripWhenSupported()
    {
        if (!MLDsa.IsSupported)
        {
            if (OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows PIB acceptance requires native ML-DSA.");
            return;
        }
        using var requester = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65); using var responder = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        var baseTranscript = ValidShape(); var requestKey = requester.ExportMLDsaPublicKey().ToImmutableArray(); var responseKey = responder.ExportMLDsaPublicKey().ToImmutableArray();
        var request = baseTranscript.Request with { RequestedProtocolSigningAlgorithms = ["ML-DSA-65"], RequesterProtocolSigningAlgorithm = "ML-DSA-65",
            RequesterProtocolIdentityPublicKey = requestKey, RequesterProtocolIdentityFingerprint = Fingerprint("ML-DSA-65", requestKey) };
        request = request with { RequesterSignature = requester.SignData(Canonical.RequestPreimage(request)).ToImmutableArray() };
        var candidate = baseTranscript.Candidate with { ProtocolSigningAlgorithm = "ML-DSA-65", ProtocolIdentityPublicKey = responseKey,
            ProtocolIdentityFingerprint = Fingerprint("ML-DSA-65", responseKey), RequestHashHex = Canonical.RequestHash(request) };
        candidate = candidate with { Signature = responder.SignData(Canonical.CandidatePreimage(candidate)).ToImmutableArray() };
        var transaction = Complete(request, candidate, request.SentAt, candidate.ExpiresAt);
        var confirm = transaction.Confirm with { RequesterSignature = requester.SignData(Canonical.ConfirmPreimage(transaction.Confirm)).ToImmutableArray() };
        var ack = transaction.Ack with { ConfirmHashHex = Canonical.ConfirmHash(confirm) };
        ack = ack with { ResponderSignature = responder.SignData(Canonical.FinalAckPreimage(ack)).ToImmutableArray() };
        request = Wire.DecodeRequest(Wire.EncodeRequest(request)); candidate = Wire.DecodeCandidate(Wire.EncodeCandidate(candidate));
        confirm = Wire.DecodeConfirm(Wire.EncodeConfirm(confirm)); ack = Wire.DecodeFinalAck(Wire.EncodeFinalAck(ack));
        Validate.RequireFinalAckBindings(request, candidate, confirm, ack, Now(transaction));
        void Verify(ImmutableArray<byte> publicKey, byte[] bytes, ImmutableArray<byte> signature)
        {
            using var verifier = MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm.MLDsa65, publicKey.AsSpan());
            Require(verifier.VerifyData(bytes, signature.AsSpan()), "Native PIB signature failed.");
            bytes[^1] ^= 1; Require(!verifier.VerifyData(bytes, signature.AsSpan()), "Tampered PIB preimage verified."); NativeSignaturesVerified++;
        }
        Verify(request.RequesterProtocolIdentityPublicKey, Canonical.RequestPreimage(request), request.RequesterSignature);
        Verify(candidate.ProtocolIdentityPublicKey, Canonical.CandidatePreimage(candidate), candidate.Signature);
        Verify(request.RequesterProtocolIdentityPublicKey, Canonical.ConfirmPreimage(confirm), confirm.RequesterSignature);
        Verify(candidate.ProtocolIdentityPublicKey, Canonical.FinalAckPreimage(ack), ack.ResponderSignature);
    }
}
