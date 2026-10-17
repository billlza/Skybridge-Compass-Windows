using System.Text.Json;
using System.Text.Json.Nodes;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.RemoteControl;

internal static class ProtocolOnlyPairingMaterialTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("PIB identity-only material has explicit versioned state without invented KEM bytes", RoundTrip),
        ("legacy pairing material still rejects missing KEM and keeps its original schema", LegacyContract),
        ("identity-only pairing JSON rejects implicit absent keys ambiguous fields and tampered identity", StrictIdentityWire),
        ("explicit KEM upgrades add material while preserving every existing key", AdditiveUpgrades),
        ("KEM upgrades cannot replace a protocol identity device ID or existing KEM", UpgradeConflicts),
        ("identity-only state remains distinct from outbound KEM readiness", OutboundReadiness),
        ("identity-only paired authority resolves only its exact MAIN SOA and pin candidate", InboundCandidate),
        ("identity-only public material retains ownership across source and export mutations", ImmutablePublicMaterial)
    ];
    private const string PeerId = "id:bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    private const string LocalId = "id:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    private static byte[] PublicKey => Enumerable.Repeat((byte)0x33, 1952).ToArray();
    private static byte[] MlKey => Enumerable.Repeat((byte)0x44, 1184).ToArray();
    private static byte[] QKey => Enumerable.Repeat((byte)0x55, 1216).ToArray();
    private static RemoteControlPairingMaterial Identity() => RemoteControlPairingMaterial.CreateProtocolIdentity(PeerId, "Mobile peer", PublicKey);
    private static RemoteControlPairingMaterial Ml() => RemoteControlPairingMaterial.Create(PeerId, "Mobile peer", PublicKey, MlKey);
    private static RemoteControlPairingMaterial Q() => RemoteControlPairingMaterial.CreatePolicyBound(PeerId, "Mobile peer", PublicKey, [], QKey);
    private static RemoteControlPairingMaterial Both() => RemoteControlPairingMaterial.CreatePolicyBound(PeerId, "Mobile peer", PublicKey, MlKey, QKey);
    private static void Require(bool value, string message) { if (!value) throw new InvalidOperationException(message); }
    private static void Reject(Action action)
    {
        try { action(); }
        catch (Exception e) when (e is InvalidDataException or InvalidOperationException or JsonException or WebRtcProductHandshakeCodecException) { return; }
        throw new InvalidOperationException("Invalid pairing state was accepted.");
    }
    private static string Change(string json, Action<JsonObject> edit)
    { var body = JsonNode.Parse(json)!.AsObject(); edit(body); return body.ToJsonString(); }

    private static Task RoundTrip()
    {
        var material = Identity(); using var json = JsonDocument.Parse(material.ToJson());
        Require(json.RootElement.GetProperty("schemaVersion").GetInt32() == 2 &&
            json.RootElement.GetProperty("kemPublicKeys").GetArrayLength() == 0, "Identity-only state was hidden in legacy wire or invented a KEM.");
        var parsed = RemoteControlPairingMaterial.Parse(material.ToJson());
        Require(parsed.IsProtocolIdentityOnly && parsed.MlKem768PublicKey.IsEmpty && parsed.QPeriaptPublicKey.IsEmpty &&
            parsed.HasSameAuthority(material) && parsed.ProtocolSigningAlgorithm == "ML-DSA-65", "Identity-only round trip changed authority.");
        return Task.CompletedTask;
    }
    private static Task LegacyContract()
    {
        foreach (var material in new[] { Ml(), Q(), Both() })
        {
            using var json = JsonDocument.Parse(material.ToJson());
            Require(json.RootElement.GetProperty("schemaVersion").GetInt32() == 1 && !material.IsProtocolIdentityOnly,
                "Existing nonempty-KEM export schema changed.");
            Require(RemoteControlPairingMaterial.Parse(material.ToJson()).HasSameAuthority(material), "Existing pairing roundtrip changed.");
            Reject(() => RemoteControlPairingMaterial.Parse(Change(material.ToJson(), o => o["kemPublicKeys"] = new JsonArray())));
            Reject(() => RemoteControlPairingMaterial.Parse(Change(material.ToJson(), o => o["schemaVersion"] = 2)));
        }
        Reject(() => RemoteControlPairingMaterial.Create(PeerId, "Peer", PublicKey, []));
        Reject(() => RemoteControlPairingMaterial.CreatePolicyBound(PeerId, "Peer", PublicKey, [], []));
        return Task.CompletedTask;
    }
    private static Task StrictIdentityWire()
    {
        var json = Identity().ToJson();
        foreach (var change in new Action<JsonObject>[] {
            o => o.Remove("kemPublicKeys"), o => o["kemPublicKeys"] = null,
            o => o["kemPublicKeys"] = new JsonArray(JsonNode.Parse(Ml().ToJson())!["kemPublicKeys"]![0]!.DeepClone()),
            o => o["schemaVersion"] = 1, o => o["schemaVersion"] = 3, o => o["schemaVersion"] = "2",
            o => o["protocolPublicKeyFingerprint"] = new string('a', 64), o => o["protocolSigningAlgorithm"] = "Ed25519",
            o => o["protocolPublicKey"] = Convert.ToBase64String(new byte[32]), o => o["deviceId"] = "192.168.1.1",
            o => o["approved"] = true }) Reject(() => RemoteControlPairingMaterial.Parse(Change(json, change)));
        Reject(() => RemoteControlPairingMaterial.Parse(json.Replace("\"schemaVersion\": 2", "\"schemaVersion\": 2, \"schemaVersion\": 2", StringComparison.Ordinal)));
        return Task.CompletedTask;
    }
    private static Task AdditiveUpgrades()
    {
        var identity = Identity(); var ml = Ml(); var q = Q(); var both = Both();
        foreach (var ready in new[] { ml, q, both })
        {
            Require(identity.CanAddKemMaterial(ready) && !ready.CanAddKemMaterial(identity), "Identity-to-KEM upgrade was blocked or permitted downgrade.");
            Require(identity.HasSameProtocolIdentity(ready) && !identity.HasSameAuthority(ready), "Signer identity and material availability were conflated.");
        }
        Require(ml.CanAddKemMaterial(both) && q.CanAddKemMaterial(both), "Adding a previously absent supported KEM was rejected.");
        Require(!both.CanAddKemMaterial(ml) && !both.CanAddKemMaterial(q) && !both.CanAddKemMaterial(both) && !identity.CanAddKemMaterial(identity),
            "Removal or identical material became an additive update.");
        return Task.CompletedTask;
    }
    private static Task UpgradeConflicts()
    {
        var different = PublicKey; different[0] ^= 1;
        var differentMl = MlKey; differentMl[0] ^= 1;
        var differentQ = QKey; differentQ[0] ^= 1;
        Require(!Identity().CanAddKemMaterial(RemoteControlPairingMaterial.Create("id:cccccccc-cccc-cccc-cccc-cccccccccccc", "Peer", PublicKey, MlKey)), "Public key created another ID authority.");
        Require(!Identity().CanAddKemMaterial(RemoteControlPairingMaterial.Create(PeerId, "Peer", different, MlKey)), "Device ID replaced signer.");
        Require(!Ml().CanAddKemMaterial(RemoteControlPairingMaterial.CreatePolicyBound(PeerId, "Peer", PublicKey, differentMl, QKey)), "Q addition hid a changed existing ML-KEM.");
        Require(!Q().CanAddKemMaterial(RemoteControlPairingMaterial.CreatePolicyBound(PeerId, "Peer", PublicKey, MlKey, differentQ)), "ML addition hid a changed existing Q key.");
        Require(!Both().CanAddKemMaterial(RemoteControlPairingMaterial.CreatePolicyBound(PeerId, "Peer", PublicKey, differentMl, QKey)), "Existing KEM replacement was accepted.");
        return Task.CompletedTask;
    }
    private static Task OutboundReadiness()
    {
        Reject(() => Identity().RequireInitiatorKem());
        foreach (var ready in new[] { Ml(), Q(), Both() }) ready.RequireInitiatorKem();
        return Task.CompletedTask;
    }
    private static Task InboundCandidate()
    {
        var identity = Identity(); var pin = identity.ProtocolPublicKeyFingerprint;
        byte[] Frame(string target, byte[] signingKey) => new WebRtcProductHandshakeMessageA(
            [0x0101], [new(0x0101, new byte[1088])], new byte[32],
            new(["ML-KEM-768"], ["ML-DSA-65"], ["pqc"], ["AES-256-GCM"], false, "controlled-candidate-test", "liboqs"),
            WebRtcProductHandshakePolicy.Default, new WebRtcProductProtocolIdentityPublicKey(WebRtcProductSignatureAlgorithm.MlDsa65, signingKey).Encode(),
            new RemoteControlHandshakeSoa(RemoteControlHandshakeBinding.PeerId(PeerId), RemoteControlHandshakeBinding.PeerId(target), new byte[16]).EncodeTlv(),
            new byte[] { 1 }).Encode();
        // This checks only pre-auth candidate resolution. Signature/KEM/Finished and
        // account/playback authorization have not been performed by this fixture.
        var candidate = RemoteControlHandshakeBinding.ValidateAndResolveMessageA(Frame(LocalId, PublicKey), LocalId, [new(PeerId, pin)]);
        Require(candidate.Peer.PeerDeviceId == PeerId && candidate.Peer.PeerPublicKeyFingerprint == pin, "Identity-only authority could not resolve its existing candidate.");
        Reject(() => RemoteControlHandshakeBinding.ValidateAndResolveMessageA(Frame("id:cccccccc-cccc-cccc-cccc-cccccccccccc", PublicKey), LocalId, [new(PeerId, pin)]));
        var wrongKey = PublicKey; wrongKey[0] ^= 1;
        Reject(() => RemoteControlHandshakeBinding.ValidateAndResolveMessageA(Frame(LocalId, wrongKey), LocalId, [new(PeerId, pin)]));
        Reject(() => RemoteControlHandshakeBinding.ValidateAndResolveMessageA(Frame(LocalId, PublicKey), LocalId, []));
        return Task.CompletedTask;
    }
    private static Task ImmutablePublicMaterial()
    {
        var bytes = PublicKey; var material = RemoteControlPairingMaterial.CreateProtocolIdentity(PeerId, "Peer", bytes); var json = material.ToJson();
        bytes[0] ^= 1; var exported = material.ProtocolPublicKey;
        if (System.Runtime.InteropServices.MemoryMarshal.TryGetArray(exported, out var backing)) backing.Array![backing.Offset] ^= 1;
        Require(material.ToJson() == json, "External public-key mutation rewrote approved material.");
        return Task.CompletedTask;
    }
}
