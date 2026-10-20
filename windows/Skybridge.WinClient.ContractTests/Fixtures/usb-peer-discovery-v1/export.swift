import Foundation
import CryptoKit
import SkyBridgeProtocolCore

// Build against the Apple repository's actual SkyBridgeProtocolCore target.
// Only ephemeral public keys, signatures and transcripts are exported.
@main
struct Export {
    struct RequestEnvelope: Encodable { let usbPeerDiscoveryRequest: USBPeerDiscoveryRequest }
    struct ResponseEnvelope: Encodable { let usbPeerDiscoveryResponse: USBPeerDiscoveryResponse }
    struct Vector: Encodable {
        let name: String
        let nowMilliseconds: Int64
        let requestWire: Data
        let responseWire: Data
        let signingData: Data
    }
    static func main() async throws {
        let now = Date(timeIntervalSince1970: 1_792_512_000)
        let key = try MLDSA65.PrivateKey()
        let publicKey = key.publicKey.rawRepresentation
        let identity = HandshakeManagementIdentity(
            deviceID: "12345678-1234-4321-abcd-0123456789ab", algorithm: "ML-DSA-65",
            publicKey: publicKey,
            fingerprint: ProtocolIdentityBinding.computeFingerprint(algorithm: .mlDSA65, publicKeyBytes: publicKey))
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        var vectors: [Vector] = []
        guard let nonce = UUID(uuidString: "ABCDEFAB-1234-4ABC-8DEF-ABCDEFABCDEF") else {
            throw CocoaError(.fileReadCorruptFile)
        }
        for name in ["iPad", "我的 iPad / 日本語", "📱 <&> \"USB\" \\ device", "Line\u{2028}paragraph\u{2029}", "Private\u{e000}"] {
            let request = try USBPeerDiscoveryRequest(nonce: nonce, now: now)
            let unsigned = USBPeerDiscoveryResponse(request: request, identity: identity, name: name,
                platform: "ios", signature: Data())
            let signingData = try unsigned.signingData
            let response = USBPeerDiscoveryResponse(request: request, identity: identity, name: name,
                platform: "ios", signature: try key.signature(for: signingData))
            try await response.validate(for: request, now: now, verify: { data, signature, _ in
                key.publicKey.isValidSignature(signature, for: data)
            })
            vectors.append(Vector(name: name, nowMilliseconds: 1_792_512_000_000,
                requestWire: try encoder.encode(RequestEnvelope(usbPeerDiscoveryRequest: request)),
                responseWire: try encoder.encode(ResponseEnvelope(usbPeerDiscoveryResponse: response)),
                signingData: signingData))
        }
        encoder.outputFormatting.insert(.prettyPrinted)
        FileHandle.standardOutput.write(try encoder.encode(vectors))
    }
}
