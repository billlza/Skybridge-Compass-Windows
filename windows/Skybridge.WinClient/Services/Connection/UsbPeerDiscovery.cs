using System.Collections.Immutable;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Skybridge.WinClient.Services.RemoteControl;

namespace Skybridge.WinClient.Services.Connection;

internal sealed record UsbPeerDiscoveryRequest(int Version, Guid Nonce, long IssuedAtMilliseconds);
internal sealed record UsbPeerIdentity(string DeviceID, string Algorithm, ImmutableArray<byte> PublicKey, string Fingerprint);
internal sealed record UsbPeerDiscoveryResponse(UsbPeerDiscoveryRequest Request, UsbPeerIdentity Identity,
    string Name, string Platform, ImmutableArray<byte> Signature);

/// <summary>A verified public advertisement on one USB route, never a pairing or account grant.</summary>
internal sealed class UsbPeerInspection
{
    private UsbPeerInspection(string udid, UsbPeerDiscoveryResponse response, DateTimeOffset observedAt)
    { Udid = udid; Response = response; ObservedAt = observedAt; }
    internal string Udid { get; }
    internal UsbPeerDiscoveryResponse Response { get; }
    internal DateTimeOffset ObservedAt { get; }

    internal static UsbPeerInspection Verify(string udid, UsbPeerDiscoveryResponse response,
        UsbPeerDiscoveryRequest expected, DateTimeOffset now,
        Action<UsbPeerIdentity, byte[], ImmutableArray<byte>> verifySignature)
    {
        if (!UsbMuxProtocol.ValidUdid(udid)) throw new InvalidDataException("USB discovery has no valid cable route.");
        UsbPeerDiscoveryWire.Validate(response, expected, now);
        verifySignature(response.Identity, UsbPeerDiscoveryWire.SigningData(response), response.Signature);
        return new(udid, response, now);
    }
}

internal static class UsbPeerDiscoveryWire
{
    internal const int MaximumFrameBytes = 64 * 1024;
    private static readonly UTF8Encoding Utf8 = new(false, true);
    internal static UsbPeerDiscoveryRequest Request(DateTimeOffset now) => new(1, Guid.NewGuid(), now.ToUnixTimeMilliseconds());
    internal static byte[] Encode(UsbPeerDiscoveryRequest request) => LanBootstrapWire.Encode("usbPeerDiscoveryRequest", request);
    internal static UsbPeerDiscoveryResponse Decode(ReadOnlySpan<byte> frame)
    {
        if (frame.IsEmpty || frame.Length > MaximumFrameBytes) throw new InvalidDataException("USB discovery response exceeds its bound.");
        return LanBootstrapWire.Decode<UsbPeerDiscoveryResponse>(frame, "usbPeerDiscoveryResponse");
    }

    internal static void Validate(UsbPeerDiscoveryResponse response, UsbPeerDiscoveryRequest expected, DateTimeOffset now)
    {
        long milliseconds = now.ToUnixTimeMilliseconds();
        if (milliseconds < 0 || expected.Version != 1 || expected.IssuedAtMilliseconds < 0 ||
            expected.IssuedAtMilliseconds >= 9_000_000_000_000_000 ||
            expected.IssuedAtMilliseconds < milliseconds - 30_000 || expected.IssuedAtMilliseconds > milliseconds + 5_000)
            throw new InvalidDataException("USB discovery request is invalid or expired.");
        if (response.Request != expected || response.Identity is null || string.IsNullOrEmpty(response.Name) ||
            Utf8.GetByteCount(response.Name) > 128 || response.Name.EnumerateRunes().Any(rune =>
                Rune.GetUnicodeCategory(rune) is UnicodeCategory.Control or UnicodeCategory.Format) ||
            response.Platform is not ("ios" or "macos") || response.Signature.IsDefaultOrEmpty || response.Signature.Length > 8192)
            throw new InvalidDataException("USB discovery response does not match the current request.");
        var identity = response.Identity;
        if (identity.Algorithm != "ML-DSA-65")
            throw new NotSupportedException("This Windows peer handshake requires ML-DSA-65.");
        if (!Guid.TryParseExact(identity.DeviceID, "D", out var device) ||
            device.ToString("D") != identity.DeviceID || identity.PublicKey.IsDefault ||
            identity.PublicKey.Length != 1952 ||
            WebRtcProductProtocolIdentityPublicKey.ComputeAuthoritativeFingerprint(
                WebRtcProductSignatureAlgorithm.MlDsa65, identity.PublicKey.AsSpan()) != identity.Fingerprint)
            throw new InvalidDataException("USB discovery protocol identity is invalid.");
    }

    // Swift JSONEncoder(.sortedKeys, .withoutEscapingSlashes) is the v1 signing
    // contract. Standard .NET JSON encoders additionally escape some Unicode
    // scalars (including separators/private-use characters), changing signatures.
    // Write these fixed sorted fields with JSON's required escaping only.
    internal static byte[] SigningData(UsbPeerDiscoveryResponse response)
    {
        var value = new StringBuilder();
        value.Append("{\"domain\":\"SkyBridge.USBPeerDiscovery.v1\",\"identity\":{\"algorithm\":");
        String(value, response.Identity.Algorithm);
        value.Append(",\"deviceID\":"); String(value, response.Identity.DeviceID);
        value.Append(",\"fingerprint\":"); String(value, response.Identity.Fingerprint);
        value.Append(",\"publicKey\":"); String(value, Convert.ToBase64String(response.Identity.PublicKey.AsSpan()));
        value.Append("},\"name\":"); String(value, response.Name);
        value.Append(",\"platform\":"); String(value, response.Platform);
        value.Append(",\"request\":{\"issuedAtMilliseconds\":")
            .Append(response.Request.IssuedAtMilliseconds.ToString(CultureInfo.InvariantCulture)).Append(",\"nonce\":");
        String(value, response.Request.Nonce.ToString("D").ToUpperInvariant());
        value.Append(",\"version\":").Append(response.Request.Version.ToString(CultureInfo.InvariantCulture)).Append("}}");
        return Utf8.GetBytes(value.ToString());
    }

    private static void String(StringBuilder target, string value)
    {
        target.Append('"');
        foreach (char character in value)
        {
            switch (character)
            {
                case '"': target.Append("\\\""); break;
                case '\\': target.Append("\\\\"); break;
                case '\b': target.Append("\\b"); break;
                case '\f': target.Append("\\f"); break;
                case '\n': target.Append("\\n"); break;
                case '\r': target.Append("\\r"); break;
                case '\t': target.Append("\\t"); break;
                default:
                    if (character < 0x20) target.Append("\\u").Append(((int)character).ToString("x4", CultureInfo.InvariantCulture));
                    else target.Append(character);
                    break;
            }
        }
        target.Append('"');
    }

    internal static void VerifyNativeSignature(UsbPeerIdentity identity, byte[] message, ImmutableArray<byte> signature) =>
        RemoteControlIdentityStore.VerifyPibSignature(identity.PublicKey, message, signature);
}
