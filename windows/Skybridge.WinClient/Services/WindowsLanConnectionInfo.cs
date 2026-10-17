using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Skybridge.WinClient.Services.RemoteControl;

namespace Skybridge.WinClient.Services;

/// <summary>Public route hint using the shared LAN v1 format. It carries no
/// pairing approval, account authority, KEM key or private identity material.</summary>
internal static class WindowsLanConnectionInfo
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    internal static string Encode(IPEndPoint endpoint, RemoteControlPairingMaterial identity)
    {
        ArgumentNullException.ThrowIfNull(endpoint); ArgumentNullException.ThrowIfNull(identity);
        // The current Windows MAIN listener binds one explicitly selected IPv4
        // interface. Do not publish a wildcard, loopback or unsupported route.
        var address = endpoint.Address;
        if (address.AddressFamily != AddressFamily.InterNetwork || endpoint.Port is < 1 or > 65535)
            throw new InvalidDataException("A concrete IPv4 MAIN endpoint is required.");
        var octets = address.GetAddressBytes();
        if (octets[0] is 0 or 127 or >= 224 || octets[0] == 169 && octets[1] == 254)
            throw new InvalidDataException("This address cannot be used as a LAN connection hint.");
        ValidateText(identity.DeviceId, 256); ValidateText(identity.DeviceName, 128);
        var fingerprint = identity.ProtocolPublicKeyFingerprint;
        if (fingerprint.Length != 64 || fingerprint.Any(c => c is not (>= '0' and <= '9' or >= 'a' and <= 'f')))
            throw new InvalidDataException("The public protocol fingerprint is not canonical.");
        var result = $"skybridge://lan/v1/{Field(address.ToString())}/{endpoint.Port.ToString(CultureInfo.InvariantCulture)}/" +
            $"{Field(identity.DeviceId)}/{fingerprint}/{Field(identity.DeviceName)}/windows";
        if (result.Length > 2048) throw new InvalidDataException("The LAN connection hint is too long.");
        return result;
    }

    private static string Field(string text) => Convert.ToBase64String(StrictUtf8.GetBytes(text))
        .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static void ValidateText(string text, int maximum)
    {
        if (text.Length is 0 || text.Length > maximum || BoundaryWhitespace(text[0]) || BoundaryWhitespace(text[^1]) ||
            text.Any(c => c < 0x20 || c is >= '\u007f' and <= '\u009f'))
            throw new InvalidDataException("The public device text cannot be represented in the LAN format.");
        try { _ = StrictUtf8.GetByteCount(text); }
        catch (EncoderFallbackException error) { throw new InvalidDataException("The public device text is not valid Unicode.", error); }
    }
    private static bool BoundaryWhitespace(char c) => c is >= '\u0009' and <= '\u000d' or '\u0020' or '\u0085' or
        '\u00a0' or '\u1680' or >= '\u2000' and <= '\u200b' or '\u2028' or '\u2029' or '\u202f' or '\u205f' or '\u3000' or '\ufeff';
}

/// <summary>A snapshot of a live route. The owner callback must check the exact
/// listener and account at capture and immediately before the copy is admitted.</summary>
internal sealed class LanConnectionInfoPublication
{
    private readonly Func<IPEndPoint> _readCurrentEndpoint;
    private readonly IPEndPoint _endpoint;
    private readonly string _text;

    internal LanConnectionInfoPublication(RemoteControlPairingMaterial identity, Func<IPEndPoint> readCurrentEndpoint)
    {
        ArgumentNullException.ThrowIfNull(readCurrentEndpoint);
        _readCurrentEndpoint = readCurrentEndpoint;
        var current = readCurrentEndpoint();
        _endpoint = new(new IPAddress(current.Address.GetAddressBytes()), current.Port);
        _text = WindowsLanConnectionInfo.Encode(_endpoint, identity);
    }

    internal Task CopyAsync(Func<string, Task> copy)
    {
        ArgumentNullException.ThrowIfNull(copy);
        if (!_endpoint.Equals(_readCurrentEndpoint()))
            throw new InvalidOperationException("The MAIN listener changed. Copy its current connection information again.");
        // This is effect admission. No promise is made that a published route will
        // remain reachable after this check or after the clipboard operation.
        return copy(_text);
    }
}
