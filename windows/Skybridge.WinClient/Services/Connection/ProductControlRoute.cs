using System.Net;

namespace Skybridge.WinClient.Services.Connection;

/// <summary>One cable selection and its signed bootstrap binding. No IP address
/// or arbitrary discovered alias can stand in for this route.</summary>
internal sealed record UsbControlRoute
{
    private UsbControlRoute(UsbPeerInspection inspection)
    {
        Udid = inspection.Udid; EndpointDigest = inspection.EndpointDigest;
        PeerDeviceId = RemoteControlHandshakeBinding.CanonicalDeviceId(inspection.Response.Identity.DeviceID);
        Fingerprint = inspection.Response.Identity.Fingerprint;
    }
    internal string Udid { get; }
    internal string EndpointDigest { get; }
    internal string PeerDeviceId { get; }
    internal string Fingerprint { get; }
    internal static UsbControlRoute From(UsbPeerInspection inspection)
    { ArgumentNullException.ThrowIfNull(inspection); return new(inspection); }
}

internal abstract record ProductPeerRoute
{
    private ProductPeerRoute() { }
    internal sealed record Network(DiscoveryPeerEndpoint Endpoint) : ProductPeerRoute;
    internal sealed record Usb(UsbControlRoute Route) : ProductPeerRoute;
}

/// <summary>Actual admitted carrier facts. Incoming TCP has an address but no
/// implied outbound DNS-SD route. USB has an exact cable binding and no IP.</summary>
internal abstract record ProductControlCarrier
{
    private ProductControlCarrier() { }
    internal sealed record Network(IPAddress RemoteAddress, DiscoveryPeerEndpoint? OutboundEndpoint) : ProductControlCarrier;
    internal sealed record Usb(UsbControlRoute Route, Audio.AudioAccountScope AccountScope) : ProductControlCarrier;
}
