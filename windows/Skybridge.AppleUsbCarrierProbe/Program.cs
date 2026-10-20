using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Net.Sockets;
using Skybridge.AppleUsbCarrier;
using Skybridge.WinClient.Services.Connection;

// Qualification only. This executable does not create an authenticated session.
if (args is ["--self-test"]) return await CarrierChecks.Run();
if (args is not ["--probe-list"] && args is not ["--probe-control", _])
{
    Console.Error.WriteLine("Use --self-test, --probe-list, or --probe-control <observed USB UDID>.");
    return 2;
}
try
{
    var connector = OperatingSystem.IsWindows() ? UsbMuxConnector.WindowsService() :
        OperatingSystem.IsMacOS() ? new UsbMuxConnector(token =>
            UsbMuxConnector.ConnectSocket(new UnixDomainSocketEndPoint("/var/run/usbmuxd"), token)) :
        throw new PlatformNotSupportedException("This qualification requires Windows or macOS.");
    using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(15));
    var devices = await connector.DevicesAsync(stop.Token);
    bool opened = false;
    if (args.Length == 2)
    {
        await using var stream = await connector.OpenAsync(args[1], UsbMuxConnector.ControlPort, stop.Token);
        opened = true; // A byte carrier only; do not send unauthenticated SkyBridge commands.
    }
    Console.WriteLine(JsonSerializer.Serialize(new {
        scope = "isolated-usb-multiplex-carrier", platform = Environment.OSVersion.Platform.ToString(),
        daemon = OperatingSystem.IsWindows() ? "Apple-local-TCP" : "Mac-qualification-Unix",
        usbDevices = devices.Select(d => new {
            deviceId = d.DeviceId, productId = d.ProductId,
            udidSha256 = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(d.Udid)))
        }),
        controlCarrierOpened = opened, applicationAuthenticated = false, audioPlayed = false
    }));
    return 0;
}
catch (Exception error)
{
    Console.WriteLine(JsonSerializer.Serialize(new {
        scope = "isolated-usb-multiplex-carrier", result = "failed",
        errorType = error.GetType().Name, error.HResult,
        usbFailure = (error as UsbMuxException)?.Failure.ToString(), applicationAuthenticated = false, audioPlayed = false
    }));
    return 1;
}
