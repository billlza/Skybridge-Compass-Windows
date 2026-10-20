using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Xml.Linq;

namespace Skybridge.WinClient.Services.Connection;

// Multiplex ownership exists before an application bootstrap transport can take
// over. Keep this failure in the carrier layer, which is also linked by the probe.
internal sealed class UsbMuxReleaseException(Stream retainedOwner, Exception failure)
    : IOException("USB multiplex stream release was not confirmed.", failure)
{
    internal Stream RetainedOwner { get; } = retainedOwner;
}

/// <summary>USB carrier: one bounded daemon request per connection. Successful Connect hands
/// the same stream to its caller, without consuming any application bytes.</summary>
internal sealed class UsbMuxConnector
{
    internal const ushort ControlPort = 9527;
    private readonly Func<CancellationToken, Task<Stream>> _connect;
    private readonly TimeSpan _timeout;

    internal UsbMuxConnector(Func<CancellationToken, Task<Stream>> connect, TimeSpan? timeout = null)
    {
        _connect = connect;
        _timeout = timeout ?? TimeSpan.FromSeconds(6);
        if (_timeout <= TimeSpan.Zero || _timeout > TimeSpan.FromSeconds(6)) throw new ArgumentOutOfRangeException(nameof(timeout));
    }

    internal static UsbMuxConnector WindowsService()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("The Windows Apple service requires Windows.");
        return new(token => ConnectSocket(new IPEndPoint(IPAddress.Loopback, 27015), token));
    }

    internal static async Task<Stream> ConnectSocket(EndPoint endpoint, CancellationToken token)
    {
        var socket = new Socket(endpoint.AddressFamily, SocketType.Stream,
            endpoint.AddressFamily == AddressFamily.Unix ? ProtocolType.Unspecified : ProtocolType.Tcp);
        try
        {
            await socket.ConnectAsync(endpoint, token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch { socket.Dispose(); throw; }
    }

    internal async Task<IReadOnlyList<UsbMuxDevice>> DevicesAsync(CancellationToken token)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(_timeout);
        try { return await Enumerate(deadline.Token).ConfigureAwait(false); }
        catch (OperationCanceledException error) when (!token.IsCancellationRequested && deadline.IsCancellationRequested)
        { throw new TimeoutException("USB device enumeration exceeded its deadline.", error); }
    }

    private async Task<IReadOnlyList<UsbMuxDevice>> Enumerate(CancellationToken token)
    {
        var stream = await _connect(token).ConfigureAwait(false);
        IReadOnlyList<UsbMuxDevice> devices;
        try
        {
            var response = await Exchange(stream, UsbMuxProtocol.Request("ListDevices"), 1, token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            devices = UsbMuxProtocol.Devices(response);
        }
        catch (Exception failure)
        {
            await ReleaseFailed(stream, failure).ConfigureAwait(false);
            throw;
        }
        try { await stream.DisposeAsync().ConfigureAwait(false); }
        catch (Exception cleanup) { throw new UsbMuxReleaseException(stream, cleanup); }
        return devices;
    }

    internal async Task<Stream> OpenAsync(string udid, ushort port, CancellationToken token)
    {
        if (!UsbMuxProtocol.ValidUdid(udid) || port == 0) throw new ArgumentException("A USB UDID and nonzero port are required.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(_timeout); // Includes re-enumeration, connect and response.
        try
        {
            var devices = await Enumerate(deadline.Token).ConfigureAwait(false);
            var device = devices.SingleOrDefault(d => d.Udid == udid)
                ?? throw new UsbMuxException(UsbMuxFailure.DeviceUnavailable);
            var stream = await _connect(deadline.Token).ConfigureAwait(false);
            try
            {
                var request = UsbMuxProtocol.Request("Connect");
                request.Add(new XElement("key", "DeviceID"), new XElement("integer", device.DeviceId),
                    new XElement("key", "PortNumber"), new XElement("integer", BinaryPrimitives.ReverseEndianness(port)));
                var response = await Exchange(stream, request, 2, deadline.Token).ConfigureAwait(false);
                UsbMuxProtocol.RequireConnected(response);
                deadline.Token.ThrowIfCancellationRequested();
                return stream;
            }
            catch (Exception failure)
            {
                await ReleaseFailed(stream, failure).ConfigureAwait(false);
                throw;
            }
        }
        catch (OperationCanceledException error) when (!token.IsCancellationRequested && deadline.IsCancellationRequested)
        { throw new TimeoutException("USB connect exceeded its deadline.", error); }
    }

    private static async Task<XElement> Exchange(Stream stream, XElement request, uint tag, CancellationToken token)
    {
        await stream.WriteAsync(UsbMuxProtocol.Packet(request, tag), token).ConfigureAwait(false);
        return await UsbMuxProtocol.ReadAsync(stream, tag, token).ConfigureAwait(false);
    }

    private static async Task ReleaseFailed(Stream stream, Exception failure)
    {
        try { await stream.DisposeAsync().ConfigureAwait(false); }
        catch (Exception cleanup)
        { throw new UsbMuxReleaseException(stream, new AggregateException("USB request and stream release failed.", failure, cleanup)); }
    }
}
