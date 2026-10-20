using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Linq;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.Connection;

// Test-only local service. It never imports user identities or grants an account/session.
internal sealed class NativeUsbDiscoveryFixture : IAsyncDisposable
{
    internal const string DeviceName = "USB iPad fixture";
    internal const string Serial = "00008132-1111111111111111";
    private readonly MLDsa _key;
    private readonly UsbPeerIdentity _identity;
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly SemaphoreSlim _signing = new(1, 1);
    private readonly SemaphoreSlim _markers = new(1, 1);
    private readonly string? _observationsPath;
    private readonly List<Task> _workers = [];
    private readonly Task _accepting;
    private readonly Func<bool> _closedPort;
    private readonly TaskCompletionSource _responded = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _responses, _portRefusals, _earlyCloses;
    internal int Responses => Volatile.Read(ref _responses);
    internal EndPoint Endpoint => _listener.LocalEndpoint;

    internal NativeUsbDiscoveryFixture(int port = 0, Func<bool>? closedPort = null, string? observationsPath = null)
    {
        if (!OperatingSystem.IsWindows() || !MLDsa.IsSupported)
            throw new PlatformNotSupportedException("The native USB fixture requires Windows ML-DSA.");
        _key = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        var publicKey = _key.ExportMLDsaPublicKey().ToImmutableArray();
        _identity = new(Guid.NewGuid().ToString("D"), "ML-DSA-65", publicKey,
            WebRtcProductProtocolIdentityPublicKey.ComputeAuthoritativeFingerprint(WebRtcProductSignatureAlgorithm.MlDsa65, publicKey.AsSpan()));
        _closedPort = closedPort ?? (() => false);
        _observationsPath = observationsPath;
        _listener = new(IPAddress.Loopback, port);
        try { _listener.Start(); } catch { _key.Dispose(); throw; }
        _accepting = AcceptAsync();
    }

    private async Task AcceptAsync()
    {
        while (!_lifetime.IsCancellationRequested)
        {
            var client = await _listener.AcceptTcpClientAsync(_lifetime.Token).ConfigureAwait(false);
            if (_workers.Count >= 128) { client.Dispose(); throw new IOException("USB fixture request capacity exceeded."); }
            _workers.Add(ServeAsync(client));
        }
    }

    private async Task ServeAsync(TcpClient client)
    {
        ProductControlStreamTransport? owner = null;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);
        deadline.CancelAfter(TimeSpan.FromSeconds(8));
        try
        {
            var stream = client.GetStream();
            byte[] header = new byte[16]; await stream.ReadExactlyAsync(header, deadline.Token);
            uint length = BinaryPrimitives.ReadUInt32LittleEndian(header);
            uint tag = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(12));
            if (length is < 16 or > 65_536 || tag is not (1 or 2)) throw new InvalidDataException("Invalid fixture request header.");
            byte[] packet = new byte[checked((int)length)]; header.CopyTo(packet, 0);
            await stream.ReadExactlyAsync(packet.AsMemory(16), deadline.Token);
            using var frame = new MemoryStream(packet);
            var request = await UsbMuxProtocol.ReadAsync(frame, tag, deadline.Token);
            string kind = UsbMuxProtocol.Required(request, "MessageType", "string").Value;
            if (kind == "ListDevices")
            {
                var row = UsbMuxProtocol.Dictionary(("DeviceID", new("integer", 7)), ("Properties",
                    UsbMuxProtocol.Dictionary(("DeviceID", new("integer", 7)), ("ProductID", new("integer", 4779)),
                        ("SerialNumber", new("string", Serial)), ("ConnectionType", new("string", "USB")))));
                await stream.WriteAsync(UsbMuxProtocol.Packet(UsbMuxProtocol.Dictionary(("DeviceList", new("array", row))), tag), deadline.Token);
                return;
            }
            if (kind != "Connect" || UsbMuxProtocol.Integer(request, "DeviceID") != 7 ||
                UsbMuxProtocol.Integer(request, "PortNumber") != BinaryPrimitives.ReverseEndianness(UsbMuxConnector.ControlPort))
                throw new InvalidDataException("Fixture received an unexpected device or port.");
            bool closed = _closedPort();
            await stream.WriteAsync(UsbMuxProtocol.Packet(UsbMuxProtocol.Dictionary(
                ("MessageType", new("string", "Result")), ("Number", new("integer", closed ? 3 : 0))), tag), deadline.Token);
            if (closed)
            {
                Interlocked.Increment(ref _portRefusals);
                await PublishObservationsAsync();
                return;
            }
            owner = new(client, UsbPeerDiscoveryWire.MaximumFrameBytes, UsbPeerDiscoveryWire.MaximumFrameBytes);
            var payload = await owner.ReadAsync(deadline.Token);
            var discovery = LanBootstrapWire.Decode<UsbPeerDiscoveryRequest>(payload.Span, "usbPeerDiscoveryRequest");
            var unsigned = new UsbPeerDiscoveryResponse(discovery, _identity, DeviceName, "ios", []);
            ImmutableArray<byte> signature;
            await _signing.WaitAsync(deadline.Token);
            try { signature = _key.SignData(UsbPeerDiscoveryWire.SigningData(unsigned)).ToImmutableArray(); }
            finally { _signing.Release(); }
            await owner.SendAsync(LanBootstrapWire.Encode("usbPeerDiscoveryResponse", unsigned with { Signature = signature }), deadline.Token);
            Interlocked.Increment(ref _responses);
            await PublishObservationsAsync();
            _responded.TrySetResult();
        }
        catch (EndOfStreamException) { Interlocked.Increment(ref _earlyCloses); }
        finally
        {
            if (owner is not null) await owner.DisposeAsync();
            else client.Dispose();
        }
    }

    public async ValueTask DisposeAsync()
    {
        _lifetime.Cancel(); _listener.Stop();
        var failures = new List<Exception>();
        foreach (var task in new[] { _accepting })
        {
            try { await task.ConfigureAwait(false); }
            catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { }
            catch (Exception error) { failures.Add(error); }
        }
        foreach (var task in _workers)
        {
            try { await task.ConfigureAwait(false); }
            catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { }
            catch (Exception error) { failures.Add(error); }
        }
        try { _key.Dispose(); } catch (Exception error) { failures.Add(error); }
        _signing.Dispose(); _markers.Dispose(); _lifetime.Dispose();
        if (failures.Count > 0) throw new AggregateException("Native USB fixture failed.", failures);
    }

    private string Observations(bool drained) => JsonSerializer.Serialize(new
    {
        responses = Responses, portRefusals = Volatile.Read(ref _portRefusals), earlyCloses = Volatile.Read(ref _earlyCloses),
        drained, mode = "synthetic-service", actualAppleService = false, actualUsbDevice = false, audioPlayed = false
    });
    private async Task PublishObservationsAsync()
    {
        if (_observationsPath is not { } path) return;
        await _markers.WaitAsync();
        try { await WriteAtomicAsync(path, Observations(drained: false)); }
        finally { _markers.Release(); }
    }
    private static async Task WriteAtomicAsync(string path, string contents)
    {
        string temporary = path + ".tmp";
        await File.WriteAllTextAsync(temporary, contents);
        File.Move(temporary, path, overwrite: true);
    }

    internal static async Task RoundTrip()
    {
        await using var server = new NativeUsbDiscoveryFixture();
        var connector = new UsbMuxConnector(token => UsbMuxConnector.ConnectSocket(server.Endpoint, token));
        var client = new UsbPeerDiscoveryClient(connector);
        using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(12));
        var result = await client.InspectAsync(Serial, limit.Token);
        await server._responded.Task.WaitAsync(limit.Token);
        if (result.Response.Identity.DeviceID != server._identity.DeviceID ||
            result.Response.Identity.Algorithm != server._identity.Algorithm ||
            result.Response.Identity.Fingerprint != server._identity.Fingerprint ||
            !result.Response.Identity.PublicKey.AsSpan().SequenceEqual(server._identity.PublicKey.AsSpan()) ||
            result.Response.Name != DeviceName || server.Responses != 1)
            throw new InvalidDataException("Actual native USB discovery did not bind its signed peer.");
    }

    internal static async Task RunUiAsync(string directory)
    {
        if (Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true")
            throw new InvalidOperationException("The fixed-port UI fixture is restricted to the owned CI runner.");
        directory = Path.GetFullPath(directory); Directory.CreateDirectory(directory);
        string ready = Path.Combine(directory, "ready.json"), stop = Path.Combine(directory, "stop"), closedPort = Path.Combine(directory, "closed-port");
        if (Directory.EnumerateFileSystemEntries(directory).Any()) throw new IOException("Choose a fresh USB fixture directory.");
        string observations = Path.Combine(directory, "observations.json");
        var server = new NativeUsbDiscoveryFixture(27015, () => File.Exists(closedPort), observations);
        try
        {
            await server.PublishObservationsAsync();
            await WriteAtomicAsync(ready, JsonSerializer.Serialize(new { processId = Environment.ProcessId, name = DeviceName,
                mode = "synthetic-service", actualAppleService = false, actualUsbDevice = false }));
            var expires = DateTimeOffset.UtcNow.AddMinutes(5);
            while (!File.Exists(stop))
            {
                if (DateTimeOffset.UtcNow >= expires) throw new TimeoutException("The UI fixture reached its five-minute limit.");
                if (server._accepting.IsCompleted) { await server._accepting; throw new IOException("The fixture listener ended before stop."); }
                await Task.Delay(100);
            }
        }
        finally { await server.DisposeAsync(); }
        await WriteAtomicAsync(observations, server.Observations(drained: true));
    }
}
