using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.Connection;

namespace Skybridge.AppleUsbCarrier;

internal static class CarrierChecks
{
    private const string Serial = "00008132-0000000000000001";
    private static XElement Row(uint id = 7, string serial = Serial, string connection = "USB") =>
        UsbMuxProtocol.Dictionary(("DeviceID", new("integer", id)),
            ("Properties", UsbMuxProtocol.Dictionary(("DeviceID", new("integer", id)),
                ("ProductID", new("integer", 4811)), ("SerialNumber", new("string", serial)),
                ("ConnectionType", new("string", connection)))));
    private static XElement List(params XElement[] rows) => UsbMuxProtocol.Dictionary(("DeviceList", new("array", rows)));
    private static XElement Result(uint code) => UsbMuxProtocol.Dictionary(
        ("MessageType", new("string", "Result")), ("Number", new("integer", code)));
    private static XElement Decode(XElement value) => UsbMuxProtocol.Parse(
        UsbMuxProtocol.Packet(value, 1).AsSpan(16).ToArray());

    internal static async Task<int> Run()
    {
        var cases = new List<(string Name, Func<Task> Run)> {
            ("USB selected and Network twin excluded", () => Sync(() => {
                var rows = UsbMuxProtocol.Devices(Decode(List(Row(), Row(8, connection: "Network"))));
                Require(rows.Count == 1 && rows[0].DeviceId == 7, "Network entry entered USB route");
            })),
            ("Empty device list is a legitimate snapshot", () => Sync(() => Require(
                UsbMuxProtocol.Devices(Decode(List())).Count == 0, "Empty snapshot rejected"))),
            ("Duplicate USB serial rejected", () => Expect<UsbMuxException>(() => Sync(() =>
                UsbMuxProtocol.Devices(Decode(List(Row(), Row(8))))))),
            ("Duplicate USB ephemeral ID rejected", () => Expect<UsbMuxException>(() => Sync(() =>
                UsbMuxProtocol.Devices(Decode(List(Row(), Row(serial: "00008132-0000000000000002"))))))),
            ("Mismatched row and property IDs rejected", () => Expect<UsbMuxException>(() => Sync(() => {
                var row = Row(); row.Elements().ElementAt(1).Value = "9";
                UsbMuxProtocol.Devices(Decode(List(row)));
            }))),
            ("Boolean is not an integer ID", () => Expect<UsbMuxException>(() => Sync(() => {
                var row = Row(); row.Elements().ElementAt(1).ReplaceWith(new XElement("true"));
                UsbMuxProtocol.Devices(Decode(List(row)));
            }))),
            ("Oversized device list rejected", () => Expect<UsbMuxException>(() => Sync(() =>
                UsbMuxProtocol.Devices(Decode(List(Enumerable.Range(1, 257).Select(i => Row((uint)i)).ToArray())))))),
            ("Unknown connection type rejected", () => Expect<UsbMuxException>(() => Sync(() =>
                UsbMuxProtocol.Devices(Decode(List(Row(connection: "Other"))))))),
            ("Invalid UDID rejected", () => Expect<UsbMuxException>(() => Sync(() =>
                UsbMuxProtocol.Devices(Decode(List(Row(serial: "../../etc/passwd"))))))),
            ("Duplicate plist key rejected", () => Expect<UsbMuxException>(() => Sync(() => Decode(
                UsbMuxProtocol.Dictionary(("Number", new("integer", 0)), ("Number", new("integer", 3))))))),
            ("Unstructured plist root content rejected", () => Expect<UsbMuxException>(() => Sync(() =>
                UsbMuxProtocol.Parse(Encoding.UTF8.GetBytes("<plist version='1.0'>other<dict/></plist>"))))),
            ("XML depth bounded before allocation of plist tree", () => Expect<UsbMuxException>(() => Sync(() =>
                UsbMuxProtocol.Parse(Encoding.UTF8.GetBytes("<plist version='1.0'><dict><key>x</key>" +
                    string.Concat(Enumerable.Repeat("<array>", 17)) + "<string>x</string>" +
                    string.Concat(Enumerable.Repeat("</array>", 17)) + "</dict></plist>"))))),
            ("External entities cannot provide data", () => Expect<InvalidDataException>(() => Sync(() =>
                UsbMuxProtocol.Parse(Encoding.UTF8.GetBytes("<!DOCTYPE plist [<!ENTITY x SYSTEM 'file:///not-read'>]>" +
                    "<plist version='1.0'><dict><key>x</key><string>&x;</string></dict></plist>"))))),
            ("Ordinary plist DOCTYPE needs no network", () => Sync(() => {
                var root = UsbMuxProtocol.Parse(Encoding.UTF8.GetBytes(
                    "<!DOCTYPE plist PUBLIC '-//Apple//DTD PLIST 1.0//EN' 'http://www.apple.com/DTDs/PropertyList-1.0.dtd'>" +
                    "<plist version='1.0'><dict><key>DeviceList</key><array/></dict></plist>"));
                Require(UsbMuxProtocol.Devices(root).Count == 0, "DOCTYPE changed data");
            })),
            ("Fragmented packet leaves application bytes untouched", Fragmented),
            ("Fresh enumeration binds Connect and network port order", Handoff),
            ("Canceled receive releases its daemon connection", () => Stalled(cancel: true)),
            ("Deadline releases a partial daemon reply", () => Stalled(cancel: false)),
            ("Failed request preserves its cleanup failure", CleanupFailure),
            ("Mux handoff preserves product framing across handshake and control readers", FramedHandoff),
            ("Mux disconnect during a product frame remains a truncated-frame failure", TruncatedFrame)
        };
        foreach (int offset in new[] { 0, 4, 8, 12 })
        {
            int field = offset;
            cases.Add(($"Invalid header field {field} rejected", async () => {
                var packet = UsbMuxProtocol.Packet(List(), 1);
                BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(field), field == 0 ? uint.MaxValue : 99);
                using var stream = new MemoryStream(packet);
                await Expect<UsbMuxException>(() => UsbMuxProtocol.ReadAsync(stream, 1, CancellationToken.None));
            }));
        }
        foreach (uint code in new uint[] { 1, 2, 3, 6, 99 })
        {
            uint value = code;
            cases.Add(($"Connect result {value} fails without fallback", () => RejectConnection(value)));
        }
        cases.AddRange(ProductControlStreamOwnershipTests.Cases);
        int passed = 0;
        foreach (var item in cases)
        {
            try { await item.Run().WaitAsync(TimeSpan.FromSeconds(5)); passed++; }
            catch (Exception failure) {
                Console.WriteLine(JsonSerializer.Serialize(new { result = "failed", item.Name,
                    failure = failure.ToString(), passed, total = cases.Count })); return 1;
            }
        }
        Console.WriteLine(JsonSerializer.Serialize(new { result = "passed", passed, failed = 0,
            nativeWindowsServiceVerified = false, cases = cases.Select(c => c.Name) }));
        return 0;
    }

    private static async Task Fragmented()
    {
        byte[] packet = UsbMuxProtocol.Packet(List(Row()), 1);
        await using var source = new FragmentedStream([.. packet, 21, 22, 23]);
        var decoded = await UsbMuxProtocol.ReadAsync(source, 1, CancellationToken.None);
        Require(UsbMuxProtocol.Devices(decoded).Single().Udid == Serial, "Fragmented response changed");
        Require(source.Position == packet.Length, "Read consumed application payload");
    }

    private static async Task Handoff()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
        using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        var server = Task.Run(async () => {
            for (uint id = 7; id <= 9; id += 2)
            {
                using var socket = await listener.AcceptTcpClientAsync(limit.Token);
                var request = await UsbMuxProtocol.ReadAsync(socket.GetStream(), 1, limit.Token);
                Require(UsbMuxProtocol.Required(request, "MessageType", "string").Value == "ListDevices", "Expected list");
                await socket.GetStream().WriteAsync(UsbMuxProtocol.Packet(List(Row(id)), 1), limit.Token);
            }
            using var connected = await listener.AcceptTcpClientAsync(limit.Token);
            var stream = connected.GetStream();
            var connect = await UsbMuxProtocol.ReadAsync(stream, 2, limit.Token);
            Require(UsbMuxProtocol.Integer(connect, "DeviceID") == 9, "Stale daemon device ID used");
            Require(UsbMuxProtocol.Integer(connect, "PortNumber") == 14117, "9527 must use network byte order");
            byte[] reply = [.. UsbMuxProtocol.Packet(Result(0), 2), 21, 22, 23];
            await stream.WriteAsync(reply, limit.Token);
            Require(await stream.ReadAsync(new byte[1], limit.Token) == 0, "Carrier was not released");
        }, limit.Token);
        var connector = new UsbMuxConnector(t => UsbMuxConnector.ConnectSocket(listener.LocalEndpoint, t));
        Require((await connector.DevicesAsync(limit.Token)).Single().DeviceId == 7, "Initial list");
        await using (var carrier = await connector.OpenAsync(Serial, 9527, limit.Token))
        {
            byte[] payload = new byte[3]; await carrier.ReadExactlyAsync(payload, limit.Token);
            Require(payload.SequenceEqual(new byte[] { 21, 22, 23 }), "Stream handoff lost bytes");
        }
        await server;
    }

    private static async Task Stalled(bool cancel)
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
        using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        using var caller = new CancellationTokenSource();
        var server = Task.Run(async () => {
            using var socket = await listener.AcceptTcpClientAsync(limit.Token);
            var stream = socket.GetStream();
            _ = await UsbMuxProtocol.ReadAsync(stream, 1, limit.Token);
            await stream.WriteAsync(new byte[] { 30, 0, 0 }, limit.Token);
            if (cancel) caller.Cancel();
            Require(await stream.ReadAsync(new byte[1], limit.Token) == 0, "Canceled owner retained the socket");
        }, limit.Token);
        var connector = new UsbMuxConnector(t => UsbMuxConnector.ConnectSocket(listener.LocalEndpoint, t),
            timeout: TimeSpan.FromMilliseconds(200));
        if (cancel) await Expect<OperationCanceledException>(() => connector.DevicesAsync(caller.Token));
        else await Expect<TimeoutException>(() => connector.DevicesAsync(caller.Token));
        await server;
    }

    private static async Task FramedHandoff()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
        using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        var server = Task.Run(async () => {
            using (var enumeration = await listener.AcceptTcpClientAsync(limit.Token))
            {
                _ = await UsbMuxProtocol.ReadAsync(enumeration.GetStream(), 1, limit.Token);
                await enumeration.GetStream().WriteAsync(UsbMuxProtocol.Packet(List(Row()), 1), limit.Token);
            }
            using var connected = await listener.AcceptTcpClientAsync(limit.Token);
            var stream = connected.GetStream();
            _ = await UsbMuxProtocol.ReadAsync(stream, 2, limit.Token);
            // One native write deliberately crosses mux, handshake-reader and MAIN-reader boundaries.
            byte[] reply = [.. UsbMuxProtocol.Packet(Result(0), 2), 0, 0, 0, 2, 21, 22, 0, 0, 0, 1, 23];
            await stream.WriteAsync(reply, limit.Token);
            var response = new byte[5]; await stream.ReadExactlyAsync(response, limit.Token);
            Require(response.SequenceEqual(new byte[] { 0, 0, 0, 1, 31 }), "Product writer changed its frame");
            Require(await stream.ReadAsync(new byte[1], limit.Token) == 0, "Product owner did not release mux stream");
        }, limit.Token);
        var connector = new UsbMuxConnector(token => UsbMuxConnector.ConnectSocket(listener.LocalEndpoint, token));
        var carrier = await connector.OpenAsync(Serial, UsbMuxConnector.ControlPort, limit.Token);
        await using (var transport = new ProductControlStreamTransport(carrier, 64, 64))
        {
            IProductHandshakeTransport handshakeReader = transport;
            Require((await handshakeReader.ReadAsync(limit.Token)).Span.SequenceEqual(new byte[] { 21, 22 }),
                "Handshake reader lost coalesced bytes");
            Require((await transport.ReadBoundedAsync(64, limit.Token)).Span.SequenceEqual(new byte[] { 23 }),
                "MAIN reader lost the next frame");
            await transport.SendAdmittedAsync(() => new byte[] { 31 }, limit.Token);
        }
        await server;
    }

    private static async Task TruncatedFrame()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
        using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        var server = Task.Run(async () => {
            using (var enumeration = await listener.AcceptTcpClientAsync(limit.Token))
            {
                _ = await UsbMuxProtocol.ReadAsync(enumeration.GetStream(), 1, limit.Token);
                await enumeration.GetStream().WriteAsync(UsbMuxProtocol.Packet(List(Row()), 1), limit.Token);
            }
            using var connected = await listener.AcceptTcpClientAsync(limit.Token);
            var stream = connected.GetStream();
            _ = await UsbMuxProtocol.ReadAsync(stream, 2, limit.Token);
            byte[] reply = [.. UsbMuxProtocol.Packet(Result(0), 2), 0, 0, 0, 5, 21, 22];
            await stream.WriteAsync(reply, limit.Token);
        }, limit.Token);
        var connector = new UsbMuxConnector(token => UsbMuxConnector.ConnectSocket(listener.LocalEndpoint, token));
        var carrier = await connector.OpenAsync(Serial, UsbMuxConnector.ControlPort, limit.Token);
        await using var transport = new ProductControlStreamTransport(carrier, 64, 64);
        await Expect<EndOfStreamException>(() => transport.ReadAsync(limit.Token));
        await server;
    }

    private static async Task RejectConnection(uint code)
    {
        var streams = new Queue<ReplyStream>(new[] {
            new ReplyStream(UsbMuxProtocol.Packet(List(Row()), 1)), new ReplyStream(UsbMuxProtocol.Packet(Result(code), 2))
        });
        var owners = streams.ToArray();
        var connector = new UsbMuxConnector(_ => Task.FromResult<Stream>(streams.Dequeue()));
        var failure = await Expect<UsbMuxException>(() => connector.OpenAsync(Serial, 9527, CancellationToken.None));
        Require(failure.Failure == (code == 2 ? UsbMuxFailure.DeviceUnavailable :
            code == 3 ? UsbMuxFailure.PortUnavailable : UsbMuxFailure.ServiceRejected), "Incorrect result classification");
        Require(streams.Count == 0 && owners.All(s => s.Released), "Failed connect retained an owner or retried");
    }

    private static async Task CleanupFailure()
    {
        var connector = new UsbMuxConnector(_ => Task.FromResult<Stream>(new ReplyStream([1, 2], failClose: true)));
        var failure = await Expect<AggregateException>(() => connector.DevicesAsync(CancellationToken.None));
        Require(failure.InnerExceptions.Count == 2 && failure.InnerExceptions[0] is EndOfStreamException &&
            failure.InnerExceptions[1] is IOException, "Cleanup masked request failure");
    }

    private sealed class FragmentedStream(byte[] bytes) : MemoryStream(bytes)
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default) =>
            base.ReadAsync(buffer[..Math.Min(1, buffer.Length)], token);
    }
    private sealed class ReplyStream(byte[] bytes, bool failClose = false) : MemoryStream(bytes)
    {
        internal bool Released { get; private set; }
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken token = default)
        { token.ThrowIfCancellationRequested(); return ValueTask.CompletedTask; }
        public override ValueTask DisposeAsync()
        {
            Released = true; base.Dispose();
            return failClose ? ValueTask.FromException(new IOException("fixture cleanup failure")) : ValueTask.CompletedTask;
        }
    }
    private static Task Sync(Action action) { action(); return Task.CompletedTask; }
    private static void Require(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); }
    private static async Task<T> Expect<T>(Func<Task> operation) where T : Exception
    {
        try { await operation(); } catch (T failure) { return failure; }
        throw new InvalidOperationException($"Expected {typeof(T).Name}");
    }
}
