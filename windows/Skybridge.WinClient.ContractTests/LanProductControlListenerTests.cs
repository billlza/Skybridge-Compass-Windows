using System.Net;
using System.Net.Sockets;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.RemoteControl;

internal static class LanProductControlListenerTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("MAIN listener caps actual sockets and stop waits for real peer cleanup", CapacityAndDrain),
        ("MAIN listener isolates a rejected peer and admits a later connection", RejectedPeer),
        ("MAIN listener closes sockets on captured account revocation", AccountRevocation),
        ("MAIN listener caller cancellation closes its actual bound endpoint", CallerCancellation),
        ("MAIN listener rejects wildcard multicast and expired authority before binding", InvalidStart),
        ("MAIN listener retains uncertain peer ownership and stops accepting", UnreleasedPeer),
        ("MAIN listener preserves cancellation cleanup failure after draining", CancellationFailure),
        ("MAIN withdrawal begins during peer drain and stop waits for both owners", PublicationDuringDrain),
        ("MAIN publication reuses the native advertisement lifecycle with a distinct service", MainAdvertisement)
    ];
    private static void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
    private static async Task Eventually(Func<bool> condition)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (!condition()) await Task.Delay(10, deadline.Token);
    }
    private static async Task<T> Throws<T>(Func<Task> action) where T : Exception
    {
        try { await action(); } catch (T error) { return error; }
        throw new InvalidOperationException($"Expected {typeof(T).Name}.");
    }
    private static async Task<TcpClient> Connect(LanProductControlListener listener)
    {
        var endpoint = listener.ReadSnapshot().Endpoint ?? throw new InvalidOperationException("No bound endpoint.");
        var client = new TcpClient();
        try { await client.ConnectAsync(endpoint).WaitAsync(TimeSpan.FromSeconds(3)); return client; }
        catch { client.Dispose(); throw; }
    }
    private static async Task RequireClosed(TcpClient client)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        try { Require(await client.GetStream().ReadAsync(new byte[1], deadline.Token) == 0, "Closed peer produced bytes."); }
        catch (IOException) { /* A TCP reset is also a terminal socket. A timeout is not. */ }
    }
    private static async Task CapacityAndDrain()
    {
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int started = 0, finished = 0;
        await using var listener = new LanProductControlListener(async (_, token) =>
        {
            Interlocked.Increment(ref started);
            await release.Task; // Deliberately non-cooperative cleanup must remain owned.
            Require(token.IsCancellationRequested, "Peer released before stop reached its lifetime.");
            Interlocked.Increment(ref finished);
        }, () => true);
        listener.Start(IPAddress.Loopback, CancellationToken.None);
        var clients = new List<TcpClient>();
        try
        {
            for (int i = 0; i < 8; i++) clients.Add(await Connect(listener));
            await Eventually(() => Volatile.Read(ref started) == 8);
            using var rejected = await Connect(listener); await RequireClosed(rejected);
            Require(listener.ReadSnapshot().ActiveConnections == 8 && listener.ReadSnapshot().RejectedConnections == 1,
                "Listener exceeded its active owner bound.");
            var stop = listener.StopAsync();
            await Eventually(() => listener.ReadSnapshot().Endpoint is null);
            Require(!stop.IsCompleted, "Stop abandoned live callbacks after requesting cancellation.");
            release.SetResult(); await stop.WaitAsync(TimeSpan.FromSeconds(5));
            Require(finished == 8 && listener.ReadSnapshot().ActiveConnections == 0, "Stop did not drain every actual peer.");
        }
        finally { release.TrySetResult(); foreach (var client in clients) client.Dispose(); }
    }
    private static async Task RejectedPeer()
    {
        int attempts = 0;
        var second = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var listener = new LanProductControlListener(async (client, token) =>
        {
            if (Interlocked.Increment(ref attempts) == 1) throw new InvalidDataException("fixture invalid signature");
            await using var transport = new ProductControlStreamTransport(client, 64, 64);
            var bytes = await transport.ReadAsync(token); await transport.SendAsync(bytes, token); second.SetResult();
        }, () => true);
        listener.Start(IPAddress.Loopback, CancellationToken.None);
        using var bad = await Connect(listener); await RequireClosed(bad);
        await Eventually(() => listener.ReadSnapshot().ActiveConnections == 0);
        Require(listener.ReadSnapshot().Failure is InvalidDataException && !listener.ReadSnapshot().ReleaseUnconfirmed,
            "Ordinary rejection was hidden or treated as unknown cleanup.");
        using var good = await Connect(listener);
        await using var wire = new ProductControlStreamTransport(good, 64, 64);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        await wire.SendAsync(new byte[] { 1, 2, 3 }, deadline.Token);
        Require((await wire.ReadAsync(deadline.Token)).Span.SequenceEqual(new byte[] { 1, 2, 3 }), "Later peer lost framing or ordering.");
        await second.Task; await listener.StopAsync();
    }
    private static async Task AccountRevocation()
    {
        int current = 1;
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var listener = new LanProductControlListener(async (_, token) =>
        { entered.SetResult(); await Task.Delay(Timeout.Infinite, token); }, () => Volatile.Read(ref current) == 1);
        listener.Start(IPAddress.Loopback, CancellationToken.None);
        using var peer = await Connect(listener); await entered.Task.WaitAsync(TimeSpan.FromSeconds(3));
        Interlocked.Exchange(ref current, 0);
        await listener.NetworkEnded.WaitAsync(TimeSpan.FromSeconds(3)); await listener.StopAsync();
        await RequireClosed(peer);
        Require(listener.ReadSnapshot().Endpoint is null && listener.ReadSnapshot().ActiveConnections == 0,
            "Revoked account retained listener or peer ownership.");
    }
    private static async Task CallerCancellation()
    {
        using var cancellation = new CancellationTokenSource();
        await using var listener = new LanProductControlListener((_, token) => Task.Delay(Timeout.Infinite, token), () => true);
        listener.Start(IPAddress.Loopback, cancellation.Token); using var peer = await Connect(listener);
        await Eventually(() => listener.ReadSnapshot().ActiveConnections == 1);
        cancellation.Cancel(); await listener.StopAsync(); await RequireClosed(peer);
        Require(listener.ReadSnapshot().Endpoint is null, "Canceled bound endpoint remained published.");
    }
    private static async Task InvalidStart()
    {
        foreach (var address in new[] { IPAddress.Any, IPAddress.Broadcast, IPAddress.Parse("224.0.0.1") })
        {
            await using var listener = new LanProductControlListener((_, _) => throw new InvalidOperationException("Unexpected peer."), () => true);
            await Throws<InvalidDataException>(() => { listener.Start(address, CancellationToken.None); return Task.CompletedTask; });
            Require(listener.ReadSnapshot().Endpoint is null, "Invalid address bound a listener.");
        }
        await using var revoked = new LanProductControlListener((_, _) => Task.CompletedTask, () => false);
        await Throws<InvalidOperationException>(() => { revoked.Start(IPAddress.Loopback, CancellationToken.None); return Task.CompletedTask; });
        Require(revoked.ReadSnapshot().Endpoint is null, "Expired authority bound a listener.");
    }
    private static async Task UnreleasedPeer()
    {
        var owner = new object();
        var error = new LanIncomingPeerCleanupException(owner, new IOException("fixture unreleased output"));
        var listener = new LanProductControlListener((_, _) => Task.FromException(error), () => true);
        listener.Start(IPAddress.Loopback, CancellationToken.None);
        using var peer = await Connect(listener);
        await listener.NetworkEnded.WaitAsync(TimeSpan.FromSeconds(3));
        var failed = await Throws<AggregateException>(listener.StopAsync);
        Require(failed.InnerExceptions.Contains(error) && ReferenceEquals(error.RetainedOwner, owner) &&
            listener.ReadSnapshot() is { ReleaseUnconfirmed: true, ActiveConnections: 1, Endpoint: null },
            "Failed cleanup disappeared or new peers remained enabled.");
        await Throws<AggregateException>(() => listener.DisposeAsync().AsTask());
        await RequireClosed(peer);
    }
    private static async Task CancellationFailure()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var listener = new LanProductControlListener(async (_, token) =>
        {
            using var registration = token.Register(() => throw new IOException("fixture cancellation callback"));
            entered.SetResult(); await Task.Delay(Timeout.Infinite, token);
        }, () => true);
        listener.Start(IPAddress.Loopback, CancellationToken.None); using var peer = await Connect(listener);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(3));
        var error = await Throws<AggregateException>(listener.StopAsync);
        Require(error.Flatten().InnerExceptions.Any(e => e.Message == "fixture cancellation callback") &&
            listener.ReadSnapshot().ActiveConnections == 0, "Cancellation failure was hidden or actual peer not drained.");
        await listener.StopAsync(); await RequireClosed(peer);
    }
    private sealed class Backend : IWindowsDnsSdAdvertisementBackend
    {
        internal WindowsRemoteControlAdvertisementOptions? Options;
        internal int Removed;
        public bool IsRegistered { get; private set; }
        public Task RegisterAsync(WindowsRemoteControlAdvertisementOptions options)
        { Options = options; IsRegistered = true; return Task.CompletedTask; }
        public Task DeregisterAsync() { if (IsRegistered) Removed++; IsRegistered = false; return Task.CompletedTask; }
    }
    private static async Task PublicationDuringDrain()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var peerRelease = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var withdrawing = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var publicationRelease = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var listener = new LanProductControlListener(async (_, _) => { entered.SetResult(); await peerRelease.Task; }, () => true);
        listener.Start(IPAddress.Loopback, CancellationToken.None); using var peer = await Connect(listener);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(3));
        var stop = listener.StopWithPublicationAsync(async () => { withdrawing.SetResult(); await publicationRelease.Task; });
        try
        {
            await withdrawing.Task.WaitAsync(TimeSpan.FromSeconds(2));
            Require(!stop.IsCompleted && !peerRelease.Task.IsCompleted && listener.ReadSnapshot().Endpoint is null,
                "Withdrawal waited behind native peer drain or listener acceptance remained active.");
            peerRelease.SetResult(); await Eventually(() => listener.ReadSnapshot().ActiveConnections == 0);
            Require(!stop.IsCompleted, "Stop abandoned the actual publication removal.");
            publicationRelease.SetResult(); await stop.WaitAsync(TimeSpan.FromSeconds(3));
        }
        finally { peerRelease.TrySetResult(); publicationRelease.TrySetResult(); await stop; }
    }
    private static async Task MainAdvertisement()
    {
        using var socket = new TcpListener(IPAddress.Any, 0); socket.Start();
        var properties = new Dictionary<string, string> { ["version"] = "2", ["deviceId"] = "id:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            ["platform"] = "windows", ["pubKeyFP"] = new string('a', 64) };
        var options = new WindowsRemoteControlAdvertisementOptions("Fixture", "fixture.local", IPAddress.Parse("192.0.2.10"),
            ((IPEndPoint)socket.LocalEndpoint).Port, 1, properties, WindowsProductAdvertisementService.MainControl);
        var backend = new Backend(); await using var advertisement = new WindowsRemoteControlAdvertisement(backend);
        await advertisement.StartAsync(socket, options);
        Require(advertisement.IsRegistered && backend.Options?.ServiceName == "Fixture._skybridge._tcp.local",
            "MAIN was advertised as remote desktop or bypassed the existing publisher.");
        await advertisement.StopAsync(); Require(backend.Removed == 1 && !advertisement.IsRegistered, "MAIN publication outlived stop.");
    }
}
