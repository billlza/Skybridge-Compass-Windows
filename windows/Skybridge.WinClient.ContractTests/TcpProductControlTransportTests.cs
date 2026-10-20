using System.Net;
using System.Net.Sockets;
using Skybridge.WinClient.Services;

internal static class TcpProductControlTransportTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("TCP frame admission runs after writer acquisition and refusal writes no prefix", QueuedAdmission),
        ("TCP cancellation while queued never invokes frame admission", QueuedCancellation),
        ("TCP policy cancellation is not misreported as a transport deadline", PolicyCancellation),
        ("TCP callback cancellation retains its cause when the writer deadline also expires", PolicyCancellationAtDeadline),
        ("TCP admitted frames still enforce nonempty and maximum lengths", PreparedFrameBounds),
        .. ProductControlStreamOwnershipTests.Cases
    ];

    private static async Task QueuedAdmission()
    {
        await using var fixture = await Fixture.Connect();
        await using var held = new HeldWriter(fixture.Transport, fixture.Token, [11]);
        await held.Entered.WaitAsync(fixture.Token);
        var allowed = true; var calls = 0;
        var queued = fixture.Transport.SendAdmittedAsync(() =>
        {
            calls++;
            if (!allowed) throw new UnauthorizedAccessException("Fixture permission revoked while queued.");
            return new byte[] { 99 };
        }, fixture.Token);
        Require(!queued.IsCompleted && calls == 0, "Admission ran before acquiring the shared writer.");
        allowed = false; held.Release(); await held.Completion;
        await Throws<UnauthorizedAccessException>(() => queued);
        Require(calls == 1, "Admission was skipped or retried.");
        await fixture.Transport.SendAsync(new byte[] { 22 }, fixture.Token);
        Require((await fixture.Remote.ReadAsync(fixture.Token)).Span.SequenceEqual(new byte[] { 11 }) &&
            (await fixture.Remote.ReadAsync(fixture.Token)).Span.SequenceEqual(new byte[] { 22 }),
            "Refused admission wrote bytes or damaged the following frame.");
    }

    private static async Task QueuedCancellation()
    {
        await using var fixture = await Fixture.Connect();
        await using var held = new HeldWriter(fixture.Transport, fixture.Token, [31]);
        await held.Entered.WaitAsync(fixture.Token);
        using var canceled = new CancellationTokenSource(); var calls = 0;
        var queued = fixture.Transport.SendAdmittedAsync(() => { calls++; return new byte[] { 99 }; }, canceled.Token);
        canceled.Cancel(); await Throws<OperationCanceledException>(() => queued);
        Require(calls == 0, "Canceled queued operation reached its effect callback.");
        held.Release(); await held.Completion;
        await fixture.Transport.SendAsync(new byte[] { 32 }, fixture.Token);
        Require((await fixture.Remote.ReadAsync(fixture.Token)).Span.SequenceEqual(new byte[] { 31 }) &&
            (await fixture.Remote.ReadAsync(fixture.Token)).Span.SequenceEqual(new byte[] { 32 }), "Queued cancellation damaged framing.");
    }

    private static async Task PolicyCancellation()
    {
        await using var fixture = await Fixture.Connect();
        var original = new OperationCanceledException("Fixture policy authority is no longer current.");
        var observed = await Throws<OperationCanceledException>(() => fixture.Transport.SendAdmittedAsync(() => throw original, fixture.Token));
        Require(ReferenceEquals(observed, original), "Policy cancellation was replaced with another cause.");
        await fixture.Transport.SendAsync(new byte[] { 41 }, fixture.Token);
        Require((await fixture.Remote.ReadAsync(fixture.Token)).Span.SequenceEqual(new byte[] { 41 }), "Policy cancellation touched the wire.");
    }

    private static async Task PreparedFrameBounds()
    {
        await using var fixture = await Fixture.Connect();
        foreach (var bytes in new[] { Array.Empty<byte>(), new byte[65] })
            await Throws<InvalidDataException>(() => fixture.Transport.SendAdmittedAsync(() => bytes, fixture.Token));
        var maximum = Enumerable.Range(1, 64).Select(value => (byte)value).ToArray();
        await fixture.Transport.SendAdmittedAsync(() => maximum, fixture.Token);
        Require((await fixture.Remote.ReadAsync(fixture.Token)).Span.SequenceEqual(maximum), "Invalid prepared length leaked a prefix or exact maximum failed.");
    }

    private static async Task PolicyCancellationAtDeadline()
    {
        await using var fixture = await Fixture.Connect(TimeSpan.FromMilliseconds(30));
        var original = new OperationCanceledException("Fixture permission revoked during admission.");
        var observed = await Throws<OperationCanceledException>(() => fixture.Transport.SendAdmittedAsync(() =>
        {
            // Force the competing timer into the callback interval. Production callbacks must not block.
            Thread.Sleep(150);
            throw original;
        }, fixture.Token));
        Require(ReferenceEquals(observed, original), "Coincident deadline hid the callback's own cancellation cause.");
        await fixture.Transport.SendAsync(new byte[] { 51 }, fixture.Token);
        Require((await fixture.Remote.ReadAsync(fixture.Token)).Span.SequenceEqual(new byte[] { 51 }), "Callback refusal damaged the next frame.");
        await Throws<TimeoutException>(() => fixture.Transport.SendAdmittedAsync(() =>
        {
            Thread.Sleep(150);
            return new byte[] { 99 };
        }, fixture.Token));
        await fixture.Transport.SendAsync(new byte[] { 52 }, fixture.Token);
        Require((await fixture.Remote.ReadAsync(fixture.Token)).Span.SequenceEqual(new byte[] { 52 }),
            "A callback that returned after the deadline still wrote its frame.");
    }

    // Holds the real shared writer before its first byte, allowing deterministic queue ordering.
    internal sealed class HeldWriter : IAsyncDisposable
    {
        private readonly ManualResetEventSlim _release = new();
        private readonly TaskCompletionSource _entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal Task Entered => _entered.Task;
        internal Task Completion { get; }
        internal HeldWriter(ProductControlStreamTransport transport, CancellationToken token, byte[] frame)
        {
            Completion = Task.Run(() => transport.SendAdmittedAsync(() =>
            {
                _entered.TrySetResult();
                if (!_release.Wait(TimeSpan.FromSeconds(3), token))
                    throw new TimeoutException("The test did not release its writer barrier within 3 seconds.");
                return frame;
            }, token), token);
        }
        internal void Release() => _release.Set();
        public async ValueTask DisposeAsync()
        {
            Release();
            try { await Completion.WaitAsync(TimeSpan.FromSeconds(5)); }
            finally { _release.Dispose(); }
        }
    }

    private sealed class Fixture : IAsyncDisposable
    {
        private readonly CancellationTokenSource _deadline = new(TimeSpan.FromSeconds(10));
        internal CancellationToken Token => _deadline.Token;
        internal ProductControlStreamTransport Transport { get; }
        internal ProductControlStreamTransport Remote { get; }
        private Fixture(TcpClient local, TcpClient remote, TimeSpan? timeout)
        { Transport = new(local, 64, 64, timeout); Remote = new(remote, 64, 64); }
        internal static async Task<Fixture> Connect(TimeSpan? timeout = null)
        {
            using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
            var local = new TcpClient(); await local.ConnectAsync((IPEndPoint)listener.LocalEndpoint);
            return new(local, await listener.AcceptTcpClientAsync(), timeout);
        }
        public async ValueTask DisposeAsync()
        { await Transport.DisposeAsync(); await Remote.DisposeAsync(); _deadline.Dispose(); }
    }
    private static async Task<T> Throws<T>(Func<Task> action) where T : Exception
    { try { await action(); } catch (T error) { return error; } throw new Exception($"Expected {typeof(T).Name}."); }
    private static void Require(bool condition, string reason) { if (!condition) throw new Exception(reason); }
}
