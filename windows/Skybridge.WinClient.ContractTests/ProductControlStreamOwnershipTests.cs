using System.Net;
using System.Net.Sockets;
using Skybridge.WinClient.Services;

internal static class ProductControlStreamOwnershipTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("Stream owner drains an active read and releases exactly once", DrainReader),
        ("Partial stream write cancellation retires the exact carrier", () => InterruptedWrite(false)),
        ("Partial stream write deadline retains its cause", () => InterruptedWrite(true)),
        ("Stream release failure is retained after read drain and repeated disposal", ReleaseFailure),
        ("Throwing cancellation callback cannot skip carrier release", CancellationCallbackFailure),
        ("Concurrent disposal waits for the same carrier release", ConcurrentRelease),
        ("Invalid stream construction leaves ownership with the caller", InvalidConstruction)
    ];

    private static async Task DrainReader()
    {
        await using var fixture = await Fixture.Connect();
        var read = fixture.Transport.ReadAsync(fixture.Token);
        await fixture.Carrier.ReadEntered.Task.WaitAsync(fixture.Token);
        await fixture.Transport.DisposeAsync();
        await Interrupted(read);
        await fixture.Transport.DisposeAsync();
        Require(fixture.Carrier.Disposals == 1 && fixture.Carrier.ActiveReads == 0, "Owner released twice or read not drained.");
        Require(await fixture.Peer.GetStream().ReadAsync(new byte[1], fixture.Token) == 0, "Native socket remains open.");
    }

    private static async Task InterruptedWrite(bool deadline)
    {
        await using var fixture = await Fixture.Connect(deadline ? TimeSpan.FromMilliseconds(100) : null);
        fixture.Carrier.StallBody = true;
        var read = fixture.Transport.ReadAsync(fixture.Token);
        await fixture.Carrier.ReadEntered.Task.WaitAsync(fixture.Token);
        using var cancellation = new CancellationTokenSource();
        var sending = fixture.Transport.SendAsync(new byte[] { 11, 12 }, cancellation.Token);
        await fixture.Carrier.BodyEntered.Task.WaitAsync(fixture.Token);
        if (deadline)
        {
            var failure = await Throws<TimeoutException>(() => sending);
            Require(failure.Message.Contains("frame body", StringComparison.Ordinal), "Deadline lost its actual write phase.");
        }
        else
        {
            cancellation.Cancel();
            await Throws<OperationCanceledException>(() => sending);
        }
        var readFailure = await Interrupted(read);
        Require(readFailure is AggregateException, "Reader lost the write failure that retired this carrier.");
        await Throws<IOException>(() => fixture.Transport.SendAsync(new byte[] { 99 }, fixture.Token));
        await fixture.Transport.DisposeAsync();
        var header = new byte[4]; await fixture.Peer.GetStream().ReadExactlyAsync(header, fixture.Token);
        Require(header.SequenceEqual(new byte[] { 0, 0, 0, 2 }) &&
            await fixture.Peer.GetStream().ReadAsync(new byte[1], fixture.Token) == 0,
            "Interrupted body was retried or a later frame reused the broken boundary.");
        Require(fixture.Carrier.Disposals == 1 && fixture.Carrier.ActiveReads == 0, "Interrupted writer leaked its carrier.");
    }

    private static async Task ReleaseFailure()
    {
        await using var fixture = await Fixture.Connect();
        var original = new IOException("Injected carrier release failure.");
        fixture.Carrier.DisposeFailure = original;
        var read = fixture.Transport.ReadAsync(fixture.Token);
        await fixture.Carrier.ReadEntered.Task.WaitAsync(fixture.Token);
        // Close must allow the containing session to join its other workers.
        fixture.Transport.Close();
        await Interrupted(read);
        var first = await Throws<IOException>(() => fixture.Transport.DisposeAsync().AsTask());
        var repeated = await Throws<IOException>(() => fixture.Transport.DisposeAsync().AsTask());
        Require(ReferenceEquals(first, original) && ReferenceEquals(repeated, original) &&
            fixture.Carrier.Disposals == 1 && fixture.Carrier.ActiveReads == 0, "Release failure was hidden, retried, or prevented drain.");
        fixture.ExpectedCleanupFailure = original;
    }

    private static async Task CancellationCallbackFailure()
    {
        await using var fixture = await Fixture.Connect();
        var original = new InvalidOperationException("Injected cancellation callback failure.");
        fixture.Carrier.CancelFailure = original;
        var read = fixture.Transport.ReadAsync(fixture.Token);
        await fixture.Carrier.ReadEntered.Task.WaitAsync(fixture.Token);
        var observed = await Throws<AggregateException>(() => fixture.Transport.DisposeAsync().AsTask());
        await Interrupted(read);
        Require(observed.Flatten().InnerExceptions.Contains(original) && fixture.Carrier.Disposals == 1 &&
            fixture.Carrier.ActiveReads == 0, "Cancellation failure prevented stream release or lost its cause.");
        fixture.ExpectedCleanupFailure = observed;
    }

    private static async Task ConcurrentRelease()
    {
        await using var fixture = await Fixture.Connect();
        fixture.Carrier.HoldDisposal = true;
        var first = Task.Run(async () => await fixture.Transport.DisposeAsync());
        await fixture.Carrier.DisposeEntered.Task.WaitAsync(fixture.Token);
        var second = fixture.Transport.DisposeAsync().AsTask();
        try { Require(!second.IsCompleted, "A second disposer returned before actual carrier release."); }
        finally { fixture.Carrier.ReleaseDisposal.Set(); }
        await Task.WhenAll(first, second).WaitAsync(fixture.Token);
        Require(fixture.Carrier.Disposals == 1, "Concurrent disposal released more than once.");
    }

    private static Task InvalidConstruction()
    {
        using var readonlyStream = new MemoryStream([1, 2], writable: false);
        try { _ = new ProductControlStreamTransport(readonlyStream, 64, 64); throw new Exception("Read-only stream was accepted."); }
        catch (ArgumentException) { }
        Require(readonlyStream.CanRead, "Constructor took ownership before successful validation.");
        using var duplex = new MemoryStream();
        try { _ = new ProductControlStreamTransport(duplex, 0, 64); throw new Exception("Invalid bound was accepted."); }
        catch (ArgumentOutOfRangeException) { }
        Require(duplex.CanRead && duplex.CanWrite, "Invalid limit disposed the caller's stream.");
        return Task.CompletedTask;
    }

    private sealed class Fixture : IAsyncDisposable
    {
        private readonly CancellationTokenSource _deadline = new(TimeSpan.FromSeconds(4));
        internal CancellationToken Token => _deadline.Token;
        internal ObservedStream Carrier { get; }
        internal TcpClient Peer { get; }
        internal ProductControlStreamTransport Transport { get; }
        internal Exception? ExpectedCleanupFailure { get; set; }
        private Fixture(Stream owned, TcpClient peer, TimeSpan? timeout)
        { Carrier = new(owned); Peer = peer; Transport = new(Carrier, 64, 64, timeout); }
        internal static async Task<Fixture> Connect(TimeSpan? timeout = null)
        {
            using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                await socket.ConnectAsync(listener.LocalEndpoint);
                return new(new NetworkStream(socket, ownsSocket: true), await listener.AcceptTcpClientAsync(), timeout);
            }
            catch { socket.Dispose(); throw; }
        }
        public async ValueTask DisposeAsync()
        {
            Carrier.ReleaseDisposal.Set();
            try { await Transport.DisposeAsync(); }
            catch (Exception error) when (ReferenceEquals(error, ExpectedCleanupFailure)) { /* Expected and asserted by the test. */ }
            finally { Peer.Dispose(); Carrier.ReleaseDisposal.Dispose(); _deadline.Dispose(); }
        }
    }

    // Fault injection wraps a real connected stream; it never replaces framing,
    // socket EOF, the product writer gate, cancellation or disposal ownership.
    internal sealed class ObservedStream(Stream inner, IDisposable? owner = null) : Stream
    {
        internal TaskCompletionSource ReadEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource BodyEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource DisposeEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal ManualResetEventSlim ReleaseDisposal { get; } = new();
        internal bool StallBody { get; set; }
        internal bool HoldDisposal { get; set; }
        internal Exception? DisposeFailure { get; set; }
        internal Exception? CancelFailure { get; set; }
        internal int Disposals, ActiveReads;
        private int _writes;
        public override bool CanRead => inner.CanRead;
        public override bool CanWrite => inner.CanWrite;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default)
        {
            Interlocked.Increment(ref ActiveReads);
            using var registration = token.Register(() => { if (CancelFailure is { } error) throw error; });
            try
            {
                var pending = inner.ReadAsync(buffer, token);
                ReadEntered.TrySetResult();
                return await pending;
            }
            finally { Interlocked.Decrement(ref ActiveReads); }
        }
        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken token = default)
        {
            if (Interlocked.Increment(ref _writes) == 2 && StallBody)
            {
                BodyEntered.TrySetResult();
                await Task.Delay(Timeout.InfiniteTimeSpan, token);
                throw new InvalidOperationException("Canceled write unexpectedly resumed.");
            }
            await inner.WriteAsync(buffer, token);
        }
        protected override void Dispose(bool disposing)
        {
            if (!disposing) return;
            Interlocked.Increment(ref Disposals);
            if (owner is null) inner.Dispose(); else owner.Dispose();
            DisposeEntered.TrySetResult();
            if (HoldDisposal && !ReleaseDisposal.Wait(TimeSpan.FromSeconds(3)))
                throw new TimeoutException("Test did not release disposal barrier.");
            if (DisposeFailure is { } error) throw error;
            base.Dispose(disposing);
        }
        public override void Flush() => inner.Flush();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }

    private static async Task<Exception> Interrupted(Task task)
    {
        try { await task; }
        catch (Exception error) when (error is OperationCanceledException or IOException or ObjectDisposedException or AggregateException)
        { return error; }
        throw new InvalidOperationException("Active read completed successfully after retirement.");
    }
    private static async Task<T> Throws<T>(Func<Task> operation) where T : Exception
    { try { await operation(); } catch (T error) { return error; } throw new InvalidOperationException($"Expected {typeof(T).Name}."); }
    private static void Require(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); }
}
