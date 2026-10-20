using System.Buffers.Binary;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.Connection;

internal static class ProductBootstrapExchangeTests
{
    internal static IEnumerable<(string, Func<Task>)> Cases =>
    [
        ("Bootstrap exchange releases its owned carrier before publishing a response", ReleaseBeforePublication),
        ("Bootstrap exchange preserves primary and release failures without publishing success", FailedRelease),
        ("USB scanner retains failed carrier owners and refuses new scans or successful disposal", RetainedScanner)
    ];

    private sealed class Carrier : Stream
    {
        private readonly MemoryStream _read;
        internal readonly IOException WriteFailure = new("fixture write failure"), CloseFailure = new("fixture close failure");
        internal bool FailWrite, FailClose, Readable = true;
        internal int Releases, Writes;
        internal Carrier()
        {
            byte[] wire = new byte[7];
            BinaryPrimitives.WriteInt32BigEndian(wire, 3);
            wire[4] = 7; wire[5] = 8; wire[6] = 9;
            _read = new(wire);
        }
        public override bool CanRead => Readable;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => _read.Read(buffer, offset, count);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default) => _read.ReadAsync(buffer, token);
        public override void Write(byte[] buffer, int offset, int count)
        { Writes++; if (FailWrite) throw WriteFailure; }
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken token = default)
        { token.ThrowIfCancellationRequested(); Writes++; return FailWrite ? ValueTask.FromException(WriteFailure) : ValueTask.CompletedTask; }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        protected override void Dispose(bool disposing)
        { Releases++; if (FailClose) throw CloseFailure; _read.Dispose(); base.Dispose(disposing); }
    }

    private static async Task ReleaseBeforePublication()
    {
        var carrier = new Carrier();
        var response = await ProductBootstrapExchange.ExchangeAsync(_ => Task.FromResult<Stream>(carrier), new byte[] { 1 }, 100, default);
        Require(response.Span.SequenceEqual(new byte[] { 7, 8, 9 }) && carrier.Releases == 1 && carrier.Writes > 0,
            "The reply preceded release or lost framing.");
        var invalid = new Carrier { Readable = false };
        await Reject<ArgumentException>(() => ProductBootstrapExchange.ExchangeAsync(_ => Task.FromResult<Stream>(invalid), new byte[] { 1 }, 100, default));
        Require(invalid.Releases == 1 && invalid.Writes == 0, "Failed transport construction leaked the unclaimed carrier.");
    }

    private static async Task FailedRelease()
    {
        foreach (bool failWrite in new[] { false, true })
        {
            var carrier = new Carrier { FailClose = true, FailWrite = failWrite };
            var failure = await Reject<ProductBootstrapReleaseException>(() =>
                ProductBootstrapExchange.ExchangeAsync(_ => Task.FromResult<Stream>(carrier), new byte[] { 1 }, 100, default));
            Require(Contains(failure, carrier.CloseFailure) && (!failWrite || Contains(failure, carrier.WriteFailure)),
                "Release failure discarded the primary operation failure.");
            Require(ProductBootstrapReleaseException.ContainsUnreleasedOwner(failure), "The unreleased owner was not identifiable.");
            await Reject<IOException>(() => failure.RetainedOwner.DisposeAsync().AsTask());
            Require(carrier.Releases == 1, "Repeated owner disposal silently retried an unconfirmed native release.");
        }
    }

    private static async Task RetainedScanner()
    {
        foreach (bool duringEnumeration in new[] { false, true })
        foreach (bool multiplexOwner in new[] { false, true })
        {
            int enumerations = 0, inspections = 0;
            var carrier = new Carrier { FailClose = true };
            Exception failure = multiplexOwner ? new UsbMuxReleaseException(carrier, carrier.CloseFailure)
                : new ProductBootstrapReleaseException(carrier, carrier.CloseFailure);
            var scanner = new UsbPeerScanner(_ =>
            {
                enumerations++;
                return duringEnumeration ? Task.FromException<IReadOnlyList<UsbMuxDevice>>(failure)
                    : Task.FromResult<IReadOnlyList<UsbMuxDevice>>([new(1, "00008132-1111111111111111", 4779)]);
            }, (_, _) => { inspections++; return Task.FromException<UsbPeerInspection>(failure); }, null);
            var report = await scanner.ScanAsync();
            Require(duringEnumeration ? ReferenceEquals(report.Failure, failure)
                : report.Entries.Single().Failure == failure && report.Entries[0].Inspection is null,
                "Unreleased discovery became a peer or empty successful bus.");
            await Reject<InvalidOperationException>(() => scanner.ScanAsync());
            var close = await Reject<InvalidOperationException>(() => scanner.DisposeAsync().AsTask());
            var again = await Reject<InvalidOperationException>(() => scanner.DisposeAsync().AsTask());
            Require(Contains(close, failure) && Contains(again, failure) && enumerations == 1 && inspections == (duringEnumeration ? 0 : 1),
                "Scanner lost the retained failure or admitted additional native work.");
        }
    }

    private static bool Contains(Exception value, Exception expected) => ReferenceEquals(value, expected) ||
        value is AggregateException aggregate && aggregate.InnerExceptions.Any(e => Contains(e, expected)) ||
        value.InnerException is { } inner && Contains(inner, expected);
    private static void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
    private static async Task<T> Reject<T>(Func<Task> operation) where T : Exception
    {
        try { await operation(); } catch (T error) { return error; }
        throw new InvalidOperationException($"Expected {typeof(T).Name}.");
    }
}
