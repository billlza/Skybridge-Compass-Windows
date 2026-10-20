using System.Runtime.ExceptionServices;

namespace Skybridge.WinClient.Services.Connection;

internal sealed class ProductBootstrapReleaseException(IAsyncDisposable retainedOwner, Exception failure)
    : IOException("Bootstrap carrier release was not confirmed.", failure)
{
    internal IAsyncDisposable RetainedOwner { get; } = retainedOwner;
    internal static bool ContainsUnreleasedOwner(Exception error) =>
        error is ProductBootstrapReleaseException or UsbMuxReleaseException or LanResponderCryptoReleaseException ||
        error is AggregateException aggregate && aggregate.InnerExceptions.Any(ContainsUnreleasedOwner) ||
        error.InnerException is { } inner && ContainsUnreleasedOwner(inner);
}

/// <summary>One request/reply on an owned carrier. The caller supplies the bounded
/// stage lifetime and validates the reply; release completes before publication.</summary>
internal static class ProductBootstrapExchange
{
    internal static async Task<ReadOnlyMemory<byte>> ExchangeAsync(
        Func<CancellationToken, Task<Stream>> open, ReadOnlyMemory<byte> request,
        int maximumFrameBytes, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(open);
        if (maximumFrameBytes is <= 0 or > LanBootstrapWire.MaximumBytes ||
            request.IsEmpty || request.Length > maximumFrameBytes)
            throw new ArgumentOutOfRangeException(nameof(maximumFrameBytes));
        token.ThrowIfCancellationRequested();
        Stream? unclaimed = null;
        ProductControlStreamTransport? owner = null;
        ReadOnlyMemory<byte>? response = null;
        Exception? failure = null;
        try
        {
            unclaimed = await open(token).ConfigureAwait(false);
            ArgumentNullException.ThrowIfNull(unclaimed);
            owner = new(unclaimed, maximumFrameBytes, maximumFrameBytes);
            unclaimed = null;
            await owner.SendAsync(request, token).ConfigureAwait(false);
            response = await owner.ReadAsync(token).ConfigureAwait(false);
        }
        catch (Exception error) { failure = error; }
        try
        {
            if (owner is not null) await owner.DisposeAsync().ConfigureAwait(false);
            else if (unclaimed is not null) await unclaimed.DisposeAsync().ConfigureAwait(false);
        }
        catch (Exception cleanup)
        {
            IAsyncDisposable retained = (IAsyncDisposable?)owner ?? unclaimed
                ?? throw new InvalidOperationException("Bootstrap cleanup lost its resource owner.", cleanup);
            throw new ProductBootstrapReleaseException(retained,
                failure is null ? cleanup : new AggregateException(failure, cleanup));
        }
        if (failure is not null) ExceptionDispatchInfo.Capture(failure).Throw();
        token.ThrowIfCancellationRequested();
        return response ?? throw new InvalidOperationException("Bootstrap exchange ended without a response.");
    }
}
