using System.Collections.Immutable;
using System.Runtime.ExceptionServices;

namespace Skybridge.WinClient.Services.Connection;

internal sealed class UsbPeerDiscoveryClient
{
    private readonly UsbMuxConnector _connector;
    private readonly TimeProvider _time;
    private readonly Action<UsbPeerIdentity, byte[], ImmutableArray<byte>> _verify;
    private readonly TimeSpan _timeout;

    internal UsbPeerDiscoveryClient(UsbMuxConnector connector, TimeProvider? time = null,
        Action<UsbPeerIdentity, byte[], ImmutableArray<byte>>? verify = null, TimeSpan? timeout = null)
    {
        ArgumentNullException.ThrowIfNull(connector);
        _connector = connector;
        _time = time ?? TimeProvider.System;
        _verify = verify ?? UsbPeerDiscoveryWire.VerifyNativeSignature;
        _timeout = timeout ?? TimeSpan.FromSeconds(8);
        if (_timeout <= TimeSpan.Zero || _timeout > TimeSpan.FromSeconds(8))
            throw new ArgumentOutOfRangeException(nameof(timeout));
    }

    internal async Task<UsbPeerInspection> InspectAsync(string udid, CancellationToken token)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(_timeout); // Enumeration, dial, one request, one response and verification.
        ProductControlStreamTransport? transport = null;
        Stream? unclaimed = null;
        UsbPeerInspection? inspection = null;
        Exception? failure = null;
        try
        {
            unclaimed = await _connector.OpenAsync(udid, UsbMuxConnector.ControlPort, deadline.Token).ConfigureAwait(false);
            transport = new(unclaimed, UsbPeerDiscoveryWire.MaximumFrameBytes, UsbPeerDiscoveryWire.MaximumFrameBytes);
            unclaimed = null;
            var request = UsbPeerDiscoveryWire.Request(_time.GetUtcNow());
            await transport.SendAsync(UsbPeerDiscoveryWire.Encode(request), deadline.Token).ConfigureAwait(false);
            var bytes = await transport.ReadAsync(deadline.Token).ConfigureAwait(false);
            inspection = UsbPeerInspection.Verify(udid, UsbPeerDiscoveryWire.Decode(bytes.Span), request,
                _time.GetUtcNow(), _verify);
            deadline.Token.ThrowIfCancellationRequested();
        }
        catch (OperationCanceledException error) when (!token.IsCancellationRequested && deadline.IsCancellationRequested)
        { failure = new TimeoutException("USB peer discovery exceeded its deadline.", error); }
        catch (Exception error) { failure = error; }
        try
        {
            if (transport is not null) await transport.DisposeAsync().ConfigureAwait(false);
            else if (unclaimed is not null) await unclaimed.DisposeAsync().ConfigureAwait(false);
        }
        catch (Exception cleanup)
        {
            Exception[] errors = failure is null ? [cleanup] : [failure, cleanup];
            throw new AggregateException("USB discovery and carrier release did not complete successfully.",
                errors);
        }
        if (failure is not null) ExceptionDispatchInfo.Capture(failure).Throw();
        if (deadline.IsCancellationRequested && !token.IsCancellationRequested)
            throw new TimeoutException("USB peer discovery expired before publication.");
        token.ThrowIfCancellationRequested();
        return inspection ?? throw new InvalidOperationException("USB discovery completed without a verified response.");
    }
}
