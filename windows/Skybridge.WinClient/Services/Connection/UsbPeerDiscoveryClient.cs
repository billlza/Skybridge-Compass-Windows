using System.Collections.Immutable;

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
        try
        {
            var request = UsbPeerDiscoveryWire.Request(_time.GetUtcNow());
            var bytes = await ProductBootstrapExchange.ExchangeAsync(
                current => _connector.OpenAsync(udid, UsbMuxConnector.ControlPort, current),
                UsbPeerDiscoveryWire.Encode(request), UsbPeerDiscoveryWire.MaximumFrameBytes, deadline.Token).ConfigureAwait(false);
            var inspection = UsbPeerInspection.Verify(udid, UsbPeerDiscoveryWire.Decode(bytes.Span), request,
                _time.GetUtcNow(), _verify);
            deadline.Token.ThrowIfCancellationRequested();
            return inspection;
        }
        catch (OperationCanceledException error) when (!token.IsCancellationRequested && deadline.IsCancellationRequested)
        { throw new TimeoutException("USB peer discovery exceeded its deadline.", error); }
    }
}
