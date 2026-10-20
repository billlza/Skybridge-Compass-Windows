using System.Runtime.ExceptionServices;
using Skybridge.WinClient.Services.Connection;

namespace Skybridge.WinClient.Services;

internal sealed partial class LanProductControlSession
{
    /// <summary>Consumes the prepared native provider and one USB stream. The
    /// temporary bootstrap token bounds setup; the session retains the caller
    /// and workspace lifetimes independently after that linkage is disposed.</summary>
    internal static async Task<LanProductControlSession> ConnectUsbAsync(ProductPeerAuthentication authentication,
        UsbMuxConnector connector, Audio.AudioAccountScope accountScope, Func<bool> isAccountCurrent, CancellationToken bootstrapToken,
        CancellationToken sessionLifetime, CancellationToken workspaceLifetime)
    {
        ArgumentNullException.ThrowIfNull(authentication);
        Stream? unclaimed = null;
        ProductControlStreamTransport? transport = null;
        LanProductControlSession? session = null;
        Exception? failure = null;
        try
        {
            ArgumentNullException.ThrowIfNull(connector); ArgumentNullException.ThrowIfNull(isAccountCurrent);
            ArgumentNullException.ThrowIfNull(accountScope); accountScope.Validate();
            bootstrapToken.ThrowIfCancellationRequested(); authentication.RequireCurrent();
            if (authentication.Route is not ProductPeerRoute.Usb { Route: { } route } ||
                route.PeerDeviceId != authentication.Peer.PeerDeviceId || route.Fingerprint != authentication.Peer.PeerPublicKeyFingerprint)
                throw new InvalidDataException("USB control requires the exact prepared cable and paired identity.");
            void RequireSetup()
            {
                bootstrapToken.ThrowIfCancellationRequested(); sessionLifetime.ThrowIfCancellationRequested();
                workspaceLifetime.ThrowIfCancellationRequested(); authentication.RequireCurrent();
                if (!isAccountCurrent()) throw new InvalidOperationException("USB connection account authority has ended.");
            }
            RequireSetup();
            unclaimed = await connector.OpenAsync(route.Udid, UsbMuxConnector.ControlPort, bootstrapToken).ConfigureAwait(false);
            transport = new(unclaimed, LanProductControlMessages.MaximumFrameBytes, LanProductControlMessages.MaximumFrameBytes);
            unclaimed = null;
            RequireSetup();
            using var handshake = await new ProductHandshakeCore(authentication.Crypto)
                .StartInitiatorAsync(new UsbHandshakeTransport(transport, RequireSetup), authentication.Peer, bootstrapToken).ConfigureAwait(false);
            RequireSetup();
            // No TCP file listener or USB original-file consumer is implied by
            // establishing MAIN. Feature capabilities are installed separately.
            session = new(transport, handshake.Keys, authentication.Peer,
                LanProductControlMessages.LocalIdentity(authentication, null, DateTimeOffset.UtcNow),
                new ProductControlCarrier.Usb(route, accountScope), sessionLifetime, handshake.LocalProtocolIdentity,
                handshake.PeerProtocolIdentity, handshake.ExportInitiatorExtensions(), isAccountCurrent, workspaceLifetime);
            transport = null;
        }
        catch (Exception error) { failure = error; }
        // The native provider must be confirmed released before a live session
        // is published. Preserve this owner if release itself fails.
        try { authentication.Dispose(); }
        catch (Exception cleanup)
        { failure = new LanResponderCryptoReleaseException(authentication, failure is null ? cleanup : new AggregateException(failure, cleanup)); }
        if (failure is null)
        {
            try
            {
                authentication.RequireCurrent();
                await (session ?? throw new InvalidOperationException("USB handshake did not produce a session."))
                    .CompleteAdmissionAsync(bootstrapToken).ConfigureAwait(false);
                bootstrapToken.ThrowIfCancellationRequested(); authentication.RequireCurrent();
                if (!session.IsReady) throw new InvalidOperationException("USB account or connection ended before admission completed.");
                return session;
            }
            catch (Exception error) { failure = error; }
        }
        IAsyncDisposable? retained = (IAsyncDisposable?)session ?? (IAsyncDisposable?)transport ?? unclaimed;
        try
        {
            if (session is not null) await session.DisposeAsync().ConfigureAwait(false);
            else if (transport is not null) await transport.DisposeAsync().ConfigureAwait(false);
            else if (unclaimed is not null) await unclaimed.DisposeAsync().ConfigureAwait(false);
        }
        catch (Exception cleanup)
        {
            throw new ProductBootstrapReleaseException(retained ?? throw new InvalidOperationException("USB cleanup lost its owner.", cleanup),
                new AggregateException(failure, cleanup));
        }
        ExceptionDispatchInfo.Capture(failure).Throw();
        throw new InvalidOperationException("Unreachable USB admission result.");
    }

    internal void RequireUsbRoute(UsbPeerInspection selected, Audio.AudioAccountScope accountScope)
    {
        ArgumentNullException.ThrowIfNull(selected); ArgumentNullException.ThrowIfNull(accountScope);
        lock (_stateGate)
        {
            if (!IsReady || Carrier is not ProductControlCarrier.Usb usb || usb.Route != UsbControlRoute.From(selected) || usb.AccountScope != accountScope)
                throw new InvalidDataException("The selected USB route does not belong to this live authenticated session.");
        }
    }

    private sealed class UsbHandshakeTransport(ProductControlStreamTransport transport, Action requireCurrent) : IProductHandshakeTransport
    {
        public Task SendAsync(ReadOnlyMemory<byte> frame, CancellationToken cancellationToken = default) =>
            transport.SendAdmittedAsync(() =>
            {
                requireCurrent();
                if (frame.Length > LanProductControlResponder.MaximumHandshakeFrameBytes)
                    throw new InvalidDataException("USB handshake frame exceeds its admission bound.");
                return frame;
            }, cancellationToken);

        public async Task<ReadOnlyMemory<byte>> ReadAsync(CancellationToken cancellationToken = default)
        {
            requireCurrent();
            var frame = await transport.ReadBoundedAsync(LanProductControlResponder.MaximumHandshakeFrameBytes, cancellationToken).ConfigureAwait(false);
            requireCurrent(); return frame;
        }
    }
}
