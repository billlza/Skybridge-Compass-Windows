using System.Net;
using System.Net.Sockets;
using System.Runtime.ExceptionServices;
using Skybridge.WinClient.Services.RemoteControl;

namespace Skybridge.WinClient.Services;

internal sealed class LanResponderCryptoReleaseException(IDisposable retainedOwner, Exception failure)
    : IOException("Incoming MAIN crypto release was not confirmed.", failure)
{
    internal IDisposable RetainedOwner { get; } = retainedOwner;
}

/// <summary>Admits one already-accepted MAIN socket using existing paired authority.
/// This does not open a listener, grant trust, authorize an account, or permit playback.</summary>
internal abstract record LanIncomingControlResult
{
    private LanIncomingControlResult() { }
    internal sealed record Main(LanProductControlSession Session) : LanIncomingControlResult;
    internal sealed record KemRefreshCompleted : LanIncomingControlResult;
    internal sealed record PairingExchangeCompleted : LanIncomingControlResult;
}

internal static class LanProductControlResponder
{
    // Compatible handshake payloads are at most 16 KiB plus their padding envelope.
    internal const int MaximumHandshakeFrameBytes = 16_640;

    /// <summary>Takes ownership of client, including on failure. The caller owns the
    /// returned session and must cancel its lifetime when the trusted snapshot expires.
    /// The generic port only permits an explicitly disposable crypto owner; production
    /// callers supply RemoteControlIdentityStore.CreateCryptoProvider.</summary>
    internal static async Task<LanProductControlSession> AcceptAsync<TCrypto>(TcpClient client,
        RemoteControlSecurityIdentity accountDevice, RemoteControlPairingMaterial localPairing,
        IReadOnlyCollection<RemoteControlTrustedPeer> trustedPeers, Func<TCrypto> createCrypto,
        ushort? localFileTransferPort, CancellationToken cancellationToken)
        where TCrypto : class, IProductHandshakeCryptoProvider, IDisposable
    {
        var result = await AcceptCoreAsync(client, accountDevice, localPairing, () => trustedPeers, createCrypto,
            localFileTransferPort, cancellationToken, null, null, true).ConfigureAwait(false);
        return result is LanIncomingControlResult.Main main ? main.Session
            : throw new InvalidOperationException("A handshake-only admission returned a bootstrap result.");
    }

    internal static Task<LanIncomingControlResult> AcceptWithBootstrapAsync<TCrypto>(TcpClient client,
        RemoteControlSecurityIdentity accountDevice, RemoteControlPairingMaterial localPairing,
        IReadOnlyCollection<RemoteControlTrustedPeer> trustedPeers, Func<TCrypto> createCrypto,
        ushort? localFileTransferPort, CancellationToken cancellationToken, SignedLanKemRefreshResponder refresh)
        where TCrypto : class, IProductHandshakeCryptoProvider, IDisposable =>
        AcceptCoreAsync(client, accountDevice, localPairing, () => trustedPeers, createCrypto,
            localFileTransferPort, cancellationToken, refresh, null, true);

    internal static Task<LanIncomingControlResult> AcceptWithBootstrapAsync<TCrypto>(TcpClient client,
        RemoteControlSecurityIdentity accountDevice, RemoteControlPairingMaterial localPairing,
        Func<IReadOnlyCollection<RemoteControlTrustedPeer>> readTrusted, Func<TCrypto> createCrypto,
        ushort? localFileTransferPort, CancellationToken cancellationToken, SignedLanKemRefreshResponder refresh,
        LanPibResponder pairing, bool advertiseGeneralFiles = true)
        where TCrypto : class, IProductHandshakeCryptoProvider, IDisposable =>
        AcceptCoreAsync(client, accountDevice, localPairing, readTrusted, createCrypto,
            localFileTransferPort, cancellationToken, refresh, pairing, advertiseGeneralFiles);

    private static async Task<LanIncomingControlResult> AcceptCoreAsync<TCrypto>(TcpClient client,
        RemoteControlSecurityIdentity accountDevice, RemoteControlPairingMaterial localPairing,
        Func<IReadOnlyCollection<RemoteControlTrustedPeer>> readTrusted, Func<TCrypto> createCrypto,
        ushort? localFileTransferPort, CancellationToken cancellationToken, SignedLanKemRefreshResponder? refresh,
        LanPibResponder? pairing, bool advertiseGeneralFiles)
        where TCrypto : class, IProductHandshakeCryptoProvider, IDisposable
    {
        ArgumentNullException.ThrowIfNull(client);
        TcpProductControlTransport? transport = null;
        LanProductControlSession? session = null;
        try
        {
            ArgumentNullException.ThrowIfNull(readTrusted);
            ArgumentNullException.ThrowIfNull(createCrypto);
            cancellationToken.ThrowIfCancellationRequested();
            var localIdentity = LanProductControlMessages.LocalIdentity(accountDevice, localPairing,
                localFileTransferPort, DateTimeOffset.UtcNow, advertiseGeneralFiles);
            var remoteAddress = (client.Client.RemoteEndPoint as IPEndPoint)?.Address
                ?? throw new IOException("The incoming MAIN connection has no IP endpoint.");
            transport = new(client, LanProductControlMessages.MaximumFrameBytes, LanProductControlMessages.MaximumFrameBytes);
            var handshakeTransport = new HandshakeTransport(transport);
            ReadOnlyMemory<byte> firstFrame;
            using (var first = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                first.CancelAfter(TimeSpan.FromSeconds(5));
                try { firstFrame = await transport.ReadBoundedAsync(refresh is null && pairing is null ? MaximumHandshakeFrameBytes : LanBootstrapWire.MaximumBytes,
                    first.Token).ConfigureAwait(false); }
                catch (OperationCanceledException error) when (!cancellationToken.IsCancellationRequested && first.IsCancellationRequested)
                { throw new TimeoutException("The incoming MAIN peer did not send its initial frame within 5 seconds.", error); }
            }
            if ((refresh is not null || pairing is not null) && IsJson(firstFrame.Span))
            {
                // This sole reader handles exactly one bootstrap request. No MAIN
                // session, account-device binding or audio capability is created here.
                var kind = LanBootstrapWire.ReadDiscriminator(firstFrame.Span);
                if (pairing is not null && kind is "protocolIdentityBindingRequest" or "protocolIdentityBindingConfirm")
                {
                    await RespondPairingAsync(transport, firstFrame, kind, pairing, cancellationToken).ConfigureAwait(false);
                    await transport.DisposeAsync().ConfigureAwait(false); transport = null;
                    return new LanIncomingControlResult.PairingExchangeCompleted();
                }
                if (refresh is null || kind != "kemRefreshRequest")
                    throw new InvalidDataException("Unsupported initial LAN bootstrap message.");
                var request = SignedLanKemRefreshWire.DecodeRequest(firstFrame.Span);
                try
                {
                    var response = refresh.Respond(request, cancellationToken);
                    await transport.SendAdmittedAsync(() =>
                    {
                        refresh.RequireSend(request, response, cancellationToken);
                        return SignedLanKemRefreshWire.EncodeResponse(response);
                    }, cancellationToken).ConfigureAwait(false);
                }
                catch (LanKemRefreshRejectedException rejection)
                {
                    try
                    {
                        await transport.SendAsync(SignedLanKemRefreshWire.EncodeFailure(request, rejection.Code), cancellationToken).ConfigureAwait(false);
                    }
                    catch (Exception sendFailure) { throw new AggregateException("SKR rejection and diagnostic send failed.", rejection, sendFailure); }
                    throw;
                }
                await transport.DisposeAsync().ConfigureAwait(false); transport = null;
                return new LanIncomingControlResult.KemRefreshCompleted();
            }
            if (firstFrame.Length > MaximumHandshakeFrameBytes)
                throw new InvalidDataException("MAIN handshake frame exceeds its pre-admission bound.");
            var trustedPeers = readTrusted() ?? throw new InvalidOperationException("MAIN pairing authority is unavailable.");
            if (trustedPeers.Count is < 1 or > 64)
                throw new InvalidOperationException("MAIN admission requires a bounded existing trusted peer set.");
            var trusted = trustedPeers.Select(peer => new RemoteControlTrustedPeer(peer.DeviceId,
                peer.ProtocolPublicKeyFingerprint, peer.KnownDeviceIds?.ToArray())).ToArray();
            // This resolves a candidate only. Signature verification and both FIN1
            // checks must finish before transferring the sole reader to MAIN.
            var candidate = RemoteControlHandshakeBinding.ValidateAndResolveMessageA(firstFrame, localPairing.DeviceId, trusted);
            using (var handshake = await HandshakeAndReleaseCryptoAsync(createCrypto, handshakeTransport,
                candidate, cancellationToken).ConfigureAwait(false))
            {
                session = new(transport, handshake.Keys, candidate.Peer, localIdentity, controlEndpoint: null,
                    remoteAddress, cancellationToken, handshake.LocalProtocolIdentity, handshake.PeerProtocolIdentity,
                    handshake.ExportInitiatorExtensions());
                transport = null;
            }
            await session.CompleteAdmissionAsync(cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            return new LanIncomingControlResult.Main(session);
        }
        catch (Exception failure)
        {
            try
            {
                if (session is not null) await session.DisposeAsync().ConfigureAwait(false);
                else if (transport is not null) await transport.DisposeAsync().ConfigureAwait(false);
                else client.Dispose();
            }
            catch (Exception cleanup) { throw new AggregateException("Incoming MAIN admission and cleanup failed.", failure, cleanup); }
            throw;
        }
    }

    private static async Task RespondPairingAsync(TcpProductControlTransport transport, ReadOnlyMemory<byte> frame,
        string kind, LanPibResponder pairing, CancellationToken token)
    {
        if (kind == "protocolIdentityBindingRequest")
        {
            var request = LanPibWire.DecodeRequest(frame.Span);
            using var scope = CancellationTokenSource.CreateLinkedTokenSource(token);
            scope.CancelAfter(TimeSpan.FromSeconds(30));
            try
            {
                var candidate = pairing.CreateCandidate(request, scope.Token, token);
                await transport.SendAdmittedAsync(() =>
                {
                    pairing.RequireCandidateSend(request, candidate, scope.Token);
                    return LanPibWire.EncodeCandidate(candidate);
                }, scope.Token).ConfigureAwait(false);
            }
            catch (LanPibRejectedException rejection)
            {
                await SendPairingRejectionAsync(transport, request.RequesterDeviceId, request.TargetDeviceId,
                    LanPibCanonical.RequestHash(request), "identity_binding", rejection, token).ConfigureAwait(false);
                throw;
            }
        }
        else
        {
            var confirm = LanPibWire.DecodeConfirm(frame.Span);
            try
            {
                var ack = await pairing.ConfirmAsync(confirm, token).ConfigureAwait(false);
                await transport.SendAdmittedAsync(() =>
                {
                    pairing.RequireAckSend(confirm, ack, token);
                    return LanPibWire.EncodeFinalAck(ack);
                }, token).ConfigureAwait(false);
            }
            catch (LanPibRejectedException rejection)
            {
                await SendPairingRejectionAsync(transport, confirm.RequesterDeviceId, confirm.ResponderDeviceId,
                    confirm.RequestHashHex, "identity_binding_confirm", rejection, token).ConfigureAwait(false);
                throw;
            }
        }
    }
    private static async Task SendPairingRejectionAsync(TcpProductControlTransport transport, string requester,
        string target, string requestHash, string stage, LanPibRejectedException rejection, CancellationToken token)
    {
        // Compatibility diagnostic only. It is never an authenticated ACK or an
        // instruction to change algorithms, trust, account authority or policy.
        try
        {
            await transport.SendAsync(LanBootstrapWire.Encode("kemRefreshFailure", new
            {
                version = 1, requesterDeviceId = requester, targetDeviceId = target, stage,
                reasonCode = rejection.Code, reason = rejection.Code, requestHashHex = requestHash,
                sentAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0 - 978307200.0
            }), token).ConfigureAwait(false);
        }
        catch (Exception sendFailure) { throw new AggregateException("PIB rejection and diagnostic send failed.", rejection, sendFailure); }
    }

    private static bool IsJson(ReadOnlySpan<byte> frame)
    {
        foreach (var value in frame)
        {
            if (value is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n') continue;
            return value == (byte)'{';
        }
        return false;
    }

    private static async Task<AuthenticatedProductHandshake> HandshakeAndReleaseCryptoAsync<TCrypto>(Func<TCrypto> createCrypto,
        IProductHandshakeTransport transport, RemoteControlHandshakeCandidate candidate, CancellationToken token)
        where TCrypto : class, IProductHandshakeCryptoProvider, IDisposable
    {
        var crypto = createCrypto() ?? throw new InvalidOperationException("MAIN crypto provider is missing.");
        AuthenticatedProductHandshake? result = null;
        Exception? failure = null;
        try
        {
            result = await new ProductHandshakeCore(crypto, TimeSpan.FromSeconds(20))
                .AcceptResponderAsync(transport, candidate.Peer, candidate.MessageAFrame, token).ConfigureAwait(false);
        }
        catch (Exception error) { failure = error; }
        try { crypto.Dispose(); }
        catch (Exception cleanup)
        {
            result?.Dispose();
            throw new LanResponderCryptoReleaseException(crypto, failure is null ? cleanup :
                new AggregateException("MAIN handshake and crypto release failed.", failure, cleanup));
        }
        if (failure is not null) ExceptionDispatchInfo.Capture(failure).Throw();
        return result ?? throw new InvalidOperationException("MAIN handshake produced no authenticated result.");
    }

    private sealed class HandshakeTransport(TcpProductControlTransport transport) : IProductHandshakeTransport
    {
        public Task<ReadOnlyMemory<byte>> ReadAsync(CancellationToken cancellationToken) =>
            transport.ReadBoundedAsync(MaximumHandshakeFrameBytes, cancellationToken);
        public Task SendAsync(ReadOnlyMemory<byte> frame, CancellationToken cancellationToken)
        {
            if (frame.IsEmpty || frame.Length > MaximumHandshakeFrameBytes)
                throw new InvalidDataException("MAIN handshake frame exceeds its pre-admission bound.");
            return transport.SendAsync(frame, cancellationToken);
        }
    }
}
