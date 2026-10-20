using System.Net;
using System.Security.Cryptography;
using Skybridge.WinClient.Services.FileTransfer;
using Skybridge.WinClient.Services.Connection;

namespace Skybridge.WinClient.Services.Audio;

/// <summary>One approved file offer on one actual MAIN owner. File metadata and
/// encryption remain classic v2; its authority cannot be borrowed from another
/// session, same-account device, stream or playback output.</summary>
internal sealed class AudioOriginalFileAdmission
{
    private readonly LanProductControlSession _session;
    private readonly ILanAudioStreamInbox _inbox;
    private readonly AudioPlaybackPermission _permission;
    private readonly string _endpoint;
    private readonly TimeSpan _transferTimeout;
    private int _claimed;

    internal AudioOriginalFileAdmission(LanProductControlSession session, ILanAudioStreamInbox inbox,
        AudioPlaybackPermission permission, string endpoint, TimeSpan? transferTimeout = null)
    {
        _session = session ?? throw new ArgumentNullException(nameof(session));
        _inbox = inbox ?? throw new ArgumentNullException(nameof(inbox));
        _permission = permission ?? throw new ArgumentNullException(nameof(permission));
        _endpoint = endpoint;
        _transferTimeout = transferTimeout ?? TimeSpan.FromMinutes(5);
        if (_transferTimeout <= TimeSpan.Zero || _transferTimeout > TimeSpan.FromMinutes(30))
            throw new ArgumentOutOfRangeException(nameof(transferTimeout));
        Source = inbox.Source as AudioPlaybackSource.OriginalFile
            ?? throw new InvalidDataException("Original-file admission requires its exact file offer.");
        if (Source.Length > ClassicFileTransferWire.MaximumFileBytes)
            throw new InvalidDataException("The file exceeds the current classic receive limit.");
        permission.Request.RequireInitialMembership();
        RequireCurrent();
    }
    internal AudioPlaybackSource.OriginalFile Source { get; }
    internal LanProductControlSession Session => _session;
    internal bool HasClaimedTransfer => Volatile.Read(ref _claimed) != 0;
    internal void RequireCurrent()
    {
        _session.RequireOwnedAudioInbox(_inbox);
        _permission.RequireCurrent(_inbox, Source, _endpoint);
    }
    internal void RequireEffectCurrent()
    {
        _inbox.RequireEffectCurrent();
        _permission.RequireEffectCurrent(_inbox, Source, _endpoint);
    }

    internal void ValidateIncomingMetadata(ClassicFileMetadata metadata, IPAddress remoteAddress)
    {
        var key = AuthorizeMetadata(metadata, remoteAddress);
        CryptographicOperations.ZeroMemory(key);
    }
    private byte[] AuthorizeMetadata(ClassicFileMetadata metadata, IPAddress remoteAddress)
    {
        RequireCurrent();
        return BindMetadata(metadata, _session.AuthorizeIncomingTransfer(metadata, remoteAddress));
    }
    internal void ValidateIncomingUsbMetadata(ClassicFileMetadata metadata, UsbControlRoute route)
    {
        var key = AuthorizeUsbMetadata(metadata, route);
        CryptographicOperations.ZeroMemory(key);
    }
    private byte[] AuthorizeUsbMetadata(ClassicFileMetadata metadata, UsbControlRoute route)
    {
        RequireCurrent();
        return BindMetadata(metadata, _session.AuthorizeUsbIncomingTransfer(metadata, route));
    }
    private byte[] BindMetadata(ClassicFileMetadata metadata, byte[] key)
    {
        try
        {
            if (!Guid.TryParseExact(metadata.TransferId, "D", out var transfer) || transfer != Source.TransferId ||
                metadata.FileSize != Source.Length || metadata.FileHash != Source.Sha256Hex)
                throw new InvalidDataException("The authenticated file does not match this exact audio offer.");
            RequireCurrent(); return key;
        }
        catch { CryptographicOperations.ZeroMemory(key); throw; }
    }

    // The listener retains and awaits this actual producer during cancellation.
    // No registered capability or network endpoint is implied by creating admission.
    internal Task<AudioOriginalFileArtifact> ReceiveAsync(Stream network, ClassicFileMetadata metadata,
        IPAddress remoteAddress, string privateDirectory, CancellationToken token) =>
        ReceiveScopedAsync(network, metadata, () => AuthorizeMetadata(metadata, remoteAddress), privateDirectory, token);

    internal Task<AudioOriginalFileArtifact> ReceiveUsbAsync(Stream stream, ClassicFileMetadata metadata,
        UsbControlRoute route, string privateDirectory, CancellationToken token) =>
        ReceiveScopedAsync(stream, metadata, () => AuthorizeUsbMetadata(metadata, route), privateDirectory, token);

    private async Task<AudioOriginalFileArtifact> ReceiveScopedAsync(Stream network, ClassicFileMetadata metadata,
        Func<byte[]> authorizeMetadata, string privateDirectory, CancellationToken token)
    {
        using var scope = CancellationTokenSource.CreateLinkedTokenSource(token, _session.Lifetime);
        scope.CancelAfter(_transferTimeout);
        try { return await ReceiveCoreAsync(network, metadata, authorizeMetadata, privateDirectory, scope.Token).ConfigureAwait(false); }
        catch (OperationCanceledException error) when (!token.IsCancellationRequested && !_session.Lifetime.IsCancellationRequested && scope.IsCancellationRequested)
        { throw new TimeoutException("The original audio file exceeded its transfer deadline.", error); }
    }
    private async Task<AudioOriginalFileArtifact> ReceiveCoreAsync(Stream network, ClassicFileMetadata metadata,
        Func<byte[]> authorizeMetadata, string privateDirectory, CancellationToken token)
    {
        token.ThrowIfCancellationRequested(); RequireCurrent();
        var key = authorizeMetadata();
        AudioOriginalFileArtifact? artifact = null;
        try
        {
            token.ThrowIfCancellationRequested(); RequireCurrent();
            if (Interlocked.CompareExchange(ref _claimed, 1, 0) != 0)
                throw new InvalidOperationException("This original-file offer has already been claimed.");
            // A failed claimed attempt remains consumed; retries need a new offer.
            artifact = await AudioOriginalFileArtifact.ReceiveAsync(network, metadata, key,
                privateDirectory, RequireEffectCurrent, token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested(); RequireCurrent();
            await ClassicFileTransferOperation.SendReceiptAsync(network,
                new(metadata.TransferId, true, metadata.FileSize, ClassicFileTransferWire.SecurityVersion, metadata.FileHash),
                key, token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested(); RequireCurrent();
            return artifact;
        }
        catch (Exception primary)
        {
            if (artifact is not null)
            {
                try { await artifact.DisposeAsync().ConfigureAwait(false); }
                catch (Exception cleanup) { throw new AudioOriginalFileCleanupException(artifact, new AggregateException(primary, cleanup)); }
            }
            throw;
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }
}
