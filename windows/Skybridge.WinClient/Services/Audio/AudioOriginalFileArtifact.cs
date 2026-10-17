using Skybridge.WinClient.Services.FileTransfer;
using System.Security.Cryptography;

namespace Skybridge.WinClient.Services.Audio;

internal sealed class AudioOriginalFileCleanupException(AudioOriginalFileArtifact owner, Exception failure)
    : IOException("The private audio artifact could not be released.", failure)
{
    internal AudioOriginalFileArtifact RetainedOwner { get; } = owner;
}

/// <summary>One verified private artifact, pinned by its original descriptor.
/// Windows denies other opens and marks this handle delete-on-close: cleanup never
/// follows a pathname supplied by a peer. No receipt, output or playback is implied.</summary>
internal sealed class AudioOriginalFileArtifact : IAsyncDisposable
{
    internal const int MaximumReadBytes = 65_536;
    private readonly FileStream _file;
    private readonly Action _requireAuthorization;
    private readonly SemaphoreSlim _io = new(1, 1);
    private readonly object _closeGate = new();
    private Task? _closing;
    private int _closed, _verified, _released;

    private AudioOriginalFileArtifact(FileStream file, ClassicFileMetadata metadata, Action requireAuthorization)
    { _file = file; Length = metadata.FileSize; Sha256Hex = metadata.FileHash; _requireAuthorization = requireAuthorization; }
    internal long Length { get; }
    internal string Sha256Hex { get; }
    internal bool IsReleased => Volatile.Read(ref _released) != 0;

    internal Task<AudioWavePcmMetadata> InspectWaveAsync(CancellationToken token) =>
        AudioWavePcmFile.InspectAsync(Length, ReadAsync, token);

    // The caller must authenticate the same MAIN/offer before entering this storage
    // boundary. This method separately verifies the metadata MAC and all file bytes.
    internal static async Task<AudioOriginalFileArtifact> ReceiveAsync(Stream network, ClassicFileMetadata metadata,
        ReadOnlyMemory<byte> key, string privateDirectory, Action requireAuthorization, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(requireAuthorization);
        token.ThrowIfCancellationRequested(); requireAuthorization();
        ClassicFileTransferWire.Verify(metadata, key.Span);
        var root = ClassicFileTransferReceiver.ValidateReceiveDirectory(privateDirectory);
        token.ThrowIfCancellationRequested(); requireAuthorization();
        var file = new FileStream(Path.Combine(root, $".skybridge-audio-{Guid.NewGuid():N}.private"),
            FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, MaximumReadBytes,
            FileOptions.Asynchronous | FileOptions.RandomAccess | FileOptions.DeleteOnClose);
        var artifact = new AudioOriginalFileArtifact(file, metadata, requireAuthorization);
        try
        {
            await ClassicFileTransferReceiver.ReceiveContentAsync(network, metadata, key,
                (bytes, cancellation) => file.WriteAsync(bytes, cancellation), requireAuthorization, token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested(); requireAuthorization();
            await file.FlushAsync(token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested(); requireAuthorization();
            file.Flush(flushToDisk: true);
            token.ThrowIfCancellationRequested(); requireAuthorization();
            if (file.Length != metadata.FileSize) throw new InvalidDataException("Private audio length changed before verification.");
            // Read the actual stored bytes through this same pinned descriptor;
            // successful writes and a wire hash alone are not an artifact receipt.
            file.Position = 0;
            using var storedDigest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = new byte[MaximumReadBytes];
            try
            {
                long remaining = metadata.FileSize;
                while (remaining != 0)
                {
                    token.ThrowIfCancellationRequested(); requireAuthorization();
                    int count = (int)Math.Min(remaining, buffer.Length);
                    await file.ReadExactlyAsync(buffer.AsMemory(0, count), token).ConfigureAwait(false);
                    token.ThrowIfCancellationRequested(); requireAuthorization();
                    storedDigest.AppendData(buffer.AsSpan(0, count)); remaining -= count;
                }
                if (file.Length != metadata.FileSize || Convert.ToHexStringLower(storedDigest.GetHashAndReset()) != metadata.FileHash)
                    throw new InvalidDataException("The stored audio differs from the offered file.");
            }
            finally { CryptographicOperations.ZeroMemory(buffer); }
            Volatile.Write(ref artifact._verified, 1);
            return artifact;
        }
        catch (Exception primary)
        {
            try { await artifact.DisposeAsync().ConfigureAwait(false); }
            catch (Exception cleanup) { throw new AudioOriginalFileCleanupException(artifact, new AggregateException(primary, cleanup)); }
            throw;
        }
    }

    internal async Task<byte[]> ReadAsync(long offset, int count, CancellationToken token)
    {
        if (offset < 0 || count is <= 0 or > MaximumReadBytes || offset > Length || count > Length - offset)
            throw new InvalidDataException("Private audio read exceeds its verified range.");
        Check(token);
        await _io.WaitAsync(token).ConfigureAwait(false);
        try
        {
            Check(token);
            if (_file.Length != Length) throw new InvalidDataException("Private audio length changed after verification.");
            _file.Position = offset;
            var bytes = new byte[count];
            await _file.ReadExactlyAsync(bytes, token).ConfigureAwait(false);
            Check(token);
            return bytes;
        }
        finally { _io.Release(); }
    }
    private void Check(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _closed) != 0, this);
        if (Volatile.Read(ref _verified) == 0) throw new InvalidOperationException("Private audio is not verified.");
        _requireAuthorization();
    }
    public ValueTask DisposeAsync()
    {
        lock (_closeGate)
        {
            Interlocked.Exchange(ref _closed, 1);
            return new(_closing ??= CloseAsync());
        }
    }
    private async Task CloseAsync()
    {
        await _io.WaitAsync().ConfigureAwait(false);
        try
        {
            await _file.DisposeAsync().ConfigureAwait(false);
            Volatile.Write(ref _released, 1);
        }
        catch (Exception error) { throw new AudioOriginalFileCleanupException(this, error); }
        finally { _io.Release(); }
    }
}
