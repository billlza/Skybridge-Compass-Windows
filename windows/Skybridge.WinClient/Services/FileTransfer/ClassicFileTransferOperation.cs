namespace Skybridge.WinClient.Services.FileTransfer;

internal sealed record ClassicFileTransferProgress(string TransferId, string FileName, long Bytes, long TotalBytes, bool IsIncoming);
internal sealed record ClassicFileTransferResult(string TransferId, string FileName, long Bytes, string FileHash, string? SavedPath = null);

internal sealed class ClassicFileTransferRejectedException(string message) : IOException(message);

/// <summary>Deadline policy for the existing classic transfer framing. A failed frame is never retried.</summary>
internal static class ClassicFileTransferOperation
{
    internal static async Task WriteAsync(Stream stream, ClassicFileFrameType type, ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken, Action? requireAuthorization = null)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(30));
        try { await ClassicFileTransferFrames.WriteAsync(stream, type, payload, deadline.Token, requireAuthorization).ConfigureAwait(false); }
        catch (OperationCanceledException failure) when (deadline.IsCancellationRequested &&
            failure.CancellationToken == deadline.Token && !cancellationToken.IsCancellationRequested)
        { throw new TimeoutException($"File-transfer {type} write exceeded 30 seconds.", failure); }
    }

    internal static async Task<ClassicFileFrame> ReadAsync(Stream stream, TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        try { return await ClassicFileTransferFrames.ReadAsync(stream, deadline.Token).ConfigureAwait(false); }
        catch (OperationCanceledException failure) when (!cancellationToken.IsCancellationRequested)
        { throw new TimeoutException($"File-transfer frame was not received within {timeout.TotalSeconds:F0} seconds.", failure); }
    }

    internal static async Task SendReceiptAsync(Stream stream, ClassicFileReceipt receipt, ReadOnlyMemory<byte> key,
        CancellationToken cancellationToken) => await WriteAsync(stream, ClassicFileFrameType.Receipt,
            ClassicFileTransferWire.Encode(ClassicFileTransferWire.Authenticate(receipt, key.Span)), cancellationToken).ConfigureAwait(false);

    internal static async Task SendApprovalAsync(Stream stream, ClassicFileMetadata metadata, ReadOnlyMemory<byte> key,
        string? refusal, Action requireAuthorization, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requireAuthorization);
        cancellationToken.ThrowIfCancellationRequested(); requireAuthorization();
        var response = ClassicFileTransferWire.CreateApproval(metadata, key.Span, refusal);
        await WriteAsync(stream, ClassicFileFrameType.Approval, ClassicFileTransferWire.Encode(response),
            cancellationToken, requireAuthorization).ConfigureAwait(false);
    }

    internal static string Hash(ReadOnlySpan<byte> digest) => Convert.ToHexStringLower(digest);
}
