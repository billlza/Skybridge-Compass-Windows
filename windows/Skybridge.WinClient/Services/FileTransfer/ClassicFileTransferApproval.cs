using System.Security.Cryptography;

namespace Skybridge.WinClient.Services.FileTransfer;

internal sealed record ClassicFileApproval(string TransferId, string MetadataDigest, bool Accepted,
    int SecurityVersion, byte[] AuthTag, string? Reason = null);

internal static partial class ClassicFileTransferWire
{
    internal const string ApprovalProtocol = "metadata-bound-v1";
    internal const string ApprovalCapability = "classic_approval_v1";
    internal const int MaximumApprovalPayloadBytes = 2048;

    // The caller owns local permission and live-session admission. This only
    // authenticates a decision for the exact already-authenticated metadata.
    internal static ClassicFileApproval CreateApproval(ClassicFileMetadata metadata, ReadOnlySpan<byte> key,
        string? refusal = null)
    {
        RequireApprovalRequest(metadata, key);
        var response = new ClassicFileApproval(metadata.TransferId,
            Convert.ToHexStringLower(SHA256.HashData(MetadataTranscript(metadata))), refusal is null,
            SecurityVersion, [], refusal);
        return response with { AuthTag = HMACSHA256.HashData(key, ApprovalTranscript(response)) };
    }

    // A verified refusal remains a refusal. This is never a file receipt.
    internal static string? VerifyApproval(ClassicFileApproval response, ClassicFileMetadata metadata,
        ReadOnlySpan<byte> key)
    {
        ArgumentNullException.ThrowIfNull(response);
        RequireApprovalRequest(metadata, key);
        var transcript = ApprovalTranscript(response);
        if (response.TransferId != metadata.TransferId ||
            response.MetadataDigest != Convert.ToHexStringLower(SHA256.HashData(MetadataTranscript(metadata))))
            throw new InvalidDataException("The file approval belongs to different metadata.");
        RequireAuthentication(response.AuthTag, transcript, key);
        return response.Reason;
    }

    private static void RequireApprovalRequest(ClassicFileMetadata metadata, ReadOnlySpan<byte> key)
    {
        Verify(metadata, key);
        if (metadata.ApprovalProtocol != ApprovalProtocol)
            throw new InvalidDataException("This file did not request metadata-bound approval.");
    }

    private static byte[] ApprovalTranscript(ClassicFileApproval value)
    {
        ValidateVersion(value.SecurityVersion); ValidateTransferId(value.TransferId); ValidateHash(value.MetadataDigest);
        if (value.Reason is not (null or "denied" or "unavailable") || value.Accepted != (value.Reason is null))
            throw new InvalidDataException("Invalid file approval decision.");
        return Transcript(5, value.SecurityVersion,
        [
            ("transfer_id", value.TransferId), ("metadata_digest", value.MetadataDigest),
            ("accepted", value.Accepted ? "1" : "0"), ("reason", value.Reason), ("approval_protocol", ApprovalProtocol)
        ]);
    }
}
