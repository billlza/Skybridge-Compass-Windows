using System.Net;
using System.Net.Http;

namespace Skybridge.WinClient.Services.Audio;

// Only the authentication/registry request boundary may create this marker.
// The renewal scheduler must not infer retryability from arbitrary session errors.
internal sealed class AudioMembershipRequestUnavailableException(Exception cause)
    : IOException("Audio account renewal is temporarily unavailable.", cause);

internal sealed class AudioMembershipRequestBusyException()
    : InvalidOperationException("An audio account request is still queued or executing.");

internal sealed class AudioMembershipQueryTimeoutException(OperationCanceledException cause)
    : TimeoutException("Audio account device query exceeded its finite request deadline.", cause);

internal static class AudioMembershipRequestFailure
{
    internal static bool IsTemporary(AuthClientFailure? failure) => failure switch
    {
        { Kind: AuthFailureKind.Timeout, Cause: OperationCanceledException } => true,
        { Kind: AuthFailureKind.Network, Cause: HttpRequestException error } => IsTemporary(error),
        { Kind: AuthFailureKind.Network, Cause: HttpIOException error } => IsTemporary(error),
        { Kind: AuthFailureKind.HttpFailure, StatusCode: { } status } => IsTemporary(status),
        _ => false
    };
    internal static bool IsTemporary(HttpRequestException failure) => failure.StatusCode is null &&
        failure.HttpRequestError is HttpRequestError.NameResolutionError or HttpRequestError.ConnectionError or HttpRequestError.ResponseEnded;
    internal static bool IsTemporary(HttpIOException failure) => failure.HttpRequestError == HttpRequestError.ResponseEnded;
    internal static bool IsTemporary(HttpStatusCode status) => status is HttpStatusCode.RequestTimeout or
        HttpStatusCode.TooManyRequests or HttpStatusCode.InternalServerError or HttpStatusCode.BadGateway or
        HttpStatusCode.ServiceUnavailable or HttpStatusCode.GatewayTimeout;
}
