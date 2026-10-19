using System.Text.Json.Serialization;

namespace Skybridge.WinClient.Services.Audio;

// Separate fields avoid scope delimiter collisions. This scope comes from a server-verified
// account snapshot; it is not accepted from a peer or user-editable profile metadata.
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record AudioAccountScope(SessionAuthority Authority, string Subject, string TenantId)
{
    internal static AudioAccountScope From(AccountDeviceAuthentication authentication) =>
        new(authentication.Authority, authentication.Subject, authentication.TenantId);
}

/// <summary>One local authenticated-account publication. Token refresh may preserve it; sign-out,
/// replacement and hard authentication rejection revoke it before any asynchronous cleanup.</summary>
internal sealed class AccountAudioAuthorization(AudioAccountScope scope)
{
    private int _revoked;
    internal AudioAccountScope Scope { get; } = scope ?? throw new ArgumentNullException(nameof(scope));
    internal bool IsCurrent => Volatile.Read(ref _revoked) == 0;
    internal void Revoke() => Interlocked.Exchange(ref _revoked, 1);
    internal void RequireCurrent()
    {
        if (!IsCurrent) throw new InvalidOperationException("The audio account authorization has ended.");
    }
    internal void RequireAuthentication(AccountDeviceAuthentication authentication)
    {
        RequireCurrent();
        if (Scope != AudioAccountScope.From(authentication))
            throw new InvalidDataException("Audio account authentication changed authority, subject or tenant.");
        RequireCurrent();
    }
}
