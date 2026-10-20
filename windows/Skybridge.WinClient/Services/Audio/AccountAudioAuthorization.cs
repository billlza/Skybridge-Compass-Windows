using System.Text;
using System.Text.Json.Serialization;

namespace Skybridge.WinClient.Services.Audio;

// Separate fields avoid scope delimiter collisions. This scope comes from a server-verified
// account snapshot; it is not accepted from a peer or user-editable profile metadata.
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record AudioAccountScope(SessionAuthority Authority, string Subject, string TenantId)
{
    internal static AudioAccountScope From(AccountDeviceAuthentication authentication) =>
        new(authentication.Authority, authentication.Subject, authentication.TenantId);
    internal static AudioAccountScope FromStoredCredentials(PersistedSession session, SessionAuthority expected)
    {
        if (session.Authority != expected || !SessionJwtValidator.TryValidate(session.AccessToken, expected, session.Subject,
                requireUnexpired: false, out var claims, out _) || claims is null)
            throw new InvalidDataException("Saved audio scope does not match the configured account authority.");
        var scope = new AudioAccountScope(expected, claims.Subject, AccountDeviceAuthentication.ReadBoundTenant(session.AccessToken!, claims.Subject));
        scope.Validate();
        return scope;
    }
    internal void Validate()
    {
        if (Authority is null || !Authority.IsWellFormed() || string.IsNullOrWhiteSpace(Subject) ||
            Subject.Length > 2048 || Subject.Any(char.IsControl) || string.IsNullOrWhiteSpace(TenantId) ||
            TenantId.Trim() != TenantId || Encoding.UTF8.GetByteCount(TenantId) > 256 || TenantId.Any(char.IsControl))
            throw new InvalidDataException("Invalid audio account scope.");
    }
}

/// <summary>One local authenticated-account publication. Token refresh may preserve it; sign-out,
/// replacement and hard authentication rejection revoke it before any asynchronous cleanup.</summary>
internal sealed class AccountAudioAuthorization(AudioAccountScope scope, IAudioAccountObservationStore? observations = null,
    AudioAccountRecoverySnapshot? recovery = null, bool offline = false)
{
    private int _revoked;
    private int _offline = offline ? 1 : 0;
    internal AudioAccountScope Scope { get; } = scope ?? throw new ArgumentNullException(nameof(scope));
    internal IAudioAccountObservationStore? Observations { get; } = observations;
    internal AudioAccountRecoverySnapshot? Recovery { get; } = recovery;
    internal bool IsOffline => Volatile.Read(ref _offline) != 0;
    internal bool IsCurrent
    {
        get
        {
            if (Volatile.Read(ref _revoked) != 0) return false;
            if (IsOffline && (Recovery is null || !Recovery.HasCurrentCandidate)) Revoke();
            return Volatile.Read(ref _revoked) == 0;
        }
    }
    // Only the account owner calls this after successful live verification and
    // durable settlement. Individual leases retain their original deadlines.
    internal bool TryPromoteOnline()
    {
        if (!IsCurrent) return false;
        Volatile.Write(ref _offline, 0);
        return Volatile.Read(ref _revoked) == 0;
    }
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
