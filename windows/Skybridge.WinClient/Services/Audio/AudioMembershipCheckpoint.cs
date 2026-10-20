using System.Text.Json.Serialization;

namespace Skybridge.WinClient.Services.Audio;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record AudioCheckpointIdentity(string DeviceId, string Algorithm, string Fingerprint)
{
    internal static AudioCheckpointIdentity From(AudioDeviceIdentity identity) => new(identity.DeviceId, identity.Algorithm, identity.Fingerprint);
    internal bool Matches(AudioDeviceIdentity identity) => this == From(identity);
    internal void Validate()
    {
        if (string.IsNullOrWhiteSpace(DeviceId) || string.IsNullOrWhiteSpace(Algorithm) ||
            Fingerprint is not { Length: 64 } || Fingerprint.Any(c => !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) ||
            CurrentPathProtocolIdentityBinding.NormalizeDeviceId(DeviceId) != DeviceId ||
            (Algorithm != CurrentPathProtocolSigningAlgorithms.ToWireName(CurrentPathProtocolSigningAlgorithm.Ed25519) &&
             Algorithm != CurrentPathProtocolSigningAlgorithms.ToWireName(CurrentPathProtocolSigningAlgorithm.MLDsa65)))
            throw new InvalidDataException("Invalid audio checkpoint device identity.");
    }
}

// Storage value only: it must come from the current protected canonical account
// record, with its login/revocation state checked before Restore is called. Never
// accept it from a peer or treat parsing these fields as account authentication.
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record AudioMembershipCheckpoint(int SchemaVersion, Guid LoginId, Guid EvidenceId,
    AudioAccountScope Scope, AudioCheckpointIdentity Local, AudioCheckpointIdentity Peer,
    AudioAuthorizationTime Issued, AudioAuthorizationTime Expires, AudioLogonSeal Continuity)
{
    internal const int CurrentSchema = 1;

    internal static AudioMembershipCheckpoint Capture(Guid loginId, AudioAccountMembershipEvidence evidence,
        Func<AudioAuthorizationTime> clock, IAudioLogonContinuity continuity)
    {
        if (loginId == Guid.Empty) throw new InvalidDataException("Audio checkpoint requires a durable login.");
        evidence.RequireValid(evidence.Scope, evidence.Local, evidence.Peer, clock());
        var result = new AudioMembershipCheckpoint(CurrentSchema, loginId, evidence.Id, evidence.Scope,
            AudioCheckpointIdentity.From(evidence.Local), AudioCheckpointIdentity.From(evidence.Peer),
            evidence.Issued, evidence.Expires, continuity.Create());
        result.Validate();
        evidence.RequireValid(evidence.Scope, evidence.Local, evidence.Peer, clock());
        return result;
    }

    internal void Validate()
    {
        if (SchemaVersion != CurrentSchema || LoginId == Guid.Empty || EvidenceId == Guid.Empty ||
            Scope is null ||
            Local is null || Peer is null || Local.DeviceId == Peer.DeviceId || Continuity is null ||
            Issued.WallMilliseconds <= 0 || Issued.ContinuousMilliseconds < 0 ||
            Expires.WallMilliseconds <= Issued.WallMilliseconds || Expires.ContinuousMilliseconds <= Issued.ContinuousMilliseconds ||
            (decimal)Expires.WallMilliseconds - Issued.WallMilliseconds > AudioAccountMembershipEvidence.MaximumLifetimeMilliseconds ||
            (decimal)Expires.ContinuousMilliseconds - Issued.ContinuousMilliseconds != (decimal)Expires.WallMilliseconds - Issued.WallMilliseconds)
            throw new InvalidDataException("Invalid finite audio checkpoint.");
        Scope.Validate(); Local.Validate(); Peer.Validate(); Continuity.Validate();
    }

    internal AudioAccountMembershipEvidence Restore(Guid expectedLogin, AudioAccountScope expectedScope,
        AudioDeviceIdentity actualLocal, AudioDeviceIdentity actualPeer, Func<AudioAuthorizationTime> clock, IAudioLogonContinuity continuity) =>
        AudioAccountMembershipEvidence.RestoreCheckpoint(this, expectedLogin, expectedScope, actualLocal, actualPeer, clock, continuity);
}
