using System.Diagnostics;

namespace Skybridge.WinClient.Services.Audio;

internal enum AudioMembershipFailure { InvalidResponse = 1, InactiveDevice, Expired, ClockChanged, Revoked, IdentityChanged, ScopeChanged }
internal sealed class AudioMembershipException(AudioMembershipFailure reason, Exception? cause = null)
    : IOException($"Audio membership: {reason}.", cause)
{
    internal AudioMembershipFailure Reason { get; } = reason;
}

internal readonly record struct AudioAuthorizationTime(long WallMilliseconds, long ContinuousMilliseconds)
{
    // Stopwatch uses QPC on Windows, including system sleep/hibernation. Do not silently use
    // another platform's timer with different suspend semantics for an offline authorization.
    internal static AudioAuthorizationTime ReadWindows()
    {
        if (!OperatingSystem.IsWindows() || !Stopwatch.IsHighResolution)
            throw new PlatformNotSupportedException("Audio authorization requires the Windows continuous performance counter.");
        return new(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            checked((long)((Int128)Stopwatch.GetTimestamp() * 1000 / Stopwatch.Frequency)));
    }
}

internal sealed record AudioDeviceIdentity
{
    private AudioDeviceIdentity(string deviceId, string algorithm, string fingerprint)
    { DeviceId = deviceId; Algorithm = algorithm; Fingerprint = fingerprint; }
    internal string DeviceId { get; }
    internal string Algorithm { get; }
    internal string Fingerprint { get; }

    internal static CurrentPathProtocolIdentityBinding QueryBinding(string deviceId, ProductHandshakeProtocolIdentity signer)
    {
        var algorithm = signer.Algorithm switch
        {
            WebRtcProductSignatureAlgorithm.Ed25519 => CurrentPathProtocolSigningAlgorithm.Ed25519,
            WebRtcProductSignatureAlgorithm.MlDsa65 => CurrentPathProtocolSigningAlgorithm.MLDsa65,
            _ => throw new AudioMembershipException(AudioMembershipFailure.IdentityChanged)
        };
        // Compute from the actual public key, rather than trusting the optional fingerprint argument.
        var binding = new CurrentPathProtocolIdentityBinding(deviceId, algorithm, signer.ExportPublicKey());
        if (binding.DeviceId != deviceId || binding.ProtocolPublicKeyFingerprint != signer.Fingerprint)
            throw new AudioMembershipException(AudioMembershipFailure.IdentityChanged);
        return binding;
    }
    internal static AudioDeviceIdentity From(string deviceId, ProductHandshakeProtocolIdentity signer)
    {
        var binding = QueryBinding(deviceId, signer);
        return new(binding.DeviceId, binding.ProtocolSigningAlgorithmWireName, binding.ProtocolPublicKeyFingerprint);
    }
    internal static AudioDeviceIdentity FromRegistryBinding(CurrentPathProtocolIdentityBinding binding)
    {
        var actual = new CurrentPathProtocolIdentityBinding(binding.DeviceId, binding.ProtocolSigningAlgorithm, binding.ProtocolPublicKeyBytes);
        if (actual.ProtocolPublicKeyFingerprint != binding.ProtocolPublicKeyFingerprint)
            throw new AudioMembershipException(AudioMembershipFailure.IdentityChanged);
        return new(actual.DeviceId, actual.ProtocolSigningAlgorithmWireName, actual.ProtocolPublicKeyFingerprint);
    }
    internal bool Matches(AccountDeviceEntry row) => row.DeviceId == DeviceId && row.Algorithm == Algorithm && row.Fingerprint == Fingerprint;
}

/// <summary>Fresh, local, authenticated GET observation. Scope is attached from the captured request,
/// never read from a peer or invented as a server response field.</summary>
internal sealed class AudioRegistryObservation
{
    private AudioRegistryObservation(AudioAccountScope scope, AudioDeviceIdentity caller,
        AccountDeviceRosterSnapshot snapshot, AudioAuthorizationTime started, AudioAuthorizationTime received)
    { Scope = scope; Caller = caller; Snapshot = snapshot; Started = started; Received = received; }
    internal AudioAccountScope Scope { get; }
    internal AudioDeviceIdentity Caller { get; }
    internal AccountDeviceRosterSnapshot Snapshot { get; }
    internal AudioAuthorizationTime Started { get; }
    internal AudioAuthorizationTime Received { get; }

    internal static AudioRegistryObservation FromResponse(AccountDeviceAuthentication authentication, AudioDeviceIdentity caller,
        AccountDeviceRosterSnapshot snapshot, AudioAuthorizationTime started, AudioAuthorizationTime received)
    {
        if (started.WallMilliseconds <= 0 || started.ContinuousMilliseconds < 0 ||
            received.WallMilliseconds < started.WallMilliseconds || received.ContinuousMilliseconds < started.ContinuousMilliseconds ||
            received.WallMilliseconds - started.WallMilliseconds > AudioAccountMembershipEvidence.MaximumRequestMilliseconds ||
            received.ContinuousMilliseconds - started.ContinuousMilliseconds > AudioAccountMembershipEvidence.MaximumRequestMilliseconds ||
            snapshot.GeneratedAt <= 0 || snapshot.CallerDeviceId != caller.DeviceId || snapshot.Devices.Count > 200 ||
            Math.Abs((decimal)snapshot.GeneratedAt - received.WallMilliseconds) > AudioAccountMembershipEvidence.MaximumRequestMilliseconds ||
            snapshot.Devices.Any(row => row.IsCaller != caller.Matches(row)))
            throw new AudioMembershipException(AudioMembershipFailure.InvalidResponse);
        var frozen = snapshot with { Devices = Array.AsReadOnly(snapshot.Devices.ToArray()) };
        return new(AudioAccountScope.From(authentication), caller, frozen, started, received);
    }

    internal void RequireFreshAt(AudioAuthorizationTime now)
    {
        if (now.WallMilliseconds < Received.WallMilliseconds || now.ContinuousMilliseconds < Received.ContinuousMilliseconds ||
            now.WallMilliseconds - Received.WallMilliseconds > AudioAccountMembershipEvidence.MaximumRequestMilliseconds ||
            now.ContinuousMilliseconds - Received.ContinuousMilliseconds > AudioAccountMembershipEvidence.MaximumRequestMilliseconds)
            throw new AudioMembershipException(AudioMembershipFailure.InvalidResponse);
    }

    internal bool Contradicts(AudioDeviceIdentity local, AudioDeviceIdentity peer) => new[] { local, peer }.Any(identity =>
    {
        var matches = Snapshot.Devices.Where(identity.Matches).ToArray();
        return matches.Any(row => row.Status != "active") || (!Snapshot.Truncated && matches.Length != 1);
    });
}

/// <summary>Finite runtime evidence, never a transferable certificate. A protected checkpoint
/// can restore its original identity and clock anchors after the owning account record is checked.
/// The first expiry/rollback/revocation is terminal for this runtime instance.</summary>
internal sealed class AudioAccountMembershipEvidence
{
    internal const long MaximumLifetimeMilliseconds = 3_600_000;
    internal const long MaximumRequestMilliseconds = 30_000;
    private int _failure;
    private AudioAccountMembershipEvidence(AudioAccountScope scope, AudioDeviceIdentity local, AudioDeviceIdentity peer,
        AudioAuthorizationTime issued, AudioAuthorizationTime expires, Guid id)
    { Scope = scope; Local = local; Peer = peer; Issued = issued; Expires = expires; Id = id; }
    internal Guid Id { get; }
    internal AudioAccountScope Scope { get; }
    internal AudioDeviceIdentity Local { get; }
    internal AudioDeviceIdentity Peer { get; }
    internal AudioAuthorizationTime Issued { get; }
    internal AudioAuthorizationTime Expires { get; }

    internal static AudioAccountMembershipEvidence Create(AudioRegistryObservation observation, AudioDeviceIdentity local,
        AudioDeviceIdentity peer, long lifetimeMilliseconds = MaximumLifetimeMilliseconds)
    {
        if (observation.Caller != local || local.DeviceId == peer.DeviceId || observation.Snapshot.Truncated ||
            lifetimeMilliseconds is <= 0 or > MaximumLifetimeMilliseconds)
            throw new AudioMembershipException(AudioMembershipFailure.InvalidResponse);
        var callers = observation.Snapshot.Devices.Where(local.Matches).ToArray();
        var peers = observation.Snapshot.Devices.Where(peer.Matches).ToArray();
        if (callers.Length != 1 || !callers[0].IsCaller || callers[0].Status != "active" ||
            peers.Length != 1 || peers[0].IsCaller || peers[0].Status != "active")
            throw new AudioMembershipException(AudioMembershipFailure.InactiveDevice);
        AudioAuthorizationTime expiry;
        try
        {
            expiry = new(checked(observation.Started.WallMilliseconds + lifetimeMilliseconds),
                checked(observation.Started.ContinuousMilliseconds + lifetimeMilliseconds));
        }
        catch (OverflowException) { throw new AudioMembershipException(AudioMembershipFailure.InvalidResponse); }
        if (expiry.WallMilliseconds <= observation.Received.WallMilliseconds ||
            expiry.ContinuousMilliseconds <= observation.Received.ContinuousMilliseconds)
            throw new AudioMembershipException(AudioMembershipFailure.InvalidResponse);
        return new(observation.Scope, local, peer, observation.Started, expiry, Guid.NewGuid());
    }

    // The caller supplies the current protected record's login and actual carrier
    // identities. This boundary verifies the checkpoint before constructing authority.
    internal static AudioAccountMembershipEvidence RestoreCheckpoint(AudioMembershipCheckpoint checkpoint, Guid expectedLogin,
        AudioAccountScope scope, AudioDeviceIdentity local, AudioDeviceIdentity peer,
        Func<AudioAuthorizationTime> clock, IAudioLogonContinuity continuity)
    {
        checkpoint.Validate();
        if (checkpoint.LoginId != expectedLogin || checkpoint.Scope != scope)
            throw new AudioMembershipException(AudioMembershipFailure.ScopeChanged);
        if (!checkpoint.Local.Matches(local) || !checkpoint.Peer.Matches(peer))
            throw new AudioMembershipException(AudioMembershipFailure.IdentityChanged);
        continuity.RequireCurrent(checkpoint.Continuity);
        var evidence = new AudioAccountMembershipEvidence(scope, local, peer, checkpoint.Issued, checkpoint.Expires, checkpoint.EvidenceId);
        evidence.RequireValid(scope, local, peer, clock());
        return evidence;
    }

    internal void RequireValid(AudioAccountScope scope, AudioDeviceIdentity local, AudioDeviceIdentity peer, AudioAuthorizationTime now)
    {
        ThrowIfFailed();
        if (scope != Scope) throw new AudioMembershipException(AudioMembershipFailure.ScopeChanged);
        if (local != Local || peer != Peer) throw new AudioMembershipException(AudioMembershipFailure.IdentityChanged);
        if (now.WallMilliseconds < Issued.WallMilliseconds || now.ContinuousMilliseconds < Issued.ContinuousMilliseconds)
            Fail(AudioMembershipFailure.ClockChanged);
        if (now.WallMilliseconds >= Expires.WallMilliseconds || now.ContinuousMilliseconds >= Expires.ContinuousMilliseconds)
            Fail(AudioMembershipFailure.Expired);
        ThrowIfFailed();
    }
    internal void Revoke() => Interlocked.CompareExchange(ref _failure, (int)AudioMembershipFailure.Revoked, 0);
    private void Fail(AudioMembershipFailure reason)
    { Interlocked.CompareExchange(ref _failure, (int)reason, 0); ThrowIfFailed(); }
    private void ThrowIfFailed()
    { if (Volatile.Read(ref _failure) is var failure && failure != 0) throw new AudioMembershipException((AudioMembershipFailure)failure); }
}
