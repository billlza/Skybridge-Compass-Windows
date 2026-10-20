using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Skybridge.WinClient.Services.Audio;

internal interface IAudioAccountObservationStore
{
    ValueTask<AudioJournalTicket> BeginAsync(AccountAudioAuthorization epoch, AudioDeviceIdentity caller,
        AccountDeviceRegistryRequest kind, AudioCheckpointIdentity? removalTarget, CancellationToken cancellationToken,
        AudioDeviceIdentity? membershipPeer = null);
    ValueTask<AudioJournalCompletion> CompleteAsync(AudioJournalTicket ticket, AudioJournalEffects effects, Exception? failure);
}

internal enum AudioJournalCompletion { Committed, RetiredOwner, Contradicted }
internal sealed class AudioJournalPendingObservationException()
    : InvalidOperationException("Audio recovery requires every owned observation to be settled.");
internal sealed record AudioJournalTicket(Guid LoginId, AccountAudioAuthorization Epoch, AudioJournalPending Request);
internal sealed record AudioJournalEffects(AudioRegistryObservation? Registry, AudioCheckpointIdentity? Removed,
    bool CallerRejected, AudioMembershipCheckpoint? Granted = null);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record AudioJournalPending(Guid Id, AccountDeviceRegistryRequest Kind,
    AudioCheckpointIdentity Caller, AudioCheckpointIdentity? RemovalTarget,
    AudioCheckpointIdentity? MembershipPeer = null, bool Contradicted = false)
{
    internal void Validate()
    {
        if (Id == Guid.Empty || !Enum.IsDefined(Kind) || Caller is null ||
            (Kind == AccountDeviceRegistryRequest.Removal) != (RemovalTarget is not null) ||
            MembershipPeer is not null && (Kind != AccountDeviceRegistryRequest.List || MembershipPeer.DeviceId == Caller.DeviceId) ||
            Contradicted && MembershipPeer is null)
            throw new InvalidDataException("Invalid owned audio observation.");
        Caller.Validate(); RemovalTarget?.Validate(); MembershipPeer?.Validate();
    }
}

// This is data in SessionStore's protected canonical record, not a separate
// credential or an authority-bearing wire message. Only an owned fresh membership
// query can attach its already verified finite checkpoint; registry observations
// alone cannot issue or renew one.
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record AudioAccountJournalState(int SchemaVersion, Guid LoginId, AudioAccountScope Scope,
    AudioJournalPending[] Pending, AudioMembershipCheckpoint[] Checkpoints)
{
    internal const int CurrentSchema = 2;
    internal const int Capacity = 32;

    internal static AudioAccountJournalState Empty(Guid loginId, AudioAccountScope scope) =>
        new(CurrentSchema, loginId, scope, [], []);

    internal static AudioAccountJournalState Read(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Audio journal must be a JSON object.");
        RequireUniqueFields(value);
        // Schema 2 must encode the contradiction bit explicitly. A missing
        // field cannot silently deserialize to false and revive a pending query.
        if (value.TryGetProperty(nameof(SchemaVersion), out var version) && version.ValueKind == JsonValueKind.Number &&
            version.TryGetInt32(out var schema) && schema == CurrentSchema &&
            value.TryGetProperty(nameof(Pending), out var pending) && pending.ValueKind == JsonValueKind.Array)
            foreach (var item in pending.EnumerateArray())
                if (item.ValueKind != JsonValueKind.Object || new[] { nameof(AudioJournalPending.Id), nameof(AudioJournalPending.Kind),
                    nameof(AudioJournalPending.Caller), nameof(AudioJournalPending.RemovalTarget), nameof(AudioJournalPending.MembershipPeer),
                    nameof(AudioJournalPending.Contradicted) }.Any(field => !item.TryGetProperty(field, out _)))
                    throw new InvalidDataException("Audio journal observation is missing an explicit ownership field.");
        AudioAccountJournalState state;
        try { state = value.Deserialize<AudioAccountJournalState>() ?? throw new InvalidDataException("Missing audio journal."); }
        catch (JsonException error) { throw new InvalidDataException("Invalid audio journal JSON.", error); }
        // Schema 1 only owned registry observations. Preserve every old pending
        // entry and checkpoint; migration cannot invent membership-query owners.
        if (state.SchemaVersion == 1)
        {
            if (state.Pending is null || state.Pending.Any(p => p is null || p.MembershipPeer is not null || p.Contradicted))
                throw new InvalidDataException("Invalid legacy audio journal ownership.");
            state = state with { SchemaVersion = CurrentSchema };
        }
        state.Validate();
        return state;
    }

    internal void Validate()
    {
        if (SchemaVersion != CurrentSchema || LoginId == Guid.Empty || Scope is null ||
            Pending is null || Checkpoints is null || Pending.Length > Capacity || Checkpoints.Length > Capacity ||
            Pending.Any(p => p is null) || Checkpoints.Any(c => c is null))
            throw new InvalidDataException("Invalid or unsupported audio journal.");
        Scope.Validate();
        foreach (var request in Pending) request.Validate();
        foreach (var checkpoint in Checkpoints)
        {
            checkpoint.Validate();
            if (checkpoint.LoginId != LoginId || checkpoint.Scope != Scope)
                throw new InvalidDataException("Audio journal checkpoint belongs to another account owner.");
        }
        if (Pending.Select(p => p.Id).Distinct().Count() != Pending.Length ||
            Checkpoints.Select(c => c.EvidenceId).Distinct().Count() != Checkpoints.Length ||
            Checkpoints.Select(c => (c.Local, c.Peer)).Distinct().Count() != Checkpoints.Length)
            throw new InvalidDataException("Duplicate audio journal ownership or evidence.");
    }

    internal AudioAccountJournalState Begin(AudioJournalPending request)
    {
        Validate(); request.Validate();
        if (request.Contradicted || Pending.Length >= Capacity || Pending.Any(p => p.Id == request.Id))
            throw new InvalidOperationException("The audio observation journal cannot admit this request.");
        return this with { Pending = [.. Pending, request] };
    }

    // Eligibility to inspect saved evidence only. Each candidate still requires
    // its original clock bounds, exact peer binding and logon seal to restore;
    // transport admission and source/output consent remain separate.
    internal IReadOnlyList<AudioMembershipCheckpoint> ReadRecoveryCandidates(Guid expectedLogin, AudioAccountScope expectedScope)
    {
        Validate();
        if (LoginId != expectedLogin || Scope != expectedScope)
            throw new InvalidDataException("Audio recovery belongs to another account owner.");
        if (Pending.Length != 0) throw new AudioJournalPendingObservationException();
        return Array.AsReadOnly(Checkpoints.ToArray());
    }

    internal (AudioAccountJournalState State, AudioJournalCompletion Completion) Complete(
        AudioJournalPending request, AudioJournalEffects effects, Exception? failure)
    {
        Validate(); request.Validate();
        var owned = Pending.SingleOrDefault(p => (p with { Contradicted = false }) == request)
            ?? throw new InvalidOperationException("Audio observation no longer owns its journal entry.");
        if (effects.Registry is { } registry && (request.Kind != AccountDeviceRegistryRequest.List || registry.Scope != Scope ||
                !request.Caller.Matches(registry.Caller)) ||
            effects.Removed is { } removed && (request.Kind != AccountDeviceRegistryRequest.Removal || removed != request.RemovalTarget) ||
            failure is null && request.Kind == AccountDeviceRegistryRequest.List && effects.Registry is null ||
            failure is null && request.Kind == AccountDeviceRegistryRequest.Removal && effects.Removed is null)
            throw new InvalidDataException("Audio observation completion does not match its prepared request.");
        if (effects.Granted is { } granted)
        {
            granted.Validate();
            if (failure is not null || request.MembershipPeer is null || effects.Registry is not { } fresh ||
                granted.LoginId != LoginId || granted.Scope != Scope || granted.Local != request.Caller ||
                granted.Peer != request.MembershipPeer || granted.Issued != fresh.Started || fresh.Snapshot.Truncated ||
                granted.Expires.WallMilliseconds <= fresh.Received.WallMilliseconds ||
                granted.Expires.ContinuousMilliseconds <= fresh.Received.ContinuousMilliseconds ||
                new[] { granted.Local, granted.Peer }.Any(identity => {
                    var rows = fresh.Snapshot.Devices.Where(row => row.DeviceId == identity.DeviceId &&
                        row.Algorithm == identity.Algorithm && row.Fingerprint == identity.Fingerprint).ToArray();
                    return rows.Length != 1 || rows[0].Status != "active" || rows[0].IsCaller != (identity == granted.Local);
                }))
                throw new InvalidDataException("Audio checkpoint does not belong to this fresh membership observation.");
        }

        // A confirmed negative is applied even when the waiter was canceled or
        // its callback subsequently failed. An uncertain removal cannot retain
        // the selected identity's offline authority. Known temporary read-only
        // failures preserve the original finite evidence, without renewal.
        bool uncertainRemoval = request.Kind == AccountDeviceRegistryRequest.Removal && failure is not null;
        bool parsedInactivePeer = effects.Registry is not null && failure is AudioMembershipException { Reason: AudioMembershipFailure.InactiveDevice };
        bool terminalFailure = failure is not null && !parsedInactivePeer && !PreservesUncontradictedEvidence(failure);
        bool Keep(AudioCheckpointIdentity local, AudioCheckpointIdentity? peer)
        {
            bool Contains(AudioCheckpointIdentity identity) => local == identity || peer == identity;
            if ((effects.CallerRejected || terminalFailure) && Contains(request.Caller)) return false;
            if (effects.Removed is { } target && Contains(target)) return false;
            if (uncertainRemoval && request.RemovalTarget is { } uncertain && Contains(uncertain)) return false;
            if (effects.Registry is { } observed && new[] { local, peer }.OfType<AudioCheckpointIdentity>().Any(identity =>
            {
                var matches = observed.Snapshot.Devices.Where(row => row.DeviceId == identity.DeviceId &&
                    row.Algorithm == identity.Algorithm && row.Fingerprint == identity.Fingerprint).ToArray();
                return matches.Any(row => row.Status != "active") || (!observed.Snapshot.Truncated && matches.Length != 1);
            })) return false;
            return true;
        }
        bool contradicted = owned.Contradicted || !Keep(owned.Caller, owned.MembershipPeer);
        var checkpoints = Checkpoints.Where(c => Keep(c.Local, c.Peer)).ToList();
        if (effects.Granted is { } checkpoint && !contradicted)
        {
            // A fresh authenticated observation supplies both clock readings.
            // Remove only evidence that its original finite bounds already
            // reject; capacity pressure must not evict a still-valid grant.
            var now = effects.Registry!.Received;
            checkpoints.RemoveAll(c => now.WallMilliseconds < c.Issued.WallMilliseconds ||
                now.ContinuousMilliseconds < c.Issued.ContinuousMilliseconds ||
                now.WallMilliseconds >= c.Expires.WallMilliseconds || now.ContinuousMilliseconds >= c.Expires.ContinuousMilliseconds);
            checkpoints.RemoveAll(c => c.Local == checkpoint.Local && c.Peer == checkpoint.Peer);
            if (checkpoints.Count >= Capacity) throw new InvalidOperationException("The audio checkpoint store is full.");
            checkpoints.Add(checkpoint);
        }
        var state = this with {
            Pending = Pending.Where(p => p.Id != request.Id).Select(p => p.MembershipPeer is not null &&
                !Keep(p.Caller, p.MembershipPeer) ? p with { Contradicted = true } : p).ToArray(),
            Checkpoints = checkpoints.ToArray()
        };
        state.Validate();
        return (state, effects.Granted is not null && contradicted ? AudioJournalCompletion.Contradicted : AudioJournalCompletion.Committed);
    }

    private static bool PreservesUncontradictedEvidence(Exception failure) => failure switch
    {
        OperationCanceledException => true,
        AudioMembershipSupersededException => true,
        AudioMembershipQueryTimeoutException => true,
        HttpRequestException request => AudioMembershipRequestFailure.IsTemporary(request),
        HttpIOException response => AudioMembershipRequestFailure.IsTemporary(response),
        CurrentPathSignalServerException response => AccountDeviceWire.ErrorCode(response) != "current_identity_mismatch" &&
            !AudioAccountMembershipProvider.IsDeviceDenial(response) && AudioMembershipRequestFailure.IsTemporary(response.StatusCode),
        _ => false
    };

    private static void RequireUniqueFields(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in value.EnumerateObject())
            {
                if (!names.Add(property.Name)) throw new InvalidDataException("Duplicate audio journal JSON field.");
                RequireUniqueFields(property.Value);
            }
        }
        else if (value.ValueKind == JsonValueKind.Array)
            foreach (var item in value.EnumerateArray()) RequireUniqueFields(item);
    }
}

internal sealed class AudioJournalStorageException(string stage, string status, SessionStoreFailure? failure = null,
    SessionStoreFailure? cleanupFailure = null) : IOException($"Audio journal {stage} failed: {status}.")
{
    internal SessionStoreFailure? Failure { get; } = failure;
    internal SessionStoreFailure? CleanupFailure { get; } = cleanupFailure;
}
