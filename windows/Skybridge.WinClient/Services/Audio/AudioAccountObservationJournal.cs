using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Skybridge.WinClient.Services.Audio;

internal interface IAudioAccountObservationStore
{
    ValueTask<AudioJournalTicket> BeginAsync(AccountAudioAuthorization epoch, AudioDeviceIdentity caller,
        AccountDeviceRegistryRequest kind, AudioCheckpointIdentity? removalTarget, CancellationToken cancellationToken);
    ValueTask<AudioJournalCompletion> CompleteAsync(AudioJournalTicket ticket, AudioJournalEffects effects, Exception? failure);
}

internal enum AudioJournalCompletion { Committed, RetiredOwner }
internal sealed class AudioJournalPendingObservationException()
    : InvalidOperationException("Audio recovery requires every owned observation to be settled.");
internal sealed record AudioJournalTicket(Guid LoginId, AccountAudioAuthorization Epoch, AudioJournalPending Request);
internal sealed record AudioJournalEffects(AudioRegistryObservation? Registry, AudioCheckpointIdentity? Removed, bool CallerRejected);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record AudioJournalPending(Guid Id, AccountDeviceRegistryRequest Kind,
    AudioCheckpointIdentity Caller, AudioCheckpointIdentity? RemovalTarget)
{
    internal void Validate()
    {
        if (Id == Guid.Empty || !Enum.IsDefined(Kind) || Caller is null ||
            (Kind == AccountDeviceRegistryRequest.Removal) != (RemovalTarget is not null))
            throw new InvalidDataException("Invalid owned audio observation.");
        Caller.Validate(); RemovalTarget?.Validate();
    }
}

// This is data in SessionStore's protected canonical record, not a separate
// credential or an authority-bearing wire message. No method here issues grants.
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record AudioAccountJournalState(int SchemaVersion, Guid LoginId, AudioAccountScope Scope,
    AudioJournalPending[] Pending, AudioMembershipCheckpoint[] Checkpoints)
{
    internal const int CurrentSchema = 1;
    internal const int Capacity = 32;

    internal static AudioAccountJournalState Empty(Guid loginId, AudioAccountScope scope) =>
        new(CurrentSchema, loginId, scope, [], []);

    internal static AudioAccountJournalState Read(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Audio journal must be a JSON object.");
        RequireUniqueFields(value);
        AudioAccountJournalState state;
        try { state = value.Deserialize<AudioAccountJournalState>() ?? throw new InvalidDataException("Missing audio journal."); }
        catch (JsonException error) { throw new InvalidDataException("Invalid audio journal JSON.", error); }
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
        if (Pending.Length >= Capacity || Pending.Any(p => p.Id == request.Id))
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

    internal AudioAccountJournalState Complete(AudioJournalPending request, AudioJournalEffects effects, Exception? failure)
    {
        Validate(); request.Validate();
        if (!Pending.Any(p => p == request))
            throw new InvalidOperationException("Audio observation no longer owns its journal entry.");
        if (effects.Registry is { } registry && (request.Kind != AccountDeviceRegistryRequest.List || registry.Scope != Scope ||
                !request.Caller.Matches(registry.Caller)) ||
            effects.Removed is { } removed && (request.Kind != AccountDeviceRegistryRequest.Removal || removed != request.RemovalTarget) ||
            failure is null && request.Kind == AccountDeviceRegistryRequest.List && effects.Registry is null ||
            failure is null && request.Kind == AccountDeviceRegistryRequest.Removal && effects.Removed is null)
            throw new InvalidDataException("Audio observation completion does not match its prepared request.");

        // A confirmed negative is applied even when the waiter was canceled or
        // its callback subsequently failed. An uncertain removal cannot retain
        // the selected identity's offline authority. Known temporary read-only
        // failures preserve the original finite evidence, without renewal.
        bool uncertainRemoval = request.Kind == AccountDeviceRegistryRequest.Removal && failure is not null;
        bool terminalFailure = failure is not null && !IsTemporaryOrCanceled(failure);
        bool Keep(AudioMembershipCheckpoint checkpoint)
        {
            bool Contains(AudioCheckpointIdentity identity) => checkpoint.Local == identity || checkpoint.Peer == identity;
            if ((effects.CallerRejected || terminalFailure) && Contains(request.Caller)) return false;
            if (effects.Removed is { } target && Contains(target)) return false;
            if (uncertainRemoval && request.RemovalTarget is { } uncertain && Contains(uncertain)) return false;
            if (effects.Registry is { } observed && new[] { checkpoint.Local, checkpoint.Peer }.Any(identity =>
            {
                var matches = observed.Snapshot.Devices.Where(row => row.DeviceId == identity.DeviceId &&
                    row.Algorithm == identity.Algorithm && row.Fingerprint == identity.Fingerprint).ToArray();
                return matches.Any(row => row.Status != "active") || (!observed.Snapshot.Truncated && matches.Length != 1);
            })) return false;
            return true;
        }
        return this with { Pending = Pending.Where(p => p.Id != request.Id).ToArray(), Checkpoints = Checkpoints.Where(Keep).ToArray() };
    }

    private static bool IsTemporaryOrCanceled(Exception failure) => failure switch
    {
        OperationCanceledException => true,
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
