using System.Collections.Immutable;
using Skybridge.WinClient.Services.RemoteControl;

namespace Skybridge.WinClient.Services;

internal sealed record LanPibLocalIdentity(string DeviceId, string DeviceName, ImmutableArray<byte> PublicKey);
internal sealed record LanPibApprovalRequest(LanPibRequest Request, LanPibCandidate Candidate,
    string SasCode, Action RequireCurrent);
internal interface ILanPibApprovalPresenter
{
    bool StageCandidate => false;
    Task<bool> ShowAsync(LanPibApprovalRequest request, CancellationToken token);
}
internal sealed class LanPibRejectedException(string code, string message, Exception? inner = null) : IOException(message, inner)
{
    internal string Code { get; } = code;
}

/// <summary>One listener/account lifetime, spanning two short TCP connections.
/// Candidate creation never grants trust. Only a verified confirmation plus local
/// SAS approval reaches the durable commit port, and the ACK is cached after commit.
/// All native and UI work stays owned by the accepting worker until it actually ends.</summary>
internal sealed class LanPibResponder
{
    internal const int MaximumTransactions = 32, MaximumPerRequester = 4;
    internal const int MaximumAttemptsPerWindow = 64, MaximumRequesterAttempts = 8;
    private readonly object _gate = new(), _clockGate = new();
    private readonly LanPibLocalIdentity _local;
    private readonly string _fingerprint;
    private readonly Func<byte[], ImmutableArray<byte>> _sign;
    private readonly Action<ImmutableArray<byte>, byte[], ImmutableArray<byte>> _verify;
    private readonly Action<RemoteControlPairingMaterial> _preflight;
    private readonly Func<RemoteControlPairingMaterial, Action, CancellationToken, Task> _commit;
    private readonly ILanPibApprovalPresenter _approval;
    private readonly Action _requireCurrent;
    private readonly TimeProvider _time;
    private readonly Dictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly Queue<(string Fingerprint, long Stamp)> _attempts = [];
    private long _lastWall = long.MinValue;
    private enum Phase { Building, Candidate, Confirming, Completed, Failed }
    private sealed class Entry(LanPibRequest request, long admitted)
    {
        internal LanPibRequest Request { get; } = request;
        internal long Admitted { get; } = admitted;
        internal Phase Phase = Phase.Building;
        internal LanPibCandidate? Candidate;
        internal string? ConfirmHash;
        internal Task<LanPibFinalAck>? Finalization;
        internal LanPibFinalAck? Ack;
        internal Task<(bool Match, Exception? Failure)>? EarlyApproval;
    }

    internal LanPibResponder(LanPibLocalIdentity local, Func<byte[], ImmutableArray<byte>> sign,
        Action<ImmutableArray<byte>, byte[], ImmutableArray<byte>> verify,
        Action<RemoteControlPairingMaterial> preflight,
        Func<RemoteControlPairingMaterial, Action, CancellationToken, Task> commit,
        ILanPibApprovalPresenter approval, Action requireCurrent, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(local); ArgumentNullException.ThrowIfNull(sign);
        ArgumentNullException.ThrowIfNull(verify); ArgumentNullException.ThrowIfNull(preflight);
        ArgumentNullException.ThrowIfNull(commit); ArgumentNullException.ThrowIfNull(approval);
        ArgumentNullException.ThrowIfNull(requireCurrent);
        if (RemoteControlHandshakeBinding.CanonicalDeviceId(local.DeviceId) != local.DeviceId)
            throw new InvalidDataException("PIB requires the actual canonical local device identity.");
        _fingerprint = new WebRtcProductProtocolIdentityPublicKey(WebRtcProductSignatureAlgorithm.MlDsa65,
            local.PublicKey.ToArray()).AuthoritativeFingerprint;
        _ = LanPibCanonical.Token(local.DeviceName);
        _local = local; _sign = sign; _verify = verify; _preflight = preflight;
        _commit = commit; _approval = approval; _requireCurrent = requireCurrent; _time = time ?? TimeProvider.System;
    }

    internal LanPibCandidate CreateCandidate(LanPibRequest request, CancellationToken token, CancellationToken? ownerLifetime = null)
    {
        RequireCurrent(token);
        var now = ObserveTime();
        LanPibValidation.RequireRequestFreshness(request, now.Wall);
        if (request.RequesterProtocolSigningAlgorithm != "ML-DSA-65" ||
            !request.RequestedProtocolSigningAlgorithms.Contains("ML-DSA-65", StringComparer.Ordinal))
            throw Reject("unsupportedSignatureAlgorithm", "This Windows identity requires ML-DSA-65 in both pairing directions.");
        if (RemoteControlHandshakeBinding.CanonicalDeviceId(request.TargetDeviceId) != _local.DeviceId)
            throw Reject("targetIdentityMismatch", "The PIB request targets a different device.");
        var material = RequesterMaterial(request);
        if (material.DeviceId == _local.DeviceId || material.ProtocolPublicKeyFingerprint == _fingerprint)
            throw Reject("selfPairing", "The local device cannot pair with itself.");
        lock (_gate)
        {
            now = ObserveTime();
            LanPibValidation.RequireRequestFreshness(request, now.Wall);
            Prune(now.Stamp, now.Wall); AdmitAttempt(material.ProtocolPublicKeyFingerprint, now.Stamp);
            var id = LanPibCanonical.Transaction(request.TransactionId);
            if (_entries.TryGetValue(id, out var prior))
            {
                // RequestHash excludes its signature, but SAS includes it. Both
                // must match before returning a previously signed candidate.
                if (LanPibCanonical.RequestHash(prior.Request) != LanPibCanonical.RequestHash(request) ||
                    !prior.Request.RequesterSignature.AsSpan().SequenceEqual(request.RequesterSignature.AsSpan()))
                    throw Reject("conflictingTransaction", "This transaction already binds another request.");
                if (prior.Phase == Phase.Failed) throw Reject("replay", "This pairing transaction previously failed.");
                var existing = RequireCandidate(prior);
                RequireLive(prior, token);
                return existing;
            }
            if (_entries.Count >= MaximumTransactions ||
                _entries.Values.Count(e => LanPibCanonical.Hex(e.Request.RequesterProtocolIdentityFingerprint) == material.ProtocolPublicKeyFingerprint) >= MaximumPerRequester)
                throw Reject("capacityReached", "PIB transaction capacity is exhausted until existing entries expire.");
            _verify(request.RequesterProtocolIdentityPublicKey, LanPibCanonical.RequestPreimage(request), request.RequesterSignature);
            RequireCurrent(token); _preflight(material);
            var entry = new Entry(request, _time.GetTimestamp()); _entries.Add(id, entry);
            try
            {
                var issued = ObserveTime().Wall / 1000.0 - 978307200.0;
                var candidate = new LanPibCandidate(2, request.TransactionId, request.TargetDeviceId, "ML-DSA-65",
                    _local.PublicKey, _fingerprint, issued, issued + 300, request.Nonce, LanPibCanonical.RequestHash(request), [],
                    [], _local.DeviceName, BonjourEndpointDigest: request.BonjourEndpointDigest);
                candidate = candidate with { Signature = _sign(LanPibCanonical.CandidatePreimage(candidate)) };
                RequireCurrent(token);
                LanPibValidation.RequireCandidateBindings(request, candidate, _fingerprint, ObserveTime().Wall);
                if (_time.GetElapsedTime(entry.Admitted, _time.GetTimestamp()) >= TimeSpan.FromMinutes(5))
                    throw Reject("expired", "Candidate generation outlived its transaction.");
                entry.Candidate = candidate; entry.Phase = Phase.Candidate;
                if (_approval.StageCandidate) entry.EarlyApproval = StageAsync(entry, candidate, ownerLifetime ?? token);
                return candidate;
            }
            catch { entry.Phase = Phase.Failed; throw; }
        }
    }

    // The receiver must show the digits while the requester is comparing them.
    // Its choice alone cannot sign an ACK or write an identity.
    private async Task<(bool Match, Exception? Failure)> StageAsync(Entry entry, LanPibCandidate candidate, CancellationToken lifetime)
    {
        await Task.Yield();
        using var scope = CancellationTokenSource.CreateLinkedTokenSource(lifetime);
        try
        {
            scope.CancelAfter(TimeSpan.FromMinutes(5));
            void Check() => RequireLive(entry, scope.Token);
            Check();
            var request = new LanPibApprovalRequest(entry.Request, candidate, LanPibCanonical.SasCode(entry.Request, candidate), Check);
            var match = await _approval.ShowAsync(request, scope.Token).ConfigureAwait(false);
            Check(); return (match, null);
        }
        catch (Exception failure) { return (false, failure); }
    }

    internal async Task<LanPibFinalAck> ConfirmAsync(LanPibConfirm confirm, CancellationToken token)
    {
        RequireCurrent(token); LanPibValidation.RequireConfirmShape(confirm);
        Task<LanPibFinalAck> completion;
        lock (_gate)
        {
            var now = ObserveTime(); Prune(now.Stamp, now.Wall);
            AdmitAttempt(LanPibCanonical.Hex(confirm.RequesterProtocolIdentityFingerprint), now.Stamp);
            if (!_entries.TryGetValue(LanPibCanonical.Transaction(confirm.TransactionId), out var entry))
                throw Reject("transactionMissingOrExpired", "The PIB transaction is absent or expired.");
            var candidate = RequireCandidate(entry); RequireLive(entry, token);
            LanPibValidation.RequireConfirmBindings(entry.Request, candidate, confirm, now.Wall);
            var hash = LanPibCanonical.ConfirmHash(confirm);
            if (entry.ConfirmHash is not null && entry.ConfirmHash != hash)
                throw Reject("conflictingConfirmation", "The PIB transaction already binds another confirmation.");
            if (entry.Phase == Phase.Failed) throw Reject("replay", "This pairing transaction previously failed.");
            if (entry.Phase == Phase.Completed)
            {
                var cached = entry.Ack ?? throw new InvalidOperationException("A committed PIB transaction lost its ACK.");
                LanPibValidation.RequireFinalAckBindings(entry.Request, candidate, confirm, cached, now.Wall);
                return cached;
            }
            if (entry.Phase == Phase.Candidate)
            {
                _verify(entry.Request.RequesterProtocolIdentityPublicKey, LanPibCanonical.ConfirmPreimage(confirm), confirm.RequesterSignature);
                RequireLive(entry, token);
                entry.ConfirmHash = hash; entry.Phase = Phase.Confirming;
                entry.Finalization = FinalizeAsync(entry, confirm, token);
            }
            completion = entry.Finalization ?? throw new InvalidOperationException("A PIB confirmation has no owned finalization.");
        }
        // A duplicate waits for the same actual owner. Its cancellation cannot
        // detach or cancel an independently approved primary request.
        var ack = await completion.ConfigureAwait(false);
        token.ThrowIfCancellationRequested();
        return ack;
    }

    private async Task<LanPibFinalAck> FinalizeAsync(Entry entry, LanPibConfirm confirm, CancellationToken token)
    {
        await Task.Yield(); // Publish the owned task before invoking any UI callback.
        using var scope = CancellationTokenSource.CreateLinkedTokenSource(token);
        try
        {
            var candidate = RequireCandidate(entry);
            var nowAtPrompt = ObserveTime();
            var parentExpiry = Math.Min(LanPibCanonical.Milliseconds(candidate.ExpiresAt), LanPibCanonical.Milliseconds(confirm.ExpiresAt));
            var remaining = Math.Min(195, Math.Min((parentExpiry - (double)nowAtPrompt.Wall) / 1000.0,
                300 - _time.GetElapsedTime(entry.Admitted, nowAtPrompt.Stamp).TotalSeconds));
            if (remaining <= 0) throw Reject("expired", "The pairing deadline elapsed before approval.");
            scope.CancelAfter(TimeSpan.FromSeconds(remaining));
            void RequireConfirmation()
            {
                var now = RequireLive(entry, scope.Token);
                LanPibValidation.RequireConfirmBindings(entry.Request, candidate, confirm, now);
            }
            RequireConfirmation();
            var request = new LanPibApprovalRequest(entry.Request, candidate,
                LanPibCanonical.SasCode(entry.Request, candidate), RequireConfirmation);
            bool approved;
            if (entry.EarlyApproval is { } pending)
            {
                var early = await pending.WaitAsync(scope.Token).ConfigureAwait(false);
                if (early.Failure != null) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(early.Failure).Throw();
                approved = early.Match;
            }
            else approved = await _approval.ShowAsync(request, scope.Token).ConfigureAwait(false);
            RequireConfirmation();
            if (!approved) throw Reject("userRejected", "The local operator declined the pairing code.");
            var now = ObserveTime().Wall / 1000.0 - 978307200.0;
            var ack = new LanPibFinalAck(3, entry.Request.TransactionId, entry.Request.RequesterDeviceId, candidate.DeviceId,
                entry.Request.RequesterProtocolIdentityFingerprint, candidate.ProtocolIdentityFingerprint, entry.Request.Nonce,
                confirm.ConfirmationNonce, LanPibCanonical.RequestHash(entry.Request), LanPibCanonical.CandidateHash(candidate),
                LanPibCanonical.ConfirmHash(confirm), LanPibCanonical.SasTranscriptHash(entry.Request, candidate),
                true, now, Math.Min(candidate.ExpiresAt, confirm.ExpiresAt), []);
            ack = ack with { ResponderSignature = _sign(LanPibCanonical.FinalAckPreimage(ack)) };
            void RequireCommit()
            {
                var current = RequireLive(entry, scope.Token);
                LanPibValidation.RequireFinalAckBindings(entry.Request, candidate, confirm, ack, current);
            }
            RequireCommit();
            await _commit(RequesterMaterial(entry.Request), RequireCommit, scope.Token).ConfigureAwait(false);
            // Once persistence reports actual success, retain that fact even if
            // cancellation/expiry now prevents sending. Transport loss is not rollback.
            lock (_gate) { entry.Ack = ack; entry.Phase = Phase.Completed; }
            return ack;
        }
        catch (OperationCanceledException error) when (!token.IsCancellationRequested && scope.IsCancellationRequested &&
            error.CancellationToken == scope.Token && error.InnerException is null)
        {
            lock (_gate) entry.Phase = Phase.Failed;
            throw new LanPibRejectedException("expired", "The pairing approval deadline elapsed.", error);
        }
        catch { lock (_gate) entry.Phase = Phase.Failed; throw; }
    }

    internal void RequireCandidateSend(LanPibRequest request, LanPibCandidate candidate, CancellationToken token)
    {
        lock (_gate)
        {
            if (!_entries.TryGetValue(LanPibCanonical.Transaction(request.TransactionId), out var entry) ||
                !ReferenceEquals(entry.Candidate, candidate) || entry.Phase == Phase.Failed)
                throw Reject("transactionMissingOrExpired", "The candidate no longer belongs to this listener.");
            LanPibValidation.RequireCandidateBindings(request, candidate, _fingerprint, RequireLive(entry, token));
        }
    }
    internal void RequireAckSend(LanPibConfirm confirm, LanPibFinalAck ack, CancellationToken token)
    {
        lock (_gate)
        {
            if (!_entries.TryGetValue(LanPibCanonical.Transaction(confirm.TransactionId), out var entry) ||
                entry.Phase != Phase.Completed || !ReferenceEquals(entry.Ack, ack))
                throw Reject("transactionMissingOrExpired", "The ACK has no committed transaction in this listener.");
            LanPibValidation.RequireFinalAckBindings(entry.Request, RequireCandidate(entry), confirm, ack, RequireLive(entry, token));
        }
    }
    private static RemoteControlPairingMaterial RequesterMaterial(LanPibRequest request)
    {
        var canonical = RemoteControlHandshakeBinding.CanonicalDeviceId(request.RequesterDeviceId);
        // PIB does not carry a requester display name; store its actual stable ID.
        return RemoteControlPairingMaterial.CreateProtocolIdentity(canonical, canonical[3..],
            request.RequesterProtocolIdentityPublicKey.AsSpan());
    }
    private static LanPibCandidate RequireCandidate(Entry entry) => entry.Candidate ??
        throw Reject("transactionUnavailable", "The PIB transaction has no completed candidate.");
    private long RequireLive(Entry entry, CancellationToken token)
    {
        // No transaction monitor here: persistence invokes this under the identity
        // store lock immediately before its atomic commit. Avoid lock inversion.
        RequireCurrent(token); var now = ObserveTime();
        if (_time.GetElapsedTime(entry.Admitted, now.Stamp) >= TimeSpan.FromMinutes(5) ||
            LanPibCanonical.Milliseconds(RequireCandidate(entry).ExpiresAt) <= now.Wall)
            throw Reject("expired", "The PIB transaction has expired.");
        return now.Wall;
    }
    private void RequireCurrent(CancellationToken token) { token.ThrowIfCancellationRequested(); _requireCurrent(); }
    private (long Wall, long Stamp) ObserveTime()
    {
        lock (_clockGate)
        {
            var wall = _time.GetUtcNow().ToUnixTimeMilliseconds();
            if (wall < 0 || wall < _lastWall) throw Reject("clockRollback", "The pairing clock moved behind an observed timestamp.");
            _lastWall = wall; return (wall, _time.GetTimestamp());
        }
    }
    private void Prune(long stamp, long wall)
    {
        // A stalled wall clock must not let an identical still-"fresh" request
        // resurrect a transaction whose monotonic TTL has elapsed.
        foreach (var pair in _entries.Where(p => p.Value.Phase is not (Phase.Building or Phase.Confirming) &&
            _time.GetElapsedTime(p.Value.Admitted, stamp) >= TimeSpan.FromMinutes(5) &&
            (decimal)wall - LanPibCanonical.Milliseconds(p.Value.Request.SentAt) > 120_000).ToArray()) _entries.Remove(pair.Key);
        while (_attempts.TryPeek(out var attempt) && _time.GetElapsedTime(attempt.Stamp, stamp) >= TimeSpan.FromSeconds(10)) _attempts.Dequeue();
    }
    private void AdmitAttempt(string fingerprint, long stamp)
    {
        if (_attempts.Count >= MaximumAttemptsPerWindow || _attempts.Count(a => a.Fingerprint == fingerprint) >= MaximumRequesterAttempts)
            throw Reject("rateLimited", "PIB request rate is exhausted until the ten-second window expires.");
        _attempts.Enqueue((fingerprint, stamp));
    }
    private static LanPibRejectedException Reject(string code, string message) => new(code, message);
}
