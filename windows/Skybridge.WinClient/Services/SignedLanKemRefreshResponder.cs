using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;

namespace Skybridge.WinClient.Services;

internal sealed record LanKemRefreshInventory(string DeviceId, ImmutableArray<byte> SigningPublicKey,
    ImmutableArray<LanKemRefreshPublicKey> Keys, string Platform, string OsVersion, string QAuthProfile);

internal sealed class LanKemRefreshRejectedException(string code, string message) : IOException(message)
{
    internal string Code { get; } = code;
}

/// <summary>One immutable identity/inventory and one captured account lifetime. Only
/// public replies are cached; current approved authority is sampled for each request.
/// A claimed requester pin is not a proof of possession.</summary>
internal sealed class SignedLanKemRefreshResponder
{
    internal const int MaximumEntries = 256;
    internal const int RequestsPerMinute = 10;
    private readonly object _gate = new();
    private readonly LanKemRefreshInventory _inventory;
    private readonly Func<IReadOnlyCollection<RemoteControlTrustedPeer>> _readTrusted;
    private readonly Func<byte[], ImmutableArray<byte>> _sign;
    private readonly Action _requireCurrent;
    private readonly TimeProvider _time;
    private readonly string _fingerprint;
    private readonly ImmutableArray<int> _permitted;
    private readonly Dictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Queue<long>> _windows = new(StringComparer.Ordinal);
    private long _lastWall = long.MinValue;
    private sealed class Entry(long admitted)
    {
        internal long Admitted { get; } = admitted;
        internal LanSignedKemRefresh? Completed { get; set; }
    }

    internal SignedLanKemRefreshResponder(LanKemRefreshInventory inventory,
        IReadOnlyCollection<RemoteControlTrustedPeer> trusted, Func<byte[], ImmutableArray<byte>> sign,
        Action requireCurrent, TimeProvider? time = null)
        : this(inventory, Capture(trusted), sign, requireCurrent, time) { }

    internal SignedLanKemRefreshResponder(LanKemRefreshInventory inventory,
        Func<IReadOnlyCollection<RemoteControlTrustedPeer>> readTrusted, Func<byte[], ImmutableArray<byte>> sign,
        Action requireCurrent, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(inventory); ArgumentNullException.ThrowIfNull(readTrusted);
        ArgumentNullException.ThrowIfNull(sign); ArgumentNullException.ThrowIfNull(requireCurrent);
        if (inventory.Keys.IsDefault || inventory.Keys.Length != 2 ||
            !inventory.Keys.Select(k => k.SuiteWireId).Order().SequenceEqual(new[] { 0x0012, 0x0101 }))
            throw new InvalidDataException("Windows SKR requires the actual Q and ML-KEM inventory.");
        foreach (var key in inventory.Keys) SignedLanKemRefreshCanonical.RequireKey(key);
        _permitted = inventory.Keys.Select(k => k.SuiteWireId).Order().ToImmutableArray();
        SignedLanKemRefreshCanonical.RequireCapabilities(_permitted, inventory.Platform, inventory.OsVersion, inventory.QAuthProfile, true);
        _fingerprint = new WebRtcProductProtocolIdentityPublicKey(WebRtcProductSignatureAlgorithm.MlDsa65,
            inventory.SigningPublicKey.ToArray()).AuthoritativeFingerprint;
        if (RemoteControlHandshakeBinding.CanonicalDeviceId(inventory.DeviceId) != inventory.DeviceId)
            throw new InvalidDataException("SKR local identity is not canonical.");
        _readTrusted = readTrusted;
        _ = ReadTrusted();
        _inventory = inventory; _sign = sign; _requireCurrent = requireCurrent; _time = time ?? TimeProvider.System;
    }
    private static Func<IReadOnlyCollection<RemoteControlTrustedPeer>> Capture(IReadOnlyCollection<RemoteControlTrustedPeer> trusted)
    {
        ArgumentNullException.ThrowIfNull(trusted);
        var snapshot = trusted.Select(p => new RemoteControlTrustedPeer(p.DeviceId,
            p.ProtocolPublicKeyFingerprint, p.KnownDeviceIds?.ToArray())).ToArray();
        return () => snapshot;
    }
    private ImmutableArray<RemoteControlTrustedPeer> ReadTrusted()
    {
        var trusted = _readTrusted() ?? throw new InvalidOperationException("SKR pairing authority is unavailable.");
        if (trusted.Count > 64) throw new InvalidDataException("SKR requires bounded existing pairing authority.");
        var snapshot = trusted.Select(p => new RemoteControlTrustedPeer(RemoteControlHandshakeBinding.CanonicalDeviceId(p.DeviceId),
            p.ProtocolPublicKeyFingerprint, p.KnownDeviceIds?.Select(RemoteControlHandshakeBinding.CanonicalDeviceId).ToArray())).ToImmutableArray();
        if (snapshot.Any(p => p.ProtocolPublicKeyFingerprint.Length != 64 || p.ProtocolPublicKeyFingerprint.Any(c => !char.IsAsciiHexDigit(c)) ||
            p.KnownDeviceIds?.Count > 32)) throw new InvalidDataException("Invalid existing SKR pairing authority.");
        return snapshot;
    }

    internal LanSignedKemRefresh Respond(LanKemRefreshRequest request, CancellationToken token)
    {
        RequireCurrent(token);
        var now = ObserveTime();
        SignedLanKemRefreshCanonical.RequireRequestFreshness(request, now.Wall);
        var requester = RemoteControlHandshakeBinding.CanonicalDeviceId(request.RequesterDeviceId);
        var pin = request.RequesterProtocolIdentityFingerprint!.Trim().ToLowerInvariant();
        var candidates = ReadTrusted().Where(p => p.DeviceId == requester || p.KnownDeviceIds?.Contains(requester) == true).ToArray();
        if (candidates.Length == 0 || candidates.Select(p => p.DeviceId).Distinct(StringComparer.Ordinal).Count() != 1 ||
            candidates.Select(p => p.ProtocolPublicKeyFingerprint.ToLowerInvariant()).Distinct(StringComparer.Ordinal).Count() != 1 ||
            candidates[0].ProtocolPublicKeyFingerprint.ToLowerInvariant() != pin)
            throw Reject("untrustedRequester", "SKR requester does not match an existing paired identity.");
        if (RemoteControlHandshakeBinding.CanonicalDeviceId(request.TargetDeviceId) != _inventory.DeviceId ||
            request.TargetProtocolIdentityFingerprint?.Trim().ToLowerInvariant() != _fingerprint)
            throw Reject("targetIdentityMismatch", "SKR target does not match this pinned identity.");
        // Hash the original immutable request, never the normalized lookup values.
        var hash = SignedLanKemRefreshCanonical.RequestHash(request);
        var requesterKey = candidates[0].DeviceId + "|" + pin;
        Entry entry;
        lock (_gate)
        {
            Prune(now.Stamp);
            if (!_windows.TryGetValue(requesterKey, out var window)) _windows.Add(requesterKey, window = new());
            if (window.Count >= RequestsPerMinute) throw Reject("rateLimited", "SKR requester exceeded its one-minute limit.");
            window.Enqueue(now.Stamp);
            if (_entries.TryGetValue(hash, out var prior))
            {
                if (prior.Completed is not { } cached) throw Reject("replay", "SKR request is already pending or previously failed.");
                RequireCurrent(token);
                SignedLanKemRefreshCanonical.RequireResponseBindings(request, cached, _fingerprint, now.Wall);
                return cached;
            }
            if (_entries.Count >= MaximumEntries) throw Reject("capacityReached", "SKR request capacity is exhausted until entries expire.");
            entry = new(now.Stamp); _entries.Add(hash, entry);
        }
        var ids = request.Version == 3
            ? SignedLanKemRefreshCanonical.Intersection(request.RequestedSuiteWireIds, _permitted, request.QPeriaptAuthProfile, _inventory.QAuthProfile)
            : request.RequestedSuiteWireIds.Where(_permitted.Contains).ToImmutableArray();
        if (request.Version != 3 && ids.IsEmpty) throw Reject("noCommonSuite", "SKR has no requested supported KEM suite.");
        var keys = _inventory.Keys.Where(k => ids.Contains(k.SuiteWireId)).OrderBy(k => k.SuiteWireId).ToImmutableArray();
        // The request target was resolved to this actual local identity above. Sign
        // only that spelling: a peer may trust just this identifier, and an SKR reply
        // cannot enlarge its existing alias authority with our canonical/bare variants.
        var responseDeviceId = request.TargetDeviceId.Trim();
        var sent = now.Wall / 1000.0 - 978307200.0;
        var response = new LanSignedKemRefresh(responseDeviceId, "ML-DSA-65", _inventory.SigningPublicKey, _fingerprint,
            keys, KeyId(_fingerprint, keys), now.Wall, sent, sent + 300.0, request.Nonce, [], request.Version,
            [], hash, BonjourEndpointDigest: request.BonjourEndpointDigest,
            Platform: request.Version >= 2 ? _inventory.Platform : null, OsVersion: request.Version >= 2 ? _inventory.OsVersion : null,
            PermittedSuiteWireIds: request.Version == 3 ? _permitted : null, QPeriaptAuthProfile: request.Version == 3 ? _inventory.QAuthProfile : null);
        RequireCurrent(token);
        // Synchronous native signing stays owned by the accepting worker. Cancellation
        // never detaches it; the signer port must confirm actual release before returning.
        var signature = _sign(SignedLanKemRefreshCanonical.ResponsePreimage(response));
        response = response with { Signature = signature };
        RequireCurrent(token);
        var completed = ObserveTime();
        SignedLanKemRefreshCanonical.RequireResponseBindings(request, response, _fingerprint, completed.Wall);
        lock (_gate)
        {
            if (!_entries.TryGetValue(hash, out var current) || !ReferenceEquals(entry, current) ||
                _time.GetElapsedTime(entry.Admitted, completed.Stamp) > TimeSpan.FromMinutes(5))
                throw Reject("expired", "SKR admission expired before signing completed.");
            RequireCurrent(token); entry.Completed = response;
        }
        return response;
    }

    internal void RequireSend(LanKemRefreshRequest request, LanSignedKemRefresh response, CancellationToken token)
    {
        RequireCurrent(token);
        SignedLanKemRefreshCanonical.RequireResponseBindings(request, response, _fingerprint, ObserveTime().Wall);
    }
    private void RequireCurrent(CancellationToken token) { token.ThrowIfCancellationRequested(); _requireCurrent(); }
    private (long Wall, long Stamp) ObserveTime()
    {
        lock (_gate)
        {
            var wall = _time.GetUtcNow().ToUnixTimeMilliseconds();
            if (wall < 0 || wall < _lastWall) throw Reject("clockRollback", "SKR clock moved behind an observed generation.");
            _lastWall = wall; return (wall, _time.GetTimestamp());
        }
    }
    private void Prune(long stamp)
    {
        foreach (var key in _entries.Where(p => _time.GetElapsedTime(p.Value.Admitted, stamp) > TimeSpan.FromMinutes(5)).Select(p => p.Key).ToArray())
            _entries.Remove(key);
        foreach (var pair in _windows.ToArray())
        {
            while (pair.Value.TryPeek(out var first) && _time.GetElapsedTime(first, stamp) > TimeSpan.FromMinutes(1)) pair.Value.Dequeue();
            if (pair.Value.Count == 0) _windows.Remove(pair.Key);
        }
    }
    private static LanKemRefreshRejectedException Reject(string code, string message) => new(code, message);
    internal static string KeyId(string fingerprint, ImmutableArray<LanKemRefreshPublicKey> keys)
    {
        using var material = new MemoryStream(); material.Write(Encoding.UTF8.GetBytes("SkyBridge-SKR-1-KeyId\n"));
        Span<byte> header = stackalloc byte[6];
        foreach (var key in keys.OrderBy(k => k.SuiteWireId))
        {
            BinaryPrimitives.WriteUInt16LittleEndian(header, checked((ushort)key.SuiteWireId));
            BinaryPrimitives.WriteUInt32LittleEndian(header[2..], checked((uint)key.PublicKey.Length));
            material.Write(header); material.Write(key.PublicKey.AsSpan());
        }
        return "skr1-" + fingerprint[..12] + "-" + Convert.ToHexStringLower(SHA256.HashData(material.ToArray()).AsSpan(0, 8));
    }
}
