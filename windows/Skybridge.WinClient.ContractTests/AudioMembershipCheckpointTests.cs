using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Skybridge.WinClient.Services.Audio;
using static AudioAccountMembershipTests;

internal static class AudioMembershipCheckpointTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("audio checkpoint preserves evidence identity and original deadlines through serialization", RoundTrip),
        ("audio checkpoint rejects another login account tenant and exact device identity", Binding),
        ("audio recovery discovery aliases only select candidates and never restore exact membership", DiscoveryCandidate),
        ("audio checkpoint rejects unknown malformed and excessive authority before logon verification", Shape),
        ("audio checkpoint deserialization rejects unknown authority fields", UnknownFields),
        ("audio checkpoint rejects expiry and rollback without renewing its finite interval", ClockLimits),
        ("audio checkpoint capture rejects revoked evidence and expiry during sealing", CaptureRetirement),
        ("audio checkpoint restore checks expiry after logon verification", RestoreRetirement),
        ("audio checkpoint keeps protection failures observable", ProtectionFailure),
        ("audio checkpoint native continuity has an explicit platform boundary", NativeContinuity)
    ];
    // This fake checks lifecycle/encoding only. The native workflow separately
    // exercises the actual Windows protection and cross-process logon boundary.
    internal sealed class Continuity : IAudioLogonContinuity
    {
        internal AudioLogonSeal Seal = new(Convert.ToBase64String(new byte[32]), Convert.ToBase64String(Enumerable.Repeat((byte)7, 32).ToArray()));
        internal Action? OnCreate, OnVerify;
        internal int Verifications;
        public AudioLogonSeal Create() { OnCreate?.Invoke(); return Seal; }
        public void RequireCurrent(AudioLogonSeal seal)
        {
            Verifications++; OnVerify?.Invoke();
            if (seal != Seal) throw new CryptographicException("Fixture continuity changed.");
        }
    }
    private static async Task<(AudioAccountMembershipEvidence Evidence, AudioMembershipCheckpoint Checkpoint, Continuity Continuity)> Prepare(Fixture f)
    {
        var evidence = AudioAccountMembershipEvidence.Create(await f.Observe(), Local(f.Binding), Peer(f.Binding));
        var continuity = new Continuity();
        return (evidence, AudioMembershipCheckpoint.Capture(Guid.NewGuid(), evidence, f.Clock.Read, continuity), continuity);
    }
    private static AudioAccountMembershipEvidence Restore(Fixture f, AudioMembershipCheckpoint p, Continuity continuity) =>
        p.Restore(p.LoginId, AudioAccountScope.From(f.Auth), Local(f.Binding), Peer(f.Binding), f.Clock.Read, continuity);

    private static async Task RoundTrip()
    {
        foreach (bool postQuantum in new[] { false, true })
        {
            using var f = new Fixture(AudioAccountMembershipTests.Binding(mlDsa: postQuantum));
            var (evidence, checkpoint, continuity) = await Prepare(f);
            var encoded = JsonSerializer.SerializeToUtf8Bytes(checkpoint);
            var restoredValue = JsonSerializer.Deserialize<AudioMembershipCheckpoint>(encoded) ?? throw new Exception("Checkpoint missing.");
            f.Clock.Advance(50_000);
            var restored = Restore(f, restoredValue, continuity);
            Require(restored.Id == evidence.Id && restored.Issued == evidence.Issued && restored.Expires == evidence.Expires,
                "Restoration changed the evidence identity or renewed a deadline.");
            Require(restored.Local == evidence.Local && restored.Peer == evidence.Peer && restored.Scope == evidence.Scope,
                "Restoration changed an identity binding.");
            var next = AudioMembershipCheckpoint.Capture(checkpoint.LoginId, restored, f.Clock.Read, continuity);
            Require(next.EvidenceId == checkpoint.EvidenceId && next.Issued == checkpoint.Issued && next.Expires == checkpoint.Expires,
                "Re-saving restored evidence extended its authority.");
            Require(f.HttpCalls == 1 && f.AuthCalls == 0, "Restore issued a new registry request.");
        }
    }

    private static async Task Binding()
    {
        using var f = new Fixture(); var (_, p, c) = await Prepare(f);
        var scope = AudioAccountScope.From(f.Auth); var local = Local(f.Binding); var peer = Peer(f.Binding);
        Reject<AudioMembershipException>(() => p.Restore(Guid.NewGuid(), scope, local, peer, f.Clock.Read, c));
        Reject<AudioMembershipException>(() => p.Restore(p.LoginId, scope with { Subject = "other" }, local, peer, f.Clock.Read, c));
        Reject<AudioMembershipException>(() => p.Restore(p.LoginId, scope with { TenantId = "other" }, local, peer, f.Clock.Read, c));
        Reject<AudioMembershipException>(() => p.Restore(p.LoginId, scope with { Authority = scope.Authority with { Issuer = "https://other.invalid/auth/v1" } }, local, peer, f.Clock.Read, c));
        Reject<AudioMembershipException>(() => p.Restore(p.LoginId, scope, peer, local, f.Clock.Read, c));
        Reject<AudioMembershipException>(() => p.Restore(p.LoginId, scope, local, Peer(AudioAccountMembershipTests.Binding(peer: 1)), f.Clock.Read, c));
        var changedKey = p with { Peer = p.Peer with { Fingerprint = new string('0', 64) } };
        Reject<AudioMembershipException>(() => Restore(f, changedKey, c));
        Require(c.Verifications == 0, "Mismatched ownership reached logon verification.");
    }

    private static async Task DiscoveryCandidate()
    {
        using var f = new Fixture(); var (_, p, continuity) = await Prepare(f);
        var snapshot = new AudioAccountRecoverySnapshot(p.LoginId, p.Scope, "test", "test", [p], f.Clock.Read);
        var local = Local(f.Binding); var exact = Peer(f.Binding);
        var alias = AudioDeviceIdentity.From("android-membership-0", f.Binding.PeerProtocolIdentity);
        Require(snapshot.HasProtocolCandidate(local, alias) && snapshot.Find(local, alias) is null &&
            snapshot.Find(local, exact) == p, "Routing alias was either unusable for bootstrap or became exact membership authority.");
        Reject<AudioMembershipException>(() => p.Restore(p.LoginId, p.Scope, local, alias, f.Clock.Read, continuity));
        Require(continuity.Verifications == 0 && !snapshot.HasProtocolCandidate(local, Peer(AudioAccountMembershipTests.Binding(peer: 1))) &&
            !snapshot.HasProtocolCandidate(local, Peer(AudioAccountMembershipTests.Binding(mlDsa: true))),
            "Discovery candidate matching ignored a changed ID or signing identity.");
        f.Clock.Now = p.Expires;
        Require(!snapshot.HasProtocolCandidate(local, alias), "An expired discovery candidate remained usable.");
        f.Clock.Now = p.Issued;
        Require(!snapshot.HasProtocolCandidate(local, exact) && snapshot.Find(local, exact) is null,
            "Clock recovery revived an expired candidate.");
    }

    private static async Task Shape()
    {
        using var f = new Fixture(); var (_, p, c) = await Prepare(f);
        foreach (var bad in new[] {
            p with { SchemaVersion = 2 }, p with { LoginId = Guid.Empty }, p with { EvidenceId = Guid.Empty },
            p with { Local = p.Peer }, p with { Scope = p.Scope with { TenantId = " tenant" } },
            p with { Peer = p.Peer with { Algorithm = "unknown" } },
            p with { Peer = p.Peer with { Fingerprint = new string('g', 64) } },
            p with { Continuity = p.Continuity with { ProtectedNonce = "bad" } },
            p with { Issued = p.Issued with { ContinuousMilliseconds = -1 } },
            p with { Expires = p.Expires with { ContinuousMilliseconds = p.Expires.ContinuousMilliseconds + 1 } },
            p with { Expires = new(long.MaxValue, long.MaxValue) },
            p with { Expires = new(p.Issued.WallMilliseconds + 3_600_001, p.Issued.ContinuousMilliseconds + 3_600_001) }
        }) Reject<InvalidDataException>(() => Restore(f, bad, c));
        Require(c.Verifications == 0, "Malformed checkpoint reached logon verification.");
    }

    private static async Task ClockLimits()
    {
        foreach (int mode in Enumerable.Range(0, 4))
        {
            using var f = new Fixture(); var (_, p, c) = await Prepare(f);
            f.Clock.Now = mode switch {
                0 => new(p.Expires.WallMilliseconds, p.Issued.ContinuousMilliseconds),
                1 => new(p.Issued.WallMilliseconds, p.Expires.ContinuousMilliseconds),
                2 => new(p.Issued.WallMilliseconds - 1, p.Issued.ContinuousMilliseconds),
                _ => new(p.Issued.WallMilliseconds, p.Issued.ContinuousMilliseconds - 1) };
            Reject<AudioMembershipException>(() => Restore(f, p, c));
        }
    }

    private static async Task UnknownFields()
    {
        using var f = new Fixture(); var (_, p, _) = await Prepare(f);
        foreach (string target in new[] { "root", "Local", "Peer", "Scope", "Scope.Authority", "Issued", "Expires", "Continuity" })
        {
            var document = JsonSerializer.SerializeToNode(p) as JsonObject ?? throw new Exception("Missing JSON object.");
            var value = document;
            if (target != "root") foreach (string part in target.Split('.'))
                value = value[part] as JsonObject ?? throw new Exception("Missing nested object.");
            value["unknownAuthorityField"] = "must not be ignored";
            Reject<JsonException>(() => document.Deserialize<AudioMembershipCheckpoint>());
        }
    }

    private static async Task CaptureRetirement()
    {
        foreach (bool revoke in new[] { false, true })
        {
            using var f = new Fixture(); var (e, p, c) = await Prepare(f);
            c.OnCreate = () => { if (revoke) e.Revoke(); else f.Clock.Now = e.Expires; };
            Reject<AudioMembershipException>(() => AudioMembershipCheckpoint.Capture(p.LoginId, e, f.Clock.Read, c));
        }
        using var retired = new Fixture(); var (old, checkpoint, continuity) = await Prepare(retired);
        old.Revoke(); continuity.OnCreate = () => throw new Exception("Revoked evidence reached sealing.");
        Reject<AudioMembershipException>(() => AudioMembershipCheckpoint.Capture(checkpoint.LoginId, old, retired.Clock.Read, continuity));
    }

    private static async Task RestoreRetirement()
    {
        using var f = new Fixture(); var (_, p, c) = await Prepare(f);
        c.OnVerify = () => f.Clock.Now = p.Expires;
        Reject<AudioMembershipException>(() => Restore(f, p, c));
    }

    private static async Task ProtectionFailure()
    {
        using var f = new Fixture(); var (e, p, c) = await Prepare(f);
        var error = new CryptographicException("Fixture protection failure.");
        c.OnVerify = () => throw error;
        Require(ReferenceEquals(Reject<CryptographicException>(() => Restore(f, p, c)), error), "Logon failure was replaced.");
        c.OnCreate = () => throw error;
        Require(ReferenceEquals(Reject<CryptographicException>(() => AudioMembershipCheckpoint.Capture(p.LoginId, e, f.Clock.Read, c)), error), "Seal creation failure was hidden.");
    }

    private static Task NativeContinuity()
    {
        var native = WindowsAudioLogonContinuity.Instance;
        if (!OperatingSystem.IsWindows()) Reject<PlatformNotSupportedException>(() => native.Create());
        else
        {
            var seal = native.Create(); native.RequireCurrent(seal);
            Reject<CryptographicException>(() => native.RequireCurrent(seal with { NonceDigest = Convert.ToBase64String(new byte[32]) }));
            Reject<InvalidDataException>(() => native.RequireCurrent(seal with { ProtectedNonce = "bad" }));
        }
        return Task.CompletedTask;
    }
    private static T Reject<T>(Action action) where T : Exception
    {
        try { action(); } catch (T failure) { return failure; }
        throw new InvalidOperationException("Expected " + typeof(T).Name + ".");
    }
    private static void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
}
