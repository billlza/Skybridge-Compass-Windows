using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using Skybridge.WinClient.Services.RemoteControl;

namespace Skybridge.WinClient.Services;

internal sealed class WebRtcPairingDeclinedException() : IOException("The six digits were not confirmed on both devices.");

internal enum WebRtcComparison { Reject, AllowOnce, Remember }
internal sealed record WebRtcPairingPolicy(bool Remembered, bool LegacyTrusted,
    Func<string, string, CancellationToken, Task<WebRtcComparison>> Compare,
    Action<RemoteControlPairingMaterial, CancellationToken> Remember);

// One object per FIN-verified owner. The control reader delivers authenticated votes
// while the independent worker waits for the operator and the other screen.
internal sealed class WindowsWebRtcPairing(RemoteControlPairingMaterial candidate, ReadOnlyMemory<byte> transcript, WebRtcPairingPolicy policy)
{
    internal const string Capability = "webrtc_pairing_sas_v1";
    private readonly TaskCompletionSource<(RemoteControlPairingMaterial Material, bool SupportsSas)> _identity = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource<bool> _vote = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource<RemoteControlPairingMaterial> _approved = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal Task<RemoteControlPairingMaterial> Approved => _approved.Task;
    private readonly string _transcriptHex = Convert.ToHexStringLower(transcript.Span);
    internal static string VerificationCode(ReadOnlySpan<byte> transcript)
    {
        if (transcript.Length != 32) throw new InvalidDataException("Invalid pairing transcript.");
        byte[] hash = SHA256.HashData([.."SkyBridge-Pairing-SAS|"u8, ..transcript]);
        return (BinaryPrimitives.ReadUInt32BigEndian(hash) % 1_000_000).ToString("D6", CultureInfo.InvariantCulture);
    }
    internal void ReceiveIdentity(LanProductIdentity peer)
    {
        LanProductControlMessages.ValidateIdentity(peer, new(candidate.DeviceId, candidate.ProtocolPublicKeyFingerprint));
        var signer = peer.ProtocolIdentityPublicKeys!.Single(p => p.ProtocolSigningAlgorithm == candidate.ProtocolSigningAlgorithm);
        var confirmed = Material(peer.DeviceId, peer.DeviceName ?? candidate.DeviceName, signer.PublicKey, peer.KemPublicKeys);
        if (!candidate.HasSameProtocolIdentity(confirmed)) throw new InvalidDataException("The authenticated identity changed.");
        bool supports = peer.Capabilities?.Contains(Capability, StringComparer.Ordinal) == true;
        if (supports && !candidate.HasSameAuthority(confirmed) && !candidate.CanAddKemMaterial(confirmed))
            throw new InvalidDataException("The authenticated KEM keys conflict with the connection identity.");
        if (!_identity.TrySetResult((confirmed, supports)))
        {
            var previous = _identity.Task.GetAwaiter().GetResult();
            if (previous.SupportsSas != supports || !previous.Material.HasSameAuthority(confirmed))
                throw new InvalidDataException("The pairing identity changed within this secure session.");
        }
    }
    internal static RemoteControlPairingMaterial Material(string id, string name, byte[] signer, IEnumerable<LanKemPublicKey> keys)
    {
        var list = keys.ToArray();
        if (list.Length is 0 or > 8) throw new InvalidDataException("Invalid number of peer KEM keys.");
        var ml = list.Where(k => k.SuiteWireId is 0x0101 or 0x0102).Select(k => k.PublicKey).ToArray();
        if (ml.Length == 0 || ml.Any(k => k.Length != 1184 || !k.AsSpan().SequenceEqual(ml[0])))
            throw new InvalidDataException("The peer has missing or conflicting ML-KEM public keys.");
        var q = list.SingleOrDefault(k => k.SuiteWireId == WebRtcProductHandshakeCodec.SuiteQPeriaptPolicyBound);
        return RemoteControlPairingMaterial.CreatePolicyBound(id, name, signer, ml[0], q?.PublicKey ?? []);
    }
    internal void ReceiveVote(JsonElement envelope, int size)
    {
        if (size > 1024 || envelope.EnumerateObject().Count() != 1) throw new InvalidDataException("Invalid pairing decision envelope.");
        var fields = envelope.GetProperty("pairingSASDecision");
        if (fields.ValueKind != JsonValueKind.Object || fields.EnumerateObject().Count() != 3 ||
            !fields.TryGetProperty("version", out var version) || !version.TryGetInt32(out var v) || v != 1 ||
            !fields.TryGetProperty("transcriptHashHex", out var hash) || hash.GetString() != _transcriptHex ||
            !fields.TryGetProperty("accepted", out var decision) || decision.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            throw new InvalidDataException("The pairing decision does not match the current signed handshake.");
        bool accepted = decision.GetBoolean();
        if (!_vote.TrySetResult(accepted) && _vote.Task.GetAwaiter().GetResult() != accepted)
            throw new InvalidDataException("The peer changed its pairing decision.");
        if (!accepted) throw new WebRtcPairingDeclinedException();
    }

    internal async Task RunAsync(Func<byte[], CancellationToken, Task> send, CancellationToken token)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromMinutes(3));
        try
        {
            var (material, supports) = await _identity.Task.WaitAsync(deadline.Token).ConfigureAwait(false);
            if (!supports)
            {
                if (policy.Remembered || !policy.LegacyTrusted)
                    throw new InvalidDataException("This device must support comparing the six digits.");
            }
            else
            {
                var choice = policy.Remembered ? WebRtcComparison.AllowOnce :
                    await policy.Compare(material.DeviceName, VerificationCode(transcript.Span), deadline.Token).ConfigureAwait(false);
                var accepted = choice is WebRtcComparison.AllowOnce or WebRtcComparison.Remember;
                await send(JsonSerializer.SerializeToUtf8Bytes(new { pairingSASDecision = new { version = 1, transcriptHashHex = _transcriptHex, accepted } }),
                    deadline.Token).ConfigureAwait(false);
                if (!accepted || !await _vote.Task.WaitAsync(deadline.Token).ConfigureAwait(false))
                    throw new WebRtcPairingDeclinedException();
                deadline.Token.ThrowIfCancellationRequested();
                if (choice == WebRtcComparison.Remember) policy.Remember(material, deadline.Token);
            }
            deadline.Token.ThrowIfCancellationRequested();
            _approved.SetResult(material);
        }
        catch (Exception error)
        {
            _approved.TrySetException(error);
            throw;
        }
    }
}
