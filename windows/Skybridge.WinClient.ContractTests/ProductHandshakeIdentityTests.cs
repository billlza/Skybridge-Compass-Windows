using System.Security.Cryptography;
using System.Runtime.InteropServices;
using Skybridge.WinClient.Services;

internal static class ProductHandshakeIdentityTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("handshake identity snapshots own input and exported public bytes", SnapshotOwnership),
        ("initiator identity survives public message buffer reuse after send", InitiatorSnapshot),
        ("responder identity survives public message buffer reuse after send", ResponderSnapshot),
        ("actual MessageA extensions are frozen before transport and crypto callbacks", ExtensionsSnapshot),
        ("invalid Finished never returns signing identity evidence", InvalidFinished),
        ("cancellation at local Finished send never publishes a receipt", CanceledFinished),
        ("malformed local signing identities fail before sending", MalformedLocalIdentity),
        ("wrong trusted peer pin cannot produce identity evidence", WrongPeerPin)
    ];

    // The crypto port is synthetic; these tests exercise capture/order and the real FIN1 KDF/MAC.
    // They do not stand in for the existing native signature/KEM tests or physical device acceptance.
    private static readonly byte[] Secret = Enumerable.Range(0, 32).Select(i => (byte)(i + 17)).ToArray();
    private static WebRtcProductProtocolIdentityPublicKey Identity(byte marker) =>
        new(WebRtcProductSignatureAlgorithm.Ed25519, Enumerable.Repeat(marker, 32).ToArray());

    private static Task SnapshotOwnership()
    {
        foreach (var algorithm in new[] { WebRtcProductSignatureAlgorithm.Ed25519, WebRtcProductSignatureAlgorithm.MlDsa65 })
        {
            var bytes = algorithm switch
            {
                WebRtcProductSignatureAlgorithm.Ed25519 => Enumerable.Repeat((byte)23, 32).ToArray(),
                WebRtcProductSignatureAlgorithm.MlDsa65 => Enumerable.Repeat((byte)45, 1952).ToArray(),
                _ => throw new InvalidOperationException("Unhandled test algorithm.")
            };
            var encoded = new WebRtcProductProtocolIdentityPublicKey(algorithm, bytes).Encode();
            var captured = ProductHandshakeProtocolIdentity.Capture(encoded, "test");
            var pin = captured.Fingerprint;
            encoded.AsSpan().Fill(0);
            captured.ExportPublicKey().AsSpan().Fill(0);
            Require(captured.Algorithm == algorithm && captured.Fingerprint == pin && captured.MatchesPublicKey(bytes),
                "Input/export mutation changed captured evidence.");
            bytes[1] ^= 1;
            Require(!captured.MatchesPublicKey(bytes), "Different public bytes matched the snapshot.");
        }
        var legacy = new byte[] { 4 }.Concat(new byte[64]).ToArray();
        Throws<ProductHandshakeException>(() => ProductHandshakeProtocolIdentity.Capture(legacy, "legacy"));
        Throws<ProductHandshakeException>(() => ProductHandshakeProtocolIdentity.Capture(
            new WebRtcProductProtocolIdentityPublicKey(WebRtcProductSignatureAlgorithm.P256Ecdsa, legacy).Encode(), "legacy wrapped"));
        Throws<ProductHandshakeException>(() => ProductHandshakeProtocolIdentity.Capture(new byte[] { 1, 2, 3 }, "bad"));
        return Task.CompletedTask;
    }

    private static async Task InitiatorSnapshot()
    {
        var provider = new Provider();
        var original = provider.Current;
        var transport = new ScriptedTransport(provider.B.Encode(), Finished(provider, ProductHandshakeRole.Responder));
        transport.BeforeSend = frame => {
            if (!frame.AsSpan().StartsWith("FIN1"u8)) ReusePublicIdentityBuffer(provider.A.IdentityPublicKey);
            provider.Current = Identity(91);
        };
        using var result = await new ProductHandshakeCore(provider).StartInitiatorAsync(transport, provider.Remote);
        Require(result.LocalProtocolIdentity.Fingerprint == original.AuthoritativeFingerprint,
            "Initiator used a later preferred signer.");
        Require(result.PeerProtocolIdentity.Fingerprint == provider.Remote.PeerPublicKeyFingerprint,
            "Initiator lost its actual peer signer.");
        Require(result.LocalProtocolIdentity.MatchesPublicKey(original.PublicKey.Span), "Initiator public bytes changed.");
        Require(ProductHandshakeProtocolIdentity.Capture(provider.A.IdentityPublicKey.Span, "reused").Fingerprint !=
            result.LocalProtocolIdentity.Fingerprint, "The source buffer was not actually changed by the test.");
        Require(transport.Sent.Count == 2 && transport.Sent[1].AsSpan().StartsWith("FIN1"u8), "Receipt preceded local Finished.");
        Require(result.ExportInitiatorExtensions().Length == 0, "Generic no-SOA handshake must remain supported.");
    }

    private static async Task ResponderSnapshot()
    {
        var provider = new Provider();
        var original = ProductHandshakeProtocolIdentity.Capture(provider.B.IdentityPublicKey.Span, "expected");
        var peer = new ProductHandshakePeerContext("initiator", Identity(23).AuthoritativeFingerprint);
        var transport = new ScriptedTransport(Finished(provider, ProductHandshakeRole.Initiator));
        transport.BeforeSend = frame => {
            if (!frame.AsSpan().StartsWith("FIN1"u8)) ReusePublicIdentityBuffer(provider.B.IdentityPublicKey);
            provider.Current = Identity(92);
        };
        using var result = await new ProductHandshakeCore(provider).AcceptResponderAsync(transport, peer, provider.A.Encode());
        Require(result.LocalProtocolIdentity.Fingerprint == original.Fingerprint, "Responder used a later signer.");
        Require(result.PeerProtocolIdentity.Fingerprint == peer.PeerPublicKeyFingerprint, "Responder signer roles reversed.");
        Require(ProductHandshakeProtocolIdentity.Capture(provider.B.IdentityPublicKey.Span, "reused").Fingerprint !=
            result.LocalProtocolIdentity.Fingerprint, "The responder buffer was not actually changed by the test.");
        Require(transport.Sent.Count == 2 && transport.Sent[1].AsSpan().StartsWith("FIN1"u8), "Responder Finished missing.");
        var material = provider.LastMaterial ?? throw new InvalidOperationException("Responder material was not created.");
        Throws<ObjectDisposedException>(() => _ = material.SharedSecret);
        Require(result.ExportInitiatorExtensions().Length == 0, "Generic responder must not require SOA.");
    }

    private static async Task ExtensionsSnapshot()
    {
        // An unknown extension is valid opaque handshake data; no audio parser belongs in the generic core.
        var expected = new byte[] { 77, 0, 4, 0, 11, 12, 13, 14 };
        foreach (var responder in new[] { false, true })
        {
            var provider = new Provider(extensions: expected);
            ReadOnlyMemory<byte> reused = default;
            var transport = responder
                ? new ScriptedTransport(Finished(provider, ProductHandshakeRole.Initiator))
                : new ScriptedTransport(provider.B.Encode(), Finished(provider, ProductHandshakeRole.Responder));
            void Reuse(WebRtcProductHandshakeMessageA a)
            {
                reused = a.ExtensionsRaw;
                if (!MemoryMarshal.TryGetArray(reused, out var segment) || segment.Array is null)
                    throw new InvalidOperationException("Extensions fixture must expose its actual backing array.");
                segment.Array[segment.Offset + 4] ^= 1;
            }
            if (responder) provider.BeforeRespond = Reuse;
            else transport.BeforeSend = frame => { if (!frame.AsSpan().StartsWith("FIN1"u8)) Reuse(provider.A); };
            using var result = responder
                ? await new ProductHandshakeCore(provider).AcceptResponderAsync(transport,
                    new("initiator", Identity(23).AuthoritativeFingerprint), provider.A.Encode())
                : await new ProductHandshakeCore(provider).StartInitiatorAsync(transport, provider.Remote);
            Require(!reused.Span.SequenceEqual(expected), "Test did not mutate the actual MessageA extensions.");
            Require(result.ExportInitiatorExtensions().SequenceEqual(expected), "Receipt retained a reused extensions buffer.");
            result.ExportInitiatorExtensions().AsSpan().Fill(0);
            Require(result.ExportInitiatorExtensions().SequenceEqual(expected), "Caller modified the frozen extension evidence.");
        }
    }

    private static async Task InvalidFinished()
    {
        foreach (var responder in new[] { false, true })
        {
            var provider = new Provider();
            var finished = Finished(provider, responder ? ProductHandshakeRole.Initiator : ProductHandshakeRole.Responder);
            finished[^1] ^= 1;
            var transport = responder ? new ScriptedTransport(finished) : new ScriptedTransport(provider.B.Encode(), finished);
            await ThrowsAsync<ProductHandshakeException>(async () =>
            {
                using var unexpected = responder
                    ? await new ProductHandshakeCore(provider).AcceptResponderAsync(transport,
                        new("initiator", Identity(23).AuthoritativeFingerprint), provider.A.Encode())
                    : await new ProductHandshakeCore(provider).StartInitiatorAsync(transport, provider.Remote);
            });
        }
    }

    private static async Task CanceledFinished()
    {
        var provider = new Provider();
        using var cancellation = new CancellationTokenSource();
        var transport = new ScriptedTransport(provider.B.Encode(), Finished(provider, ProductHandshakeRole.Responder));
        transport.BeforeSend = frame => { if (frame.AsSpan().StartsWith("FIN1"u8)) cancellation.Cancel(); };
        await ThrowsAsync<OperationCanceledException>(async () =>
        {
            using var unexpected = await new ProductHandshakeCore(provider)
                .StartInitiatorAsync(transport, provider.Remote, cancellation.Token);
        });
    }

    private static async Task MalformedLocalIdentity()
    {
        var initiator = new Provider(malformedA: true);
        var transport = new ScriptedTransport();
        await ThrowsAsync<ProductHandshakeException>(async () =>
        {
            using var unexpected = await new ProductHandshakeCore(initiator).StartInitiatorAsync(transport, initiator.Remote);
        });
        Require(transport.Sent.Count == 0 && initiator.Aborts == 1, "Malformed local A reached the wire or retained a pending secret.");
        var responder = new Provider(malformedB: true);
        await ThrowsAsync<ProductHandshakeException>(async () =>
        {
            using var unexpected = await new ProductHandshakeCore(responder).AcceptResponderAsync(transport,
                new("initiator", Identity(23).AuthoritativeFingerprint), responder.A.Encode());
        });
        Require(transport.Sent.Count == 0, "Malformed local B reached the wire.");
        var material = responder.LastMaterial ?? throw new InvalidOperationException("Responder material was not created.");
        Throws<ObjectDisposedException>(() => _ = material.SharedSecret);
    }

    private static async Task WrongPeerPin()
    {
        var provider = new Provider(); var transport = new ScriptedTransport(provider.B.Encode());
        await ThrowsAsync<ProductHandshakeException>(async () =>
        {
            using var unexpected = await new ProductHandshakeCore(provider)
                .StartInitiatorAsync(transport, provider.Remote with { PeerPublicKeyFingerprint = Identity(99).AuthoritativeFingerprint });
        });
        Require(provider.OpenCalls == 0 && provider.Aborts == 1, "Pin mismatch reached crypto open or retained pending state.");
    }

    private static byte[] Finished(Provider provider, ProductHandshakeRole role)
    {
        using var keys = ProductHandshakeKeyDerivation.Derive(Secret, 0x1001,
            SHA256.HashData(provider.A.EncodeWithoutSignature()), SHA256.HashData(provider.B.EncodeWithoutSignature()),
            provider.A.ClientNonce.Span, provider.B.ServerNonce.Span, role);
        return ProductHandshakeKeyDerivation.CreateFinished(keys).Encode();
    }

    // ReadOnlyMemory alone does not freeze an array; emulate a callback retaining/reusing that public buffer.
    private static void ReusePublicIdentityBuffer(ReadOnlyMemory<byte> encoded)
    {
        if (!MemoryMarshal.TryGetArray(encoded, out var segment) || segment.Array is null || segment.Count < 4)
            throw new InvalidOperationException("Fixture must expose its actual encoded identity backing array.");
        segment.Array[segment.Offset + 3] ^= 1;
    }

    private sealed class Provider : IProductHandshakeCryptoProvider
    {
        internal WebRtcProductProtocolIdentityPublicKey Current = Identity(23);
        internal WebRtcProductHandshakeMessageA A { get; }
        internal WebRtcProductHandshakeMessageB B { get; }
        internal ProductHandshakePeerContext Remote { get; } = new("responder", Identity(47).AuthoritativeFingerprint);
        internal WebRtcProductHandshakeResponderMaterial? LastMaterial;
        internal Action<WebRtcProductHandshakeMessageA>? BeforeRespond;
        internal int Aborts, OpenCalls;
        internal Provider(bool malformedA = false, bool malformedB = false, byte[]? extensions = null)
        {
            A = new([0x1001], [new(0x1001, new byte[32])], new byte[32],
                new(["X25519"], ["Ed25519"], ["classic"], ["AES-256-GCM"], false, "fixture", "CryptoKit-Classic"),
                WebRtcProductHandshakePolicy.Default, malformedA ? new byte[] { 1 } : Current.Encode(),
                extensions ?? Array.Empty<byte>(), new byte[] { 1 });
            B = new(0x1001, new byte[32], new byte[32], new(0x1001, Array.Empty<byte>(), new byte[12], new byte[] { 1 }, new byte[16]),
                malformedB ? new byte[] { 1 } : Identity(47).Encode(), new byte[] { 1 });
        }
        public ValueTask<WebRtcProductHandshakeMessageA> CreateInitiatorMessageAAsync(ProductHandshakePeerContext context,
            CancellationToken cancellationToken = default) => ValueTask.FromResult(A);
        public ValueTask<ProductHandshakeSharedSecret> OpenResponderMessageBAsync(ProductHandshakePeerContext context,
            WebRtcProductHandshakeMessageA messageA, ReadOnlyMemory<byte> transcriptHashA, WebRtcProductHandshakeMessageB messageB,
            CancellationToken cancellationToken = default)
        { OpenCalls++; return ValueTask.FromResult(new ProductHandshakeSharedSecret(Secret)); }
        public ValueTask<WebRtcProductHandshakeResponderMaterial> CreateResponderMessageBAsync(ProductHandshakePeerContext context,
            WebRtcProductHandshakeMessageA messageA, ReadOnlyMemory<byte> transcriptHashA, CancellationToken cancellationToken = default)
        { BeforeRespond?.Invoke(messageA); LastMaterial = new(B, Secret); return ValueTask.FromResult(LastMaterial); }
        public void AbortInitiatorSecret(ReadOnlyMemory<byte> transcriptHashA) { Aborts++; }
    }

    private sealed class ScriptedTransport(params byte[][] received) : IProductHandshakeTransport
    {
        private readonly Queue<byte[]> _received = new(received);
        internal List<byte[]> Sent { get; } = [];
        internal Action<byte[]>? BeforeSend;
        public Task SendAsync(ReadOnlyMemory<byte> frame, CancellationToken cancellationToken = default)
        { var bytes = frame.ToArray(); Sent.Add(bytes); BeforeSend?.Invoke(bytes); return Task.CompletedTask; }
        public Task<ReadOnlyMemory<byte>> ReadAsync(CancellationToken cancellationToken = default)
        { cancellationToken.ThrowIfCancellationRequested(); return Task.FromResult<ReadOnlyMemory<byte>>(_received.Dequeue()); }
    }

    private static void Require(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); }
    private static void Throws<T>(Action action) where T : Exception
    { try { action(); } catch (T) { return; } throw new InvalidOperationException($"Expected {typeof(T).Name}."); }
    private static async Task ThrowsAsync<T>(Func<Task> action) where T : Exception
    { try { await action(); } catch (T) { return; } throw new InvalidOperationException($"Expected {typeof(T).Name}."); }
}
