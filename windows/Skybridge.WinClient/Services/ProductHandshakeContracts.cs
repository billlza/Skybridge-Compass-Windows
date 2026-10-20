using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Skybridge.WinClient.Services;

public enum ProductHandshakeRole
{
    Initiator,
    Responder
}

/// <summary>Authority resolved by the transport's trusted peer binding, never by a host name or address.</summary>
public sealed record ProductHandshakePeerContext(string PeerDeviceId, string PeerPublicKeyFingerprint);

public interface IProductHandshakeCryptoProvider
{
    ValueTask<WebRtcProductHandshakeMessageA> CreateInitiatorMessageAAsync(
        ProductHandshakePeerContext context, CancellationToken cancellationToken = default);

    ValueTask<ProductHandshakeSharedSecret> OpenResponderMessageBAsync(
        ProductHandshakePeerContext context,
        WebRtcProductHandshakeMessageA messageA,
        ReadOnlyMemory<byte> transcriptHashA,
        WebRtcProductHandshakeMessageB messageB,
        CancellationToken cancellationToken = default);

    ValueTask<WebRtcProductHandshakeResponderMaterial> CreateResponderMessageBAsync(
        ProductHandshakePeerContext context,
        WebRtcProductHandshakeMessageA messageA,
        ReadOnlyMemory<byte> transcriptHashA,
        CancellationToken cancellationToken = default);

    void AbortInitiatorSecret(ReadOnlyMemory<byte> transcriptHashA);
}

public sealed class ProductHandshakeException : InvalidOperationException
{
    public ProductHandshakeException(string message) : base(message) { }

    public ProductHandshakeException(string message, Exception innerException) : base(message, innerException) { }
}

public sealed class ProductHandshakeSharedSecret : IDisposable
{
    private readonly byte[] _bytes;
    private bool _disposed;

    public ProductHandshakeSharedSecret(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != 32) { throw new InvalidDataException("Product handshake shared secret must be 32 bytes."); }
        _bytes = bytes.ToArray();
    }

    public ReadOnlyMemory<byte> Bytes
    {
        get { ObjectDisposedException.ThrowIf(_disposed, this); return _bytes; }
    }

    public void Dispose()
    {
        if (_disposed) { return; }
        CryptographicOperations.ZeroMemory(_bytes);
        _disposed = true;
    }
}

/// <summary>Exact authenticated session secrets. Callers own the instance and must dispose it at session teardown.</summary>
public sealed class ProductSessionKeys : IDisposable
{
    private readonly byte[] _transcriptHash;
    private readonly byte[] _sendKey;
    private readonly byte[] _receiveKey;
    private bool _disposed;

    public ProductSessionKeys(
        ProductHandshakeRole role, string sessionId, ReadOnlyMemory<byte> transcriptHash,
        ReadOnlyMemory<byte> sendKey, ReadOnlyMemory<byte> receiveKey)
    {
        if (role is not ProductHandshakeRole.Initiator and not ProductHandshakeRole.Responder)
        {
            throw new InvalidDataException("Product session role is invalid.");
        }
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionId);
        RequireLength(transcriptHash, nameof(transcriptHash));
        RequireLength(sendKey, nameof(sendKey));
        RequireLength(receiveKey, nameof(receiveKey));
        Role = role;
        SessionId = sessionId;
        _transcriptHash = transcriptHash.ToArray();
        _sendKey = sendKey.ToArray();
        _receiveKey = receiveKey.ToArray();
    }

    public ProductHandshakeRole Role { get; }
    public string SessionId { get; }
    public ReadOnlyMemory<byte> TranscriptHash { get { ThrowIfDisposed(); return _transcriptHash; } }
    public ReadOnlyMemory<byte> SendKey { get { ThrowIfDisposed(); return _sendKey; } }
    public ReadOnlyMemory<byte> ReceiveKey { get { ThrowIfDisposed(); return _receiveKey; } }
    public ProductSessionKeys Clone() => new(Role, SessionId, TranscriptHash, SendKey, ReceiveKey);

    public void Dispose()
    {
        if (_disposed) { return; }
        CryptographicOperations.ZeroMemory(_transcriptHash);
        CryptographicOperations.ZeroMemory(_sendKey);
        CryptographicOperations.ZeroMemory(_receiveKey);
        _disposed = true;
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);

    private static void RequireLength(ReadOnlyMemory<byte> bytes, string field)
    {
        if (bytes.Length != 32) { throw new InvalidDataException($"Product session {field} must be 32 bytes."); }
    }
}

/// <summary>Immutable public signing identity captured from one actual handshake message, not current settings.
/// This value alone is neither account membership nor permission to use a product capability.</summary>
public sealed class ProductHandshakeProtocolIdentity
{
    private readonly byte[] _publicKey;

    private ProductHandshakeProtocolIdentity(WebRtcProductProtocolIdentityPublicKey identity)
    {
        Algorithm = identity.Algorithm;
        _publicKey = identity.PublicKey.ToArray();
        Fingerprint = WebRtcProductProtocolIdentityPublicKey.ComputeAuthoritativeFingerprint(Algorithm, _publicKey);
    }

    public WebRtcProductSignatureAlgorithm Algorithm { get; }
    public string Fingerprint { get; }
    public byte[] ExportPublicKey() => _publicKey.AsSpan().ToArray();
    public bool MatchesPublicKey(ReadOnlySpan<byte> bytes) => bytes.SequenceEqual(_publicKey);

    internal static ProductHandshakeProtocolIdentity Capture(ReadOnlySpan<byte> encoded, string message)
    {
        try { return new(WebRtcProductProtocolIdentityPublicKey.DecodeWithLegacyFallback(encoded)); }
        catch (WebRtcProductHandshakeCodecException error)
        { throw new ProductHandshakeException($"Product handshake {message} protocol identity is invalid.", error); }
    }
}

/// <summary>Returned only after the peer's signature and Finished were verified and the local Finished was sent.</summary>
public sealed class AuthenticatedProductHandshake : IDisposable
{
    private readonly byte[] _initiatorExtensions;

    internal AuthenticatedProductHandshake(
        ProductSessionKeys keys, ushort suiteWireId, byte[] messageA, byte[] messageB,
        ProductHandshakeProtocolIdentity localIdentity, ProductHandshakeProtocolIdentity peerIdentity,
        ReadOnlySpan<byte> initiatorExtensions)
    {
        ArgumentNullException.ThrowIfNull(localIdentity);
        ArgumentNullException.ThrowIfNull(peerIdentity);
        LocalProtocolIdentity = localIdentity;
        PeerProtocolIdentity = peerIdentity;
        _initiatorExtensions = initiatorExtensions.ToArray();
        Keys = keys.Clone();
        SuiteWireId = suiteWireId;
        MessageABytes = messageA.Length;
        MessageBBytes = messageB.Length;
        MessageASha256 = Convert.ToHexString(SHA256.HashData(messageA)).ToLowerInvariant();
        MessageBSha256 = Convert.ToHexString(SHA256.HashData(messageB)).ToLowerInvariant();
    }

    public ProductSessionKeys Keys { get; }
    public ProductHandshakeProtocolIdentity LocalProtocolIdentity { get; }
    public ProductHandshakeProtocolIdentity PeerProtocolIdentity { get; }
    // Opaque signed MessageA extensions. Feature admission must validate their semantics.
    public byte[] ExportInitiatorExtensions() => _initiatorExtensions.AsSpan().ToArray();
    public ushort SuiteWireId { get; }
    public int MessageABytes { get; }
    public int MessageBBytes { get; }
    public string MessageASha256 { get; }
    public string MessageBSha256 { get; }
    public void Dispose() => Keys.Dispose();
}

public sealed class WebRtcProductHandshakeResponderMaterial : IDisposable
{
    private readonly byte[] _sharedSecret;
    private bool _disposed;

    public WebRtcProductHandshakeResponderMaterial(
        WebRtcProductHandshakeMessageB messageB,
        ReadOnlyMemory<byte> sharedSecret)
    {
        MessageB = messageB ?? throw new ArgumentNullException(nameof(messageB));
        _sharedSecret = sharedSecret.ToArray();
    }

    public WebRtcProductHandshakeMessageB MessageB { get; }

    public ReadOnlyMemory<byte> SharedSecret
    {
        get
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(WebRtcProductHandshakeResponderMaterial));
            }

            return _sharedSecret;
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        CryptographicOperations.ZeroMemory(_sharedSecret);
    }
}
