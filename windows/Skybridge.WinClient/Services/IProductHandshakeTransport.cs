namespace Skybridge.WinClient.Services;

/// <summary>One ordered, framed carrier. Ownership remains with the session across the handshake boundary.</summary>
public interface IProductHandshakeTransport
{
    Task SendAsync(ReadOnlyMemory<byte> frame, CancellationToken cancellationToken = default);
    Task<ReadOnlyMemory<byte>> ReadAsync(CancellationToken cancellationToken = default);
}
