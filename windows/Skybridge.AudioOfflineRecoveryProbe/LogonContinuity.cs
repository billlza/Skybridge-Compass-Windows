using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace Skybridge.AudioOfflineRecoveryProbe;

/// <summary>
/// An isolated experiment, not a product credential or a disk-store implementation.
/// The entire returned value MUST be inside the same authenticated CurrentUser DPAPI
/// record as the original finite grant, login ID and revocation revision. It proves
/// continuity of one Windows logon only; it never establishes account membership.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class LogonContinuity
{
    internal const int NonceBytes = 32;
    internal const uint SameLogon = 2;

    internal sealed record Seal(byte[] ProtectedNonce, byte[] NonceDigest);

    internal static Seal Create(uint protection = SameLogon)
    {
        var nonce = RandomNumberGenerator.GetBytes(NonceBytes);
        try
        {
            var digest = SHA256.HashData(nonce);
            // A SHA-256 commitment detects a wrong key/flag/logon even when the
            // native API returns success with an unpredictable plaintext. Its
            // binding to the checkpoint is provided by the enclosing DPAPI MAC.
            if (!CryptProtectMemory(nonce, NonceBytes, protection))
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "CryptProtectMemory failed.");
            return new(nonce.ToArray(), digest);
        }
        finally { CryptographicOperations.ZeroMemory(nonce); }
    }

    internal static void RequireCurrent(Seal seal)
    {
        if (seal.ProtectedNonce is not { Length: NonceBytes } || seal.NonceDigest is not { Length: 32 })
            throw new InvalidDataException("Invalid logon continuity seal.");
        var nonce = seal.ProtectedNonce.ToArray();
        try
        {
            if (!CryptUnprotectMemory(nonce, NonceBytes, SameLogon))
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "CryptUnprotectMemory failed.");
            Span<byte> digest = stackalloc byte[32];
            try
            {
                SHA256.HashData(nonce, digest);
                if (!CryptographicOperations.FixedTimeEquals(digest, seal.NonceDigest))
                    throw new LogonContinuityException();
            }
            finally { CryptographicOperations.ZeroMemory(digest); }
        }
        finally { CryptographicOperations.ZeroMemory(nonce); }
    }

    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectMemory([In, Out] byte[] data, uint count, uint flags);

    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectMemory([In, Out] byte[] data, uint count, uint flags);
}

internal sealed class LogonContinuityException() : CryptographicException("Windows logon continuity is unavailable.");
