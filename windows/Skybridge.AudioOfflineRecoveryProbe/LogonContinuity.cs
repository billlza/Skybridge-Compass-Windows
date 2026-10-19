using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Skybridge.WinClient.Services.Audio;

namespace Skybridge.AudioOfflineRecoveryProbe;

/// <summary>
/// Experiment adapter for the actual product continuity tag. The separate
/// same-process creation path exists only to construct a negative test input.
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
        if (protection == SameLogon)
        {
            var seal = WindowsAudioLogonContinuity.Instance.Create();
            return new(Convert.FromBase64String(seal.ProtectedNonce), Convert.FromBase64String(seal.NonceDigest));
        }
        if (protection != 0) throw new ArgumentOutOfRangeException(nameof(protection));
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
        try
        {
            WindowsAudioLogonContinuity.Instance.RequireCurrent(new(
                Convert.ToBase64String(seal.ProtectedNonce), Convert.ToBase64String(seal.NonceDigest)));
        }
        catch (CryptographicException failure) { throw new LogonContinuityException(failure); }
    }

    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectMemory([In, Out] byte[] data, uint count, uint flags);

}

internal sealed class LogonContinuityException(Exception cause) : CryptographicException("Windows logon continuity is unavailable.", cause);
