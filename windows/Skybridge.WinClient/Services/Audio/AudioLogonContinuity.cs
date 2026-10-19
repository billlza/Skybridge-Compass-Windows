using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Skybridge.WinClient.Services.Audio;

// This value is a continuity tag, not encryption or authentication for an account
// record. The complete checkpoint must be authenticated by the enclosing DPAPI record.
internal sealed record AudioLogonSeal(string ProtectedNonce, string NonceDigest)
{
    internal const int ByteLength = 32;
    internal static byte[] Decode(string value)
    {
        if (value is not { Length: 44 }) throw new InvalidDataException("Invalid logon continuity encoding.");
        byte[] bytes;
        try { bytes = Convert.FromBase64String(value); }
        catch (FormatException error) { throw new InvalidDataException("Invalid logon continuity encoding.", error); }
        if (bytes.Length == ByteLength && Convert.ToBase64String(bytes) == value) return bytes;
        CryptographicOperations.ZeroMemory(bytes);
        throw new InvalidDataException("Invalid logon continuity encoding.");
    }
    internal void Validate()
    {
        var nonce = Decode(ProtectedNonce);
        try { var digest = Decode(NonceDigest); CryptographicOperations.ZeroMemory(digest); }
        finally { CryptographicOperations.ZeroMemory(nonce); }
    }
}

internal interface IAudioLogonContinuity
{
    AudioLogonSeal Create();
    void RequireCurrent(AudioLogonSeal seal);
}

internal sealed class WindowsAudioLogonContinuity : IAudioLogonContinuity
{
    internal static WindowsAudioLogonContinuity Instance { get; } = new();
    private const uint SameLogon = 2;
    private WindowsAudioLogonContinuity() { }

    public AudioLogonSeal Create()
    {
        RequireWindows();
        var nonce = RandomNumberGenerator.GetBytes(AudioLogonSeal.ByteLength);
        var digest = SHA256.HashData(nonce);
        try
        {
            if (!CryptProtectMemory(nonce, AudioLogonSeal.ByteLength, SameLogon))
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "Logon continuity protection failed.");
            return new(Convert.ToBase64String(nonce), Convert.ToBase64String(digest));
        }
        finally { CryptographicOperations.ZeroMemory(nonce); CryptographicOperations.ZeroMemory(digest); }
    }

    public void RequireCurrent(AudioLogonSeal seal)
    {
        RequireWindows(); ArgumentNullException.ThrowIfNull(seal);
        var nonce = AudioLogonSeal.Decode(seal.ProtectedNonce);
        try
        {
            var commitment = AudioLogonSeal.Decode(seal.NonceDigest);
            Span<byte> actual = stackalloc byte[AudioLogonSeal.ByteLength];
            try
            {
                if (!CryptUnprotectMemory(nonce, AudioLogonSeal.ByteLength, SameLogon))
                    throw new Win32Exception(Marshal.GetLastPInvokeError(), "Logon continuity recovery failed.");
                // A different protection flag can return success with unpredictable
                // bytes. Only the authenticated original commitment can admit it.
                SHA256.HashData(nonce, actual);
                if (!CryptographicOperations.FixedTimeEquals(actual, commitment))
                    throw new CryptographicException("The Windows logon continuity tag no longer matches.");
            }
            finally { CryptographicOperations.ZeroMemory(commitment); CryptographicOperations.ZeroMemory(actual); }
        }
        finally { CryptographicOperations.ZeroMemory(nonce); }
    }

    private static void RequireWindows()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Audio logon continuity requires Windows.");
    }
    [DllImport("crypt32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectMemory([In, Out] byte[] bytes, uint length, uint flags);
    [DllImport("crypt32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectMemory([In, Out] byte[] bytes, uint length, uint flags);
}
