using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Skybridge.WinClient.Services;

public interface ISessionProtector
{
    byte[] Protect(byte[] bytes);

    byte[] Unprotect(byte[] bytes);
}

internal interface ISessionFileCommitter
{
    void Commit(string temporaryPath, string destinationPath);
}

internal sealed class AtomicSessionFileCommitter : ISessionFileCommitter
{
    private const uint MoveFileReplaceExisting = 0x1;
    private const uint MoveFileWriteThrough = 0x8;
    public static AtomicSessionFileCommitter Instance { get; } = new();

    private AtomicSessionFileCommitter()
    {
    }

    public void Commit(string temporaryPath, string destinationPath)
    {
        var temporary = Path.GetFullPath(temporaryPath);
        var destination = Path.GetFullPath(destinationPath);
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        if (string.Equals(temporary, destination, comparison) ||
            !string.Equals(Path.GetDirectoryName(temporary), Path.GetDirectoryName(destination), comparison))
            throw new ArgumentException("A protected record requires a distinct temporary file in its destination directory.");

        if (!OperatingSystem.IsWindows())
        {
            // Portable contract tests exercise replacement and failure behavior.
            // Only the Windows branch provides the product's write-through request.
            File.Move(temporary, destination, overwrite: true);
            return;
        }

        // Callers close and Flush(true) the complete temporary file first. Request
        // write-through for the final name change too. Never delete the old head
        // first, allow cross-volume copy, or fall back after a native failure.
        // This commit alone is not compare-and-swap or a revocation journal.
        if (!MoveFileExW(ExtendedPath(temporary), ExtendedPath(destination), MoveFileReplaceExisting | MoveFileWriteThrough))
        {
            var failure = new Win32Exception(Marshal.GetLastPInvokeError());
            throw new IOException("Protected record commit failed.", failure);
        }
    }

    private static string ExtendedPath(string fullPath) => fullPath.StartsWith(@"\\?\", StringComparison.Ordinal)
        ? fullPath
        : fullPath.StartsWith(@"\\", StringComparison.Ordinal) ? @"\\?\UNC\" + fullPath[2..] : @"\\?\" + fullPath;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool MoveFileExW(string existingFile, string newFile, uint flags);
}

