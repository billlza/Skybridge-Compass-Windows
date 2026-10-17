using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

namespace Skybridge.WinClient.Services;

internal static class SkybridgeNativeLibraryResolver
{
    private const string LibraryName = "skybridge_core";

    private static readonly object Sync = new();
    private static bool _registered;

    public static void Register()
    {
        lock (Sync)
        {
            if (_registered)
            {
                return;
            }

            NativeLibrary.SetDllImportResolver(typeof(SkybridgeNativeLibraryResolver).Assembly, Resolve);
            _registered = true;
        }
    }

    private static nint Resolve(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        bool flac = string.Equals(libraryName, "skybridge_flac", StringComparison.Ordinal);
        if (!flac && !string.Equals(libraryName, LibraryName, StringComparison.Ordinal))
        {
            return nint.Zero;
        }

        var libraryPath = Path.Combine(AppContext.BaseDirectory, GetPlatformLibraryFileName(flac));
        if (!File.Exists(libraryPath))
        {
            throw new DllNotFoundException(
                flac ? $"SkyBridge strict FLAC library was not found in the application directory: {libraryPath}" :
                $"SkyBridge native Core library was not found in the application directory: {libraryPath}");
        }

        return NativeLibrary.Load(libraryPath);
    }

    private static string GetPlatformLibraryFileName(bool flac)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return flac ? "skybridge_flac.dll" : "skybridge_core.dll";
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            return flac ? "libskybridge_flac.dylib" : "libskybridge_core.dylib";
        }

        return flac ? "libskybridge_flac.so" : "libskybridge_core.so";
    }
}
