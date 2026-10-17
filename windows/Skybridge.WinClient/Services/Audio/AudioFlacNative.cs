using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;

namespace Skybridge.WinClient.Services.Audio;

internal enum AudioFlacDecoderStatus
{
    Ready, Frame, Complete,
    InvalidArgument = 100, AllocationFailed, SourceError, Cancelled, MetadataMismatch,
    CodecError, FormatChanged, FrameSequenceError, FrameSizeError, ResourceLimit,
    SampleRangeError, SampleCountError, InputEndMismatch, Md5Mismatch
}

internal sealed class AudioFlacDecodeException(AudioFlacDecoderStatus status, int codecError = -1)
    : IOException($"Strict FLAC decoding failed: {status} (codec {codecError}).")
{
    internal AudioFlacDecoderStatus Status { get; } = status;
    internal int CodecError { get; } = codecError;
}

internal sealed class AudioFlacComponentException(string message, Exception? inner = null) : IOException(message, inner);

// Native declarations mirror the checksum-bound shared C header. The resolver
// loads only the application directory. No system codec or alternate DLL fallback.
internal static class AudioFlacNative
{
    private const string Library = "skybridge_flac";
    internal const string RequiredVersion = "1.5.0";
    [StructLayout(LayoutKind.Sequential)]
    internal struct Source
    {
        internal uint SampleRate, Channels, ValidBits, MinimumBlockFrames, MaximumBlockFrames,
            MinimumFrameBytes, MaximumFrameBytes;
        internal ulong TotalFrames, FirstFrameByteOffset, Md5Low, Md5High;
    }
    [StructLayout(LayoutKind.Sequential)]
    internal struct ReadAccess { internal nint Context, Read, IsCancelled; }
    [StructLayout(LayoutKind.Sequential)]
    internal struct Result
    {
        internal AudioFlacDecoderStatus Status;
        internal ulong FirstFrameIndex;
        internal uint FrameCount;
        internal nuint ByteCount;
        internal ulong TotalFrames, EncodedBytesConsumed;
        internal int Md5Available, Md5Verified, CodecError;
    }
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int ReadCallback(nint context, ulong offset, nint buffer, nuint capacity, out nuint bytesRead);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int CancelCallback(nint context);

    internal static void RequireCompatible()
    {
        try
        {
            SkybridgeNativeLibraryResolver.Register();
            if (!BitConverter.IsLittleEndian || IntPtr.Size != 8 || AbiVersion() != 1 ||
                SourceSize() != (nuint)Marshal.SizeOf<Source>() || AccessSize() != (nuint)Marshal.SizeOf<ReadAccess>() ||
                ResultSize() != (nuint)Marshal.SizeOf<Result>() || Marshal.PtrToStringUTF8(LinkedVersion()) != RequiredVersion)
                throw new AudioFlacComponentException("The packaged FLAC decoder ABI or version is incompatible.");
            // Resolve the release entry point before any SafeHandle can be created.
            // The C contract explicitly accepts null; no codec state is allocated.
            Destroy(0);
        }
        catch (Exception failure) when (failure is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
        { throw new AudioFlacComponentException("The packaged strict FLAC decoder cannot be loaded.", failure); }
    }
    // Absence is an explicit unsupported optional role. A present but incompatible
    // binary fails initialization; it must not be hidden as a missing capability.
    internal static bool IsPackaged => File.Exists(Path.Combine(AppContext.BaseDirectory,
        OperatingSystem.IsWindows() ? "skybridge_flac.dll" : OperatingSystem.IsMacOS() ? "libskybridge_flac.dylib" : "libskybridge_flac.so"));

    [DllImport(Library, EntryPoint = "sbflac_decoder_create", CallingConvention = CallingConvention.Cdecl)]
    internal static extern AudioFlacDecoderStatus Create(in Source source, ulong fileBytes, ulong maximumFrames, out nint decoder);
    [DllImport(Library, EntryPoint = "sbflac_decoder_next", CallingConvention = CallingConvention.Cdecl)]
    internal static extern AudioFlacDecoderStatus Next(DecoderHandle decoder, in ReadAccess access,
        [Out] byte[] output, nuint capacity, out Result result);
    [DllImport(Library, EntryPoint = "sbflac_decoder_destroy", CallingConvention = CallingConvention.Cdecl)]
    private static extern void Destroy(nint decoder);
    [DllImport(Library, EntryPoint = "sbflac_linked_version", CallingConvention = CallingConvention.Cdecl)]
    private static extern nint LinkedVersion();
    [DllImport(Library, EntryPoint = "sbflac_bridge_abi_version", CallingConvention = CallingConvention.Cdecl)]
    private static extern uint AbiVersion();
    [DllImport(Library, EntryPoint = "sbflac_source_description_size", CallingConvention = CallingConvention.Cdecl)]
    private static extern nuint SourceSize();
    [DllImport(Library, EntryPoint = "sbflac_read_access_size", CallingConvention = CallingConvention.Cdecl)]
    private static extern nuint AccessSize();
    [DllImport(Library, EntryPoint = "sbflac_result_size", CallingConvention = CallingConvention.Cdecl)]
    private static extern nuint ResultSize();

    internal sealed class DecoderHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal DecoderHandle(nint decoder) : base(true) => SetHandle(decoder);
        protected override bool ReleaseHandle() { Destroy(handle); return true; }
    }
}
