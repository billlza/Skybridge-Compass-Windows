using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;

namespace Skybridge.WinClient.Services.Audio;

internal enum AudioAlacDecoderStatus
{
    Ready, Frame, Complete,
    InvalidArgument = 100, AllocationFailed, UnqualifiedProvider, InvalidSource, Cancelled,
    CodecError, MissingFrame, FormatChanged, FrameCountMismatch, ExtraOutput, SampleRangeError, SequenceError
}

internal sealed class AudioAlacDecodeException(AudioAlacDecoderStatus status, int codecError)
    : IOException($"Strict ALAC decoding failed: {status} (codec {codecError}).")
{
    internal AudioAlacDecoderStatus Status { get; } = status;
    internal int CodecError { get; } = codecError;
}
internal sealed class AudioAlacComponentException(string message, Exception? inner = null) : IOException(message, inner);

// Mirrors the pinned C boundary plus its size/version exports. No OS decoder,
// system FFmpeg search, resampling or alternate native library is permitted.
internal static class AudioAlacNative
{
    private const string Library = "skybridge_alac";
    internal const string RequiredVersion = "8.1.3";
    [StructLayout(LayoutKind.Sequential)]
    internal struct Source
    {
        // The opaque 24-byte configuration, copied as three little-endian words.
        // Its contents remain in their original big-endian codec representation.
        internal ulong Configuration0, Configuration1, Configuration2, TotalFrames, PacketCount;
    }
    [StructLayout(LayoutKind.Sequential)]
    internal struct Control { internal nint Context, IsCancelled; }
    [StructLayout(LayoutKind.Sequential)]
    internal struct Result
    {
        internal AudioAlacDecoderStatus Status;
        internal int CodecError;
        internal ulong PacketIndex, FirstFrameIndex;
        internal uint FrameCount;
        internal nuint ByteCount;
        internal ulong DecodedFrames, DecodedPackets;
    }
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int CancelCallback(nint context);

    private static string LibraryPath => Path.Combine(AppContext.BaseDirectory,
        OperatingSystem.IsWindows() ? "skybridge_alac.dll" : OperatingSystem.IsMacOS() ? "libskybridge_alac.dylib" : "libskybridge_alac.so");
    internal static bool IsPackaged => File.Exists(LibraryPath);

    internal static void RequireCompatible()
    {
        try
        {
            SkybridgeNativeLibraryResolver.Register();
            // A matching version/size alone must not advertise a DLL missing a
            // decode or finish entry point. Pin every required export before allocation.
            nint library = NativeLibrary.Load(LibraryPath);
            try
            {
                string[] exports = ["sbalac_decoder_create", "sbalac_decoder_decode", "sbalac_decoder_finish",
                    "sbalac_decoder_destroy", "sbalac_linked_version", "sbalac_provider_contract_version",
                    "sbalac_bridge_abi_version", "sbalac_source_description_size", "sbalac_control_size", "sbalac_result_size"];
                foreach (string entry in exports)
                    if (!NativeLibrary.TryGetExport(library, entry, out _))
                        throw new EntryPointNotFoundException("The packaged ALAC decoder is missing " + entry + ".");
            }
            finally { NativeLibrary.Free(library); }
            if (!BitConverter.IsLittleEndian || IntPtr.Size != 8 || AbiVersion() != 1 || ProviderContract() != 1 ||
                SourceSize() != (nuint)Marshal.SizeOf<Source>() || ControlSize() != (nuint)Marshal.SizeOf<Control>() ||
                ResultSize() != (nuint)Marshal.SizeOf<Result>() || Marshal.PtrToStringUTF8(LinkedVersion()) != RequiredVersion)
                throw new AudioAlacComponentException("The packaged ALAC decoder ABI, provider contract or version is incompatible.");
            // Resolve destruction before the first allocation. The native contract accepts null.
            Destroy(0);
        }
        catch (Exception failure) when (failure is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
        { throw new AudioAlacComponentException("The packaged strict ALAC decoder cannot be loaded.", failure); }
    }

    [DllImport(Library, EntryPoint = "sbalac_decoder_create", CallingConvention = CallingConvention.Cdecl)]
    internal static extern AudioAlacDecoderStatus Create(in Source source, out nint decoder, out Result result);
    [DllImport(Library, EntryPoint = "sbalac_decoder_decode", CallingConvention = CallingConvention.Cdecl)]
    internal static extern AudioAlacDecoderStatus Decode(DecoderHandle decoder, in Control control,
        ulong packetIndex, ulong firstFrameIndex, byte[] packet, nuint packetBytes, uint expectedFrames,
        [Out] byte[] output, nuint outputCapacity, out Result result);
    [DllImport(Library, EntryPoint = "sbalac_decoder_finish", CallingConvention = CallingConvention.Cdecl)]
    internal static extern AudioAlacDecoderStatus Finish(DecoderHandle decoder, in Control control, out Result result);
    [DllImport(Library, EntryPoint = "sbalac_decoder_destroy", CallingConvention = CallingConvention.Cdecl)]
    private static extern void Destroy(nint decoder);
    [DllImport(Library, EntryPoint = "sbalac_linked_version", CallingConvention = CallingConvention.Cdecl)]
    private static extern nint LinkedVersion();
    [DllImport(Library, EntryPoint = "sbalac_provider_contract_version", CallingConvention = CallingConvention.Cdecl)]
    private static extern uint ProviderContract();
    [DllImport(Library, EntryPoint = "sbalac_bridge_abi_version", CallingConvention = CallingConvention.Cdecl)]
    private static extern uint AbiVersion();
    [DllImport(Library, EntryPoint = "sbalac_source_description_size", CallingConvention = CallingConvention.Cdecl)]
    private static extern nuint SourceSize();
    [DllImport(Library, EntryPoint = "sbalac_control_size", CallingConvention = CallingConvention.Cdecl)]
    private static extern nuint ControlSize();
    [DllImport(Library, EntryPoint = "sbalac_result_size", CallingConvention = CallingConvention.Cdecl)]
    private static extern nuint ResultSize();

    internal sealed class DecoderHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal DecoderHandle(nint decoder) : base(true) => SetHandle(decoder);
        protected override bool ReleaseHandle() { Destroy(handle); return true; }
    }
}
