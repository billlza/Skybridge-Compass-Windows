# Strict original FLAC reception

The Windows receiver uses the existing original-file offer, account approval,
classic transfer receipt and exclusive PCM output path. It advertises
`audio_flac_file_receive_v1` only alongside a live matching file listener and a
loadable, compatible packaged decoder. A missing optional decoder leaves WAVE
available; a present but broken decoder is an explicit initialization failure.

`SkyBridgeFLACDecoder.c` and its header are unchanged copies of the Apple
repository's `Sources/CSkyBridgeFLAC` implementation. Their source paths and
checksums are recorded in `source-lock.json`; update them together after shared
boundary review. This is one shared C implementation, with a C# lifetime adapter.
The additional C file exports ABI layout/version queries. C# checks all layouts
and libFLAC 1.5.0 before creating a safe native handle.

The build downloads the exact official release archive using its SHA-256,
statically links libFLAC and the Windows C runtime, disables Ogg and CLI tools, and runs the upstream
`test_libFLAC` executable. The checksum-bound CRC fixture alignment patch is the
same test-only correction used by the Apple build; it changes no production
codec bytes or test assertions. Warnings remain errors. CMake and the installed
Visual Studio 2026 C toolchain are required on Windows; nothing is installed
globally by this build. `windows/NativeFlac.targets` copies the DLL and notices to
both application and contract-test outputs and to publish outputs.

## Decoding and resource contract

- Full FLAC metadata and frame validation precedes output creation, with one
  180-second monotonic deadline, a positive declared duration of at most four
  hours, exact encoded EOF and exact sample count. Available STREAMINFO MD5 must
  match; unavailable MD5 remains explicitly unavailable. Frame errors and native
  loss recovery are terminal, including inserted silence.
- Playback uses a fresh sequential decoder over the same held verified private
  artifact. Integer samples retain rate, channels, order and declared precision;
  high alignment in the smallest byte container is reversible. There is no gain,
  float conversion, resampling or format negotiation fallback.
- The decoder retains at most one whole frame of 2,097,120 bytes. A frame step's
  result trimming can transiently hold a second array of that size. The shared
  output pump retains two prefetched blocks and one current block, each at most
  64 KiB. It joins the actual producer before releasing ownership. Cancellation
  and authorization checks apply to reads and already decoded pending samples.
- The complete second decoder receipt, source extent, native tail completion,
  native release and private-file release remain separate requirements. Receipt
  of file bytes does not imply playback completion.

## Validation

On Windows, normal app/contract builds invoke the native target. Run the existing
repository app build and visible interactive UI smoke before claiming native
acceptance, then run these focused contract selectors:

```powershell
dotnet run --project windows/Skybridge.WinClient.ContractTests -- --audio-flac-decoder
dotnet run --project windows/Skybridge.WinClient.ContractTests -- --audio-flac-product
dotnet run --project windows/Skybridge.WinClient.ContractTests -- --audio-file-playback
dotnet run --project windows/Skybridge.WinClient.ContractTests -- --audio-file-product
```

The macOS host can compile this same CMake project with Ninja, copy its dylib into
the contract-test output, and run the actual C#→C decoder and encrypted-loopback
file pipeline. That is portable integration evidence, not Windows DLL, WinUI,
WASAPI, mobile interoperability or physical DAC output evidence. The missing and
malformed component selectors require isolated output copies with the named
component respectively absent or deliberately invalid; never alter an installed
application to run them.

Reference contracts: [libFLAC decoder API](https://xiph.org/flac/api/group__flac__stream__decoder.html),
[RFC 9639](https://www.rfc-editor.org/rfc/rfc9639.html), and
[.NET native interoperability](https://learn.microsoft.com/en-us/dotnet/standard/native-interop/best-practices).
