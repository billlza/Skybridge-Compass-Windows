# Strict ALAC native boundary

This directory imports the unchanged `SkyBridgeALACDecoder.c` and public header
qualified by the Apple audio implementation. `provider-source-lock.json` retains
the official FFmpeg 8.1.3 archive/signature/key, strict-error patch, build patch,
license hashes and source revision. `source-lock.json` additionally binds this
repository's C boundary, ABI exports, linker exports, build inputs and licenses.
The receipt is a local byte/configuration record, not a release attestation.

Only the ALAC decoder in libavcodec and libavutil is admitted. The shared C
boundary preserves integer PCM at 16/20/24/32 valid bits, checks exact indexed
packet/frame counts, and requires a clean codec EOF. It performs no file/network
I/O or audio output. The caller owns the verified file, packet index, account
authorization and serialized lifetime. Every native failure invalidates the
operation's output, including any partially written PCM buffer.

`SkyBridgeALACABI.c` adds four ABI version/size exports to the six shared decoder
operations. The .NET binding checks all ten exports, structure sizes, provider
contract and linked version before allocating a decoder. Its resolver accepts
only the library in the application directory; there is no system codec fallback.
An absent optional library is distinct from a present but incompatible library.

## Current qualification

The Windows repository's C boundary and .NET owner executed on macOS arm64 using
a previously qualified, checksum-verified minimal provider. The final native
library exports exactly ten functions and has only libSystem as an external
dependency. Both native and managed builds passed with warning failures enabled.

The explicit `--audio-alac-decoder` entry passed 35 cases: all 24 real M4A files
match independent PCM byte for byte, including valid low bits and partial tails;
corrupt tails and inconsistent frame counts fail; source errors preserve their
identity; cancellation, revocation and reentrant closure each cover all 27
observed checkpoints of the selected decode; pending reads remain owned until
their actual return; concurrent reads are rejected; cached EOF still checks
ownership; packet I/O is bounded to 64 KiB. This is finite component evidence,
not a proof for every possible input or interleaving.

Four separate processes reject absent, invalid, old-ABI and missing-decode-export
libraries. Deliberately modified source, an unpatched baseline receipt and an iOS
provider offered as a macOS provider are rejected by CMake. These are explicit
negative fixtures, never deliverable libraries. The unchanged FLAC decoder's 41
cases and the native resolver static gate also pass.

Exact commands, input snapshots, binary hashes, negative fixtures and results
are retained in `artifacts/alac-native-owner-20261026/`. The focused tests require
the qualified native library and fail if it is unavailable. They are not yet
part of the default Windows test aggregate because the Windows provider build
and application packaging remain unfinished; no tests were run and skipped as
a substitute for native qualification.

## Build boundary and remaining integration

CMake consumes `SKYBRIDGE_ALAC_PROVIDER_RECEIPT`, validates its pinned version,
archive hash, minimal components, patched files, installed codec header and two
static-library hashes, then builds only the SkyBridge boundary. An Apple host
build requires an explicit `CMAKE_OSX_ARCHITECTURES=arm64` and a macOS provider.
A Windows build requires a qualified receipt naming `windows-x64` or
`windows-arm64`, matching an explicit MSVC generator platform. The Windows branch
has not executed and this repository does not yet produce that provider receipt.

The future Windows provider recipe must use the same source/patch contract with
the actual Windows compiler and runtime. FFmpeg documents its MSVC/MSYS2 build
environment and static runtime linkage in the [official platform guide](https://ffmpeg.org/platform.html#Microsoft-Visual-C_002b_002b-or-Intel-C_002b_002b-Compiler-for-Windows).
Mac binaries or an unpatched host FFmpeg installation cannot qualify a Windows
package. Source archives, patches and the upstream license notices must accompany
the eventual distribution/relinking materials.

The .NET owner now feeds the original-file receiver through a full decode-before-
output witness and the shared bounded FLAC/ALAC playback reader. The exact live
receiver advertises `audio_alac_file_receive_v1` only after its packaged native
component passes qualification. Host product-path evidence, package rejection
cases and their limits are recorded in
[`docs/windows-audio-native-output.md`](../../docs/windows-audio-native-output.md#alac-original-file-receiver-integration-2026-10-26)
and `artifacts/alac-product-receive-20261026/`. Native Windows provider/DLL
packaging, WinUI build/launch and phone/hardware interoperability remain required.
Current physical Realtek playback failures are independent and still open. The
host tests do not open output hardware.
