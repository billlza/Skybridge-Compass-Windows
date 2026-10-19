# Native exact PCM output qualification

The finite-output completion check must handle a device clock that stops at the end of the submitted source. In the Windows 11 ARM virtual machine, the x64 product output code submitted 4,800 frames at 48 kHz, observed the queue drain, and then repeatedly read position 4,800 at frequency 48,000. The driver reported a constant 10 ms maximum latency. The previous implementation required another 10 ms of device-position advance after the queue drained, so it timed out after five seconds despite having reached the exact source end. Both the native attempt and the added regression failed before the correction.

`ExclusivePcmOutput` now records which of two clock observations supports completion: continued tail advance, or an exact source-end position. The second requires `devicePosition × sourceSampleRate == submittedSourceFrames × deviceFrequency`, using 128-bit integer arithmetic without rounding. It waits the full driver-reported latency on the host clock after a fresh exact-end observation. An end first reached after the queue-drain observation starts a new latency interval; it does not extend the overall deadline. Positions just before or beyond the exact source end do not qualify as a stationary endpoint.

This comparison uses the documented stream-relative ratio, not an assumption that device positions count PCM frames. [IAudioClock::GetPosition](https://learn.microsoft.com/en-us/windows/win32/api/audioclient/nf-audioclient-iaudioclock-getposition) and [GetFrequency](https://learn.microsoft.com/en-us/windows/win32/api/audioclient/nf-audioclient-iaudioclock-getfrequency) define that ratio; [GetStreamLatency](https://learn.microsoft.com/en-us/windows/win32/api/audioclient/nf-audioclient-iaudioclient-getstreamlatency) defines the same-client maximum latency. Host time is checked independently of the device frequency. Precise monotonic clock readings, an empty consistent queue, unchanged latency, current authorization, deadline/cancellation checks and confirmed Stop/release remain required. Any earlier detected underrun remains a failure.

No source bytes, format declarations, exclusive-mode flags or authentication policy change. No silence is appended. The returned receipt describes the native driver's completion boundary, not independent DAC output or continuity proof.

## Reproducible native probe

`windows/Skybridge.WinClient.AudioProbe` links the actual format, endpoint, WASAPI and completion classes. It is an isolated diagnostic executable, not an alternate receiver or account-session admission path. It can be published with the repository SDK from a non-Windows build host; execution requires Windows. The self-contained x64 output needs no machine-wide .NET installation.

```powershell
dotnet publish windows/Skybridge.WinClient.AudioProbe/Skybridge.WinClient.AudioProbe.csproj -c Release -o artifacts/windows-audio-probe
& artifacts/windows-audio-probe/Skybridge.WinClient.AudioProbe.exe --list
& artifacts/windows-audio-probe/Skybridge.WinClient.AudioProbe.exe --probe '<observed endpoint ID>'
& artifacts/windows-audio-probe/Skybridge.WinClient.AudioProbe.exe --render-quiet-test '<observed endpoint ID>' '48000-s24-in-s32'
```

`--list` and `--probe` do not initialize or start a stream. The explicit render command synthesizes a 100 ms, 500 Hz stereo source with a nominal peak of −72 dBFS and 5 ms fades, directly in the selected format. It submits that source once into the product's requested 200 ms buffer and exercises the product completion method. It never selects another endpoint, converts an existing source, changes system volume or retries with another format.

JSON output includes format, source extent/hash, driver capacity, latency, clock evidence and cleanup observations. Failure returns exit code 1 with its causes; unsupported format is distinct from other native query failures. The diagnostic trace is capped at 4,096 observations and reports any omitted events. Instrumentation is for qualification and failure diagnosis, not a performance benchmark. Preserve the build's source/binary hashes alongside results; a filename alone does not identify the tested code.

## Observed on 2026-10-19

Windows 11 ARM build 26300.9457, x64 process under emulation, virtual High Definition Audio Device:

| Explicit stereo source format | Exact exclusive support | Render check |
| --- | --- | --- |
| 44.1 kHz, 16-bit integer | Accepted | 4,410 frames completed; exact end held; 11.5842 ms host tail wait |
| 48 kHz, 16-bit integer | Accepted | Not run |
| 48 kHz, packed 24-bit integer | Rejected | Rejected before initialization/submission; no format fallback |
| 48 kHz, 24 valid bits in 32-bit integer storage | Accepted | 4,800 frames completed; exact end held; 11.3075 ms host tail wait |
| 48 kHz, Float32 | Rejected | Not run |
| 96 kHz, packed 24-bit integer | Rejected | Not run |
| 192 kHz, packed 24-bit integer | Rejected | Not run |

The two 24-bit storage declarations are separate sources. Supporting the 32-bit container does not authorize repacking the unsupported packed source. Native invalid-command, unknown-output and unknown-format checks also failed before activation. Seven native diagnostic cases passed their explicit success/rejection expectations with no truncated trace.

Local managed regression results: 38 exclusive-output cases, 18 file-playback, 17 capture-reception, 18 original-file reception, 24 receiver/dialog/catalog, 9 FLAC reception and 41 FLAC decoder cases passed (165 total). The first FLAC reception attempt failed because its host test directory lacked the optional native decoder. The checksum-locked decoder was then built and packaged into that test directory; upstream `skybridge_libFLAC` and both FLAC groups passed. That packaging failure remains in the local evidence. The probe's initial platform-analyzer error was corrected with its accurate Windows-only assembly contract, without disabling analysis; final builds use warnings as errors.

Local receipts are under `artifacts/audio-native-20261019/receiver-review-v1/`, including the old native timeout, red/green regression, exact build inputs, complete native traces and the final seven-case batch. These results do not establish WinUI launch, an authenticated Android/iOS-to-Windows stream, long-run continuity, physical Windows audio hardware, or sample-for-sample DAC output. Full native application CI and those real-device boundaries are tracked separately.

Native run [39207253648](https://github.com/billlza/Skybridge-Compass-Windows/actions/runs/39207253648), at `90f02593d0c38510d88804182e1f4655a38ca2db`, subsequently built the WinUI client and contract executable with zero warnings/errors, passed 728 unique product cases, and decoded all 21 QR vectors. Interactive UI testing was not requested in that run. The overall workflow failed the existing online stack gate with `.NET 10 latest runtime changed: 10.0.13`; later portability checks did not complete. The downloaded validation archive matched GitHub's reported SHA-256 `0f5e80d9a20009fd9828e7ae037e3172ae01f9b929d0fbdafd93610ad0ad1f04`. Its receipts are retained separately under `artifacts/audio-native-20261019/native-ci-90f02593-v1/`; this does not change the earlier sealed component evidence or close the independent stack/UI/device gates.

## Obtain the full client for device qualification

Dispatch `Windows Portability` with `package_native_client=true` to retain `windows-native-client-<commit>` for three days. This optional artifact is captured only after the native build, product contracts and Android QR decoding succeed, before interactive application use. It includes the complete Debug `win-x64` output and a schema-2 `native-client-build.json` containing both required entry-point hashes and the length/hash of every output file. Keep its directory structure, .NET/Windows App SDK runtime files, native libraries, assets and licenses together.

Before execution, verify the run's repository and exact commit, the archive digest reported by GitHub, the receipt identity, the exact output-file set, and every file length/hash. Do not treat a five-entry schema-1 receipt as a full-directory manifest. The optional bundle is a diagnostic build, not an installer or release; the independent portability gate may still fail, and application launch, account admission, camera pairing and device playback require their own evidence.

Run [39209086128](https://github.com/billlza/Skybridge-Compass-Windows/actions/runs/39209086128) produced that bundle for `cee92cc6506c73b5904ccbad25f5e7e0f8a57b84`. Native build, 728 product cases, and 21 QR vectors passed; the independent portability gate again failed with `.NET 10 latest runtime changed: 10.0.13`. The complete client ZIP matched GitHub's SHA-256 `c51515d7d7af41a3b3c4470074cac45cfdee449bc1429d3fca64c600a4377b25`; all 624 client files matched their lengths and hashes on both Mac and the Windows VM. Starting this bundle created a responding `云桥司南` main window, but interactive acceptance remains open: the first-run Windows location prompt appeared, and the available desktop input bridge did not dismiss it. A process/window handle alone does not close the UI gate. Receipts are under `artifacts/audio-native-20261019/native-bundle-v1/`.

## Native file-pump refill qualification

The opt-in contract executable command below exercises the actual `AudioWavePcmFile` parser and `AudioFilePcmPlayback` loop with real WASAPI output. It synthesizes a fresh one-second stereo WAVE at 500 Hz, nominal peak −72 dBFS, with 5 ms fades. Only three named formats are accepted; it cannot open an arbitrary music file. Select a currently enumerated endpoint explicitly.

```powershell
dotnet publish windows/Skybridge.WinClient.ContractTests/Skybridge.WinClient.ContractTests.csproj -c Release -r win-x64 --self-contained true -p:TreatWarningsAsErrors=true -o artifacts/windows-file-pump
& artifacts/windows-file-pump/Skybridge.WinClient.ContractTests.exe --native-quiet-file-playback '<observed endpoint ID>' '48000-s24-in-s32'
```

This uses the existing controlled immutable-read seam, so it does not exercise account admission, network reception, or the verified private-artifact store. There is no separate playback loop. A native-boundary observer compares every submitted span with the corresponding original source bytes and records successful submissions, refills after Start, exact completion and resource release. The command fails if the one-second source fits in the entire native buffer, if no refill occurs, or if bytes, frame counts, Start/Stop or release observations disagree. Each invocation has a 15-second cancellation budget; individual native calls still depend on driver cooperation. It does not change system volume, format, gain, or authorization policy.

Observed on the same Windows 11 ARM VM on 2026-10-19:

| Source | Native buffer | Successful submissions / refills after Start | Completed source frames |
| --- | --- | --- | --- |
| 48 kHz, 24 valid bits in 32-bit integer storage | 9,728 frames | 463 / 461 | 48,000 |
| 44.1 kHz, 16-bit integer | 9,216 frames | 445 / 444 | 44,100 |

Both runs matched the complete original PCM byte sequence at the submission boundary, observed the exact source-end device position, waited the reported 10 ms tail (12.0022 ms and 12.9388 ms host observations respectively), and confirmed one Start, one Stop, and both native releases. Their WAVE and PCM SHA-256 values independently matched the previously prepared Python-generated one-second fixtures. These submission counts are observations, not throughput targets. Packed 48 kHz/24-bit was rejected with `0x88890008` before submission or Start and released both owners; an unknown format was rejected before endpoint activation. The cross-published diagnostic build used warnings as errors. All four native outcomes are retained under `artifacts/audio-native-20261019/native-file-pump-v1/`.

This closes the short native file-refill check only. Instrumentation, Windows ARM emulation and a virtual audio endpoint do not establish long-run continuity, physical DAC integrity, or authenticated phone-to-Windows playback.

## Local interactive qualification without remote access

The same contract executable now accepts `--native-local-audio-check <result-directory>`. It enumerates active render endpoints through the product catalog, asks for an explicit numbered selection, then calls the existing native quiet file-pump check for 48 kHz/24-in-32, 44.1 kHz/16-bit and packed 48 kHz/24-bit, in that order. It stops after the first failed case so an uncertain native cleanup cannot be hidden by starting another output owner. A rejected format is preserved as a failed case; remaining cases are explicitly not run. There is no mixer fallback, source conversion, default-endpoint substitution, account registration or service installation.

Each run has a unique result directory and an initially `running` report. Completed case receipts are retained before the next case; final report replacement is atomic. Cancellation before selecting an endpoint has a distinct result, and file errors do not produce success. The combined JSON includes the qualification assembly SHA-256, selected endpoint, runtime/platform, each native receipt and all unexecuted formats. These are qualification observations, not device attestation or account authority.

```powershell
dotnet publish windows/Skybridge.WinClient.ContractTests/Skybridge.WinClient.ContractTests.csproj -c Release -r win-x64 --self-contained true -p:RuntimeFrameworkVersion=10.0.13 -p:TreatWarningsAsErrors=true -o artifacts/windows-local-audio
& artifacts/windows-local-audio/Skybridge.WinClient.ContractTests.exe --native-local-audio-check artifacts/windows-local-audio-results
```

The Windows-target publish passed with warnings treated as errors. `dotnet run --project windows/Skybridge.WinClient.ContractTests/Skybridge.WinClient.ContractTests.csproj -c Release -p:TreatWarningsAsErrors=true -- --audio-file-playback` passed all 18 file-pump contract cases on the Mac host; this is not native Windows execution. The private portable bundle includes 283 verified binary/runtime files and a double-click launcher, with no machine-wide runtime installation. It uses an isolated .NET 10.0.13 runtime override verified against Microsoft's release metadata. This does not update the full client's stack declarations or close the existing online freshness failure.

Local packaging records are under `artifacts/audio-native-20261019/physical-local-audio-v1/`. At packaging time, physical execution of this interactive entry and authenticated phone-to-Windows playback remained unverified.
