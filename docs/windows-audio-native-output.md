# Native exact PCM output qualification

## Windows checkpoint at e4a28846, 2026-10-24

[Run 40123123386](https://github.com/billlza/Skybridge-Compass-Windows/actions/runs/40123123386)
qualified commit `e4a28846836f058325b4593a6acfc0be9b76382e` on the Windows runner.
Both the WinUI client and contract executable built with zero warnings and errors;
all 941 distinct contract cases passed. The separate USB carrier ownership check
and all 21 Windows-generated QR vectors decoded by the Android decoder also passed.
This was a new run of the current code, not reuse of the earlier native receipts.

The interactive UI step passed with 14 baseline captures and 36 observations of
the unobscured candidate window, with no permission action. The USB view exercised
an explicitly synthetic Apple-device service through open, closed and reopened
states; the real product decoder and native signatures produced the expected UI.
Pairing correctly required sign-in, and dismissing sign-in returned to the view.
The account modal was signed out. These checks did not create trust, establish a
real device session, access an actual Apple USB service or play audio.

The overall workflow **failed** at the existing online stack gate:
`Microsoft.WindowsAppSDK package is not current stable: project=2.3.1 latest=2.5.1`.
No version, check or failure policy was changed. Later portability checks and Rust
CLI coverage were not reached. The downloaded evidence archive matched GitHub's
SHA-256 `2c95fefc6a6dd24f81b622711936dd212d67f7a0b65db6a8e8aa462bbf735737`;
logs, manifests, UI observations and screenshots are retained under
`artifacts/audio-native-20261024/native-client-current-v1/`.

Physical phone-to-Windows playback, the Realtek padding failure and strict output
remain open. The existing v4 prefill experiment was reverified against all 283
packaged files, but its physical execution is deferred. It compares the original
failure revision with that revision's isolated prefill change; subsequent product
prefetch/pacing changes mean it cannot qualify the current client. Historical
sections below retain the results and limitations of their named revisions;
the protected account recovery implementation is tracked in
[the offline-state record](windows-audio-offline-state.md).

The subsequent native check of the account-presence route change at `f3a87fab`
passed 952 product cases and the same build/UI gates, while retaining the SDK
freshness failure. Its scope and receipts are recorded with
[the listener-presence implementation](windows-audio-connection-qr.md#same-account-listener-presence-2026-10-24).

## Startup location permission boundary

The native audio UI gate was repeatedly obscured by the real Windows location-consent dialog, including run `39373949550` at `03922715d3b1275d14b82a4aea7571ed5f9ba235`. The retained screenshot and UI failure are under `artifacts/audio-native-20261020/credential-journal-v1/native/winui-smoke/`. The automation provider exposed insufficient text/buttons to bind that dialog safely; the gate correctly failed.

Two product paths requested access during nominally read-only work: weather startup called `Geolocator.RequestAccessAsync`, and `SettingsPermissionsView.Loaded` used the same method to read status. [Microsoft documents that this request can prompt and should align with an appropriate user action](https://learn.microsoft.com/en-us/windows/win32/nativewifi/wi-fi-access-location-changes). [Capability checking is guaranteed not to prompt](https://learn.microsoft.com/en-us/uwp/api/windows.security.authorization.appcapabilityaccess.appcapabilityaccessstatus).

The revised permission view only checks access and observes changes while loaded. Automatic weather refresh checks existing location authorization first and retains the already-labelled approximate IP path when it is unavailable. The existing Settings permission command invokes the real native request and reports its result; a denial or native failure cannot become an in-memory successful intent. Weather rendering and strict audio authorization/output rules are unchanged.

The revised CI startup/navigation contract requires native observations of the same live, unobscured candidate window. It never grants a permission automatically. Missing observations, obscuring windows and records of permission actions fail; a zero-click count alone cannot establish success. The old prompt-handling records and their failures remain historical evidence. Native run [39379140479](https://github.com/billlza/Skybridge-Compass-Windows/actions/runs/39379140479) at `9fd05b9cacb96ae9c6817f4d68fbb2d6a3086aed` passed 869 distinct contracts and recorded 36 clear observations of the candidate window, with no permission action. The verified evidence archive SHA-256 is `e2430df15a0af2c3e814cf45183101d3d675cca14bf33047e7ad0aeb047fe288`. These are sampled startup/navigation observations, not validation of previously granted access or the explicit permission request. The workflow still failed: the account-device modal check dereferenced an absent ListView automation peer at line 309, and the existing SDK freshness gate remained unsatisfied. The later failure snapshot contains that peer and shows the signed-out account modal. The script now requires the real peer through the existing bounded visibility assertion; it does not replace a missing list with zero rows. Native run [39384990653](https://github.com/billlza/Skybridge-Compass-Windows/actions/runs/39384990653) at `024d0f68891378e9445c98e5b1d4d2dcdba8dba3` then passed the interactive UI step, all 869 native contracts, 14 visual captures and 36 clear candidate-window observations. The archive matches SHA-256 `dde08413f3fa773f834943f50650316dfa5c5238e46f178f20287dba7f8d7dc0`. The real account modal reported `signedOut`, zero rows and `authenticatedServiceRequired=false`; this validates the signed-out empty-state UI, not an authenticated device service or playback. The only failing workflow step is now the existing Windows App SDK freshness gate (`2.3.1` versus `2.5.1`). Explicit permission requests, authenticated peers, physical playback and that dependency gate remain separate requirements.

## Playback authorization renewal

Windows reception now owns a renewal task for the exact approved stream. A fresh authenticated device-list GET may advance only the same account publication, local/peer protocol identities and live inbox lease. The original source/output consent stays fixed. Its original membership ID remains frozen so renewal cannot create another original-file transfer from old consent. Replacement logins, expired or revoked consumers, changed connections and late canceled responses cannot resurrect playback.

The request slots are 120, 75 and 40 seconds before the earlier wall-clock or continuous-clock expiry. Late admission gets one immediate attempt and skips missed retry slots. Each attempt is bounded by 35 seconds and clipped before the existing expiry. Only request-boundary temporary transport failures, allowed HTTP statuses and an explicitly occupied request slot can retry. TLS, malformed responses, identity mismatches and unknown exceptions stop the consumer. Authentication adapters retain the original exception and HTTP status in memory; logging still redacts free-form server data. The fixed `current_identity_mismatch` code survives sanitization so a contradictory 503 cannot turn it into temporary unavailability. Temporary failure never extends the existing finite grant, and explicit offline/test configuration performs no renewal request.

The receive session starts renewal after approval, and after creating the original-file admission when applicable. Timeout revokes effects before waiting for an uncooperative request. Native output, private file and inbox teardown precede joining that request; completion still waits for every owner. A timer losing to successful renewal cannot revoke the new evidence. The existing status area shows the committed expiry and renewal state in English, Chinese and Japanese. This does not change PCM bytes, bit depth, sample rate, output format or the strict exclusive-output policy.

A successful token refresh that contradicts the current protected account scope now retires the old audio publication before credential persistence and the subsequent user lookup. A failed or canceled lookup cannot hide that observation or keep the predecessor alive. A later successful verification may publish a distinct account scope; an unchanged scope still preserves its original finite authorization through temporary network loss. The prior implementation failed the new deferred-lookup regression. Ambiguous protected tenant metadata, cancellation, failed persistence, and verified recovery are covered separately.

Renewal also records the first terminal cause together with consumer revocation before publishing `Failed`. The previous publish-before-revoke ordering exposed a failed snapshot while a direct effect check could still succeed; it also lost the deadline cause at that effect boundary. The original ordering failure and a deterministic cause-retention failure were both observed. The final host build has zero warnings/errors and passes 193 distinct account, renewal, capture, original-file and approval checks. The first revocation cause survives later cleanup, while another consumer sharing the finite evidence remains independently authorized. Source snapshots and failed/passing runs are retained under `artifacts/audio-native-20261019/refresh-scope-observation-v1/`. Native validation of this correction is a separate gate.

Run [39289047863](https://github.com/billlza/Skybridge-Compass-Windows/actions/runs/39289047863), source `311d7b0bc0b6d7534d03befac2a4173c91a4d39c`, passed the native client build and 205 contract records, including all eight added or strengthened authorization-boundary checks. The complete suite failed in `AudioReceiveHostTests.WithdrawnOffers`: its JSON-only MAIN barrier received plaintext starting with `S`. An SBE1 audio reply is the working hypothesis, but the original frame type, stream ID and reason were not recorded. The result alone cannot distinguish an allowed receiver-rearm decline from an unexpected message. The separate runtime-freshness gate still reports .NET 10.0.13. The downloaded evidence archive matches SHA-256 `e513c0ff9fc67f24b482f8fc59af9449d9508069b5710ffb46a6a2418e2a2a69`; 90 of the 193 host-selected cases were not reached by this native run.

The barrier now reports the unexpected audio message type, stream ID and stop reason while retaining the strict failure. Twenty serial receive-host runs on the Mac did not reproduce the native failure. The opt-in `diagnose_audio_host` workflow input preserves up to twenty native replays and stops replaying at the first failure; the complete suite still runs and any full-suite or replay failure still fails the step. This diagnostic change does not admit an additional wire outcome. Records are under `artifacts/audio-native-20261019/withdrawn-offer-order-v1/`.

Run [39294707275](https://github.com/billlza/Skybridge-Compass-Windows/actions/runs/39294707275), source `ac2cc4d39d03cd0fbd65a998c8d6d9612271860d`, passed both native builds with zero warnings/errors, all 760 distinct contract checks, all twenty additional receive-host runs, and Windows-to-Android QR decoding. This includes all 193 previously selected host cases. Its downloaded evidence archive matches SHA-256 `ae3cf78a9902ca5940c4a0417e05063f756ca4ffb3ef2c5e9812909da07b6136`. The complete workflow still failed the unchanged .NET runtime-freshness gate. The historical withdrawn-offer failure was not reproduced, so no causal repair is claimed for it. Neither this run nor the isolated continuity experiment establishes protected product restart recovery or physical audio playback.

The host build passed with warnings treated as errors. The final focused run passed 242 distinct cases across account lifecycle, membership, renewal scheduling, approvals, real encrypted TCP receive paths, original files and controlled native output. It includes renewal during a captured PCM stream and an admitted file transfer, plus output release before pending credential cleanup. Controlled clocks and account/output ports do not establish a natural one-hour session or hardware playback. Failure records and source hashes are retained under `artifacts/audio-native-20261019/membership-continuation-v1/` and `artifacts/audio-native-20261019/session-renewal-v1/`.

Native WinUI build/launch of this revision and physical phone-to-Windows playback remain separate acceptance gates. Windows account evidence is currently process-local; protected offline recovery after restarting the app is not implemented here. The physical Realtek padding failure described below remains open, and the isolated smaller-prefill experiment has not been promoted into product playback.

Windows run [39265221166](https://github.com/billlza/Skybridge-Compass-Windows/actions/runs/39265221166), for `0e39923bbb3ff58f84f3ff6e877f40b806990216`, compiled the native WinUI client and reached 520 passing contract records, including the new continuation and renewal cases. The full suite then failed on six-channel FLAC with an exhausted controlled output queue before all source samples were submitted. Its cause is not yet classified as a production defect or test timing issue. The same nine FLAC receive cases passed on the Mac host. A bounded test-endpoint wait/queue trace now preserves the evidence needed to distinguish these possibilities; no source conversion, underrun assertion, output mode or product buffer policy changes for this diagnosis.

That run also created a visible WinUI main window, but the UI gate stopped at the system location dialog: the accessibility provider exposed only the caption, so the script could not bind the application body and buttons to a unique consent target. The independent stack gate still failed with `.NET 10 latest runtime changed: 10.0.13`. The complete native suite and interactive acceptance are therefore open. Optional `diagnose_flac` dispatches retain two additional serial focused runs after the full suite; any full-suite or focused failure still fails the step.

The diagnostic followup [39270475233](https://github.com/billlza/Skybridge-Compass-Windows/actions/runs/39270475233), at `7dfeabdeca9b7761c29785df8b2630e20441ab64`, passed the complete Windows suite with 753 contract records, both additional nine-case FLAC runs and the Windows-to-Android QR image check. No playback implementation changed between these runs. In the three six-channel observations, the largest retained native-fixture wait was 16.2493, 16.13 and 17.7347 ms respectively; no early queue exhaustion was recorded. All observations for those Windows cases fit the bounded trace. This establishes successful revalidation on that runner, not the cause or repair of the earlier intermittent failure.

The full workflow remains failed because the location-dialog UI gate and the existing runtime freshness gate still fail. The native client artifact's GitHub digest (`b84a81afb093850add5bbe55a9c90709686b3f67b3aa5725424048c4ea5ec63d`) and all 624 packaged file lengths/hashes were verified after download. The package was not run on this Mac or the physical Windows computer. The original failure, diagnostic traces, native build manifests and byte readback remain under `artifacts/audio-native-20261019/flac-ci-underrun-v1/`.

## Offline recovery experiment

`windows/Skybridge.AudioOfflineRecoveryProbe/` is isolated from the product account and audio paths. Its writer process protects a synthetic finite checkpoint with CurrentUser DPAPI and a `CryptProtectMemory` SAME_LOGON nonce, then exits before a new reader process starts. The nonce commitment checks the decrypted result: [CryptUnprotectMemory](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptunprotectmemory) documents that mismatched flags may return success with unpredictable plaintext, and that the protected memory cannot be decrypted after an OS restart. Original UTC/QPC anchors and evidence/login IDs are preserved. [Windows QPC](https://learn.microsoft.com/en-us/windows/win32/sysinfo/acquiring-high-resolution-time-stamps) includes sleep and hibernation; the experiment does not substitute a new validity period on restore.

The downloaded artifact from run [39278584597](https://github.com/billlza/Skybridge-Compass-Windows/actions/runs/39278584597), source `cb3490304c3146e494358057811850eea72a79fc`, matches SHA-256 `993d2551b5e0ef13d2058cf7a0449cfeb4180f6b03d1f7dda9ae6b40f805777b`. Its native build has zero warnings/errors and its report contains 17 successful checks on Windows build 26100 with .NET 10.0.13. Same-logon process restart preserved the original identity/deadlines; process-only protection, tampering, changed identities and invalid records were rejected. Four expiry/rollback checks use controlled time inputs. Actual different-user/logon, reboot, sleep and hibernation transitions remain untested.

This establishes one candidate continuity mechanism, not product offline recovery. The existing credential store still needs a single versioned protected account/checkpoint record, durable login binding, compare-and-replace writes, and a cleared-record marker that stale requests cannot overwrite. Startup must distinguish protected finite offline authorization from an arbitrary authentication failure. No product checkpoint, migration or offline startup path is enabled by this experiment. The remaining ordering and migration obligations are specified in [Windows offline state](windows-audio-offline-state.md). Research and native readback records are retained under `artifacts/audio-native-20261019/offline-logon-probe-v1/`.

## Protected record commit preparation

The existing shared file committer now requires a distinct prepared file in the destination directory and, on Windows, requests `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH`. Callers still flush and close the complete temporary file first. A native error becomes an I/O failure retaining its Win32 cause; there is no delete-first, cross-volume-copy or retry path. Account credentials, remote-control identity and Q-Periapt policy state retain their existing formats and owners. The policy store already has a separate file lease and compare-and-swap; credential storage still lacks the versioned account/checkpoint transaction needed for offline audio recovery.

[MoveFileExW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw) documents the write-through request. This source-level hardening is not evidence of surviving a power failure. The old committer failed the new same-directory boundary regression; no before/after power-loss failure is claimed. On the Mac host, both projects built with zero warnings/errors and 128 selected storage, policy and account cases passed. The non-Windows branch only validates portable replacement behavior.

The isolated offline recovery executable also accepts `--commit-run <new-result-directory>`. It links the actual product committer and storage-boundary cases, uses synthetic DPAPI records, and tests writer termination before/after commit, occupied-destination rejection, preserved complete records and cross-process file-lease release. Its report distinguishes these process boundaries from untested power loss, interruption inside the rename syscall, account/checkpoint migration and product offline startup. Evidence is retained under `artifacts/audio-native-20261019/native-protected-commit-v1/`.

Native run [39299791109](https://github.com/billlza/Skybridge-Compass-Windows/actions/runs/39299791109) passed the 17 continuity cases and nine commit cases, then rejected replacement of an open destination with Win32 error 5. The new experiment had incorrectly assumed that `FILE_SHARE_DELETE` permits replacing an existing open target. Run [39300387612](https://github.com/billlza/Skybridge-Compass-Windows/actions/runs/39300387612) reproduced rejection using the previous `File.Move` implementation; its comparison then stopped because it had omitted that API's `UnauthorizedAccessException` outcome. Both failures are retained. The corrected comparison records both documented I/O failure types, while the strict case now requires rejection with both records intact, followed by a separate successful attempt after the reader closes. This agrees with the [standard rename rules for open targets](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information); no POSIX rename mode or automatic retry was added.

Run [39300769246](https://github.com/billlza/Skybridge-Compass-Windows/actions/runs/39300769246), source `8ce296bd9cf711d6c8f489464c4e972015dbe3ac`, completed successfully with zero build warnings/errors, all 17 continuity cases and all 12 commit cases passing. Six sharing comparisons recorded the old and new implementation with a closed target, `Read | Delete` and `ReadWrite | Delete`. Both implementations rejected both open-target modes, retained complete original/prepared records, and accepted a new attempt after the reader closed. The evidence archive matches SHA-256 `7532f428095a55f241e9b46515d6c14cfbeabdaf8fbc8eae192ce3433a4b6958`.

Full run [39301004762](https://github.com/billlza/Skybridge-Compass-Windows/actions/runs/39301004762) at the same source built the native client and contracts with zero warnings/errors and passed 533 distinct cases, including all eleven session storage/commit cases. It stopped in the previously unresolved six-channel FLAC receive case before completing the suite. Its trace records a requested 1 ms wait taking 258.6714 ms, draining a full 9,600-frame/48 kHz controlled output while 30,373 source frames remained unsubmitted. The fixture uses `Thread.Sleep(1)` and advances by the actual observed delay; the production Windows adapter already uses a high-resolution waitable timer and MMCSS. Those pacing implementations and the file pump are unchanged from `7dfeabdeca9b7761c29785df8b2630e20441ab64`. The trace establishes the immediate simulated underrun, not physical WASAPI failure, decoder starvation or a proven scheduling cause. The underrun assertion remains intact. The separate .NET 10.0.13 freshness gate also failed, and QR/UI checks were not reached. The verified archive SHA-256 is `bfdeb97e339a881591edd0079fc55a7ac8f2ec60757b0f956610f9be7a75442f`; complete product regression remains unfinished.

## Native pacing alignment

The controlled receive fixture's ordinary `Thread.Sleep(1)` path differed from the production Windows output, which already used a high-resolution waitable timer and the MMCSS `Audio` task. `WindowsAudioRenderPacing` now owns that existing timer/registration lifetime for both the real adapter and Windows receive qualification. The existing task name, timer flags, cancellation behavior and wait deadline are preserved. It enforces one owning thread and retains failed cleanup; it has no ordinary-sleep fallback on Windows. Portable Mac-host checks keep their separately identified sleep path.

The controlled device still retires samples using the full observed wait (and at least the requested interval). Buffer capacity, source extent and underrun failures are unchanged. Its bounded trace names the pacing mechanism and records GC collection counts around each wait; a collection-count change is a diagnostic correlation, not proof of the scheduling cause. Related host checks passed 71 cases, including both explicit underrun rejection cases, and both projects built with zero warnings/errors. The subsequent trace-only revision passed the nine FLAC receive cases again. These Mac runs do not execute Windows pacing.

The opt-in `Skybridge.WinClient.AudioProbe --pacing-study <new-result-directory>` command opens no audio endpoint. It checks the real pacing component's cancellation, ownership and release boundaries, then records four 512-sample runs in sleep/product/product/sleep order. It preserves all measured ticks and reports whether any product sample reached the existing 200 ms buffer duration. A finite passing sample cannot establish a scheduling upper bound or explain the earlier 258 ms delay. The dedicated native workflow uses the installed .NET runtime (`SelfContained=false`) and records its actual version. Evidence is retained under `artifacts/audio-native-20261019/flac-ci-underrun-v2/`.

Native run [39305619490](https://github.com/billlza/Skybridge-Compass-Windows/actions/runs/39305619490), source `4fe9561dc761299adb4b408601e5986b8e320625`, passed all 13 lifecycle boundaries and collected all 2,048 samples on Windows build 26100/.NET 10.0.13. Both product registrations were released. The downloaded archive matches SHA-256 `eeb3020a78e4c659336436bf4eae9ae5fc2add1ec98b333d1c9354d5491c6c5b`.

| Pacing path / run | Samples | Median wait | 99th percentile | Maximum wait |
| --- | --- | --- | --- | --- |
| Previous sleep / 1 | 512 | 15.7739 ms | 16.8128 ms | 26.1555 ms |
| Windows product / 1 | 512 | 1.5208 ms | 1.5636 ms | 1.5939 ms |
| Windows product / 2 | 512 | 1.5208 ms | 1.5489 ms | 2.0215 ms |
| Previous sleep / 2 | 512 | 15.7890 ms | 16.2670 ms | 16.4995 ms |

No sample in either path reproduced the earlier 258 ms delay. The result demonstrates the pacing difference in this measured environment, not a causal explanation for the extreme pause or a physical playback repair.

Native run [39305994601](https://github.com/billlza/Skybridge-Compass-Windows/actions/runs/39305994601) at the same source passed both builds with zero warnings/errors, all 766 distinct main-suite cases and both additional nine-case FLAC runs. Nineteen of twenty additional receive-host runs passed; the twentieth failed the immediate-withdrawal barrier. The log now identifies a `ReceiverDeclined` Stop for exactly the offered stream, before Pong. The main suite and FLAC replays were successful, but that additional failure still failed the step; the unchanged .NET runtime-freshness gate also failed. QR decoding was not reached, and UI smoke/package creation were not requested. The evidence archive matches SHA-256 `553ed6b13767830bdf57abfc891a7fd695620191d34371e9552f8e67991a3194`.

## Withdrawal during receiver rearming

The sole MAIN reader can receive a valid offer while an advertised consumer is rearming. `LanAudioReceiver.Receive` atomically retires that unattended stream and returns `DeclinedOffer`; `LanProductControlSession` awaits its exact `ReceiverDeclined` reply before reading subsequent frames. A following peer Stop for the retired stream is ignored, then Ping receives Pong. This existing negative path grants no stream or playback permission. The old generic barrier's assumption that Pong must be the first response therefore contradicted this particular immediate-withdrawal sequence.

A deterministic test creates that exact gap, sends Offer/Stop/Ping and reproduces the old barrier failure. The withdrawal-specific barrier now accepts either Pong alone or one `ReceiverDeclined` for the exact offered stream followed by its exact Pong. Foreign streams, other stop reasons, positive admission, duplicate replies and a wrong Pong fail separate encrypted-TCP counterexamples. After host cancellation finishes, another strict barrier rejects any late reply; the test also checks that no unapproved output was activated. Each barrier now has a distinct nonce. Cancellation of an existing approval owner continues using the strict barrier, which permits no Stop echo.

The receiver, transport and authorization code are unchanged by this test correction. The host build has zero warnings/errors and 141 related cases pass, including the deterministic gap and all five negative barrier cases. Raw failures, source snapshots and red/green records are retained under `artifacts/audio-native-20261019/withdrawn-offer-order-v2/`.

Native run [39310969445](https://github.com/billlza/Skybridge-Compass-Windows/actions/runs/39310969445), at commit `b65cf19e94af791034045705dd8c545d0692e418`, passed all 772 distinct main-suite cases, both additional nine-case FLAC runs and all twenty additional 25-case receive-host runs. This includes the deterministic rearm gap, the five wrong-reply counterexamples and the existing endpoint-exhaustion rejection cases. Both native builds reported zero warnings/errors. All twelve successful FLAC trace records identify the actual product timer/MMCSS path and confirmed release. The Android decoder also accepted all 21 generated Windows QR vectors; this is image/payload validation, not a physical camera result. The downloaded evidence archive matches SHA-256 `87165f05ba29fafc0648bce79256ba8ad3a510e2aafecf725e826fe7e8f65a59`.

The complete workflow still failed the unchanged online stack-freshness gate (`.NET 10 latest runtime changed: 10.0.13`); its later portability checks, including Rust CLI coverage, were not reached. UI smoke and native client packaging were not requested. A separate read-only check of the official metadata also found SDK `10.0.402` and ProtectedData `10.0.13`, whereas this branch still pins SDK `10.0.302` and ProtectedData `10.0.10`. The dependency baseline requires its own upgrade and validation; these successful audio tests do not make the full workflow green. Neither the earlier 258 ms scheduling pause nor the physical Realtek full-padding stall has been explained by this correction.

## Exact native tail completion

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

Package `Scripts/start-windows-local-audio-check.cmd` as `Start-Check.cmd` beside the complete `bin` directory. The launcher checks the required executable and runtime entry files before starting. Missing files return code 3 with extraction instructions and explicitly state that audio testing has not started. It does not claim that a report exists merely because a child process returned; the qualification program prints the actual report path after writing it.

The first physical launch failed with `The system cannot find the path specified` before the output-device list appeared. The accompanying File Explorer capture showed `Extract all` and compressed-size columns: the launcher had been opened from inside the ZIP. The archive itself contained the executable at the launcher's expected relative path. After extracting the original package, a subsequent capture showed the qualification program listing `Speakers (Realtek(R) Audio)` and waiting for output selection. This verifies launch and catalog enumeration on the physical Windows host, not audio playback. The updated launcher has only packaging/static validation so far; its missing-file branch has not been executed on Windows.

## Physical output progress failure

The first returned report from Windows build 26200, x64, .NET 10.0.13, with a Realtek speaker endpoint failed during `product-file-pump` for `48000-s24-in-s32`. The diagnostic assembly hash matched the supplied bundle. Exact-format negotiation and output initialization had succeeded, followed by two initial submissions totaling 77,824 bytes (9,728 stereo frames) and one successful Start. There were no subsequent refills. The five-second progress check failed; one Stop and both native releases were recorded. The other two formats were not run. This is a real playback failure, not an unsupported-format result or a successful strict-output qualification.

The original report did not include queue or clock samples, so it could not distinguish a stationary native endpoint from a progress-accounting defect. The diagnostic observer now records the existing native calls' format/initialization results, buffer capacity, latency, post-Start queue extrema and precise-clock positions, and completed pacing-wait durations. It keeps at most 128 samples spaced by 100 ms, reports omitted samples, and retains the last raw clock observation separately. A sample pairs a clock result with the preceding queue read; it is not an atomic hardware snapshot. No extra native query, output-mode change, source transformation, timeout extension or fallback was added.

For the non-event exclusive mode used here, [GetCurrentPadding](https://learn.microsoft.com/en-us/windows/win32/api/audioclient/nf-audioclient-iaudioclient-getcurrentpadding) defines writable capacity as the buffer length minus queued frames. [Initialize](https://learn.microsoft.com/en-us/windows/win32/api/audioclient/nf-audioclient-iaudioclient-initialize) permits a zero periodicity to select the default device period. Those contracts support the current call pattern; they do not prove this physical driver advanced correctly. The trace is intended to discriminate those cases before changing playback behavior.

The diagnostic build passed with warnings treated as errors, and all 18 file-pump regressions passed on the Mac host. Build/test inputs remained unchanged. The new 283-file package was verified entry by entry and by HTTP download hash. The original failure and diagnostic build records are under `artifacts/audio-native-20261019/physical-native-stall-v1/`.

The returned diagnostic report matched assembly SHA-256 `313a94faf78cfb950f013c4dd68cea3c173f9fbff709a81fe8a26b4b652d8eb8` and reproduced the five-second failure. Both format support and initialization returned S_OK. All 2,611 post-Start padding queries reported the full 9,728-frame buffer, while all 2,611 clock calls returned S_OK and the observed position advanced from 1 to 163,152 at frequency 48,000. The maximum completed pacing wait was 3.3344 ms. All 50 sampled observations and the final raw observation were retained, with no truncation. No refill occurred, and Stop/client/device release each completed once. This isolates the immediate blocker to padding-based writable-capacity reporting for this call pattern; it does not yet establish a driver defect or authorize deriving writable space from the advancing clock.

## Cross-runtime captured PCM contract, 2026-10-24

`AudioCaptureInteropPeer` is an explicit contract-executable entry, consumed by
the Android repository's `scripts/audio_windows_interop/interop.gradle`. It
connects the actual Kotlin capture sender to this receiver's real admission,
credit, integrity, output-owner and completion loops. The subprocess bridge
checks byte-identical SBAU codec round trips before forwarding through the
existing encrypted loopback MAIN fixture. Established keys, account responses,
source samples and the output device are controlled test boundaries. It does
not expose a product listener, read account credentials or open WASAPI.

Six cases passed on the Mac host using the pinned .NET SDK and JVM: multi-window
48 kHz Float32 stereo, an independent one-frame tail, packed 96 kHz / 24-bit
stereo, 44.1 kHz / 16-bit mono, receiver decline and a deliberately incorrect End
digest. All accepted samples at the controlled output boundary matched the
source hashes and frame counts, with no padding or format change. Float32 inputs
include low mantissa bits, negative zero and subnormals. Decline opened no source
or output; digest corruption produced ContentMismatch without either completion
receipt. Each case confirmed output release and retained MAIN by encrypted
ping/pong. All peer processes and readers exited, and test/build inputs remained
unchanged during execution. The existing 20 receive-session cases also passed;
the contract assembly built with warnings treated as errors and none reported.

Commands, source hashes, six peer transcripts and results are retained in the
Android checkout's `artifacts/android-windows-pcm-interop-20261024/`. Reproduction
and the exact source/output boundary are documented in its
`scripts/audio_windows_interop/README.md`. This is shared-runtime contract
evidence, not Windows-native execution or phone-to-Windows playback. The real
Realtek padding/progress failure above is still unresolved; no output mode,
precision, timeout or failure criterion was changed to obtain these passes.
