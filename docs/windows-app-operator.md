# Windows app operator IPC

Development implementation: public CLI 0.3.3. Native Windows acceptance is pending.
The Core diagnostic CLI remains 0.1.1 and does not provide this command family.

The public CLI selects the running `Skybridge.WinClient.exe`, then addresses
`\\.\pipe\SkyBridge.OperatorControl.v1.<PID>`. It verifies the actual pipe server
PID before sending a request. Ambiguous process discovery requires `--pid`;
process discovery alone does not establish an available operator endpoint.

```powershell
skybridge app instances --json
skybridge app --pid <pid> status --json
skybridge app --pid <pid> settings --json
skybridge app --pid <pid> settings set appearance.mode dark --json
skybridge app --pid <pid> remote-desktop interfaces --json
skybridge app --pid <pid> remote-desktop start --interface-ref <ref> --json
skybridge app --pid <pid> remote-desktop stop --generation <generation> --json
```

`MainWindow` owns the server, existing SettingsService and existing
WindowsDeviceWorkspace. Operator commands dispatch to the window thread; they
do not create a second runtime, trust store or request-file consumer. Starting
a host still requires an existing trusted controller and the actual selected
network. Incoming sessions retain the product's local approval and input-owner
rules. Stop closes the selected host generation and all of its sessions after
real resource cleanup. It is not a per-session disconnect command.

Only `appearance.mode` (`system`, `light`, `dark`) is currently writable. The
handler observes the window's RequestedTheme, saves through the existing
SettingsService and independently reloads its store. The client then requests
another settings snapshot. A successful setter response alone is insufficient.
The existing debounce writer is serialized with explicit save/readback so an
older queued save cannot overwrite the confirmed value.

Video settings are not advertised as implemented. The current video settings
properties have no live capture effect. Actual FPS/size changes belong to the
authenticated viewer/host configuration transaction and require a separate
acknowledged reconfiguration implementation. Host start succeeds only for a
confirmed enabled listener; it is not approval, first-frame or media proof.

## Wire and failure contract

One NDJSON request/response per connection; protocol `skybridge-app-control/1`,
UUID request ID, explicit method and exact parameter object. Frames are bounded
to 64 KiB. Each mutation requires an installed-app capability preflight and
independent result readback. Failed commands emit structured stderr JSON and
exit nonzero. Requests that may already have been written are never retried.

The client has one 30-second command deadline. The server retains execution
ownership until actual mutation/cancellation cleanup completes, even when the
client has stopped waiting. Cancelling a queued dispatcher action prevents it
from later mutating the app. App shutdown stops admission and awaits the same
execution owner before disposing runtime resources. An unconfirmed mutation
requires a fresh status read; timeout does not prove rollback.

The Windows pipe has an explicit current-user SID ACL, first-instance ownership,
non-inherited handle and `PIPE_REJECT_REMOTE_CLIENTS`. The native pipe flag is
necessary because an authenticated SMB client must not acquire local operator
access. The client retains Tokio's identification-only security level.
See [Microsoft CreateNamedPipe](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea)
and [Tokio ClientOptions](https://docs.rs/tokio/1.53.1/tokio/net/windows/named_pipe/struct.ClientOptions.html).

## Acceptance status

On 2026-09-13, SSH access to the Windows workstation was verified using its
existing pinned key. A new source snapshot was staged separately from the
installed app. Its first native App build was blocked before managed App
compilation: Code Integrity event 3077 rejected the `serde_core` build script
with OS error 4551. No usable code-signing certificate was found in the current
user's certificate store. The security policy was not changed and the native
target was not skipped. Therefore this document describes implemented source,
not a validated Windows release or proven live App control.

Remaining acceptance: trusted native build, real CLI-to-App named-pipe exchange,
wrong-owner/remote-client rejection, setting mutation and independent UI/store
readback with restoration, host start/stop with unchanged identity/trust data,
stale-generation refusal, and shutdown/cancellation on the Windows desktop.
