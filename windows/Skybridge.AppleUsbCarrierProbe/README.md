# Apple USB carrier qualification

This executable qualifies the product USB carrier and framed-stream implementation;
it does not advertise a usable USB audio feature in WinUI. Windows USB inventory
currently enumerates devices without creating a SkyBridge session. USB peer
selection, authenticated session establishment, file-return routing, account
admission, output approval and physical Windows validation remain integration gates.

The carrier speaks bounded plist usbmux messages. It selects only `USB`
records, rejects ambiguous identities, re-enumerates the ephemeral device ID
before each connection, and transfers the same stream without reading ahead
into application bytes. A six-second deadline includes enumeration and Connect.
Cancellation and failure release the stream; cleanup failures remain observable.
No retry, alternate network, pairing-record access, installation or service
configuration is performed. A returned stream is routing evidence only.

Windows uses the existing local Apple service at `127.0.0.1:27015`. The separate
macOS qualification path uses `/var/run/usbmuxd`; success there does not prove the
Windows service, driver or installed Apple Devices package. Protocol references:
[libusbmuxd endpoint and message implementation](https://github.com/libimobiledevice/libusbmuxd/blob/93eb168bf6b07472d17781328c21df0c60300524/src/libusbmuxd.c),
[header, result codes and Windows port](https://github.com/libimobiledevice/libusbmuxd/blob/93eb168bf6b07472d17781328c21df0c60300524/include/usbmuxd-proto.h).
The product independently implements the wire contract and does not link libusbmuxd.
Its only production endpoint is the Windows Apple service. The explicit Mac socket
adapter lives in this probe.

The probe links `Services/Connection/UsbMuxProtocol.cs` and `UsbMuxConnector.cs`
from the WinUI project, rather than maintaining a second implementation. A successful
mux Connect hands its owned stream to the same `ProductControlStreamTransport`
used by TCP MAIN and remote control. That owner retains framing bounds, writer
admission, partial-write retirement and reader drain. TCP callers retain their
existing socket liveness options; a USB stream is not wrapped in another TCP owner
or assigned a fictitious LAN peer address. Cancellation and release failures remain
observable after every worker drains, and the containing session erases its keys
even if carrier release fails.

Run the isolated contract lane with the repository-pinned .NET SDK:

```powershell
./Scripts/verify-apple-usb-carrier.ps1
# Add -PublishWindows to retain a self-contained win-x64 probe and per-file hashes.
```

Native observation is explicit:

```powershell
dotnet run --project windows/Skybridge.AppleUsbCarrierProbe -c Release -- --probe-list
dotnet run --project windows/Skybridge.AppleUsbCarrierProbe -c Release -- --probe-control <observed-USB-UDID>
```

Listing reports only hashes of device serials. The control probe opens the current
app port (9527), then closes it without sending SkyBridge commands or audio.
Use an already observed device identifier; this developer probe is not the intended
end-user interface. A missing Apple service, unavailable device or closed app port
is a failure, not an empty-success or permission to alter drivers.

The initial Mac-host revision passed 27 checks, including real loopback TCP
fragmentation, fresh-ID selection, cancellation/timeout cleanup and raw stream
handoff. That revision enumerated the USB-connected iPad and opened its current
application port through the real Mac service. These observations do not establish
Windows USB support, account authentication, transfer integrity or audio playback.
Original evidence, including the initial unavailable default SDK attempt, is in
`artifacts/audio-native-20261020/apple-usb-carrier-v1/`.

After rejecting unstructured text in the plist root, the final host lane passes
28 checks with zero compiler warnings/errors. The final-path executable again
opens the selected iPad's app port, and the repository's offline stack gate passes.
Windows-native execution and the actual Windows Apple service are separate gates.

Native run [39444823023](https://github.com/billlza/Skybridge-Compass-Windows/actions/runs/39444823023),
at `82fd3aa81b7614c3fc2ec459a65383159f783ef8`, passes the same 28 checks on
Windows with .NET SDK 10.0.402, zero build warnings/errors, and a self-contained
Windows package. All 192 package files matched their recorded lengths and hashes;
the five native source hashes matched the committed blobs after the exact
LF-to-CRLF checkout conversion. Archive SHA-256:
`a3c97a34ad3aed1087bbf89544b94047f1301883a85b61d95c31aab0fbf2abe0`.
The initial raw source comparison failed on line endings and is retained alongside
the explicit comparison. This runner exercised the Windows socket/runtime boundary,
not a physical Apple service or USB driver. No authenticated phone-to-Windows
session, audio transport, device-unplug behavior or strict output is admitted yet.

The product-stream integration adds coalesced mux/handshake/control framing,
truncated-frame and stream-owner failure checks. The tests use synthetic application
bytes over real loopback sockets; they do not execute a cryptographic handshake or
claim physical cable-unplug coverage. The separate product contract suite checks
encrypted MAIN, audio ownership and key erasure after failed cleanup. Current
integration evidence is retained in `artifacts/audio-native-20261020/usb-product-stream-v1/`.
The Mac-host integration check passes 37 carrier/ownership cases and the selected
product lane passes 215 named cases plus 68 existing protocol assertions, with
zero compiler warnings/errors. These counts overlap and are not physical output
evidence. Replacing only the session disposal method with the preceding logic
reproduces failed key erasure under an injected carrier release error; restoring
the corrected method passes the same test. Both the counterexample and successful
rerun are retained.

At source commit `ac4668d35a51990e3098ecce5bb16ba4a447ba44`, Windows-native carrier
run [39449870945](https://github.com/billlza/Skybridge-Compass-Windows/actions/runs/39449870945)
passes all 37 cases. All eight recorded source inputs match the committed files
with their exact Windows checkout line endings, and all 192 package files match
their manifest. Archive SHA-256:
`a90df41ee188dbcdbb8e23da0555b24ac3693232d345402f57ab77f04feef9a7`.

The complete client run
[39450247566](https://github.com/billlza/Skybridge-Compass-Windows/actions/runs/39450247566)
passes the native WinUI build, complete product contract suite (877 PASS records,
including the new key-erasure check), 21 QR image vectors through the Android
decoder, and interactive launch/control checks with 14 workspace captures.
Client and contract builds report zero compiler warnings/errors. The full workflow
**fails** its existing online SDK freshness gate: the project pins Windows App SDK
2.3.1 while the gate finds stable 2.5.1. The same failure occurs in preceding run
39384990653. Later portability and Rust coverage gates therefore remain incomplete.
No actual Windows Apple service, authenticated USB device session or hardware
audio playback is verified by these runs.
