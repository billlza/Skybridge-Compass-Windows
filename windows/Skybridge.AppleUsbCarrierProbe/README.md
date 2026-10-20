# Apple USB carrier qualification

This is an isolated transport candidate, not part of the WinUI client's advertised
capabilities. Windows USB inventory currently enumerates devices; it does not
create a SkyBridge session. Connecting this candidate to the product still needs
authenticated handshake/session ownership, unplug handling, file-return routing,
account admission, output approval and physical Windows validation.

The candidate speaks bounded plist usbmux messages. It selects only `USB`
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
This probe independently implements the wire contract and does not link libusbmuxd.

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
Windows-native execution and the actual Windows Apple service remain separate gates.
