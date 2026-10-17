# SkyBridge Compass Windows

This workspace contains the native Windows client and its portable core. Source implementation, host contract checks, native Windows startup, and real-device interoperability are separate evidence states.

## Current entrypoints

| Area | Entry |
| --- | --- |
| Engineering and configured stack | [AGENTS.md](AGENTS.md), project manifests and lockfiles |
| Architecture and runtime ownership | [Windows architecture](docs/windows-architecture.md) |
| Product operation | [App operator](docs/windows-app-operator.md) |
| UI and interaction contract | [UI contract](docs/windows-ui-parity-contract.md), [matrix](docs/windows-ui-parity-matrix.md) |
| Transport and acceptance | [Proof schema](docs/windows-webrtc-proof-schema.md), [acceptance map](docs/windows-portability-acceptance-map.md) |
| SSH and recovery | [Stable connection](docs/windows-stable-ssh-connection.md), [relay lifecycle](docs/windows-reverse-ssh-relay-lifecycle.md) |
| License and redistribution | [LICENSING.md](LICENSING.md) |

The shared account-device contract lives in the paired Apple checkout at `Docs/account-device-lifecycle.md`. Verified login registers the exact committed identity even for a nonempty account. My Devices uses the same confirmed removal endpoint and complete signing identity as the other native clients. A revoked identity cannot silently register itself again.

## Source layout

- `windows/Skybridge.WinClient/`: native UI, services and runtime integration.
- `windows/Skybridge.WinClient.ContractTests/`: portable service/state contract checks.
- `core/skybridge-core/`: existing portable core and FFI contracts.
- `Scripts/`: stack, portability and native acceptance gates.

Run portable account checks with:

```sh
dotnet run --project windows/Skybridge.WinClient.ContractTests/Skybridge.WinClient.ContractTests.csproj -- --account-devices
```

For native Windows work, follow the existing smoke scripts and project rules. Portable test success does not prove WinUI startup, desktop visuals, received files, remote input or cross-device parity. Native Windows acceptance remains pending while the workstation is unavailable.

The dated research synthesis and parity-gap audits retain their original findings and open gates. Refresh source, build identity and real-device receipts before making a current completion claim; the earlier generic macOS/web project description is no longer the Windows entrypoint.

## Platform repository

This checkout publishes to [Windows](https://github.com/billlza/Skybridge-Compass-Windows). The Apple client remains in
[Skybridge-Compass](https://github.com/billlza/Skybridge-Compass); its repository is
a read-only protocol/reference source for this platform, never this checkout's push target.
Native runtime and device acceptance remain separate from source upload. Local credentials,
build output and device recordings are excluded. Required vendored runtime files and their
licenses remain part of the source snapshot.
