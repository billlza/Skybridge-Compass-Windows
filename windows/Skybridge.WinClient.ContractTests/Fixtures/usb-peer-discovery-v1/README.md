# Apple USB peer discovery vectors

`apple-vectors.json` was generated on macOS on 2026-10-20 by `export.swift`, using the actual Apple `SkyBridgeProtocolCore` sources and CryptoKit ML-DSA-65. Its five names cover ASCII, Chinese/Japanese, emoji and punctuation, Unicode separators, and private-use characters. The generator verifies each signature through the Apple response validator before exporting it. Keys are freshly generated test keys; no private key, user identity or account credential is exported.

The exact vectors SHA-256 is `ec7985290f577f29425901b189569c2286f1314c0342e5f013fe67deff8b82c4`. The generator SHA-256 is `20fd000659d0235332681678b6a0d718558593fea59ec821e16e36ebb9789575`. The Apple input files that define the discovery and identity shapes were:

| Path below `Sources/SkyBridgeProtocolCore` | SHA-256 |
| --- | --- |
| `P2P/USBPeerDiscovery.swift` | `a9f19bcf8e8d6e102aa3eec713f41718c61056f69f5ba1c4dc9f0f5223369f96` |
| `P2P/HandshakeConfiguration.swift` | `6299b011d3582dcd0424bbac49cdc314551d60abc1814afe9a82bbc03cd6a58c` |

To regenerate, create an isolated Swift 6.3-or-later package targeting macOS 26, copy the Apple repository's complete `Sources/SkyBridgeProtocolCore` directory without edits, and add an executable target named `Export` containing `export.swift` with a dependency on `SkyBridgeProtocolCore`. Link CryptoKit to the protocol target and use Swift language mode 6. Run:

```sh
swift run --package-path <isolated-package> -c debug --jobs 2 -Xswiftc -warnings-as-errors Export > apple-vectors.json
```

A new run produces different public keys and signatures, so a replacement needs a new digest and a recorded Apple source snapshot. The original generation compiled all 96 protocol source files without warnings; their complete input hashes and compiler receipts are retained in the local `artifacts/audio-native-20261020/usb-peer-discovery-v1` evidence directory.

Run the consumer checks from the Windows repository root:

```sh
dotnet build windows/Skybridge.WinClient.ContractTests/Skybridge.WinClient.ContractTests.csproj -c Debug -p:TreatWarningsAsErrors=true
dotnet run --project windows/Skybridge.WinClient.ContractTests/Skybridge.WinClient.ContractTests.csproj -c Debug --no-build --no-restore -- --usb-peer-discovery
```

Host-independent cases check the exact Apple signing bytes, wire rejection, saved-key matching and scanner ownership. Their fixture attestation is not cryptographic verification. On Windows, native ML-DSA support is required: all five Apple signatures and tampering cases execute, followed by an actual loopback multiplex exchange using an ephemeral native signer.

The optional CI UI service is restricted to the disposable Windows runner and binds only loopback. Its receipt explicitly identifies it as synthetic. It drives the product's real decoder, native signature verification, USB refresh and localized state bindings through discovery, port refusal and recovery. It never creates a pairing or plays audio. Actual Apple service, USB hardware, authenticated peer/session, and audio output remain separate acceptance requirements.
