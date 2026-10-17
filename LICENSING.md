# Licensing

SkyBridge Compass first-party code and project materials are available under the
[MIT License](LICENSE), unless a file or directory explicitly states otherwise.
This agrees with the existing `license = "MIT"` declaration in the Windows Rust
core. Existing copyright notices remain in force.

Third-party components retain their respective licenses and copyright notices.
The project license does not replace licenses in vendored source, native
libraries, package dependencies, or the shipped third-party notices. Distributors
must include this project license and all notices required by those components.

The strict original-file audio receiver statically links libFLAC 1.5.0 inside
`skybridge_flac.dll`. Its Xiph/BSD license is retained in
`native/audio-flac/COPYING.Xiph` and copied to `Licenses/libFLAC.txt` in Windows
build and publish outputs. The shared decoder bridge remains under the MIT
license, with its original notice retained alongside the source. Source archive
and bridge checksums are recorded in `native/audio-flac/source-lock.json`.

The license covers the software; it does not grant access to a hosted account or
service. Native release acceptance and signing status are recorded separately
from the source license.
