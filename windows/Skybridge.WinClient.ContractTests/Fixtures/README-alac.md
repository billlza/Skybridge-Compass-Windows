# Shared ALAC container fixtures

`alac-m4a-metadata-v1.json` and `alac-packet-index-v1.json` are byte-for-byte copies
of the Apple repository's `Tests/SkyBridgeCoreTests/Fixtures/AudioStreaming/`
fixtures, also used for Android interoperability. They describe 24 generated
ALAC files: 44.1/48/96 kHz, mono/stereo, and 16/20/24/32 valid bits. Packet
positions and frame counts were exported independently of this parser.

SHA-256 of these fixture documents:

- Metadata: `7459ec48b0a56f4f6540820f37526698bf37504e679e21c2846aa25b8895e353`
- Packet index: `23a07010c0c05a6b4e68e362d94f7c241967bee0058c5b78d36aece030d53cff`

Metadata ranges intentionally omit the compressed payload. Tests reject reads
outside those ranges. `sourceSha256` joins the two fixture sets; these sparse
fixtures cannot establish the complete original file's digest or PCM contents.
Malformed-container tests fill omitted ranges with synthetic zeros and never
decode or play them. Actual decoder qualification needs the original M4A and
independent PCM references, which are not included in these two documents.

`alac-decoder-v1/` separately contains the 24 original generated M4A files, their
24 independent packed PCM references and the shared manifest, copied unchanged
from the same Apple fixture directory. `AudioAlacDecoderTests` checks every
encoded/PCM hash and compares actual native decoding byte for byte. These samples
contain deliberate extremes for byte comparison and are not listening signals.
