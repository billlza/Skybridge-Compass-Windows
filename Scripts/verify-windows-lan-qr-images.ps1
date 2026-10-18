param(
    [Parameter(Mandatory = $true)][string]$ImageDir,
    [Parameter(Mandatory = $true)][string]$EvidenceDir,
    [string]$DecoderJar = ''
)

$ErrorActionPreference = 'Stop'
$expectedDecoderSha256 = '71de5d89341b5fcf5dd89da7f44e84d825d0e084cdf3ec77c9abe26b0f0ceb13'
$decoderUri = 'https://repo.maven.apache.org/maven2/com/google/zxing/core/3.5.4/core-3.5.4.jar'
if (Test-Path -LiteralPath $EvidenceDir) { throw 'Choose a new QR validation evidence directory.' }
[void](New-Item -ItemType Directory -Path $EvidenceDir)
$result = [ordered]@{ schemaVersion = 1; status = 'failed'; decoderVersion = '3.5.4'; decoderSha256 = $expectedDecoderSha256; error = $null }
try {
    $imageRoot = (Resolve-Path -LiteralPath $ImageDir).Path
    $manifestPath = Join-Path $imageRoot 'manifest.json'
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ($manifest.schemaVersion -ne 1 -or $manifest.kind -ne 'synthetic-public-lan-qr-vectors' -or $manifest.entries.Count -ne 21) {
        throw 'Missing or unsupported QR image corpus.'
    }
    $names = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($entry in $manifest.entries) {
        if ($entry.name -notmatch '^[a-z0-9-]{1,50}$' -or -not $names.Add($entry.name) -or $entry.moduleScale -ne 6 -or $entry.quietModules -ne 4) {
            throw 'Invalid QR corpus entry.'
        }
        $png = Join-Path $imageRoot ($entry.name + '.png')
        if ((Get-FileHash -LiteralPath $png -Algorithm SHA256).Hash -ne $entry.sha256) { throw 'QR image digest mismatch.' }
        if (-not (Test-Path -LiteralPath (Join-Path $imageRoot ($entry.name + '.txt')) -PathType Leaf)) { throw 'Missing QR payload vector.' }
    }
    if ([string]::IsNullOrEmpty($DecoderJar)) {
        $DecoderJar = Join-Path $EvidenceDir 'zxing-core-3.5.4.jar'
        Invoke-WebRequest -Uri $decoderUri -OutFile $DecoderJar -TimeoutSec 30
    }
    if ((Get-FileHash -LiteralPath $DecoderJar -Algorithm SHA256).Hash -ne $expectedDecoderSha256) { throw 'The QR decoder differs from the Android-pinned artifact.' }
    $DecoderJar = (Resolve-Path -LiteralPath $DecoderJar).Path
    $qrJavaHome = $env:JAVA_HOME_17_X64
    if ($IsWindows -and $qrJavaHome) {
        $java = Join-Path $qrJavaHome 'bin/java.exe'
        $javac = Join-Path $qrJavaHome 'bin/javac.exe'
    } else {
        $java = (Get-Command java -ErrorAction Stop).Source
        $javac = (Get-Command javac -ErrorAction Stop).Source
    }
    & $java -version 2>&1 | Out-File -Encoding utf8 (Join-Path $EvidenceDir 'java-version.log')
    if ($LASTEXITCODE -ne 0) { throw 'Java runtime verification failed.' }
    $classes = Join-Path $EvidenceDir 'classes'
    [void](New-Item -ItemType Directory -Path $classes)
    $source = Join-Path $PSScriptRoot 'VerifyLanQrImages.java'
    & $javac --release 17 -encoding UTF-8 -Xlint:all -Werror -cp $DecoderJar -d $classes $source 2>&1 |
        Tee-Object (Join-Path $EvidenceDir 'compile.log')
    if ($LASTEXITCODE -ne 0) { throw 'Independent QR verifier compilation failed.' }
    $classPath = $DecoderJar + [IO.Path]::PathSeparator + (Resolve-Path -LiteralPath $classes).Path
    & $java '-Djava.awt.headless=true' -cp $classPath VerifyLanQrImages $imageRoot 2>&1 |
        Tee-Object (Join-Path $EvidenceDir 'decode.log')
    if ($LASTEXITCODE -ne 0) { throw 'Android decoder did not preserve every QR payload.' }
    $result.status = 'passed'
    $result.detector = 'bounded-multiple-candidates'
    $result.maximumLocatorPoints = 12
    $result.vectorCount = $manifest.entries.Count
    $result.manifestSha256 = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $result.verifierSha256 = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
    $result.scope = 'Generated PNGs, exact payloads and quiet zones; not a physical camera or Windows UI screenshot.'
} catch {
    $result.error = $_.Exception.Message
    throw
} finally {
    $result | ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8 (Join-Path $EvidenceDir 'result.json')
}
