param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Assert-True {
    param(
        [bool]$Condition,
        [string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Assert-Contains {
    param(
        [string]$Text,
        [string]$Needle,
        [string]$Message
    )

    Assert-True -Condition $Text.Contains($Needle) -Message $Message
}

$workflowPath = Join-Path $RepoRoot ".github/workflows/windows-portability.yml"
$portabilitySmokePath = Join-Path $RepoRoot "Scripts/verify-windows-portability-smoke.ps1"
$acceptanceEvidencePath = Join-Path $RepoRoot "Scripts/verify-windows-portability-acceptance-evidence.ps1"
$rustCoveragePath = Join-Path $RepoRoot "Scripts/verify-rust-cli-coverage.ps1"
$gitSshRemotePath = Join-Path $RepoRoot "Scripts/verify-git-ssh-remote.ps1"
$powershellAstPath = Join-Path $RepoRoot "Scripts/verify-windows-powershell-ast.ps1"

foreach ($path in @($workflowPath, $portabilitySmokePath, $acceptanceEvidencePath, $rustCoveragePath, $gitSshRemotePath, $powershellAstPath)) {
    Assert-True -Condition (Test-Path -LiteralPath $path) -Message "Missing Windows CI gate input: $path"
}

$workflow = Get-Content -Raw -LiteralPath $workflowPath
$portabilitySmoke = Get-Content -Raw -LiteralPath $portabilitySmokePath
$acceptanceEvidence = Get-Content -Raw -LiteralPath $acceptanceEvidencePath
$rustCoverage = Get-Content -Raw -LiteralPath $rustCoveragePath
$gitSshRemote = Get-Content -Raw -LiteralPath $gitSshRemotePath
$powershellAst = Get-Content -Raw -LiteralPath $powershellAstPath

foreach ($signal in @(
    "name: Windows Portability",
    "windows-latest",
    "actions/checkout@v7.0.1",
    "actions/setup-dotnet@v6.0.0",
    "global-json-file: global.json",
    "Fetch mac UI parity baseline",
    "23ba06343bbaa58c30ef6b9bbddd09bb4e80241c",
    'git fetch --no-tags --depth=1 https://github.com/billlza/Skybridge-Compass.git $baselineCommit',
    "Sources/SkyBridgeCompassApp/Dashboard/Navigation/NavigationItem.swift",
    "Sources/SkyBridgeCompassApp/Dashboard/Sections/DashboardContentView.swift",
    "Sources/SkyBridgeCompassApp/Dashboard/Sections/QuickActionsPanelView.swift",
    "Sources/SkyBridgeCompassApp/Dashboard/TopBar/TopNavigationBarView.swift",
    "rustup toolchain install 1.97.1 --profile minimal --component clippy --component llvm-tools-preview --component rustfmt",
    "rustup default 1.97.1",
    "cargo install cargo-llvm-cov --version 0.8.7 --locked",
    "Build native WinUI client",
    "dotnet restore windows/Skybridge.WinClient/Skybridge.WinClient.csproj",
    "dotnet build windows/Skybridge.WinClient/Skybridge.WinClient.csproj --configuration Debug --no-restore /p:TreatWarningsAsErrors=true",
    "Run product contracts on Windows",
    "windows/Skybridge.WinClient.ContractTests/Skybridge.WinClient.ContractTests.csproj",
    "native-client-build.json",
    "deviceAudioPlayback = 'not-run'",
    "actions/upload-artifact@v7.0.2",
    "git remote set-url origin git@github.com:billlza/Skybridge-Compass-Windows.git",
    "git remote set-url --push origin git@github.com:billlza/Skybridge-Compass-Windows.git",
    "New-Item -ItemType Directory -Force -Path artifacts",
    "Scripts\verify-windows-portability-smoke.ps1",
    "-CiMode -CheckOnlineStackFreshness -IncludeRustCliCoverage",
    "-StackFreshnessEvidencePath artifacts\windows-stack-freshness.json",
    "-RustCliCoverageEvidencePath artifacts\rust-cli-coverage.json",
    "-AcceptanceEvidencePath artifacts\windows-portability-acceptance.json",
    "Scripts\verify-windows-portability-acceptance-evidence.ps1",
    "-RequireRustCliCoverage",
    "-RequireOnlineStackFreshness",
    "permissions:",
    "contents: read"
)) {
    Assert-Contains -Text $workflow -Needle $signal -Message "Windows CI workflow missing signal: $signal"
}

$baselineFetchStepIndex = $workflow.IndexOf("Fetch mac UI parity baseline", [StringComparison]::Ordinal)
$pinSshRemoteStepIndex = $workflow.IndexOf("Pin GitHub remote to SSH", [StringComparison]::Ordinal)
Assert-True -Condition ($baselineFetchStepIndex -ge 0) -Message "Windows CI workflow missing mac UI parity baseline fetch step."
Assert-True -Condition ($pinSshRemoteStepIndex -ge 0) -Message "Windows CI workflow missing SSH remote pin step."
Assert-True -Condition ($baselineFetchStepIndex -lt $pinSshRemoteStepIndex) -Message "Windows CI workflow must fetch the mac UI parity baseline before pinning origin to SSH."

$nativeBuildStepIndex = $workflow.IndexOf("Build native WinUI client", [StringComparison]::Ordinal)
$contractStepIndex = $workflow.IndexOf("Run product contracts on Windows", [StringComparison]::Ordinal)
$portabilityStepIndex = $workflow.IndexOf("Run Windows portability gate", [StringComparison]::Ordinal)
Assert-True -Condition ($nativeBuildStepIndex -gt $pinSshRemoteStepIndex -and $contractStepIndex -gt $nativeBuildStepIndex -and $portabilityStepIndex -gt $contractStepIndex) -Message "Windows CI must build the actual WinUI product and run its contracts before the online freshness gate."
Assert-Contains -Text $workflow -Needle "!cancelled() && steps.rust-tooling.outcome == 'success'" -Message "The portability gate must still run after a native build or contract failure."
Assert-True -Condition (-not $workflow.Contains("continue-on-error:")) -Message "Windows CI must not turn failed native or portability checks into success."

$bundleStepIndex = $workflow.IndexOf("Preserve native client for device qualification", [StringComparison]::Ordinal)
$qrStepIndex = $workflow.IndexOf("Decode Windows LAN QR images with the Android decoder", [StringComparison]::Ordinal)
$uiStepIndex = $workflow.IndexOf("Verify interactive WinUI launch and controls", [StringComparison]::Ordinal)
Assert-True -Condition ($bundleStepIndex -gt $qrStepIndex -and $bundleStepIndex -lt $uiStepIndex) -Message "Native qualification output must be captured after QR contracts and before interactive use."
Assert-Contains -Text $workflow -Needle "inputs.package_native_client && steps.native-client.outcome == 'success' && steps.product-contracts.outcome == 'success' && steps.lan-qr.outcome == 'success'" -Message "Native qualification artifacts must be opt-in and require native build, product contracts and QR decoding success."
Assert-Contains -Text $workflow -Needle 'windows-native-client-${{ github.sha }}' -Message "Native qualification artifact identity must include the built commit."
Assert-Contains -Text $workflow -Needle 'Verify standalone USB carrier ownership' -Message "CI must validate the shared carrier as an independent probe."
Assert-Contains -Text $workflow -Needle '.\Scripts\verify-apple-usb-carrier.ps1' -Message "CI must build and run the carrier ownership contracts."
Assert-Contains -Text $workflow -Needle 'artifacts/apple-usb-carrier/*.json' -Message "Carrier qualification receipts must be retained."
Assert-Contains -Text $workflow -Needle 'artifacts/apple-usb-carrier/*.log' -Message "Carrier qualification failures must remain observable."
Assert-Contains -Text $workflow -Needle 'bundleFiles = $bundleFiles' -Message "Native qualification evidence must bind all output files."
Assert-Contains -Text $workflow -Needle 'windows/Skybridge.WinClient/bin/Debug/net10.0-windows10.0.22621.0/win-x64/**' -Message "Native qualification artifacts must carry the complete self-contained output."

foreach ($forbidden in @(
    "-RequireGitRemoteAccess",
    "-RequireMacSshReady",
    "-RequireMacDirectLan",
    "-RequireMacWebRtcInterop",
    "-RequireNativeDnsSdPeer",
    "-IncludeWindowsReverseSshRelayLifecycle",
    "-RequireWindowsReverseSshRelayLifecycle"
)) {
    Assert-True -Condition (-not $workflow.Contains($forbidden)) -Message "Windows CI workflow must not require local-only readiness gate: $forbidden"
}

foreach ($signal in @(
    "CiMode",
    "verify-windows-ci-workflow.ps1",
    "verify-windows-powershell-ast.ps1",
    "windows-powershell-ast",
    "CI mode keeps the SSH-only remote check",
    "RequireConfiguredSshCommand",
    "RequireKnownHosts",
    "RequireCredentialHelperReset",
    "IncludeRustCliCoverage",
    "CheckOnlineStackFreshness",
    "RustCliCoverageEvidencePath"
)) {
    Assert-Contains -Text $portabilitySmoke -Needle $signal -Message "Portability smoke missing CI signal: $signal"
}

foreach ($signal in @(
    "AcceptanceEvidencePath",
    "RequireRustCliCoverage",
    "RequireOnlineStackFreshness",
    "gateResults",
    "totalLineCoverage",
    "cliLineCoverage",
    "sourceUris",
    "online",
    "windows-powershell-ast",
    "windows-portability-acceptance-evidence: ok"
)) {
    Assert-Contains -Text $acceptanceEvidence -Needle $signal -Message "Acceptance evidence verifier missing CI signal: $signal"
}

foreach ($signal in @(
    "System.Management.Automation.Language.Parser",
    "ParseFile",
    "windows-powershell-ast: parse-ok",
    "windows-powershell-ast: ok",
    "Invoke-Expression",
    "CommandAst"
)) {
    Assert-Contains -Text $powershellAst -Needle $signal -Message "PowerShell AST gate missing signal: $signal"
}

foreach ($signal in @(
    "MinimumLineCoverage",
    "cargo fmt",
    "--check",
    "cargo clippy",
    "--all-targets",
    "--all-features",
    "-D warnings",
    "cargo llvm-cov",
    "fail-under-lines",
    "EvidencePath",
    "rust-cli-coverage: evidence=",
    "totalLineCoverage",
    "cliLineCoverage",
    "cli.rs",
    "cli.rs line coverage"
)) {
    Assert-Contains -Text $rustCoverage -Needle $signal -Message "Rust coverage gate missing CI coverage signal: $signal"
}

foreach ($signal in @(
    "Git remote",
    "must use SSH",
    "not HTTPS",
    "git-remote-https.exe",
    "RequireRemoteAccess"
)) {
    Assert-Contains -Text $gitSshRemote -Needle $signal -Message "Git SSH remote gate missing transport signal: $signal"
}

Write-Output "windows-ci-workflow: ok"
