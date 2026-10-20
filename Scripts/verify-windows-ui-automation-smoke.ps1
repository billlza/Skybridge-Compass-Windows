param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",
    [int]$TimeoutSeconds = 20,
    [string]$EvidenceDir = "",
    [string]$EvidenceBranch = "",
    [string]$EvidenceHead = "",
    [switch]$RequireAccountDeviceService,
    [switch]$RequireNoAutomaticLocationConsentForCi,
    [ValidatePattern("^[A-Fa-f0-9]{64}$")][string]$ExistingAssemblySha256,
    [string]$UsbFixtureDirectory = ""
)

$ErrorActionPreference = "Stop"
if ($RequireNoAutomaticLocationConsentForCi -and $env:GITHUB_ACTIONS -ne 'true') {
    throw 'First-start permission observation is restricted to the owned CI UI test.'
}
if ($UsbFixtureDirectory -and $env:GITHUB_ACTIONS -ne 'true') {
    throw 'The synthetic USB service check is restricted to the owned CI UI test.'
}

function Read-UsbFixtureReceipt {
    param([string]$Path)
    $stream = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    try {
        if ($stream.Length -gt 4096) { throw 'USB fixture receipt exceeds its expected bound.' }
        $reader = [IO.StreamReader]::new($stream, [Text.UTF8Encoding]::new($false, $true), $true, 1024, $true)
        try { return $reader.ReadToEnd() | ConvertFrom-Json }
        finally { $reader.Dispose() }
    } finally { $stream.Dispose() }
}


. (Join-Path $PSScriptRoot "windows-ui-automation-helpers.ps1")

$projectPath = Join-Path $RepoRoot "windows/Skybridge.WinClient/Skybridge.WinClient.csproj"
$projectText = Get-Content -Raw -LiteralPath $projectPath
$project = [xml]$projectText
Assert-UnpackagedDefaultWindowsPackageType -Project $project
$matrixPath = Join-Path $RepoRoot "docs/windows-ui-parity-matrix.md"
$actionOrderBySurface = Get-ActionOrderMatrix -MatrixPath $matrixPath

# CI/default runs still build with warnings as errors. Native acceptance can
# instead pin an already-built assembly, preserving the bytes validated by the
# notification, wallpaper and installation lanes.
if (-not $ExistingAssemblySha256) {
    & dotnet restore $projectPath | Write-Output
    Assert-True -Condition ($LASTEXITCODE -eq 0) -Message "WinUI automation smoke restore failed."
    
    & dotnet build $projectPath --configuration $Configuration --no-restore /p:TreatWarningsAsErrors=true | Write-Output
    Assert-True -Condition ($LASTEXITCODE -eq 0) -Message "WinUI automation smoke build failed."
}

$targetFramework = "net10.0-windows10.0.22621.0"
$runtimeIdentifiers = @($project.Project.PropertyGroup |
    ForEach-Object { $_.RuntimeIdentifier } |
    Where-Object { $null -ne $_ } |
    ForEach-Object { $_.InnerText.Trim() } |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
Assert-True -Condition ($runtimeIdentifiers.Count -eq 1) -Message "WinUI automation smoke requires exactly one default RuntimeIdentifier; actual=[$($runtimeIdentifiers -join ', ')]"
$exePath = Join-Path $RepoRoot "windows/Skybridge.WinClient/bin/$Configuration/$targetFramework/$($runtimeIdentifiers[0])/Skybridge.WinClient.exe"
Assert-True -Condition (Test-Path -LiteralPath $exePath) -Message "Missing WinUI executable: $exePath"
if ($ExistingAssemblySha256) {
    $assemblyPath = Join-Path (Split-Path $exePath) 'Skybridge.WinClient.dll'
    Assert-True ((Get-FileHash $assemblyPath -Algorithm SHA256).Hash -eq $ExistingAssemblySha256) "The prebuilt UI candidate does not match its expected assembly hash."
}




# UI Automation bounds and saved pixels are physical; Win32 input/geometry must
# use that same coordinate space at 150/200% display scaling.
$inputDpiContext = [NativeMethods]::SetThreadDpiAwarenessContext([IntPtr](-4))
Assert-True ($inputDpiContext -ne [IntPtr]::Zero) "Physical UI verification DPI context is unavailable."

$process = $null
$window = $null
$stage = 'startup'
$locationConsentEvents = [System.Collections.Generic.List[object]]::new()
$locationConsentDiagnostics = @{}
$stdoutTask = $null
$stderrTask = $null
try {
    $features = @(
        @{
            Id = "Dashboard"
            Title = "Dashboard"
            Anchor = "WorkspaceAction.DashboardQuickActions.ScanDevices"
            Surfaces = @("DashboardQuickActions")
            EvidenceScrollPercent = 100
            SurfaceGroups = @(
                @{ ScrollPercent = 100; Surfaces = @("DashboardQuickActions") }
            )
        },
        @{
            Id = "DeviceDiscovery"
            Title = "Device Discovery"
            Anchor = "WorkspaceAction.DeviceDiscoveryPrimary.ParseTxt"
            Surfaces = @("DeviceDiscoveryPrimary", "DeviceDiscoveryScan", "DeviceDiscoveryManualConnectFinal", "CrossNetworkQr", "CrossNetworkCodePrimary", "CrossNetworkCodeConnect")
            SurfaceGroups = @(
                @{ Mode = "LocalScan"; Surfaces = @("DeviceDiscoveryPrimary", "DeviceDiscoveryScan", "DeviceDiscoveryManualConnectFinal") },
                @{ Mode = "Qr"; Surfaces = @("CrossNetworkQr") },
                @{ Mode = "Code"; Surfaces = @("CrossNetworkCodePrimary", "CrossNetworkCodeConnect") }
            )
        },
        @{ Id = "UsbManagement"; Title = "USB Management"; Anchor = "WorkspaceAction.UsbManagementHeader.RefreshDevices"; Surfaces = @("UsbManagementHeader") },
        @{ Id = "FileTransfer"; Title = "File Transfer"; Anchor = "WorkspaceAction.FileTransfer.GenerateQr"; Surfaces = @("FileTransferHeader", "FileTransfer") },
        @{ Id = "RemoteDesktop"; Title = "Remote Desktop"; Anchor = "WorkspaceAction.RemoteDesktop.RecommendedConnect"; Surfaces = @("RemoteDesktopHeader", "RemoteDesktop") },
        # Quantum has no row of its own. FeatureCatalogClient makes it a suffix on the File
        # Transfer and Remote Desktop entries rather than a page, matching the Mac sidebar's
        # seven tabs, and the Core diagnostics panel it used to open now renders as the FIRST
        # panel of the System Monitor workspace. This table was the one place that change was
        # never propagated to, so the gate kept selecting a navigation item the shell no longer
        # has. Its surface is not dropped, only moved: listing it here keeps the runtime action
        # snapshot covering it, in the same order the workspace renders it, and AdditionalAnchors
        # keeps asserting that the Run Diagnostics action is still reachable.
        @{
            Id = "SystemMonitor"
            Title = "System Monitor"
            Anchor = "WorkspaceAction.SystemMonitorControls.Monitoring"
            Surfaces = @("QuantumDiagnosticsHeader", "SystemMonitorHeader", "SystemMonitorControls")
            AdditionalAnchors = @("WorkspaceAction.QuantumDiagnosticsHeader.RunDiagnostics")
        },
        @{
            Id = "Settings"
            Title = "Settings"
            Anchor = "WorkspaceAction.SettingsToolbar.ExportSettings"
            Surfaces = @("SettingsHeader", "SettingsToolbar", "SettingsMaintenance")
            SurfaceGroups = @(
                @{ ScrollPercent = 0; Surfaces = @("SettingsHeader", "SettingsToolbar") },
                @{ ScrollPercent = 100; Surfaces = @("SettingsMaintenance") }
            )
        }
    )
    $globalActionSurfaceGroups = @(
        @{ ScrollPercent = 0; Surfaces = @("TopBarActions") },
        @{ ScrollPercent = 100; Surfaces = @("SessionControls") }
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $exePath
    $startInfo.WorkingDirectory = Split-Path $exePath
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($variable in @(
        "SKYBRIDGE_WINDOWS_RUNTIME",
        "SKYBRIDGE_WINDOWS_TRANSPORT_ADAPTER",
        "SKYBRIDGE_WINDOWS_SETTINGS_SYSTEM_PREFERENCES",
        "SKYBRIDGE_WINDOWS_ADAPTER_KIND",
        "SKYBRIDGE_WINDOWS_ADAPTER_BINDING",
        "SKYBRIDGE_WINDOWS_LOCAL_ENDPOINT",
        "SKYBRIDGE_WINDOWS_REMOTE_ENDPOINT",
        "SKYBRIDGE_WINDOWS_SELECTED_CANDIDATE_PAIR",
        "SKYBRIDGE_WINDOWS_TRANSPORT_SECRET_FP_HEX",
        "SKYBRIDGE_WINDOWS_CAPABILITY_DIGEST_HEX",
        "SKYBRIDGE_WINDOWS_RELAY_ID",
        "SKYBRIDGE_WINDOWS_TIMESTAMP_WINDOW_MS"
    )) {
        [void]$startInfo.Environment.Remove($variable)
    }

    $process = [System.Diagnostics.Process]::Start($startInfo)
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $window = Wait-ForMainWindow -Process $process -TimeoutSeconds $TimeoutSeconds
    Restore-TestWindow -Window $window
    if ($RequireNoAutomaticLocationConsentForCi) { Assert-CiNoAutomaticLocationConsent -Window $window -Process $process -Events $locationConsentEvents -Diagnostics $locationConsentDiagnostics }
    try {
        $windowPattern = $window.GetCurrentPattern([System.Windows.Automation.WindowPattern]::Pattern)
        $windowPattern.SetWindowVisualState([System.Windows.Automation.WindowVisualState]::Normal)
    }
    catch {
        Write-Verbose "Window visual-state normalization was unavailable: $($_.Exception.Message)"
    }
    Restore-TestWindow -Window $window
    Assert-BasicLayout -Window $window -Width 1200 -Height 800
    Set-TestWindowLogicalSize -Window $window -Width 1280 -Height 900

    foreach ($requiredAnchor in @(
        "Skybridge.Navigation.List",
        "WorkspaceAction.TopBarActions.Notifications",
        "WorkspaceAction.TopBarActions.Theme"
    )) {
        [void](Assert-VisibleByAutomationId -Root $window -AutomationId $requiredAnchor)
    }
    [void](Assert-SelectedFeature -Window $window -FeatureId "Dashboard")
    [void](Assert-StatusMessageNotEmpty -Window $window)

    Assert-BasicLayout -Window $window -Width 1280 -Height 900
    [void](Get-RuntimeActionSurfaceGroupSnapshot -Window $window -ActionOrderBySurface $actionOrderBySurface -SurfaceGroups $globalActionSurfaceGroups -Context "global 1280x900")
    Set-WorkspaceScrollPercent -Window $window -VerticalPercent 0
    Assert-BasicLayout -Window $window -Width 1366 -Height 768
    [void](Get-RuntimeActionSurfaceGroupSnapshot -Window $window -ActionOrderBySurface $actionOrderBySurface -SurfaceGroups $globalActionSurfaceGroups -Context "global 1366x768")
    Set-WorkspaceScrollPercent -Window $window -VerticalPercent 0

    foreach ($feature in $features) {
        $stage = "runtime-actions/$($feature.Id)"
        if ($RequireNoAutomaticLocationConsentForCi) { Assert-CiNoAutomaticLocationConsent -Window $window -Process $process -Events $locationConsentEvents -Diagnostics $locationConsentDiagnostics }
        Select-Feature -Window $window -FeatureId $feature.Id -AnchorAutomationId $feature.Anchor
        [void](Get-FeatureRuntimeActionSurfaceSnapshot -Window $window -ActionOrderBySurface $actionOrderBySurface -Feature $feature -ContextSuffix "runtime")
    }

    if (-not [string]::IsNullOrWhiteSpace($EvidenceDir)) {
        New-Item -ItemType Directory -Path $EvidenceDir -Force | Out-Null
        $resolvedEvidenceDir = (Resolve-Path -LiteralPath $EvidenceDir).Path
        $captures = [System.Collections.Generic.List[object]]::new()

        foreach ($size in @(
            @{ Width = 1280; Height = 900 },
            @{ Width = 1366; Height = 768 }
        )) {
            Restore-TestWindow -Window $window
            Set-TestWindowLogicalSize -Window $window -Width $size.Width -Height $size.Height
            $globalActionBounds = Get-RuntimeActionSurfaceGroupSnapshot -Window $window -ActionOrderBySurface $actionOrderBySurface -SurfaceGroups $globalActionSurfaceGroups -Context "global $($size.Width)x$($size.Height)"
            Set-WorkspaceScrollPercent -Window $window -VerticalPercent 0

            foreach ($feature in $features) {
                $stage = "visual/$($size.Width)x$($size.Height)/$($feature.Id)"
                if ($RequireNoAutomaticLocationConsentForCi) { Assert-CiNoAutomaticLocationConsent -Window $window -Process $process -Events $locationConsentEvents -Diagnostics $locationConsentDiagnostics }
                Select-Feature -Window $window -FeatureId $feature.Id -AnchorAutomationId $feature.Anchor
                $featureActionBounds = Get-FeatureRuntimeActionSurfaceSnapshot -Window $window -ActionOrderBySurface $actionOrderBySurface -Feature $feature -ContextSuffix "$($size.Width)x$($size.Height)"
                if ($feature.ContainsKey("EvidenceScrollPercent")) {
                    Set-WorkspaceScrollPercent `
                        -Window $window `
                        -VerticalPercent ([double]$feature.EvidenceScrollPercent) `
                        -Required
                }
                else {
                    Set-WorkspaceScrollPercent -Window $window -VerticalPercent 0
                }
                [void](Assert-PresentAndVisibleByAutomationId -Root $window -AutomationId $feature.Anchor)
                # Surfaces that moved into another workspace still have to be reachable there.
                foreach ($additionalAnchor in @(Get-FeatureAdditionalAnchors -Feature $feature)) {
                    [void](Assert-PresentAndVisibleByAutomationId -Root $window -AutomationId $additionalAnchor)
                }
                $fileName = "{0}x{1}-{2}.png" -f $size.Width, $size.Height, (ConvertTo-SafeFileName -Value $feature.Title)
                $screenshotPath = Join-Path $resolvedEvidenceDir $fileName
                $beforeCapture = $null
                if ($RequireNoAutomaticLocationConsentForCi) {
                    $beforeCapture = {
                        # Startup and navigation must not request location. Check after
                        # activation and before admitting screenshot pixels. Any
                        # obscuring dialog is a failure; this path never clicks it.
                        Assert-CiNoAutomaticLocationConsent -Window $window -Process $process -Events $locationConsentEvents -Diagnostics $locationConsentDiagnostics
                        if ($locationConsentEvents.Count -eq 0) {
                            $locationConsentDiagnostics.candidateWindow = @(Convert-CiConsentWindowsToEvidence -Windows @(
                                Get-CiConsentWindows -Window $window -IncludeCandidateWindow -Diagnostics $locationConsentDiagnostics))
                        }
                        Assert-NoAutomaticLocationConsentReceipt -Events @($locationConsentEvents)
                    }
                }
                $screenshot = Save-WindowScreenshot -Window $window -Path $screenshotPath -BeforeCapture $beforeCapture
                Assert-True -Condition (Test-Path -LiteralPath $screenshotPath) -Message "Missing evidence screenshot: $screenshotPath"

                $anchorIds = @(
                    "Skybridge.Navigation.List",
                    $feature.Id,
                    "WorkspaceAction.TopBarActions.Notifications",
                    "WorkspaceAction.TopBarActions.Theme",
                    $feature.Anchor
                )

                $captures.Add([pscustomobject]@{
                    feature = $feature.Title
                    featureId = $feature.Id
                    heading = $feature.Title
                    anchor = $feature.Anchor
                    requestedWidth = $size.Width
                    requestedHeight = $size.Height
                    screenshotWidth = $screenshot.width
                    screenshotHeight = $screenshot.height
                    screenshot = $fileName
                    runtimeActionBounds = @($globalActionBounds + $featureActionBounds)
                    anchors = Get-AutomationAnchorSnapshot -Root $window -AutomationIds $anchorIds
                })
            }
        }

        Assert-True -Condition ($captures.Count -eq ($features.Count * 2)) -Message "Unexpected visual evidence capture count: $($captures.Count)"
        $manifestPath = Join-Path $resolvedEvidenceDir "windows-ui-visual-evidence.json"
        [pscustomobject]@{
            generatedAtUtc = (Get-Date).ToUniversalTime().ToString("o")
            app = "Skybridge.WinClient"
            configuration = $Configuration
            targetFramework = $targetFramework
            repoBranch = Get-EvidenceBranch
            repoHead = Get-EvidenceHead
            captureCount = $captures.Count
            actionOrderMatrix = "docs/windows-ui-parity-matrix.md#action-order-matrix"
            captures = @($captures)
        } | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

        Assert-True -Condition (Test-Path -LiteralPath $manifestPath) -Message "Missing visual evidence manifest: $manifestPath"
        $visualEvidenceVerifier = Join-Path $RepoRoot "Scripts/verify-windows-ui-visual-evidence.ps1"
        Assert-True -Condition (Test-Path -LiteralPath $visualEvidenceVerifier) -Message "Missing visual evidence verifier: $visualEvidenceVerifier"
        & $visualEvidenceVerifier -RepoRoot $RepoRoot -EvidenceDir $resolvedEvidenceDir | Write-Output
        Write-Output "windows-ui-visual-evidence: ok dir=$resolvedEvidenceDir manifest=$manifestPath captures=$($captures.Count)"
    }

    $stage = 'file-transfer-policy'
    Select-Feature -Window $window -FeatureId "FileTransfer" -AnchorAutomationId "WorkspaceAction.FileTransfer.GenerateQr"
    $generateQr = Assert-VisibleByAutomationId -Root $window -AutomationId "WorkspaceAction.FileTransfer.GenerateQr"
    Assert-True -Condition (-not $generateQr.Current.IsEnabled) -Message "LAN sessions must not advertise QR sharing without a real share manifest."
    [void](Assert-PresentAndVisibleByAutomationId -Root $window -AutomationId "FileTransfer.QrUnavailableReason")
    $qrImage = Find-ByAutomationId -Root $window -AutomationId "FileTransferShareQrImage"
    Assert-True -Condition ($null -eq $qrImage -or $qrImage.Current.IsOffscreen) -Message "Unsupported QR sharing must never display an empty or unrelated identity."

    $stage = 'account-device-modal'
    $accountEntry = Assert-PresentAndVisibleByAutomationId -Root $window -AutomationId "AccountDevices.OpenFooter"
    $accountEntry.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
    [void](Assert-PresentAndVisibleByAutomationId -Root $window -AutomationId "AccountDevices.Close")
    [void](Assert-PresentAndVisibleByAutomationId -Root $window -AutomationId "AccountDevices.Status")
    $serviceDeadline = (Get-Date).AddSeconds(35)
    do {
        $accountStatus = Find-ByAutomationId -Root $window -AutomationId "AccountDevices.Status"
        $accountPhase = $accountStatus.Current.ItemStatus
        if ($accountPhase -notin @("loading", "")) { break }
        Start-Sleep -Milliseconds 200
    } while ((Get-Date) -lt $serviceDeadline)
    # The status text can reach its terminal state before WinUI publishes the ListView's
    # automation peer. Require the actual list with the existing bounded wait; a missing
    # peer must fail explicitly rather than masquerade as an empty account result.
    $accountList = Assert-PresentAndVisibleByAutomationId -Root $window -AutomationId "AccountDevices.List"
    $rowCondition = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::ListItem)
    $accountRows = $accountList.FindAll([System.Windows.Automation.TreeScope]::Children, $rowCondition)
    if ($resolvedEvidenceDir) {
        [void](Save-WindowScreenshot -Window $window -Path (Join-Path $resolvedEvidenceDir "account-devices.png"))
        [pscustomobject]@{phase=$accountPhase;status=$accountStatus.Current.Name;visibleRows=$accountRows.Count;authenticatedServiceRequired=[bool]$RequireAccountDeviceService} | ConvertTo-Json | Set-Content (Join-Path $resolvedEvidenceDir "account-device-service.json") -Encoding UTF8
    }
    if ($RequireAccountDeviceService) {
        Assert-True -Condition ($accountPhase -eq "ready" -and $accountRows.Count -gt 0) -Message "Authenticated account device service did not provide real rows: phase=$accountPhase status=$($accountStatus.Current.Name)"
    }
    $closeAccount = Assert-PresentAndVisibleByAutomationId -Root $window -AutomationId "AccountDevices.Close"
    $closeAccount.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
    $accountOverlay = Find-ByAutomationId -Root $window -AutomationId "AccountDevices.Close"
    Assert-True -Condition ($null -eq $accountOverlay -or $accountOverlay.Current.IsOffscreen) -Message "Account device modal did not close."

    if ($UsbFixtureDirectory) {
        $stage = "usb-discovery/refusal-recovery"
        Set-TestWindowLogicalSize -Window $window -Width 1280 -Height 900
        Select-Feature -Window $window -FeatureId "UsbManagement" -AnchorAutomationId "WorkspaceAction.UsbManagementHeader.RefreshDevices"
        Set-WorkspaceScrollPercent -Window $window -VerticalPercent 0
        $usbStates = [Collections.Generic.List[object]]::new()
        foreach ($scenario in @(
            @{ mode = 'open'; expected = 'SkyBridge found; pairing required'; capture = 'usb-phone-found.png' },
            @{ mode = 'closed'; expected = 'Open SkyBridge on the connected Apple device'; capture = 'usb-phone-app-closed.png' },
            @{ mode = 'open'; expected = 'SkyBridge found; pairing required'; capture = 'usb-phone-app-restored.png' }
        )) {
            $closedPortMarker = Join-Path $UsbFixtureDirectory 'closed-port'
            if ($scenario.mode -eq 'closed') { [IO.File]::WriteAllText($closedPortMarker, '') }
            else { [IO.File]::Delete($closedPortMarker) }
            $before = Read-UsbFixtureReceipt (Join-Path $UsbFixtureDirectory 'observations.json')
            $refresh = Assert-PresentAndVisibleByAutomationId -Root $window -AutomationId "WorkspaceAction.UsbManagementHeader.RefreshDevices"
            $readyLimit = [DateTimeOffset]::UtcNow.AddSeconds(20)
            while (-not $refresh.Current.IsEnabled) {
                if ([DateTimeOffset]::UtcNow -ge $readyLimit) { throw 'USB refresh remained busy.' }
                Start-Sleep -Milliseconds 100
                $refresh = Assert-PresentAndVisibleByAutomationId -Root $window -AutomationId "WorkspaceAction.UsbManagementHeader.RefreshDevices"
            }
            $refresh.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
            $limit = [DateTimeOffset]::UtcNow.AddSeconds(20)
            $matched = $false
            do {
                # Refresh replaces action-row records while busy changes. Resolve
                # the current button instead of retaining a recycled UIA element.
                $refresh = Assert-PresentAndVisibleByAutomationId -Root $window -AutomationId "WorkspaceAction.UsbManagementHeader.RefreshDevices"
                $condition = [System.Windows.Automation.PropertyCondition]::new(
                    [System.Windows.Automation.AutomationElement]::AutomationIdProperty, 'Skybridge.Usb.PeerStatus')
                $statuses = @($window.FindAll([System.Windows.Automation.TreeScope]::Descendants, $condition))
                $matching = @($statuses | Where-Object { -not $_.Current.IsOffscreen -and $_.Current.Name -eq $scenario.expected })
                $after = Read-UsbFixtureReceipt (Join-Path $UsbFixtureDirectory 'observations.json')
                $freshReply = if ($scenario.mode -eq 'closed') { $after.portRefusals -gt $before.portRefusals } else { $after.responses -gt $before.responses }
                $matched = $freshReply -and $matching.Count -eq 1 -and $refresh.Current.IsEnabled
                if (-not $matched) { Start-Sleep -Milliseconds 100 }
            } while (-not $matched -and [DateTimeOffset]::UtcNow -lt $limit)
            @{
                mode = $scenario.mode; expected = $scenario.expected
                currentStatuses = @($statuses | ForEach-Object { @{ text = $_.Current.Name; visible = -not $_.Current.IsOffscreen } })
                refreshEnabled = $refresh.Current.IsEnabled; before = $before; after = $after
            } | ConvertTo-Json -Depth 5 | Set-Content -Encoding utf8 (Join-Path $EvidenceDir "usb-state-$($usbStates.Count).json")
            Assert-True $matched "USB inspection did not reach the expected real UI state: $($scenario.expected)"
            $pair = Find-ByAutomationId -Root $window -AutomationId 'Skybridge.Usb.Pair'
            if ($scenario.mode -eq 'open') {
                $pair = Assert-PresentAndVisibleByAutomationId -Root $window -AutomationId 'Skybridge.Usb.Pair'
                Assert-True $pair.Current.IsEnabled 'An eligible USB device has no enabled pairing entry.'
            } else {
                Assert-True ($null -eq $pair -or $pair.Current.IsOffscreen) 'A closed USB peer still exposes pairing.'
            }
            $usbStates.Add(@{ mode = $scenario.mode; visibleStatus = $matching[0].Current.Name; responses = $after.responses; portRefusals = $after.portRefusals })
            [void](Save-WindowScreenshot -Window $window -Path (Join-Path $EvidenceDir $scenario.capture))
        }
        $stage = 'usb-enrollment/sign-in-boundary'
        $beforePair = Read-UsbFixtureReceipt (Join-Path $UsbFixtureDirectory 'observations.json')
        $pair = Assert-PresentAndVisibleByAutomationId -Root $window -AutomationId 'Skybridge.Usb.Pair'
        $pair.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
        # The custom UserControl itself has no UIA peer. Require the actual
        # interactive sign-in controls observed in the native automation tree.
        $signInAnchors = @('EmailInput', 'PasswordInput', 'EmailSignInButton', 'Skybridge.Account.ContinueAsGuest')
        foreach ($anchor in $signInAnchors) {
            [void](Assert-PresentAndVisibleByAutomationId -Root $window -AutomationId $anchor)
        }
        [void](Save-WindowScreenshot -Window $window -Path (Join-Path $EvidenceDir 'usb-pair-signin.png'))
        $guest = Assert-PresentAndVisibleByAutomationId -Root $window -AutomationId 'Skybridge.Account.ContinueAsGuest'
        $guest.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
        $dismissLimit = [DateTimeOffset]::UtcNow.AddSeconds(10)
        do {
            $visibleSignIn = @($signInAnchors | ForEach-Object {
                $element = Find-ByAutomationId -Root $window -AutomationId $_
                if ($null -ne $element -and -not $element.Current.IsOffscreen) { $_ }
            })
            if ($visibleSignIn.Count -eq 0) { break }
            Start-Sleep -Milliseconds 100
        } while ([DateTimeOffset]::UtcNow -lt $dismissLimit)
        Assert-True ($visibleSignIn.Count -eq 0) 'The sign-in controls did not dismiss.'
        $pair = Assert-PresentAndVisibleByAutomationId -Root $window -AutomationId 'Skybridge.Usb.Pair'
        Assert-True $pair.Current.IsEnabled 'Dismissing sign-in left USB pairing disabled.'
        [void](Save-WindowScreenshot -Window $window -Path (Join-Path $EvidenceDir 'usb-pair-return.png'))
        $afterPair = Read-UsbFixtureReceipt (Join-Path $UsbFixtureDirectory 'observations.json')
        Assert-True ($afterPair.responses -eq $beforePair.responses -and $afterPair.earlyCloses -eq $beforePair.earlyCloses) 'Signed-out pairing touched the USB carrier.'
        @{
            scope = 'Synthetic USB multiplex service; real product decoder, native signatures and UI'
            states = $usbStates.ToArray(); actualAppleService = $false; actualUsbDevice = $false
            authenticatedSession = $false; audioPlayed = $false
            pairingEntryVisible = $true; signInRequired = $true; trustCreated = $false
            signInControlsObserved = $signInAnchors; signInDismissed = $true
        } | ConvertTo-Json -Depth 5 | Set-Content -Encoding utf8 (Join-Path $EvidenceDir 'usb-discovery-ui.json')
    }

    Write-Output "windows-ui-automation-smoke: ok"
}
catch {
    $primaryFailure = $_
    if ($window -and -not [string]::IsNullOrWhiteSpace($EvidenceDir)) {
        [void](New-Item -ItemType Directory -Path $EvidenceDir -Force)
        try { Save-UiFailureDiagnostics -Window $window -Failure $primaryFailure -EvidenceDir $EvidenceDir -Stage $stage }
        catch { Write-Output "windows-ui-automation-smoke: failure diagnostics could not be saved: $($_.Exception.Message)" }
    }
    if ($process -and -not $process.HasExited) {
        try { $process.Kill() } catch { }
    }

    if ($process) {
        $stdout = if ($stdoutTask) { $stdoutTask.GetAwaiter().GetResult() } else { "" }
        $stderr = if ($stderrTask) { $stderrTask.GetAwaiter().GetResult() } else { "" }
        if (-not [string]::IsNullOrWhiteSpace($stdout)) {
            Write-Output "windows-ui-automation-smoke stdout:"
            Write-Output $stdout
        }
        if (-not [string]::IsNullOrWhiteSpace($stderr)) {
            Write-Output "windows-ui-automation-smoke stderr:"
            Write-Output $stderr
        }
    }

    throw $primaryFailure
}
finally {
    if ($RequireNoAutomaticLocationConsentForCi -and -not [string]::IsNullOrWhiteSpace($EvidenceDir)) {
        [void](New-Item -ItemType Directory -Path $EvidenceDir -Force)
        @{ policy = 'no-automatic-location-prompt-during-startup-or-navigation'; events = @($locationConsentEvents); diagnostics = $locationConsentDiagnostics } |
            ConvertTo-Json -Depth 8 | Set-Content -Encoding utf8 (Join-Path $EvidenceDir 'location-consent.json')
    }
    if ($process -and -not $process.HasExited) {
        Stop-Process -Id $process.Id -Force
    }
}
