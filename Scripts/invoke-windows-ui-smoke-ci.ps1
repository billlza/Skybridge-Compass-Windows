param(
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Debug',
    [Parameter(Mandatory = $true)][string]$EvidenceDir,
    [Parameter(Mandatory = $true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExistingAssemblySha256,
    [switch]$RequireUsbDiscoveryFixture
)

$ErrorActionPreference = 'Stop'
if (-not $IsWindows -or $env:GITHUB_ACTIONS -ne 'true') {
    throw 'This display preparation is only for the disposable Windows CI runner.'
}
if (Test-Path -LiteralPath $EvidenceDir) { throw 'Choose a new UI evidence directory.' }
[void](New-Item -ItemType Directory -Path $EvidenceDir)

# Use driver-enumerated modes and CDS_TEST; never force an unsupported mode or
# update the registry. Restore the original session mode even when UI checks fail.
# https://learn.microsoft.com/windows/win32/api/winuser/nf-winuser-changedisplaysettingsexw
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class CiDisplayMode
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct Mode
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string DeviceName;
        public ushort SpecVersion, DriverVersion, Size, DriverExtra;
        public uint Fields;
        public int PositionX, PositionY;
        public uint DisplayOrientation, DisplayFixedOutput;
        public short Color, Duplex, YResolution, TTOption, Collate;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string FormName;
        public ushort LogPixels;
        public uint BitsPerPel, Width, Height, DisplayFlags, Frequency;
        public uint ICMMethod, ICMIntent, MediaType, DitherType, Reserved1, Reserved2, PanningWidth, PanningHeight;
    }

    [DllImport("user32.dll", EntryPoint = "EnumDisplaySettingsW", CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Read(string device, int index, ref Mode mode);

    [DllImport("user32.dll", EntryPoint = "ChangeDisplaySettingsExW", CharSet = CharSet.Unicode)]
    private static extern int Change(string device, ref Mode mode, IntPtr window, uint flags, IntPtr parameters);

    private static Mode Empty()
    {
        if (Marshal.SizeOf<Mode>() != 220) throw new InvalidOperationException("Invalid DEVMODEW layout.");
        return new Mode { Size = 220, DeviceName = "", FormName = "" };
    }

    public static Mode Current()
    {
        var mode = Empty();
        if (!Read(null, -1, ref mode)) throw new InvalidOperationException("Cannot read the current display mode.");
        return mode;
    }

    public static Mode[] Supported()
    {
        var result = new List<Mode>();
        for (int index = 0; index < 512; index++)
        {
            var mode = Empty();
            if (!Read(null, index, ref mode)) return result.ToArray();
            result.Add(mode);
        }
        throw new InvalidOperationException("Display mode enumeration exceeded its bound.");
    }

    public static void Test(Mode mode)
    {
        int result = Change(null, ref mode, IntPtr.Zero, 2, IntPtr.Zero);
        if (result != 0) throw new InvalidOperationException("The driver rejected the display mode test: " + result);
    }

    public static void Apply(Mode mode)
    {
        int result = Change(null, ref mode, IntPtr.Zero, 0, IntPtr.Zero);
        if (result != 0) throw new InvalidOperationException("The display mode change failed: " + result);
        var actual = Current();
        if (actual.Width != mode.Width || actual.Height != mode.Height ||
            actual.BitsPerPel != mode.BitsPerPel || mode.Frequency > 1 && actual.Frequency != mode.Frequency)
            throw new InvalidOperationException("The driver did not apply the requested display mode.");
    }
}
'@

function ConvertTo-DisplayEvidence([CiDisplayMode+Mode]$Mode) {
    return @{ width = $Mode.Width; height = $Mode.Height; bitsPerPixel = $Mode.BitsPerPel; frequency = $Mode.Frequency }
}

$result = [ordered]@{ schemaVersion = 1; status = 'failed'; modeChanged = $false; restored = $false; error = $null; restoreError = $null }
$original = $null
$restoreRequired = $false
$primaryError = $null
$restoreError = $null
$usbFixtureProcess = $null
$usbFixtureDirectory = $null
$usbFixtureOutput = $null
$usbFixtureErrors = $null
$usbFixtureCleanupError = $null
try {
    if ($RequireUsbDiscoveryFixture) {
        $usbFixtureDirectory = Join-Path ([IO.Path]::GetFullPath($EvidenceDir)) 'usb-fixture'
        $assembly = Join-Path (Split-Path -Parent $PSScriptRoot) "windows/Skybridge.WinClient.ContractTests/bin/$Configuration/net10.0/win-x64/Skybridge.WinClient.ContractTests.dll"
        if (-not (Test-Path -LiteralPath $assembly -PathType Leaf)) { throw 'The native USB fixture assembly is unavailable.' }
        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = (Get-Command dotnet).Source
        $start.UseShellExecute = $false
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $start.ArgumentList.Add($assembly)
        $start.ArgumentList.Add('--usb-discovery-ui-service')
        $start.ArgumentList.Add($usbFixtureDirectory)
        $usbFixtureProcess = [Diagnostics.Process]::Start($start)
        $usbFixtureOutput = $usbFixtureProcess.StandardOutput.ReadToEndAsync()
        $usbFixtureErrors = $usbFixtureProcess.StandardError.ReadToEndAsync()
        $ready = Join-Path $usbFixtureDirectory 'ready.json'
        $limit = [DateTimeOffset]::UtcNow.AddSeconds(20)
        while (-not (Test-Path -LiteralPath $ready -PathType Leaf)) {
            if ($usbFixtureProcess.HasExited) { throw 'The isolated USB fixture exited before readiness; inspect its retained error log.' }
            if ([DateTimeOffset]::UtcNow -ge $limit) { throw 'The isolated USB fixture did not become ready.' }
            Start-Sleep -Milliseconds 100
        }
        $publication = Get-Content -LiteralPath $ready -Raw | ConvertFrom-Json
        if ($publication.processId -ne $usbFixtureProcess.Id -or $publication.actualAppleService -ne $false -or $publication.actualUsbDevice -ne $false) {
            throw 'The isolated USB fixture readiness record has a different owner or scope.'
        }
    }
    $original = [CiDisplayMode]::Current()
    $result.original = ConvertTo-DisplayEvidence $original
    $modes = @([CiDisplayMode]::Supported())
    $result.supported = @($modes | ForEach-Object { ConvertTo-DisplayEvidence $_ })
    if ($original.Width -lt 1920 -or $original.Height -lt 1080) {
        $candidates = @($modes | Where-Object {
            $_.Width -ge 1920 -and $_.Height -ge 1080 -and
            $_.Width -le 3840 -and $_.Height -le 2160 -and $_.BitsPerPel -eq 32
        } | Sort-Object @{ Expression = { [long]$_.Width * $_.Height } }, Frequency)
        if ($candidates.Count -eq 0) { throw 'The CI display has no supported mode large enough for the existing UI checks.' }
        $selected = $candidates[0]
        $result.selected = ConvertTo-DisplayEvidence $selected
        [CiDisplayMode]::Test($selected)
        $restoreRequired = $true
        [CiDisplayMode]::Apply($selected)
        $result.modeChanged = $true
    }
    $result.active = ConvertTo-DisplayEvidence ([CiDisplayMode]::Current())
    & (Join-Path $PSScriptRoot 'verify-windows-ui-automation-smoke.ps1') -Configuration $Configuration `
        -EvidenceDir $EvidenceDir -ExistingAssemblySha256 $ExistingAssemblySha256 -RequireNoAutomaticLocationConsentForCi `
        -UsbFixtureDirectory $usbFixtureDirectory
    $result.status = 'passed'
} catch {
    $primaryError = $_.Exception
    $result.error = $primaryError.Message
} finally {
    if ($usbFixtureProcess) {
        $fixtureFailures = [Collections.Generic.List[Exception]]::new()
        try {
            if (-not $usbFixtureProcess.HasExited) {
                [IO.File]::WriteAllText((Join-Path $usbFixtureDirectory 'stop'), 'stop')
                if (-not $usbFixtureProcess.WaitForExit(12000)) {
                    throw 'The owned USB fixture failed to drain after its stop signal.'
                }
            }
            if ($usbFixtureProcess.ExitCode -ne 0) { throw "The owned USB fixture failed: exit=$($usbFixtureProcess.ExitCode)" }
            $observations = Get-Content -LiteralPath (Join-Path $usbFixtureDirectory 'observations.json') -Raw | ConvertFrom-Json
            if ($observations.responses -lt 2 -or $observations.portRefusals -lt 1 -or -not $observations.drained) {
                throw 'USB UI checks did not exercise discovery, refusal, recovery and actual service drain.'
            }
        } catch {
            $fixtureFailures.Add($_.Exception)
        } finally {
            # Stop-file failure must still retire this owned child. Keep the failure;
            # forced termination is not successful service drain.
            try {
                if (-not $usbFixtureProcess.HasExited) {
                    $usbFixtureProcess.Kill($true)
                    if (-not $usbFixtureProcess.WaitForExit(5000)) {
                        throw 'The owned USB fixture did not exit after termination.'
                    }
                }
            } catch { $fixtureFailures.Add($_.Exception) }
            foreach ($stream in @(
                @{ task = $usbFixtureOutput; path = 'usb-fixture-output.log' },
                @{ task = $usbFixtureErrors; path = 'usb-fixture-error.log' }
            )) {
                if ($null -eq $stream.task) { continue }
                try {
                    if (-not $stream.task.Wait(2000)) { throw "The owned USB fixture did not close $($stream.path)." }
                    $stream.task.GetAwaiter().GetResult() | Set-Content -Encoding utf8 (Join-Path $EvidenceDir $stream.path)
                } catch { $fixtureFailures.Add($_.Exception) }
            }
            $usbFixtureProcess.Dispose()
        }
        if ($fixtureFailures.Count -gt 0) {
            $usbFixtureCleanupError = [AggregateException]::new('The owned USB fixture did not complete cleanly.', $fixtureFailures)
            $result.status = 'failed'
            $result.usbFixtureError = $usbFixtureCleanupError.ToString()
        }
    }
    if ($restoreRequired) {
        try {
            [CiDisplayMode]::Apply($original)
            $result.restored = $true
        } catch {
            $restoreError = $_.Exception
            $result.restoreError = $restoreError.Message
            $result.status = 'failed'
        }
    }
    # Only this disposable CI runner is eligible. The product already records
    # uncaught command failures here; retain them alongside failed UI evidence.
    try {
        $runtimeLog = Join-Path $env:LOCALAPPDATA 'SkyBridge/logs/skybridge-win.log'
        if (Test-Path -LiteralPath $runtimeLog -PathType Leaf) {
            Get-Content -LiteralPath $runtimeLog -Tail 160 |
                Set-Content -Encoding utf8 (Join-Path $EvidenceDir 'native-app.log')
        }
    } catch {
        $result.runtimeLogCollectionError = $_.Exception.Message
        if ($null -eq $primaryError) { $primaryError = $_.Exception }
        $result.status = 'failed'
    }
    $result | ConvertTo-Json -Depth 5 | Set-Content -Encoding utf8 (Join-Path $EvidenceDir 'display-preparation.json')
}
$failures = @(@($primaryError, $restoreError, $usbFixtureCleanupError) | Where-Object { $null -ne $_ })
if ($failures.Count -gt 1) { throw [AggregateException]::new([Exception[]]$failures) }
if ($failures.Count -eq 1) { throw $failures[0] }
