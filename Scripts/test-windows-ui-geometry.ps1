$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot "windows-ui-geometry.ps1")

function New-Frame([double]$FirstTop, [double]$SecondTop) {
    @(
        [pscustomobject]@{ automationId = 'generate'; isOffscreen = $false; usable = $true; bounds = [pscustomobject]@{ left = 618; top = $FirstTop; width = 44; height = 36 } },
        [pscustomobject]@{ automationId = 'scan'; isOffscreen = $false; usable = $true; bounds = [pscustomobject]@{ left = 672; top = $SecondTop; width = 44; height = 36 } }
    )
}
function Require([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }

# Replay the actual failing coordinates, followed by a settled horizontal row.
$trace = [pscustomobject]@{ index = 0 }
$read = {
    $trace.index++
    if ($trace.index -eq 1) { New-Frame 856 830 } else { New-Frame 830 830 }
}
$result = Get-StableActionBoundsSnapshot -ReadSnapshot $read -Context 'moving row' -MaximumSamples 4 -PollMilliseconds 0
Require ($result.sampleCount -eq 3) 'Moving coordinates were admitted before two complete equal frames.'
Require (Test-ActionBoundsFollow $result.actions[0].bounds $result.actions[1].bounds) 'The settled row lost its actual order.'
Require (-not (Test-ActionBoundsFollow $result.frames[0][0].bounds $result.frames[0][1].bounds)) 'The original failure was not retained in the observation trace.'
Write-Output 'PASS moving-frame counterexample settles without discarding its original coordinates'

$manifest = @{ captures = @(@{ runtimeActionBounds = @(@{ geometrySamples = @(@{ frames = $result.frames }) }) }) }
$roundTrip = $manifest | ConvertTo-Json -Depth 12 -WarningAction Stop | ConvertFrom-Json
Require ($roundTrip.captures[0].runtimeActionBounds[0].geometrySamples[0].frames[0][0].bounds.top -eq 856) 'Visual evidence truncated the original geometry trace.'
Write-Output 'PASS visual evidence preserves the complete nested geometry trace'

$result = Get-StableActionBoundsSnapshot -ReadSnapshot { New-Frame 856 830 } -Context 'stable wrong order' -MaximumSamples 3 -PollMilliseconds 0
Require ($result.sampleCount -eq 2) 'Observation waited for a passing order instead of a stable frame.'
Require (-not (Test-ActionBoundsFollow $result.actions[0].bounds $result.actions[1].bounds)) 'A stable ordering failure was weakened.'
Write-Output 'PASS stable incorrect order remains an acceptance failure'

$read = {
    $frame = @(New-Frame 830 830)
    $frame[0].bounds.width = 16
    $frame[0].usable = $false
    $frame
}
$result = Get-StableActionBoundsSnapshot -ReadSnapshot $read -Context 'stable clipped action' -MaximumSamples 3 -PollMilliseconds 0
Require ($result.sampleCount -eq 2 -and -not (Test-ActionBoundsSnapshotUsable -Actions $result.actions)) 'A stable clipped action escaped the usability check.'
Write-Output 'PASS stable clipped geometry remains an acceptance failure'

$trace = [pscustomobject]@{ count = 0 }
$read = { $trace.count++; New-Frame (830 - $trace.count) (830 - $trace.count) }
$failure = $null
try { Get-StableActionBoundsSnapshot -ReadSnapshot $read -Context 'continuous movement' -MaximumSamples 3 -PollMilliseconds 0 | Out-Null }
catch { $failure = $_ }
Require ($null -ne $failure -and $failure.Exception.Message.Contains('did not stabilize') -and $trace.count -eq 3) 'Unstable geometry escaped its sample bound.'
Write-Output 'PASS continuously moving geometry fails within the sample bound'

$trace = [pscustomobject]@{ count = 0 }
$read = { $trace.count++; throw [IO.IOException]::new('geometry-reader-failed') }
$failure = $null
try { Get-StableActionBoundsSnapshot -ReadSnapshot $read -Context 'reader error' -MaximumSamples 3 -PollMilliseconds 0 | Out-Null }
catch { $failure = $_ }
Require ($null -ne $failure -and $failure.Exception.Message.Contains('geometry-reader-failed') -and $trace.count -eq 1) 'A reader error was swallowed or retried.'
Write-Output 'PASS reader failure is preserved without retry'

function Read-FromActiveCaller {
    $callerTop = 731
    function Read-CallerLocalFrame { New-Frame $callerTop $callerTop }
    Get-StableActionBoundsSnapshot -ReadSnapshot { Read-CallerLocalFrame } `
        -Context 'active caller scope' -MaximumSamples 3 -PollMilliseconds 0
}
$result = Read-FromActiveCaller
Require ($result.sampleCount -eq 2 -and $result.actions[0].bounds.top -eq 731) 'The synchronous reader lost its active caller variables or helper function.'
Write-Output 'PASS nested caller-local helpers and variables remain available'
