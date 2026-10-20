$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-ui-consent-policy.ps1')

# These are receipt-policy fixtures, never native permission evidence.
function New-Receipt([string]$Status = 'dismissed') {
    [pscustomobject]@{ application = 'Skybridge.WinClient'; action = 'allow'; status = $Status; windowHandle = 42 }
}
function Require-Rejection([object[]]$Events) {
    $failure = $null
    try { Assert-FirstStartLocationConsentReceipt -Events $Events }
    catch { $failure = $_ }
    if ($null -eq $failure) { throw 'An incomplete first-start consent observation was accepted.' }
}

# Run 39148190530 had this empty event list while its screenshots showed the prompt.
Require-Rejection -Events @()
Write-Output 'PASS a zero-action receipt cannot qualify first-start UI evidence'
foreach ($status in @('invoking', 'invoked')) { Require-Rejection -Events @((New-Receipt $status)) }
Write-Output 'PASS an attempted response without observed dismissal remains incomplete'
Require-Rejection -Events @((New-Receipt), (New-Receipt))
$wrongApplication = New-Receipt; $wrongApplication.application = 'OtherApp'
Require-Rejection -Events @($wrongApplication)
$missingWindow = New-Receipt; $missingWindow.windowHandle = 0
Require-Rejection -Events @($missingWindow)
Write-Output 'PASS duplicate, unrelated and unbound receipts are rejected'
Assert-FirstStartLocationConsentReceipt -Events @((New-Receipt))
Write-Output 'PASS a single complete receipt satisfies the policy only'

function New-ClearReceipt {
    [pscustomobject]@{ application='Skybridge.WinClient'; action='observe'; status='clear'; windowHandle=42; processId=123; foregroundRoot=42; centerRoot=42; overlappingWindowCount=0 }
}
function Require-ClearRejection([object[]]$Events) {
    $failure = $null
    try { Assert-NoAutomaticLocationConsentReceipt -Events $Events } catch { $failure = $_ }
    if ($null -eq $failure) { throw 'An unproven no-prompt observation was accepted.' }
}
Require-ClearRejection -Events @()
foreach ($field in @('application','action','status','windowHandle','processId','foregroundRoot','centerRoot','overlappingWindowCount')) {
    $missing = New-ClearReceipt; $missing.PSObject.Properties.Remove($field)
    Require-ClearRejection -Events @($missing)
}
$obscured = New-ClearReceipt; $obscured.overlappingWindowCount=1
Require-ClearRejection -Events @($obscured)
foreach ($invalidCount in @($null, 0.1, '0')) {
    $invalid = New-ClearReceipt; $invalid.overlappingWindowCount=$invalidCount
    Require-ClearRejection -Events @($invalid)
}
$clicked = New-ClearReceipt; $clicked.action='allow'
Require-ClearRejection -Events @($clicked)
$hidden = New-ClearReceipt; $hidden.foregroundRoot=0
Require-ClearRejection -Events @($hidden)
$covered = New-ClearReceipt; $covered.centerRoot=43
Require-ClearRejection -Events @($covered)
$changed = New-ClearReceipt; $changed.processId=124
Require-ClearRejection -Events @((New-ClearReceipt), $changed)
$changed = New-ClearReceipt; $changed.windowHandle=43
Require-ClearRejection -Events @((New-ClearReceipt), $changed)
Assert-NoAutomaticLocationConsentReceipt -Events @((New-ClearReceipt), (New-ClearReceipt))
Write-Output 'PASS no-prompt admission requires observed unobscured windows from the same candidate and rejects permission actions'
