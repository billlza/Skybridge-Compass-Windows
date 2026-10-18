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
