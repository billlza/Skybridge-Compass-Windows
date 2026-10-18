# Pure receipt policy for the disposable runner's first-start consent scenario.
function Assert-FirstStartLocationConsentReceipt {
    param([object[]]$Events)

    if ($null -eq $Events -or $Events.Count -ne 1) {
        throw 'The first-start UI scenario requires exactly one completed location consent receipt.'
    }
    $receipt = $Events[0]
    if ($receipt.application -cne 'Skybridge.WinClient' -or $receipt.action -cne 'allow' -or
        $receipt.status -cne 'dismissed' -or [long]$receipt.windowHandle -le 0) {
        throw 'The first-start location consent receipt is incomplete or belongs to another action.'
    }
}
