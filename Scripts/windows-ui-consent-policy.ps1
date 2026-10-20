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

# Product startup/navigation only reads access status. A nonempty observation set
# is mandatory: the absence of clicks alone does not prove the screen was clear.
function Assert-NoAutomaticLocationConsentReceipt {
    param([object[]]$Events)
    if ($null -eq $Events -or $Events.Count -eq 0) { throw 'Missing native no-prompt observations.' }
    $firstHandle = $null
    $firstProcess = $null
    foreach ($observation in $Events) {
        foreach ($required in @('application','action','status','windowHandle','processId','foregroundRoot','centerRoot','overlappingWindowCount')) {
            if ($observation.PSObject.Properties.Name -cnotcontains $required) { throw "Missing no-prompt field: $required" }
            if ($null -eq $observation.$required) { throw "Null no-prompt field: $required" }
        }
        if ($observation.overlappingWindowCount -isnot [int] -and $observation.overlappingWindowCount -isnot [long]) {
            throw 'No-prompt overlap count is not an integer observation.'
        }
        if ($observation.application -cne 'Skybridge.WinClient' -or $observation.action -cne 'observe' -or $observation.status -cne 'clear' -or
            [long]$observation.windowHandle -le 0 -or [int]$observation.processId -le 0 -or [int]$observation.overlappingWindowCount -ne 0 -or
            [long]$observation.foregroundRoot -ne [long]$observation.windowHandle -or [long]$observation.centerRoot -ne [long]$observation.windowHandle) {
            throw 'Unexpected prompt, permission action or unbound no-prompt observation.'
        }
        if ($null -eq $firstHandle) { $firstHandle = [long]$observation.windowHandle; $firstProcess = [int]$observation.processId }
        if ([long]$observation.windowHandle -ne $firstHandle -or [int]$observation.processId -ne $firstProcess) {
            throw 'No-prompt observations changed their candidate process or window.'
        }
    }
}
