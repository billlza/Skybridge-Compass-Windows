# Pure geometry observation helpers shared by native UI checks and their regression tests.

function Test-ActionBoundsFollow {
    param(
        $PreviousBounds,
        $CurrentBounds
    )

    $verticalGap = [double]$CurrentBounds.top - [double]$PreviousBounds.top
    if ($verticalGap -gt 2) {
        return $true
    }

    if ([Math]::Abs($verticalGap) -le 2 -and ([double]$CurrentBounds.left -gt ([double]$PreviousBounds.left + 2))) {
        return $true
    }

    return $false
}

function Test-ActionBoundsSnapshotUsable {
    param(
        [object[]]$Actions
    )

    foreach ($action in @($Actions)) {
        if (-not $action.usable) {
            return $false
        }
    }

    return $true
}

function Format-ActionBoundsSnapshot {
    param([object[]]$Actions)

    return (@($Actions | ForEach-Object {
                "$($_.automationId) offscreen=$($_.isOffscreen) usable=$($_.usable) bounds=left:$($_.bounds.left),top:$($_.bounds.top),width:$($_.bounds.width),height:$($_.bounds.height)"
            }) -join "; ")
}

function Test-ActionBoundsSnapshotsEqual {
    param([object[]]$Previous, [object[]]$Current)

    if ($Previous.Count -ne $Current.Count -or $Current.Count -eq 0) { return $false }
    for ($index = 0; $index -lt $Current.Count; $index++) {
        $a = $Previous[$index]; $b = $Current[$index]
        if ($a.automationId -ne $b.automationId -or $a.isOffscreen -ne $b.isOffscreen) { return $false }
        foreach ($field in @('left', 'top', 'width', 'height')) {
            if ([double]$a.bounds.$field -ne [double]$b.bounds.$field) { return $false }
        }
    }
    return $true
}

function Get-StableActionBoundsSnapshot {
    param(
        [scriptblock]$ReadSnapshot,
        [string]$Context,
        [ValidateRange(2, 50)][int]$MaximumSamples = 50,
        [ValidateRange(0, 100)][int]$PollMilliseconds = 100,
        [ValidateRange(1, 5000)][int]$TimeoutMilliseconds = 5000
    )

    $history = [System.Collections.Generic.List[object]]::new()
    $previous = @()
    $clock = [Diagnostics.Stopwatch]::StartNew()
    for ($sample = 0; $sample -lt $MaximumSamples; $sample++) {
        $current = @(& $ReadSnapshot)
        if ($current.Count -eq 0) { throw "Empty action geometry snapshot: $Context" }
        $history.Add([object]$current)
        # Stability is independent of the acceptance assertions. A stable wrong
        # order or clipped row is returned and still fails the existing checks.
        if ($clock.ElapsedMilliseconds -lt $TimeoutMilliseconds -and $sample -gt 0 -and
            (Test-ActionBoundsSnapshotsEqual -Previous $previous -Current $current)) {
            return [pscustomobject]@{ actions = $current; sampleCount = $history.Count; frames = $history.ToArray() }
        }
        $previous = $current
        if ($clock.ElapsedMilliseconds -ge $TimeoutMilliseconds) { break }
        if ($PollMilliseconds -gt 0) { Start-Sleep -Milliseconds $PollMilliseconds }
    }
    throw "Action geometry did not stabilize within the bounded observation: $Context samples=$($history.Count) last=$(Format-ActionBoundsSnapshot -Actions $previous)"
}
