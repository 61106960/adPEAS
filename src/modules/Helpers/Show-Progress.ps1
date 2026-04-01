<#
.SYNOPSIS
    Displays progress for long-running operations in Check modules.

.DESCRIPTION
    Unified progress indicator for Check modules processing large object counts.
    Automatically throttles updates to minimize performance impact.

    Features:
    - Automatic throttling (max 4 updates/sec, 250ms interval)
    - Percentage calculation
    - Optional object name display
    - Automatic cleanup on completion
    - Centralized threshold: $Script:ProgressThreshold (default: 30 items)

.PARAMETER Activity
    Activity name (e.g., "Checking user owners")

.PARAMETER Current
    Current item number (1-based)

.PARAMETER Total
    Total item count

.PARAMETER ObjectName
    Optional: Name of current object being processed

.PARAMETER MinInterval
    Minimum milliseconds between updates (default: 250ms = 4 updates/sec)

.PARAMETER Completed
    Switch to clear the progress bar

.EXAMPLE
    Show-Progress -Activity "Checking owners" -Current 34 -Total 17743
    Displays: "Testing 34 of 17743 (0.2%)"

.EXAMPLE
    Show-Progress -Activity "Testing accounts" -Current 100 -Total 5000 -ObjectName "john.doe"
    Displays: "Testing 100 of 5000 - john.doe (2%)"

.EXAMPLE
    Show-Progress -Activity "Processing users" -Completed
    Clears the progress bar

.EXAMPLE
    # Check if progress should be shown
    if ($totalCount -gt $Script:ProgressThreshold) {
        Show-Progress -Activity "Processing" -Current $i -Total $totalCount -ObjectName $item.Name
    }

.NOTES
    Author: Alexander Sturz (@_61106960_)
    Performance: <0.5% overhead with throttling
    Threshold: Use $Script:ProgressThreshold (default: 30) for consistency
#>

# Global progress threshold - minimum items before showing progress
if (-not $Script:ProgressThreshold) {
    $Script:ProgressThreshold = 30
}

function Show-Progress {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Activity = "Processing",

        [Parameter(Mandatory=$false)]
        [int]$Current = 0,

        [Parameter(Mandatory=$false)]
        [int]$Total = 0,

        [Parameter(Mandatory=$false)]
        [string]$ObjectName,

        [Parameter(Mandatory=$false)]
        [int]$MinInterval = 250,

        [Parameter(Mandatory=$false)]
        [switch]$Completed
    )

    # Progress throttling: Track last update time to avoid performance impact
    if (-not $Script:LastProgressUpdate) {
        $Script:LastProgressUpdate = @{}
    }

    $activityKey = $Activity

    if ($Completed) {
        # Clear progress bar
        Write-Progress -Activity $Activity -Completed
        if ($Script:LastProgressUpdate.ContainsKey($activityKey)) {
            $Script:LastProgressUpdate.Remove($activityKey)
        }
        return
    }

    # Skip if no total or invalid values
    if ($Total -eq 0 -or $Current -gt $Total) {
        return
    }

    # Throttle updates (except first and last item)
    $now = [DateTime]::UtcNow
    if ($Script:LastProgressUpdate.ContainsKey($activityKey)) {
        $elapsed = ($now - $Script:LastProgressUpdate[$activityKey]).TotalMilliseconds

        # Always show first, last, and every N items based on interval
        if ($Current -ne 1 -and $Current -ne $Total -and $elapsed -lt $MinInterval) {
            return
        }
    }

    $Script:LastProgressUpdate[$activityKey] = $now

    # Calculate percentage
    $percentComplete = [math]::Min(100, [int](($Current / $Total) * 100))

    # Build status message
    $status = "Testing $Current of $Total"
    if ($ObjectName) {
        $status += " - $ObjectName"
    }

    # Display progress
    Write-Progress -Activity $Activity -Status $status -PercentComplete $percentComplete -CurrentOperation "$percentComplete% complete"
}
