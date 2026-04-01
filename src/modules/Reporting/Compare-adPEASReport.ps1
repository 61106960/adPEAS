function Compare-adPEASReport {
    <#
    .SYNOPSIS
    Compares two adPEAS JSON findings exports and shows differences.

    .DESCRIPTION
    Analyzes two JSON findings caches from different scans and produces a structured
    comparison showing:

    - New findings (in current but not in baseline) - potential new vulnerabilities
    - Remediated findings (in baseline but not in current) - fixed issues
    - Changed findings (severity changed between scans)
    - Summary statistics

    This enables tracking remediation progress, detecting new vulnerabilities,
    and trend analysis across multiple scans.

    .PARAMETER Baseline
    Path to the baseline (older) JSON findings cache file.

    .PARAMETER Current
    Path to the current (newer) JSON findings cache file.

    .PARAMETER OutputPath
    Optional base path for diff report output files (without extension).
    If specified, generates a text diff report.

    .PARAMETER NoColor
    Write plain text output without ANSI color codes.

    .EXAMPLE
    Compare-adPEASReport -Baseline ".\scan_q1.json" -Current ".\scan_q2.json"

    .EXAMPLE
    Compare-adPEASReport -Baseline ".\scan_jan.json" -Current ".\scan_apr.json" -OutputPath ".\diff_report"

    .NOTES
    Author: Alexander Sturz (@_61106960_)
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Baseline,

        [Parameter(Mandatory=$true)]
        [string]$Current,

        [Parameter(Mandatory=$false)]
        [string]$OutputPath,

        [Parameter(Mandatory=$false)]
        [switch]$NoColor
    )

    begin {
        Write-Log "[Compare-adPEASReport] Starting report comparison"
    }

    process {
        # Validate input files
        if (-not (Test-Path $Baseline)) {
            Write-Error "[Compare-adPEASReport] Baseline file not found: $Baseline"
            return
        }
        if (-not (Test-Path $Current)) {
            Write-Error "[Compare-adPEASReport] Current file not found: $Current"
            return
        }

        # Save and configure output state
        $previousOutputfile = $Script:adPEAS_Outputfile
        $previousOutputColor = $Script:adPEAS_OutputColor

        try {
            # Configure file output if requested
            if ($OutputPath) {
                $resolvedBase = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
                # Strip any existing extension from the base path
                if ([System.IO.Path]::HasExtension($resolvedBase)) {
                    $resolvedBase = [System.IO.Path]::ChangeExtension($resolvedBase, $null).TrimEnd('.')
                }
                $outputDir = Split-Path -Parent $resolvedBase
                if ($outputDir -and -not (Test-Path $outputDir)) {
                    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
                }
                $textPath = "$resolvedBase.txt"
                $Script:adPEAS_Outputfile = $textPath
                [System.IO.File]::WriteAllText($textPath, "", [System.Text.Encoding]::UTF8)
            }
            $Script:adPEAS_OutputColor = if ($NoColor) { $false } else { $null }

            # 1. Load and validate JSON (single read per file, reused for metadata and import)
            $baselineCache = (Get-Content -Path $Baseline -Raw -Encoding UTF8) | ConvertFrom-Json
            $currentCache = (Get-Content -Path $Current -Raw -Encoding UTF8) | ConvertFrom-Json

            # Validate cache versions
            foreach ($entry in @(@{Name='Baseline'; Cache=$baselineCache; Path=$Baseline}, @{Name='Current'; Cache=$currentCache; Path=$Current})) {
                if (-not $entry.Cache.CacheVersion) {
                    Write-Error "[Compare-adPEASReport] Invalid JSON file ($($entry.Name)): $($entry.Path)"
                    return
                }
                if ($entry.Cache.CacheVersion -ne 1) {
                    Write-Error "[Compare-adPEASReport] Unsupported cache version $($entry.Cache.CacheVersion) in $($entry.Name): $($entry.Path)"
                    return
                }
            }

            # Extract metadata
            $baselineMeta = @{
                Domain  = if ($baselineCache.Domain) { $baselineCache.Domain } else { 'Unknown' }
                Date    = if ($baselineCache.ExportDate) { try { ([datetime]::Parse($baselineCache.ExportDate)).ToString('yyyy-MM-dd HH:mm') } catch { $baselineCache.ExportDate } } else { 'Unknown' }
                Version = if ($baselineCache.adPEASVersion) { $baselineCache.adPEASVersion } else { 'Unknown' }
                Count   = if ($baselineCache.FindingCount) { $baselineCache.FindingCount } else { 0 }
            }
            $currentMeta = @{
                Domain  = if ($currentCache.Domain) { $currentCache.Domain } else { 'Unknown' }
                Date    = if ($currentCache.ExportDate) { try { ([datetime]::Parse($currentCache.ExportDate)).ToString('yyyy-MM-dd HH:mm') } catch { $currentCache.ExportDate } } else { 'Unknown' }
                Version = if ($currentCache.adPEASVersion) { $currentCache.adPEASVersion } else { 'Unknown' }
                Count   = if ($currentCache.FindingCount) { $currentCache.FindingCount } else { 0 }
            }

            # Cross-domain warning
            if ($baselineMeta.Domain -ne 'Unknown' -and $currentMeta.Domain -ne 'Unknown' -and
                $baselineMeta.Domain -ne $currentMeta.Domain) {
                Write-Warning "[Compare-adPEASReport] Domain mismatch: Baseline='$($baselineMeta.Domain)' vs Current='$($currentMeta.Domain)'"
                Write-Warning "[Compare-adPEASReport] Comparison results may not be meaningful across different domains"
            }

            # 2. Import findings from already-parsed caches (avoids re-reading files)
            $baselineFindings = Import-FindingsFromCache -Cache $baselineCache
            $currentFindings = Import-FindingsFromCache -Cache $currentCache

            # Filter to comparable findings only (skip structural elements)
            $baselineComparable = @($baselineFindings | Where-Object { $_.Type -notin @('Header', 'SubHeader') })
            $currentComparable = @($currentFindings | Where-Object { $_.Type -notin @('Header', 'SubHeader') })

            # 3. Build identity maps
            $baselineMap = @{}
            foreach ($f in $baselineComparable) {
                $id = Get-FindingIdentity -Finding $f
                if ($id) { $baselineMap[$id] = $f }
            }
            $currentMap = @{}
            foreach ($f in $currentComparable) {
                $id = Get-FindingIdentity -Finding $f
                if ($id) { $currentMap[$id] = $f }
            }

            # 4. Compute diff
            $added = [System.Collections.ArrayList]::new()
            $removed = [System.Collections.ArrayList]::new()
            $changed = [System.Collections.ArrayList]::new()
            $unchangedCount = 0

            # Find added and changed
            foreach ($id in $currentMap.Keys) {
                if (-not $baselineMap.ContainsKey($id)) {
                    [void]$added.Add($currentMap[$id])
                } else {
                    $bf = $baselineMap[$id]
                    $cf = $currentMap[$id]
                    $severityChanged = $bf.Severity -ne $cf.Severity
                    # For KeyValue findings, also detect value changes
                    $valueChanged = $cf.Type -eq 'KeyValue' -and $bf.Value -ne $cf.Value
                    # For Line findings, detect text changes (numbers were normalized in identity)
                    $textChanged = $cf.Type -eq 'Line' -and $bf.Text -ne $cf.Text
                    if ($severityChanged -or $valueChanged -or $textChanged) {
                        [void]$changed.Add(@{ Baseline = $bf; Current = $cf; Identity = $id })
                    } else {
                        $unchangedCount++
                    }
                }
            }

            # Find removed
            foreach ($id in $baselineMap.Keys) {
                if (-not $currentMap.ContainsKey($id)) {
                    [void]$removed.Add($baselineMap[$id])
                }
            }

            # 5. Detect partial scans
            $baselineCategories = @($baselineComparable | ForEach-Object { $_.Category } | Select-Object -Unique | Sort-Object)
            $currentCategories = @($currentComparable | ForEach-Object { $_.Category } | Select-Object -Unique | Sort-Object)
            $onlyInBaseline = @($baselineCategories | Where-Object { $_ -notin $currentCategories })
            $onlyInCurrent = @($currentCategories | Where-Object { $_ -notin $baselineCategories })

            # 6. Output report
            Show-Output -Class Info -Value "adPEAS Report Comparison" -NoCollect

            Show-Line "Baseline: $(Split-Path -Leaf $Baseline) ($($baselineMeta.Date), $($baselineMeta.Domain), adPEAS $($baselineMeta.Version))" -Class Note -NoCollect
            Show-Line "Current:  $(Split-Path -Leaf $Current) ($($currentMeta.Date), $($currentMeta.Domain), adPEAS $($currentMeta.Version))" -Class Note -NoCollect

            # Summary
            Show-Output -Class Info -Value "Comparison Summary" -NoCollect

            Show-Output -Key "New findings (added)" -Value "$($added.Count)" -Class $(if ($added.Count -gt 0) { 'Finding' } else { 'Note' }) -NoCollect
            Show-Output -Key "Remediated findings (removed)" -Value "$($removed.Count)" -Class $(if ($removed.Count -gt 0) { 'Secure' } else { 'Note' }) -NoCollect
            Show-Output -Key "Changed findings" -Value "$($changed.Count)" -Class $(if ($changed.Count -gt 0) { 'Hint' } else { 'Note' }) -NoCollect
            Show-Output -Key "Unchanged findings" -Value "$unchangedCount" -Class Note -NoCollect
            Show-Output -Key "Total baseline findings" -Value "$($baselineComparable.Count)" -Class Note -NoCollect
            Show-Output -Key "Total current findings" -Value "$($currentComparable.Count)" -Class Note -NoCollect

            # New findings detail
            if ($added.Count -gt 0) {
                Show-Output -Class Info -Value "New Findings ($($added.Count))" -NoCollect

                $addedGroups = $added | Group-Object -Property { "$($_.Category) > $($_.CheckTitle)" }
                foreach ($group in ($addedGroups | Sort-Object Name)) {
                    Show-SubHeader $group.Name -NoCollect
                    foreach ($f in $group.Group) {
                        $displayName = Get-FindingDisplayName -Finding $f
                        Show-Line "$displayName ($($f.Severity))" -Class Finding -NoCollect
                    }
                }
            }

            # Remediated findings detail
            if ($removed.Count -gt 0) {
                Show-Output -Class Info -Value "Remediated Findings ($($removed.Count))" -NoCollect

                $removedGroups = $removed | Group-Object -Property { "$($_.Category) > $($_.CheckTitle)" }
                foreach ($group in ($removedGroups | Sort-Object Name)) {
                    Show-SubHeader $group.Name -NoCollect
                    foreach ($f in $group.Group) {
                        $displayName = Get-FindingDisplayName -Finding $f
                        Show-Line "$displayName (was: $($f.Severity))" -Class Secure -NoCollect
                    }
                }
            }

            # Changed findings detail
            if ($changed.Count -gt 0) {
                Show-Output -Class Info -Value "Changed Findings ($($changed.Count))" -NoCollect

                $changedGroups = $changed | Group-Object -Property { "$($_.Current.Category) > $($_.Current.CheckTitle)" }
                foreach ($group in ($changedGroups | Sort-Object Name)) {
                    Show-SubHeader $group.Name -NoCollect
                    foreach ($entry in $group.Group) {
                        $displayName = Get-FindingDisplayName -Finding $entry.Current
                        # Build change description based on what changed
                        $changeDesc = @()
                        if ($entry.Baseline.Severity -ne $entry.Current.Severity) {
                            $changeDesc += "severity: $($entry.Baseline.Severity) -> $($entry.Current.Severity)"
                        }
                        if ($entry.Current.Type -eq 'KeyValue' -and $entry.Baseline.Value -ne $entry.Current.Value) {
                            $changeDesc += "value: $($entry.Baseline.Value) -> $($entry.Current.Value)"
                        }
                        if ($entry.Current.Type -eq 'Line' -and $entry.Baseline.Text -ne $entry.Current.Text) {
                            $changeDesc += "text changed"
                        }
                        $changeText = $changeDesc -join ', '
                        Show-Line "$displayName ($changeText)" -Class Hint -NoCollect
                    }
                }
            }

            # Partial scan notice
            if ($onlyInBaseline.Count -gt 0 -or $onlyInCurrent.Count -gt 0) {
                Show-Output -Class Info -Value "Partial Scan Notice" -NoCollect

                if ($onlyInBaseline.Count -gt 0) {
                    Show-Line "Categories only in baseline: $($onlyInBaseline -join ', ')" -Class Hint -NoCollect
                }
                if ($onlyInCurrent.Count -gt 0) {
                    Show-Line "Categories only in current: $($onlyInCurrent -join ', ')" -Class Hint -NoCollect
                }
                Show-Line "Findings in non-overlapping categories appear as added/removed but may reflect scan scope differences" -Class Note -NoCollect
            }

            # File output notification
            if ($OutputPath) {
                Show-Line "Diff report saved to: $textPath" -Class Hint -NoCollect
            }

        } finally {
            $Script:adPEAS_Outputfile = $previousOutputfile
            $Script:adPEAS_OutputColor = $previousOutputColor
        }
    }

    end {
        Write-Log "[Compare-adPEASReport] Comparison completed"
    }
}

<#
.SYNOPSIS
    Computes a stable identity string for a finding to enable cross-scan matching.
.DESCRIPTION
    Generates a unique key from Category, CheckName, and type-specific identifiers
    (distinguishedName, sAMAccountName, Key, or Text) to match findings across scans.
#>
function Get-FindingIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Finding
    )

    $prefix = "$($Finding.Category)|$($Finding.CheckName)"

    switch ($Finding.Type) {
        'Object' {
            $op = $Finding.Object
            if (-not $op) { $op = $Finding.ObjectProperties }

            $oid = $null
            if ($op) {
                # Priority: distinguishedName > sAMAccountName > Name > cn > displayName
                if ($op.distinguishedName) { $oid = $op.distinguishedName }
                elseif ($op.sAMAccountName) { $oid = $op.sAMAccountName }
                elseif ($op.Name) { $oid = $op.Name }
                elseif ($op.cn) { $oid = $op.cn }
                elseif ($op.displayName) { $oid = $op.displayName }
                # For synthetic objects (ACLs, permissions) try composite key
                elseif ($op.PrincipalName -and $op.TargetObject) { $oid = "$($op.PrincipalName)->$($op.TargetObject)" }
                elseif ($op.PrincipalName) { $oid = $op.PrincipalName }
                # For credential findings (GPPCredential, SYSVOLCredential) use userName+filePath
                elseif ($op.userName -and $op.filePath) { $oid = "$($op.userName)|$($op.filePath)" }
                elseif ($op.filePath) { $oid = $op.filePath }
                elseif ($op.credentialType) { $oid = $op.credentialType }
            }
            if (-not $oid) { $oid = 'unknown' }
            return "$prefix|Object|$oid"
        }
        'KeyValue' {
            return "$prefix|KV|$($Finding.Key)"
        }
        'Line' {
            # Normalize dynamic numbers so count changes don't create phantom diffs
            # e.g., "Found 5 accounts" and "Found 3 accounts" match to same identity
            $normalizedText = $Finding.Text -replace '\d+', '#'
            return "$prefix|Line|$normalizedText"
        }
        default {
            return $null
        }
    }
}

<#
.SYNOPSIS
    Extracts a human-readable display name from a finding for diff output.
#>
function Get-FindingDisplayName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Finding
    )

    switch ($Finding.Type) {
        'Object' {
            $op = $Finding.Object
            if (-not $op) { return '[Object]' }

            if ($op.sAMAccountName) { return $op.sAMAccountName }
            if ($op.Name) { return $op.Name }
            if ($op.cn) { return $op.cn }
            if ($op.displayName) { return $op.displayName }
            if ($op.distinguishedName) {
                # Extract CN from DN for readability
                if ($op.distinguishedName -match '^CN=([^,]+)') { return $Matches[1] }
                return $op.distinguishedName
            }
            if ($op.PrincipalName) { return "$($op.PrincipalName) -> $($op.TargetObject)" }
            return '[Object]'
        }
        'KeyValue' {
            if ($Finding.Value) {
                return "$($Finding.Key): $($Finding.Value)"
            }
            return $Finding.Key
        }
        'Line' {
            return $Finding.Text
        }
        default {
            return $Finding.Text
        }
    }
}
