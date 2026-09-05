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
                # Drop one of adPEAS's own extensions if the caller typed it; anything else
                # is part of the name they chose. See Get-adPEASOutputBasePath.
                $resolvedBase = Get-adPEASOutputBasePath $resolvedBase
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

            # Extract metadata. Both sides of the date go through the invariant culture, for
            # the two reasons Import-FindingsFromCache already spells out for the same field:
            # Export-FindingsCache writes the round-trip format, which must not be read
            # through the reader's local culture, and a custom format string renders through
            # the local calendar - a host with a Thai or Saudi regional format put the
            # Buddhist or Hijri year in the report header while the file it came from said
            # something else.
            $baselineMeta = @{
                Domain  = if ($baselineCache.Domain) { $baselineCache.Domain } else { 'Unknown' }
                Date    = if ($baselineCache.ExportDate) { try { Format-adPEASDate ([datetime]::Parse($baselineCache.ExportDate, [System.Globalization.CultureInfo]::InvariantCulture)) 'yyyy-MM-dd HH:mm' } catch { $baselineCache.ExportDate } } else { 'Unknown' }
                Version = if ($baselineCache.adPEASVersion) { $baselineCache.adPEASVersion } else { 'Unknown' }
                Count   = if ($baselineCache.FindingCount) { $baselineCache.FindingCount } else { 0 }
            }
            $currentMeta = @{
                Domain  = if ($currentCache.Domain) { $currentCache.Domain } else { 'Unknown' }
                Date    = if ($currentCache.ExportDate) { try { Format-adPEASDate ([datetime]::Parse($currentCache.ExportDate, [System.Globalization.CultureInfo]::InvariantCulture)) 'yyyy-MM-dd HH:mm' } catch { $currentCache.ExportDate } } else { 'Unknown' }
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

            # Filter to comparable findings only
            # Skip structural elements (Header, SubHeader) and internal artifacts (Category = Unknown:
            # disclaimers, connection messages, merge notes, progress indicators)
            $baselineComparable = @($baselineFindings | Where-Object {
                $_.Type -notin @('Header', 'SubHeader') -and $_.Category -ne 'Unknown'
            })
            $currentComparable = @($currentFindings | Where-Object {
                $_.Type -notin @('Header', 'SubHeader') -and $_.Category -ne 'Unknown'
            })

            # 3. + 4. Diff by identity. Get-FindingSetDiff buckets by identity instead of
            # keying a single-value map, so a colliding identity (normalized Line text, the
            # 'unknown' Object fallback) never silently drops a finding - see its own
            # comment header for the matching rules.
            $diffResult = Get-FindingSetDiff -BaselineFindings $baselineComparable -CurrentFindings $currentComparable
            $added = $diffResult.Added
            $removed = $diffResult.Removed
            $changed = $diffResult.Changed
            $unchangedCount = $diffResult.UnchangedCount

            # 5. Detect scope differences (categories only in one scan)
            $baselineCategories = @($baselineComparable | ForEach-Object { $_.Category } | Select-Object -Unique | Sort-Object)
            $currentCategories = @($currentComparable | ForEach-Object { $_.Category } | Select-Object -Unique | Sort-Object)
            $onlyInBaseline = @($baselineCategories | Where-Object { $_ -notin $currentCategories })
            $onlyInCurrent = @($currentCategories | Where-Object { $_ -notin $baselineCategories })
            $sharedCategories = @($baselineCategories | Where-Object { $_ -in $currentCategories })

            # Separate scope-only findings from real added/removed
            # Findings in non-overlapping categories are NOT real changes - they reflect
            # different scan scopes (e.g., one scan ran -Module Accounts, the other ran all modules)
            $scopeOnlyBaseline = @()
            $scopeOnlyCurrent = @()
            if ($onlyInBaseline.Count -gt 0) {
                $scopeOnlyBaseline = @($removed | Where-Object { $_.Category -in $onlyInBaseline })
                $removed = [System.Collections.ArrayList]@($removed | Where-Object { $_.Category -notin $onlyInBaseline })
            }
            if ($onlyInCurrent.Count -gt 0) {
                $scopeOnlyCurrent = @($added | Where-Object { $_.Category -in $onlyInCurrent })
                $added = [System.Collections.ArrayList]@($added | Where-Object { $_.Category -notin $onlyInCurrent })
            }

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
            Show-Output -Key "Compared categories" -Value "$($sharedCategories.Count) ($($sharedCategories -join ', '))" -Class Note -NoCollect

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

            # Scope differences (different scan modules between baseline and current)
            if ($onlyInBaseline.Count -gt 0 -or $onlyInCurrent.Count -gt 0) {
                Show-Output -Class Info -Value "Scan Scope Differences" -NoCollect
                Show-Line "The following categories were not scanned in both reports and are excluded from the comparison above." -Class Note -NoCollect

                if ($onlyInCurrent.Count -gt 0) {
                    Show-Line "Only in current scan: $($onlyInCurrent -join ', ') ($($scopeOnlyCurrent.Count) finding(s) not compared)" -Class Hint -NoCollect
                }
                if ($onlyInBaseline.Count -gt 0) {
                    Show-Line "Only in baseline scan: $($onlyInBaseline -join ', ') ($($scopeOnlyBaseline.Count) finding(s) not compared)" -Class Hint -NoCollect
                }
            }

            # Generate HTML diff report
            if ($OutputPath) {
                $htmlPath = "$resolvedBase.html"
                try {
                    Export-DiffHtmlReport -OutputPath $htmlPath `
                        -BaselineMeta $baselineMeta -CurrentMeta $currentMeta `
                        -BaselineFile (Split-Path -Leaf $Baseline) -CurrentFile (Split-Path -Leaf $Current) `
                        -Added $added -Removed $removed -Changed $changed `
                        -UnchangedCount $unchangedCount `
                        -SharedCategories $sharedCategories `
                        -OnlyInBaseline $onlyInBaseline -OnlyInCurrent $onlyInCurrent `
                        -ScopeOnlyBaseline $scopeOnlyBaseline -ScopeOnlyCurrent $scopeOnlyCurrent
                    Show-Line "HTML diff report saved to: $htmlPath" -Class Hint -NoCollect
                } catch {
                    Write-Warning "[Compare-adPEASReport] Error generating HTML diff report: $_"
                }
            }

            # File output notification
            if ($OutputPath) {
                Show-Line "Text diff report saved to: $textPath" -Class Hint -NoCollect
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
    Diffs two sets of findings by identity, without ever silently dropping one.
.DESCRIPTION
    Get-FindingIdentity is not guaranteed unique: normalized Line text and the 'unknown'
    Object fallback can both legitimately collide, so two or more distinct findings can
    share one identity. A single-value map (identity -> last finding wins) would silently
    drop every finding but the last one under a collision - the comparison would look
    clean while actually missing data.

    This buckets both sides by identity (a list per identity, not one slot), then within
    each bucket:
      1. Matches byte-for-byte identical findings first (Get-FindingComparableSignature),
         order-independent, and counts them unchanged. Two findings with the same
         severity and the same Value/Text (as applicable) are indistinguishable, so which
         one is "the same one" from the scan does not matter.
      2. Pairs whatever is left over positionally and reports each pair as changed.
      3. Whatever still does not have a partner is a real add or remove, not a
         differently-ordered match - a bucket that grew has new findings in it, one that
         shrank lost some.

    A bucket of size 1 on each side degenerates to exactly the old single-value
    comparison, so this only changes behaviour when an identity actually collides.
.PARAMETER BaselineFindings
    Findings from the older scan (already filtered to comparable types).
.PARAMETER CurrentFindings
    Findings from the newer scan (already filtered to comparable types).
.OUTPUTS
    A PSCustomObject with Added, Removed, Changed (each an ArrayList) and UnchangedCount,
    matching the shape Compare-adPEASReport and Export-DiffHtmlReport already expect.
#>
function Get-FindingSetDiff {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        [array]$BaselineFindings,

        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        [array]$CurrentFindings
    )

    # Bucket both sides by identity, preserving scan order within each bucket.
    $baselineBuckets = @{}
    foreach ($f in $BaselineFindings) {
        $id = Get-FindingIdentity -Finding $f
        if (-not $id) { continue }
        if (-not $baselineBuckets.ContainsKey($id)) { $baselineBuckets[$id] = [System.Collections.ArrayList]::new() }
        [void]$baselineBuckets[$id].Add($f)
    }
    $currentBuckets = @{}
    foreach ($f in $CurrentFindings) {
        $id = Get-FindingIdentity -Finding $f
        if (-not $id) { continue }
        if (-not $currentBuckets.ContainsKey($id)) { $currentBuckets[$id] = [System.Collections.ArrayList]::new() }
        [void]$currentBuckets[$id].Add($f)
    }

    $added = [System.Collections.ArrayList]::new()
    $removed = [System.Collections.ArrayList]::new()
    $changed = [System.Collections.ArrayList]::new()
    $unchangedCount = 0

    $allIdentities = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($id in $baselineBuckets.Keys) { [void]$allIdentities.Add($id) }
    foreach ($id in $currentBuckets.Keys) { [void]$allIdentities.Add($id) }

    foreach ($id in $allIdentities) {
        $bList = if ($baselineBuckets.ContainsKey($id)) { $baselineBuckets[$id] } else { [System.Collections.ArrayList]::new() }
        $cList = if ($currentBuckets.ContainsKey($id)) { $currentBuckets[$id] } else { [System.Collections.ArrayList]::new() }

        # Phase 1: exact-content matches, order-independent. Consumes matched items from
        # a per-signature copy of the baseline list so a repeat signature on the current
        # side (e.g. three identical 'unknown' findings) matches at most as many times as
        # the baseline actually has.
        $bySignature = @{}
        foreach ($f in $bList) {
            $sig = Get-FindingComparableSignature -Finding $f
            if (-not $bySignature.ContainsKey($sig)) { $bySignature[$sig] = [System.Collections.ArrayList]::new() }
            [void]$bySignature[$sig].Add($f)
        }
        $cRemaining = [System.Collections.ArrayList]::new()
        foreach ($f in $cList) {
            $sig = Get-FindingComparableSignature -Finding $f
            if ($bySignature.ContainsKey($sig) -and $bySignature[$sig].Count -gt 0) {
                $unchangedCount++
                $bySignature[$sig].RemoveAt(0)
            } else {
                [void]$cRemaining.Add($f)
            }
        }
        $bRemaining = [System.Collections.ArrayList]::new()
        foreach ($sig in $bySignature.Keys) {
            foreach ($f in $bySignature[$sig]) { [void]$bRemaining.Add($f) }
        }

        # Phase 2: pair whatever is left positionally and call it changed; a size mismatch
        # after that is a real add or remove, not just a differently-ordered match.
        $pairCount = [Math]::Min($bRemaining.Count, $cRemaining.Count)
        for ($i = 0; $i -lt $pairCount; $i++) {
            [void]$changed.Add(@{ Baseline = $bRemaining[$i]; Current = $cRemaining[$i]; Identity = $id })
        }
        for ($i = $pairCount; $i -lt $cRemaining.Count; $i++) { [void]$added.Add($cRemaining[$i]) }
        for ($i = $pairCount; $i -lt $bRemaining.Count; $i++) { [void]$removed.Add($bRemaining[$i]) }
    }

    return [PSCustomObject]@{
        Added          = $added
        Removed        = $removed
        Changed        = $changed
        UnchangedCount = $unchangedCount
    }
}

<#
.SYNOPSIS
    A signature that says whether two same-identity findings are indistinguishable.
.DESCRIPTION
    Severity plus the one extra field Compare-adPEASReport already treats as "this
    finding changed" per type - Value for KeyValue, Text for Line, nothing extra for
    Object (an Object finding's only change dimension is Severity; its content lives in
    the identity already). Two findings with the same signature cannot be told apart by
    anything the diff reports, so matching them regardless of scan order is correct, not
    just convenient.
#>
function Get-FindingComparableSignature {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Finding
    )

    $extra = switch ($Finding.Type) {
        'KeyValue' { $Finding.Value }
        'Line'     { $Finding.Text }
        default    { '' }
    }
    return "$($Finding.Severity)|$extra"
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
                # For domain info objects, use _adPEASObjectType as stable identity
                elseif ($op._adPEASObjectType) { $oid = $op._adPEASObjectType }
                # Last resort: use first non-internal property value
                else {
                    foreach ($p in $op.PSObject.Properties) {
                        if ($p.Name -notin @('_adPEASObjectType', '_adPEASContext', '_Severity', '_Risk') -and $p.Value) {
                            $oid = "$($p.Name)=$($p.Value)"; break
                        }
                    }
                }
            }
            if (-not $oid) { $oid = 'unknown' }
            return "$prefix|Object|$oid"
        }
        'KeyValue' {
            return "$prefix|KV|$($Finding.Key)"
        }
        'Line' {
            # Normalize dynamic numbers so count changes don't create phantom diffs, e.g.
            # "Found 5 accounts" and "Found 3 accounts" match to the same identity. Digits
            # inside a quoted span are left alone: that is where adPEAS puts account and
            # computer names ("Credential found for User 'svc01'" must stay distinct from
            # '...svc02'), and a name is not a count. Get-FindingSetDiff below still
            # tolerates a remaining collision without dropping a finding - this just makes
            # one less likely.
            $normalizedText = [regex]::Replace($Finding.Text, "'[^']*'|`"[^`"]*`"|\d+", {
                param($m)
                if ($m.Value -match '^\d+$') { '#' } else { $m.Value }
            })
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
            # Domain info objects: use _adPEASObjectType or first meaningful property
            if ($op._adPEASObjectType) { return $op._adPEASObjectType }
            foreach ($p in $op.PSObject.Properties) {
                if ($p.Name -notin @('_adPEASObjectType', '_adPEASContext', '_Severity', '_Risk') -and $p.Value) {
                    $val = [string]$p.Value
                    if ($val.Length -gt 60) { $val = $val.Substring(0, 57) + '...' }
                    return $val
                }
            }
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

<#
.SYNOPSIS
    Generates a standalone HTML diff report from comparison results.
.DESCRIPTION
    Creates a self-contained HTML file with embedded CSS and JS that visualizes
    the differences between two adPEAS scans. Uses the same color scheme and
    theme system as the main adPEAS HTML report.
#>
function Export-DiffHtmlReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$OutputPath,

        [hashtable]$BaselineMeta,
        [hashtable]$CurrentMeta,
        [string]$BaselineFile,
        [string]$CurrentFile,
        $Added,
        $Removed,
        $Changed,
        [int]$UnchangedCount,
        [string[]]$SharedCategories,
        [string[]]$OnlyInBaseline,
        [string[]]$OnlyInCurrent,
        $ScopeOnlyBaseline,
        $ScopeOnlyCurrent
    )

    # Load diff template. Throws rather than warning and returning: the only caller wraps
    # this in try/catch and announces success on the line right after the call, so a quiet
    # return told the operator a diff report had been saved that was never written.
    # Export-HTMLReport reports a missing template the same way.
    $html = Get-DiffHTMLTemplate
    if (-not $html) {
        throw "[Export-DiffHtmlReport] Failed to load diff HTML template"
    }

    # Build diff sections HTML
    $sectionsHtml = [System.Text.StringBuilder]::new()

    # New Findings section
    if ($Added.Count -gt 0) {
        [void]$sectionsHtml.Append((Build-DiffSectionHtml -Title "New Findings" -Findings $Added -SectionType 'new'))
    }

    # Remediated Findings section
    if ($Removed.Count -gt 0) {
        [void]$sectionsHtml.Append((Build-DiffSectionHtml -Title "Remediated Findings" -Findings $Removed -SectionType 'remediated'))
    }

    # Changed Findings section
    if ($Changed.Count -gt 0) {
        [void]$sectionsHtml.Append((Build-DiffChangedSectionHtml -Title "Changed Findings" -ChangedEntries $Changed))
    }

    # Scope Differences section
    if ($OnlyInBaseline.Count -gt 0 -or $OnlyInCurrent.Count -gt 0) {
        $scopeHtml = [System.Text.StringBuilder]::new()
        [void]$scopeHtml.AppendLine('<section class="section">')
        [void]$scopeHtml.AppendLine('  <div class="section-header" onclick="toggleSection(this)">')
        [void]$scopeHtml.AppendLine('    <div class="section-title">Scan Scope Differences</div>')
        [void]$scopeHtml.AppendLine('    <span class="section-toggle">&#9660;</span>')
        [void]$scopeHtml.AppendLine('  </div>')
        [void]$scopeHtml.AppendLine('  <div class="section-content">')
        [void]$scopeHtml.AppendLine('    <div class="scope-info">')
        [void]$scopeHtml.AppendLine('      The following categories were not scanned in both reports and are excluded from the comparison above.<br>')
        if ($OnlyInCurrent.Count -gt 0) {
            $cats = (ConvertTo-HtmlEncode ($OnlyInCurrent -join ', '))
            [void]$scopeHtml.AppendLine("      <strong>Only in current scan:</strong> $cats ($($ScopeOnlyCurrent.Count) finding(s) not compared)<br>")
        }
        if ($OnlyInBaseline.Count -gt 0) {
            $cats = (ConvertTo-HtmlEncode ($OnlyInBaseline -join ', '))
            [void]$scopeHtml.AppendLine("      <strong>Only in baseline scan:</strong> $cats ($($ScopeOnlyBaseline.Count) finding(s) not compared)")
        }
        [void]$scopeHtml.AppendLine('    </div>')
        [void]$scopeHtml.AppendLine('  </div>')
        [void]$scopeHtml.AppendLine('</section>')
        [void]$sectionsHtml.Append($scopeHtml.ToString())
    }

    # Empty state
    if ($Added.Count -eq 0 -and $Removed.Count -eq 0 -and $Changed.Count -eq 0 -and
        $OnlyInBaseline.Count -eq 0 -and $OnlyInCurrent.Count -eq 0) {
        [void]$sectionsHtml.AppendLine('<div class="empty-state">No differences found between the two scans.</div>')
    }

    # Build info strings
    $baselineInfo = "$BaselineFile ($($BaselineMeta.Date), $($BaselineMeta.Domain), adPEAS $($BaselineMeta.Version))"
    $currentInfo = "$CurrentFile ($($CurrentMeta.Date), $($CurrentMeta.Domain), adPEAS $($CurrentMeta.Version))"
    $comparedCats = if ($SharedCategories.Count -gt 0) { "$($SharedCategories.Count) ($($SharedCategories -join ', '))" } else { "None" }
    $version = if ($Script:adPEASVersion) { $Script:adPEASVersion } else { "2.0.0" }
    $generatedDate = (Format-adPEASDate (Get-Date) 'yyyy-MM-dd HH:mm:ss')
    $domain = $BaselineMeta.Domain

    # Replace placeholders
    # Literal .Replace() for every token - a data value containing '$' + digits would otherwise be
    # read as a regex capture-group reference by -replace and overflow Int32.MaxValue (see the
    # detailed note in Export-HTMLReport.ps1). HTML-encoding does not escape '$'.
    $html = $html.Replace('{{DOMAIN}}', [string](ConvertTo-HtmlEncode $domain))
    $html = $html.Replace('{{NEW_COUNT}}', [string]$Added.Count)
    $html = $html.Replace('{{REMEDIATED_COUNT}}', [string]$Removed.Count)
    $html = $html.Replace('{{CHANGED_COUNT}}', [string]$Changed.Count)
    $html = $html.Replace('{{UNCHANGED_COUNT}}', [string]$UnchangedCount)
    $html = $html.Replace('{{BASELINE_INFO}}', [string](ConvertTo-HtmlEncode $baselineInfo))
    $html = $html.Replace('{{CURRENT_INFO}}', [string](ConvertTo-HtmlEncode $currentInfo))
    $html = $html.Replace('{{COMPARED_CATEGORIES}}', [string](ConvertTo-HtmlEncode $comparedCats))
    $html = $html.Replace('{{GENERATED}}', [string]$generatedDate)
    $html = $html.Replace('{{VERSION}}', [string]$version)
    $html = $html.Replace('{{DIFF_SECTIONS}}', $sectionsHtml.ToString())

    # Write file (UTF-8 without BOM, same as Export-HTMLReport)
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    $resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
    [System.IO.File]::WriteAllText($resolvedPath, $html, $utf8NoBom)

    Write-Log "[Export-DiffHtmlReport] HTML diff report saved to: $OutputPath"
}

<#
.SYNOPSIS
    Builds an HTML section with finding items for the diff report.
.PARAMETER Title
    Section title (e.g., "New Findings", "Remediated Findings").
.PARAMETER Findings
    Array of finding objects to render.
.PARAMETER SectionType
    Visual style: 'new' (red badge), 'remediated' (blue badge).
#>
function Build-DiffSectionHtml {
    [CmdletBinding()]
    param(
        [string]$Title,
        [array]$Findings,
        [string]$SectionType
    )

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<section class="section">')
    [void]$sb.AppendLine("  <div class=`"section-header`" onclick=`"toggleSection(this)`">")
    $escapedTitle = ConvertTo-HtmlEncode $Title
    [void]$sb.AppendLine("    <div class=`"section-title`">$escapedTitle <span class=`"section-count`">$($Findings.Count)</span></div>")
    [void]$sb.AppendLine('    <span class="section-toggle">&#9660;</span>')
    [void]$sb.AppendLine('  </div>')
    [void]$sb.AppendLine('  <div class="section-content">')

    # Group by Category > CheckTitle for readability
    $groups = $Findings | Group-Object -Property { "$($_.Category) > $($_.CheckTitle)" }
    foreach ($group in ($groups | Sort-Object Name)) {
        foreach ($f in $group.Group) {
            $displayName = ConvertTo-HtmlEncode (Get-FindingDisplayName -Finding $f)
            $severity = if ($f.Severity) { $f.Severity.ToLower() } else { 'standard' }
            $category = ConvertTo-HtmlEncode $group.Name

            $badgeClass = if ($SectionType -eq 'new') { 'badge-new' } else { 'badge-fixed' }
            $badgeText = if ($SectionType -eq 'new') { 'NEW' } else { 'FIXED' }

            [void]$sb.AppendLine("    <div class=`"diff-item`">")
            [void]$sb.AppendLine("      <div class=`"severity-bar $severity`"></div>")
            [void]$sb.AppendLine("      <div class=`"diff-item-name`">$displayName</div>")
            [void]$sb.AppendLine("      <div class=`"diff-item-meta`">$category</div>")
            [void]$sb.AppendLine("      <span class=`"diff-item-badge $badgeClass`">$badgeText</span>")
            [void]$sb.AppendLine('    </div>')
        }
    }

    [void]$sb.AppendLine('  </div>')
    [void]$sb.AppendLine('</section>')
    return $sb.ToString()
}

<#
.SYNOPSIS
    Builds an HTML section for changed findings with before/after details.
#>
function Build-DiffChangedSectionHtml {
    [CmdletBinding()]
    param(
        [string]$Title,
        [array]$ChangedEntries
    )

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<section class="section">')
    [void]$sb.AppendLine("  <div class=`"section-header`" onclick=`"toggleSection(this)`">")
    $escapedTitle = ConvertTo-HtmlEncode $Title
    [void]$sb.AppendLine("    <div class=`"section-title`">$escapedTitle <span class=`"section-count`">$($ChangedEntries.Count)</span></div>")
    [void]$sb.AppendLine('    <span class="section-toggle">&#9660;</span>')
    [void]$sb.AppendLine('  </div>')
    [void]$sb.AppendLine('  <div class="section-content">')

    $groups = $ChangedEntries | Group-Object -Property { "$($_.Current.Category) > $($_.Current.CheckTitle)" }
    foreach ($group in ($groups | Sort-Object Name)) {
        foreach ($entry in $group.Group) {
            $displayName = ConvertTo-HtmlEncode (Get-FindingDisplayName -Finding $entry.Current)
            $severity = if ($entry.Current.Severity) { $entry.Current.Severity.ToLower() } else { 'standard' }
            $category = ConvertTo-HtmlEncode $group.Name

            # Build change description
            $changeDesc = @()
            if ($entry.Baseline.Severity -ne $entry.Current.Severity) {
                $changeDesc += "$($entry.Baseline.Severity) &#8594; $($entry.Current.Severity)"
            }
            if ($entry.Current.Type -eq 'KeyValue' -and $entry.Baseline.Value -ne $entry.Current.Value) {
                $oldVal = ConvertTo-HtmlEncode ([string]$entry.Baseline.Value)
                $newVal = ConvertTo-HtmlEncode ([string]$entry.Current.Value)
                if ($oldVal.Length -gt 40) { $oldVal = $oldVal.Substring(0, 37) + '...' }
                if ($newVal.Length -gt 40) { $newVal = $newVal.Substring(0, 37) + '...' }
                $changeDesc += "$oldVal &#8594; $newVal"
            }
            if ($entry.Current.Type -eq 'Line' -and $entry.Baseline.Text -ne $entry.Current.Text) {
                $changeDesc += "text changed"
            }
            $changeHtml = $changeDesc -join ', '

            [void]$sb.AppendLine("    <div class=`"diff-item`">")
            [void]$sb.AppendLine("      <div class=`"severity-bar $severity`"></div>")
            [void]$sb.AppendLine("      <div class=`"diff-item-name`">$displayName <span style=`"font-size:12px;color:var(--text-muted)`">($changeHtml)</span></div>")
            [void]$sb.AppendLine("      <div class=`"diff-item-meta`">$category</div>")
            [void]$sb.AppendLine('      <span class="diff-item-badge badge-changed">CHANGED</span>')
            [void]$sb.AppendLine('    </div>')
        }
    }

    [void]$sb.AppendLine('  </div>')
    [void]$sb.AppendLine('</section>')
    return $sb.ToString()
}

<#
.SYNOPSIS
    Loads the diff HTML template from template files or embedded content.
.DESCRIPTION
    Tries to load from templates/diff-template.html first (development mode),
    falls back to embedded template in built standalone version.
#>
function Get-DiffHTMLTemplate {
    # Try to load from template files (development mode)
    # The guard on .Path keeps the third step reachable - Split-Path -Parent throws on a
    # null argument. Same fix as in Get-HTMLTemplate; see the note there.
    $scriptDir = $PSScriptRoot
    if (-not $scriptDir -and $MyInvocation.MyCommand.Path) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
    if (-not $scriptDir) { $scriptDir = (Get-Location).Path }

    # In dev mode, template is next to Compare-adPEASReport.ps1 in templates/
    $templatesDir = Join-Path $scriptDir "templates"
    $diffTemplatePath = Join-Path $templatesDir "diff-template.html"

    if (Test-Path $diffTemplatePath) {
        Write-Log "[Get-DiffHTMLTemplate] Loading diff template from file (development mode)"
        return (Get-Content $diffTemplatePath -Raw -Encoding UTF8)
    }

    # Fallback: embedded template (replaced by Build-Release.ps1)
    # {{DIFF_TEMPLATE_EMBEDDED}}
    Write-Warning "[Get-DiffHTMLTemplate] Diff template not found at: $diffTemplatePath"
    return $null
}
