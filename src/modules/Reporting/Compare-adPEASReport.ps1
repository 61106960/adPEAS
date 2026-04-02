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

            # Filter to comparable findings only
            # Skip structural elements (Header, SubHeader) and internal artifacts (Category = Unknown:
            # disclaimers, connection messages, merge notes, progress indicators)
            $baselineComparable = @($baselineFindings | Where-Object {
                $_.Type -notin @('Header', 'SubHeader') -and $_.Category -ne 'Unknown'
            })
            $currentComparable = @($currentFindings | Where-Object {
                $_.Type -notin @('Header', 'SubHeader') -and $_.Category -ne 'Unknown'
            })

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

            # 5. Detect scope differences (categories only in one scan)
            $baselineCategories = @($baselineComparable | ForEach-Object { $_.Category } | Select-Object -Unique | Sort-Object)
            $currentCategories = @($currentComparable | ForEach-Object { $_.Category } | Select-Object -Unique | Sort-Object)
            $onlyInBaseline = @($baselineCategories | Where-Object { $_ -notin $currentCategories })
            $onlyInCurrent = @($currentCategories | Where-Object { $_ -notin $baselineCategories })
            $sharedCategories = @($baselineCategories | Where-Object { $_ -in $currentCategories })

            # Separate scope-only findings from real added/removed
            # Findings in non-overlapping categories are NOT real changes — they reflect
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

    # Load diff template
    $html = Get-DiffHTMLTemplate
    if (-not $html) {
        Write-Warning "[Export-DiffHtmlReport] Failed to load diff HTML template"
        return
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
    $generatedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $domain = $BaselineMeta.Domain

    # Replace placeholders
    $html = $html -replace '{{DOMAIN}}', (ConvertTo-HtmlEncode $domain)
    $html = $html -replace '{{NEW_COUNT}}', $Added.Count
    $html = $html -replace '{{REMEDIATED_COUNT}}', $Removed.Count
    $html = $html -replace '{{CHANGED_COUNT}}', $Changed.Count
    $html = $html -replace '{{UNCHANGED_COUNT}}', $UnchangedCount
    $html = $html -replace '{{BASELINE_INFO}}', (ConvertTo-HtmlEncode $baselineInfo)
    $html = $html -replace '{{CURRENT_INFO}}', (ConvertTo-HtmlEncode $currentInfo)
    $html = $html -replace '{{COMPARED_CATEGORIES}}', (ConvertTo-HtmlEncode $comparedCats)
    $html = $html -replace '{{GENERATED}}', $generatedDate
    $html = $html -replace '{{VERSION}}', $version
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
    $scriptDir = $PSScriptRoot
    if (-not $scriptDir) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
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
