function Convert-adPEASReport {
    <#
    .SYNOPSIS
    Generates HTML and/or text reports from a previously exported JSON findings cache.

    .DESCRIPTION
    Converts an adPEAS JSON findings export into a fresh HTML, text, or JSON report without
    requiring an active LDAP connection. This enables:

    - Regenerating reports with a newer adPEAS version (updated finding definitions, scoring, templates)
    - Creating reports offline from previously collected scan data
    - Converting between output formats (e.g., JSON-only scan to HTML report)
    - Re-exporting JSON with updated version metadata (-Format JSON)

    The JSON file is produced automatically during any scan with -Outputfile parameter.

    .PARAMETER InputJson
    Path to the JSON findings cache file (produced by a previous adPEAS scan).

    .PARAMETER OutputPath
    Base path for output files (without extension). Files created:
    - .html (Interactive HTML report)
    - .txt  (Text report)
    - .json (Re-exported JSON with current adPEAS version metadata)

    .PARAMETER Format
    Output format: HTML, Text, JSON, or All (default: All).

    .PARAMETER License
    Optional path to a license JSON file for the report disclaimer.

    .PARAMETER NoColor
    Write plain text output without ANSI color codes.

    .EXAMPLE
    Convert-adPEASReport -InputJson ".\report.json" -OutputPath ".\new_report"

    .EXAMPLE
    Convert-adPEASReport -InputJson ".\report.json" -OutputPath ".\new_report" -Format HTML

    .EXAMPLE
    Convert-adPEASReport -InputJson ".\report.json" -OutputPath ".\new_report" -License ".\license.json"

    .NOTES
    Author: Alexander Sturz (@_61106960_)
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$InputJson,

        [Parameter(Mandatory=$true)]
        [string]$OutputPath,

        [Parameter(Mandatory=$false)]
        [ValidateSet('Text', 'HTML', 'JSON', 'All')]
        [string]$Format = 'All',

        [Parameter(Mandatory=$false)]
        [string]$License,

        [Parameter(Mandatory=$false)]
        [switch]$NoColor
    )

    begin {
        Write-Log "[Convert-adPEASReport] Starting offline report generation"
    }

    process {
        # Validate input file
        if (-not (Test-Path $InputJson)) {
            Write-Error "[Convert-adPEASReport] Input file not found: $InputJson"
            return
        }

        # Save current state for restoration
        $previousLDAPContext = $Script:LDAPContext
        $previousOutputfile = $Script:adPEAS_Outputfile
        $previousOutputColor = $Script:adPEAS_OutputColor
        $previousFindingsEnabled = $Script:adPEAS_FindingsCollectionEnabled
        $previousDisclaimer = $Script:adPEASDisclaimer

        try {
            # 1. Read and validate JSON (single read, reused for metadata and import)
            $rawJson = Get-Content -Path $InputJson -Raw -Encoding UTF8
            $cache = $rawJson | ConvertFrom-Json

            if (-not $cache.CacheVersion) {
                Write-Error "[Convert-adPEASReport] Invalid JSON file - missing CacheVersion field"
                return
            }
            if ($cache.CacheVersion -ne 1) {
                Write-Error "[Convert-adPEASReport] Unsupported cache version $($cache.CacheVersion) - expected 1"
                return
            }

            $sourceDomain = if ($cache.Domain -and $cache.Domain -ne 'Unknown') { $cache.Domain } else { 'Unknown' }
            $sourceServer = if ($cache.Server) { $cache.Server } else { 'Unknown' }
            $sourceVersion = if ($cache.adPEASVersion) { $cache.adPEASVersion } else { 'Unknown' }
            $sourceDate = if ($cache.ExportDate) { $cache.ExportDate } else { 'Unknown' }
            $findingCount = if ($cache.FindingCount) { $cache.FindingCount } else { 0 }

            # Display source info
            Show-Line "Source: $InputJson" -Class Note -NoCollect
            Show-Line "Domain: $sourceDomain, Server: $sourceServer" -Class Note -NoCollect
            Show-Line "Original scan: $sourceDate (adPEAS $sourceVersion)" -Class Note -NoCollect
            Show-Line "Findings: $findingCount" -Class Note -NoCollect
            $currentVersion = if ($Script:adPEASVersion) { $Script:adPEASVersion } else { '2.0.0' }
            if ($sourceVersion -ne $currentVersion -and $sourceVersion -ne 'Unknown') {
                Show-Line "Regenerating with adPEAS $currentVersion (updated definitions/scoring)" -Class Hint -NoCollect
            }

            # 2. Import findings from already-parsed cache (avoids re-reading the file)
            $findings = Import-FindingsFromCache -Cache $cache
            if (@($findings).Count -eq 0) {
                Write-Warning "[Convert-adPEASReport] No findings loaded from JSON file"
                return
            }

            # 3. Stub LDAPContext for report generation
            $Script:LDAPContext = @{
                Domain   = $sourceDomain
                Server   = $sourceServer
                DomainDN = $null
                Username = 'Offline'
            }

            # 4. Handle license / disclaimer
            # Priority: -License param > RuntimeLicense > EmbeddedLicense > Default disclaimer
            $_licJson = $null
            if ($License) {
                if (Test-Path $License) {
                    $_licJson = Get-Content -Path $License -Raw -Encoding UTF8
                } else {
                    Write-Warning "[Convert-adPEASReport] License file not found: $License"
                }
            } elseif ($Script:RuntimeLicense) {
                $_licJson = $Script:RuntimeLicense
            } elseif ($Script:EmbeddedLicense) {
                $_licJson = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Script:EmbeddedLicense))
            }

            $_licResult = if ($_licJson) { Test-adPEASLicense -LicenseJson $_licJson } else { $null }

            if ($_licResult -and $_licResult.IsValid -and -not $_licResult.Expired) {
                $Script:adPEASDisclaimer = $_licResult.Message
            } else {
                # Default disclaimer (XOR obfuscated) - same as Invoke-adPEAS
                $_lm="GCQlP2w+KTwjPjhsOy0/bCspIik+LTgpKGw5PyUiK2wtbDgjIyBsOCQtOGw+KT05JT4pP2wtbDotICUobC8jISEpPi8lLSBsICUvKSI/KWwqIz5sLyMiPzkgOCUiK2wjPmwhLSItKykobD8pPjolLylsOT8pYg==";$_lk=0x4C
                $Script:adPEASDisclaimer=(-join([Convert]::FromBase64String($_lm)|ForEach-Object{[char]($_-bxor$_lk)}))
            }

            # 5. Resolve output path
            $resolvedBase = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)

            # Strip any existing extension from the base path
            if ([System.IO.Path]::HasExtension($resolvedBase)) {
                $resolvedBase = [System.IO.Path]::ChangeExtension($resolvedBase, $null).TrimEnd('.')
            }

            # Warn if output JSON would overwrite the input file
            $resolvedInput = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($InputJson)
            $outputJsonPath = "$resolvedBase.json"
            if ($Format -in @('All', 'JSON') -and $resolvedInput -eq $outputJsonPath) {
                Write-Warning "[Convert-adPEASReport] Output path '$outputJsonPath' is the same as input file. JSON will be re-exported in place."
            }

            # Ensure output directory exists
            $outputDir = Split-Path -Parent $resolvedBase
            if ($outputDir -and -not (Test-Path $outputDir)) {
                New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
            }

            # 6. Generate HTML report
            if ($Format -in @('HTML', 'All')) {
                Initialize-FindingsCollection
                Set-FindingsCollection -Findings $findings

                $htmlPath = "$resolvedBase.html"
                try {
                    Export-HTMLReport -OutputPath $htmlPath
                    Show-Line "HTML report saved to: $htmlPath" -Class Hint -NoCollect
                } catch {
                    Write-Warning "[Convert-adPEASReport] Error generating HTML report: $_"
                }

                Clear-FindingsCollection
            }

            # 6b. Generate JSON export (for -Format All or -Format JSON)
            if ($Format -in @('All', 'JSON')) {
                Initialize-FindingsCollection
                Set-FindingsCollection -Findings $findings

                $jsonPath = "$resolvedBase.json"
                try {
                    Export-FindingsCache -Path $jsonPath
                    Show-Line "JSON export saved to: $jsonPath" -Class Hint -NoCollect
                } catch {
                    Write-Warning "[Convert-adPEASReport] Error saving JSON: $_"
                }

                Clear-FindingsCollection
            }

            # 7. Generate text report
            if ($Format -in @('Text', 'All')) {
                $textPath = "$resolvedBase.txt"
                $Script:adPEAS_Outputfile = $textPath
                $Script:adPEAS_OutputColor = if ($NoColor) { $false } else { $null }

                # Create/clear the text file
                $utf8Encoding = [System.Text.Encoding]::UTF8
                [System.IO.File]::WriteAllText($textPath, "", $utf8Encoding)

                # Replay findings through Show-* functions (writes to console + file)
                Invoke-FindingsReplay -Findings $findings

                $Script:adPEAS_Outputfile = $null
                Show-Line "Text report saved to: $textPath" -Class Hint -NoCollect
            }

            # Show HTML path again after text replay (the earlier message scrolls away)
            if ($Format -eq 'All' -and $htmlPath) {
                Show-Line "HTML report saved to: $htmlPath" -Class Hint -NoCollect
            }

        } finally {
            # Restore previous state
            $Script:LDAPContext = $previousLDAPContext
            $Script:adPEAS_Outputfile = $previousOutputfile
            $Script:adPEAS_OutputColor = $previousOutputColor
            $Script:adPEAS_FindingsCollectionEnabled = $previousFindingsEnabled
            $Script:adPEASDisclaimer = $previousDisclaimer
            Clear-FindingsCollection
        }
    }

    end {
        Write-Log "[Convert-adPEASReport] Report generation completed"
    }
}

<#
.SYNOPSIS
    Replays findings through the Show-* output system for text report generation.
.DESCRIPTION
    Iterates over imported findings and calls the appropriate Show-* function for each,
    producing console and file output identical to a live scan. Uses -NoCollect to avoid
    re-collecting findings that are already in the collection.
#>
function Invoke-FindingsReplay {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$Findings
    )

    foreach ($finding in $Findings) {
        switch ($finding.Type) {
            'Header' {
                # Show-Header delegates to Show-Output -Class Info which calls Write-adPEASHeader
                Show-Output -Class Info -Value $finding.Text -NoCollect
            }
            'SubHeader' {
                Show-SubHeader $finding.Text -ObjectType $finding.ObjectType -NoCollect
            }
            'Object' {
                if ($finding.Object) {
                    Show-Object $finding.Object -Class $finding.Class -NoCollect
                }
            }
            'KeyValue' {
                $kvParams = @{
                    Key       = $finding.Key
                    Value     = $finding.Value
                    Class     = $finding.Class
                    NoCollect = $true
                }
                if ($finding.FindingId) { $kvParams['FindingId'] = $finding.FindingId }
                Show-Output @kvParams
            }
            'Line' {
                $lineParams = @{
                    Text      = $finding.Text
                    Class     = $finding.Class
                    NoCollect = $true
                }
                if ($finding.FindingId) { $lineParams['FindingId'] = $finding.FindingId }
                Show-Line @lineParams
            }
        }
    }
}
