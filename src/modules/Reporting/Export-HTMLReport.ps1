<#
.SYNOPSIS
    Exports adPEAS findings to an interactive HTML report.

.DESCRIPTION
    Generates a standalone HTML report from collected findings.
    The report includes:
    - Dark/Light theme toggle (persisted in localStorage)
    - Sidebar navigation by severity and category
    - Collapsible finding sections
    - Object detail cards with attribute highlighting
    - Export buttons (Print/PDF)
    - Search functionality

    This function is called automatically by Invoke-adPEAS when -HTMLReport is specified.

.PARAMETER OutputPath
    Path for the HTML report file.

.PARAMETER DefaultTheme
    Initial theme: 'Light' or 'Dark' (default: Dark)

.EXAMPLE
    Export-HTMLReport -OutputPath ".\report.html"

.EXAMPLE
    Export-HTMLReport -OutputPath ".\report.html" -DefaultTheme Dark

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

# Helper function for HTML encoding (works in PowerShell Core without System.Web)
function ConvertTo-HtmlEncode {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return "" }
    return $Text.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;').Replace("'", '&#39;')
}

# Helper function to fix JSON Unicode escapes from ConvertTo-Json
# PowerShell's ConvertTo-Json escapes special characters as \uXXXX which displays literally in HTML
function Repair-JsonUnicodeEscapes {
    param([string]$Json)
    if ([string]::IsNullOrEmpty($Json)) { return $Json }

    # Convert Unicode escapes back to readable characters (e.g., \u0027 -> ')
    $result = [System.Text.RegularExpressions.Regex]::Replace(
        $Json,
        '\\u([0-9a-fA-F]{4})',
        { param($m) [char]::ConvertFromUtf32([Convert]::ToInt32($m.Groups[1].Value, 16)) }
    )

    # Fix double-escaped backslashes: PowerShell strings use \\ for single backslash,
    # then ConvertTo-Json escapes each \ to \\, resulting in \\\\
    # We need to convert \\\\ back to \\ for proper display in tooltips
    $result = $result -replace '\\\\\\\\', '\\'

    return $result
}

function Export-HTMLReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$OutputPath,

        [Parameter(Mandatory=$false)]
        [ValidateSet('Light', 'Dark')]
        [string]$DefaultTheme = 'Dark'
    )

    begin {
        Write-Log "[Export-HTMLReport] Starting HTML report generation"

        # Get collected findings
        $findings = Get-FindingsCollection

        if (-not $findings -or $findings.Count -eq 0) {
            Write-Warning "[Export-HTMLReport] No findings collected. HTML report will be empty."
            $findings = @()
        }

        Write-Log "[Export-HTMLReport] Processing $($findings.Count) findings"

        # Get context information
        $domain = if ($Script:LDAPContext) { $Script:LDAPContext.Domain } else { "Unknown" }
        $server = if ($Script:LDAPContext) { $Script:LDAPContext.Server } else { "Unknown" }
        $user = if ($Script:LDAPContext -and $Script:LDAPContext.Username) { $Script:LDAPContext.Username } else { "$env:USERDOMAIN\$env:USERNAME" }
        $generatedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $version = if ($Script:adPEASVersion) { $Script:adPEASVersion } else { "2.0.0" }

        # Use disclaimer from main script (decoded at startup)
        $disclaimer = if ($Script:adPEASDisclaimer) { $Script:adPEASDisclaimer } else { "" }
    }

    process {
        # Filter out Header/SubHeader for counting (they are structural, not findings)
        # Also exclude findings with Category="Unknown" (these lack check context and shouldn't be displayed)
        $contentFindings = $findings | Where-Object {
            $_.Type -notin @('Header', 'SubHeader') -and $_.Category -ne 'Unknown'
        }

        # Count items using the same logic as cards on the right side:
        # - Objects count as individual items
        # - KeyValue/Line groups (per SubHeader) count as 1 result each
        # This ensures left sidebar counts match right side card counts
        $cardCounts = Get-CardBasedCounts -AllFindings $findings

        $findingCount = $cardCounts.Finding
        $hintCount = $cardCounts.Hint
        $noteCount = $cardCounts.Note
        $secureCount = $cardCounts.Secure
        $totalCount = $cardCounts.Total

        # Group findings by category for navigation (using card-based counts)
        $categories = $cardCounts.Categories

        # Build navigation HTML
        $navHtml = Build-NavigationHtml -Categories $categories -Findings $contentFindings

        # Build findings sections HTML (pass all findings to preserve structure)
        $sectionsHtml = Build-FindingSectionsHtml -Findings $findings

        # Build the complete HTML
        $html = Get-HTMLTemplate

        # Critical: Verify template was loaded successfully
        if (-not $html) {
            Write-Error "[Export-HTMLReport] Failed to load HTML template. Ensure template files exist in 'templates/' directory or build the project first."
            return
        }

        # Export finding definitions as JSON for tooltips
        $findingDefsJson = Repair-JsonUnicodeEscapes (Export-FindingDefinitionsJson -Minified)

        # Export check descriptions as JSON for help buttons
        $checkDefsJson = Repair-JsonUnicodeEscapes (Export-CheckDescriptionsJson -Minified)

        # Build scoring context data for context-aware risk calculation
        $scoringContext = Build-ScoringContext -AllFindings $findings
        $scoringContextJson = Repair-JsonUnicodeEscapes ($scoringContext | ConvertTo-Json -Depth 10 -Compress)

        $html = $html -replace '{{DOMAIN}}', (ConvertTo-HtmlEncode $domain)
        $html = $html -replace '{{SERVER}}', (ConvertTo-HtmlEncode $server)
        $html = $html -replace '{{USER}}', (ConvertTo-HtmlEncode $user)
        $html = $html -replace '{{GENERATED}}', $generatedDate
        $html = $html -replace '{{VERSION}}', $version
        $html = $html -replace '{{DEFAULT_THEME}}', $DefaultTheme.ToLower()
        $html = $html -replace '{{FINDING_COUNT}}', $findingCount
        $html = $html -replace '{{HINT_COUNT}}', $hintCount
        $html = $html -replace '{{NOTE_COUNT}}', $noteCount
        $html = $html -replace '{{SECURE_COUNT}}', $secureCount
        $html = $html -replace '{{TOTAL_COUNT}}', $totalCount
        $html = $html -replace '{{DISCLAIMER}}', (ConvertTo-HtmlEncode $disclaimer)
        $html = $html -replace '{{NAVIGATION}}', $navHtml
        $html = $html -replace '{{FINDINGS_SECTIONS}}', $sectionsHtml
        # Use .Replace() instead of -replace for JSON to avoid regex backreference issues
        # The JSON contains PowerShell code like "$_" which -replace interprets as regex capture groups
        $html = $html.Replace('{{FINDING_DEFINITIONS_JSON}}', $findingDefsJson)
        $html = $html.Replace('{{CHECK_DESCRIPTIONS_JSON}}', $checkDefsJson)
        $html = $html.Replace('{{SCORING_CONTEXT_JSON}}', $scoringContextJson)

        # Generate scoring definitions from central PowerShell definitions
        $scoringDefinitionsJs = ConvertTo-ScoringJavaScript
        $html = $html.Replace('{{SCORING_DEFINITIONS}}', $scoringDefinitionsJs)

    }

    end {
        # Write HTML file
        # Use .NET WriteAllText with BOM-less UTF-8 encoding.
        # PowerShell 5.1's Out-File -Encoding UTF8 always prepends a UTF-8 BOM (EF BB BF),
        # which can interfere with favicon data URI detection in Chromium-based browsers,
        # especially when the report is opened via the file:// protocol.
        try {
            $utf8NoBom = New-Object System.Text.UTF8Encoding $false
            $resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
            [System.IO.File]::WriteAllText($resolvedPath, $html, $utf8NoBom)
            Write-Log "[Export-HTMLReport] Report saved to: $OutputPath"
        }
        catch {
            # Re-throw with context - no separate warning needed as throw displays the error
            throw "Failed to write HTML report to '$OutputPath': $_"
        }
    }
}

<#
.SYNOPSIS
    Calculates card-based counts matching the right-side card display logic.
.DESCRIPTION
    Processes findings to calculate counts that match what's shown on cards:
    - Objects count as individual items
    - KeyValue/Line groups (per SubHeader) count as 1 result each
    This ensures sidebar counts match card counts.
#>
function Get-CardBasedCounts {
    param(
        [array]$AllFindings
    )

    # Initialize counters
    $counts = @{
        Finding = 0
        Hint = 0
        Note = 0
        Secure = 0
        Total = 0
        Categories = @()
    }

    # Track category counts
    $categoryCounts = @{}

    # Process findings in order, grouping by SubHeader
    $currentSubHeader = $null
    $currentFindings = @()
    $currentCategory = $null

    foreach ($finding in $AllFindings) {
        if ($finding.Type -eq 'SubHeader') {
            # Process previous group if exists
            if ($currentSubHeader -and $currentFindings.Count -gt 0) {
                $groupCount = Get-GroupItemCount -Findings $currentFindings
                $groupSeverity = Get-GroupSeverity -Findings $currentFindings

                # Add to severity count
                $counts[$groupSeverity] += $groupCount

                # Add to category count
                if ($currentCategory -and $currentCategory -ne 'Unknown') {
                    if (-not $categoryCounts.ContainsKey($currentCategory)) {
                        $categoryCounts[$currentCategory] = 0
                    }
                    $categoryCounts[$currentCategory] += $groupCount
                }
            }

            # Start new group
            $currentSubHeader = $finding.Text
            $currentFindings = @()
        }
        elseif ($finding.Type -notin @('Header', 'SubHeader') -and $finding.Category -ne 'Unknown') {
            # Content finding
            $currentFindings += $finding
            $currentCategory = $finding.Category
        }
    }

    # Process last group
    if ($currentSubHeader -and $currentFindings.Count -gt 0) {
        $groupCount = Get-GroupItemCount -Findings $currentFindings
        $groupSeverity = Get-GroupSeverity -Findings $currentFindings

        $counts[$groupSeverity] += $groupCount

        if ($currentCategory -and $currentCategory -ne 'Unknown') {
            if (-not $categoryCounts.ContainsKey($currentCategory)) {
                $categoryCounts[$currentCategory] = 0
            }
            $categoryCounts[$currentCategory] += $groupCount
        }
    }

    # Calculate total
    $counts.Total = $counts.Finding + $counts.Hint + $counts.Note + $counts.Secure

    # Convert category counts to Group-Object format
    $counts.Categories = $categoryCounts.GetEnumerator() | ForEach-Object {
        [PSCustomObject]@{
            Name = $_.Key
            Count = $_.Value
        }
    } | Sort-Object Name

    return $counts
}

<#
.SYNOPSIS
    Builds scoring context data for context-aware risk scoring.
.DESCRIPTION
    Extracts relevant information from findings for JavaScript-based scoring:
    - Account information: SID, privileged group memberships, password age
    - Finding correlations: same account appearing in multiple checks
    - Credential exposure: encryption types, password policies
    This enables more accurate risk scoring based on actual impact.
#>
function Build-ScoringContext {
    param(
        [array]$AllFindings
    )

    $scoringContext = @{
        # Map of account SID -> account info (memberOf, pwdLastSet, etc.)
        accounts = @{}
        # Map of finding card ID -> additional context
        findingContext = @{}
        # Correlation data: which accounts appear in which checks
        correlations = @{}
        # Domain-level info
        domainInfo = @{
            passwordPolicy = $null
            krbtgtLastReset = $null
        }
    }

    # Track which accounts appear in which check types
    $accountToChecks = @{}

    foreach ($finding in $AllFindings) {
        if ($finding.Type -ne 'Object' -or -not $finding.Object) {
            continue
        }

        $obj = $finding.Object
        $checkTitle = $finding.CheckTitle

        # Extract account identifier (SID preferred, fallback to DN or sAMAccountName)
        $accountId = $null
        if ($obj.objectSid) {
            $accountId = $obj.objectSid
        } elseif ($obj.distinguishedName) {
            $accountId = $obj.distinguishedName
        } elseif ($obj.sAMAccountName) {
            $accountId = $obj.sAMAccountName
        }

        if (-not $accountId) {
            continue
        }

        # Track which checks this account appears in
        if (-not $accountToChecks.ContainsKey($accountId)) {
            $accountToChecks[$accountId] = @()
        }
        if ($checkTitle -and $checkTitle -notin $accountToChecks[$accountId]) {
            $accountToChecks[$accountId] += $checkTitle
        }

        # Build/update account info
        if (-not $scoringContext.accounts.ContainsKey($accountId)) {
            $scoringContext.accounts[$accountId] = @{
                sid = $obj.objectSid
                name = $obj.sAMAccountName
                dn = $obj.distinguishedName
                memberOf = @()
                memberOfSIDs = @()
                pwdLastSet = $null
                pwdAgeDays = $null
                encryptionTypes = @()
                uacFlags = @()
                isAdmin = $false
                adminTier = 'none'  # Microsoft Tiering: 'tier0'=DA/EA/SA, 'tier1'=operators, 'tier2'=other privileged, 'none'=standard
                isProtectedUser = $false  # Member of Protected Users group
            }
        }

        $acctInfo = $scoringContext.accounts[$accountId]

        # Extract memberOf (group names and SIDs)
        if ($obj.memberOf) {
            $groups = @($obj.memberOf)
            foreach ($groupDN in $groups) {
                if ($groupDN -is [string] -and $groupDN -match '^CN=([^,]+)') {
                    $groupName = $matches[1]
                    if ($groupName -notin $acctInfo.memberOf) {
                        $acctInfo.memberOf += $groupName
                    }
                }
            }
        }

        # Check for privilegedGroups (new format with SID)
        if ($obj.privilegedGroups) {
            foreach ($grp in $obj.privilegedGroups) {
                if ($grp.SID) {
                    if ($grp.SID -notin $acctInfo.memberOfSIDs) {
                        $acctInfo.memberOfSIDs += $grp.SID
                    }
                    # Check for Tier 0 admin groups (Domain Admins -512, Enterprise Admins -519, Schema Admins -518)
                    if ($grp.SID -match '-512$' -or $grp.SID -match '-519$' -or $grp.SID -match '-518$') {
                        $acctInfo.isAdmin = $true
                        $acctInfo.adminTier = 'tier0'
                    }
                    # Tier 1: Operators (Account Ops -548, Server Ops -549, Backup Ops -551)
                    elseif ($grp.SID -match '-(548|549|551)$' -and $acctInfo.adminTier -ne 'tier0') {
                        $acctInfo.isAdmin = $true
                        $acctInfo.adminTier = 'tier1'
                    }
                    # Tier 2: Other privileged
                    elseif ($acctInfo.adminTier -eq 'none') {
                        $acctInfo.isAdmin = $true
                        $acctInfo.adminTier = 'tier2'
                    }
                    # Protected Users group (SID ending with -525)
                    if ($grp.SID -match '-525$') {
                        $acctInfo.isProtectedUser = $true
                    }
                }
                if ($grp.Name -and $grp.Name -notin $acctInfo.memberOf) {
                    $acctInfo.memberOf += $grp.Name
                }
            }
        }

        # Also check memberOf for Protected Users (for objects that don't have privilegedGroups)
        if ($obj.memberOf -and -not $acctInfo.isProtectedUser) {
            foreach ($groupDN in @($obj.memberOf)) {
                # Check by name pattern (case-insensitive)
                if ($groupDN -match 'CN=Protected Users,') {
                    $acctInfo.isProtectedUser = $true
                    break
                }
            }
        }

        # Extract pwdLastSet and calculate age
        if ($obj.pwdLastSet -and -not $acctInfo.pwdLastSet) {
            $acctInfo.pwdLastSet = $obj.pwdLastSet
            # Calculate password age in days
            try {
                if ($obj.pwdLastSet -is [datetime]) {
                    $acctInfo.pwdAgeDays = [math]::Floor(((Get-Date) - $obj.pwdLastSet).TotalDays)
                } elseif ($obj.pwdLastSet -is [string] -and $obj.pwdLastSet -match '\d{4}') {
                    $pwdDate = [datetime]::Parse($obj.pwdLastSet)
                    $acctInfo.pwdAgeDays = [math]::Floor(((Get-Date) - $pwdDate).TotalDays)
                }
            } catch {
                # Ignore parsing errors
            }
        }

        # Extract encryption types (for Kerberoast analysis)
        if ($obj.'msDS-SupportedEncryptionTypes') {
            $encTypes = $obj.'msDS-SupportedEncryptionTypes'
            if ($encTypes) {
                # Decode encryption type flags
                $encValue = 0
                if ($encTypes -is [int]) { $encValue = $encTypes }
                elseif ($encTypes -is [string] -and $encTypes -match '^\d+$') { $encValue = [int]$encTypes }

                if ($encValue -band 0x1) { $acctInfo.encryptionTypes += 'DES-CBC-CRC' }
                if ($encValue -band 0x2) { $acctInfo.encryptionTypes += 'DES-CBC-MD5' }
                if ($encValue -band 0x4) { $acctInfo.encryptionTypes += 'RC4-HMAC' }
                if ($encValue -band 0x8) { $acctInfo.encryptionTypes += 'AES128' }
                if ($encValue -band 0x10) { $acctInfo.encryptionTypes += 'AES256' }
            }
        }

        # Extract UAC flags
        if ($obj.userAccountControl -and $obj.userAccountControl -is [array]) {
            $acctInfo.uacFlags = @($obj.userAccountControl)
        }

        # Update the account info
        $scoringContext.accounts[$accountId] = $acctInfo
    }

    # Build correlations: which accounts have multiple risky findings
    foreach ($accountId in $accountToChecks.Keys) {
        $checks = $accountToChecks[$accountId]
        if ($checks.Count -gt 1) {
            $scoringContext.correlations[$accountId] = @{
                checks = $checks
                count = $checks.Count
                # Check for particularly dangerous combinations
                hasDCSync = $checks -match 'DCSync|Replication' | Select-Object -First 1
                hasKerberoast = $checks -match 'Kerberoast' | Select-Object -First 1
                hasASREP = $checks -match 'AS-?REP' | Select-Object -First 1
                hasDelegation = $checks -match 'Delegation' | Select-Object -First 1
            }
        }
    }

    # Extract domain password policy from findings (if available)
    # Look for Password Policy findings which contain maxPwdAge
    foreach ($finding in $AllFindings) {
        if ($finding.CheckTitle -match 'Password Policy' -and $finding.Object) {
            $policyObj = $finding.Object

            # Extract maxPwdAge (maximum password age in days)
            if ($policyObj.maxPwdAge) {
                $maxAge = $policyObj.maxPwdAge
                # maxPwdAge can be in different formats: days as int, or timespan string
                if ($maxAge -is [int] -or $maxAge -is [double]) {
                    $scoringContext.domainInfo.maxPwdAgeDays = [int]$maxAge
                } elseif ($maxAge -is [string] -and $maxAge -match '(\d+)') {
                    $scoringContext.domainInfo.maxPwdAgeDays = [int]$matches[1]
                }
            }

            # Extract minPwdLength (handles both "12" and "12 characters" formats)
            if ($policyObj.minPwdLength) {
                $minLen = $policyObj.minPwdLength
                if ($minLen -is [int]) {
                    $scoringContext.domainInfo.minPwdLength = $minLen
                } elseif ($minLen -is [string] -and $minLen -match '(\d+)') {
                    $scoringContext.domainInfo.minPwdLength = [int]$matches[1]
                }
            }

            # Extract lockout settings (handles both "5" and "After 5 failed attempts" formats)
            if ($policyObj.lockoutThreshold) {
                $lockout = $policyObj.lockoutThreshold
                if ($lockout -is [int]) {
                    $scoringContext.domainInfo.lockoutThreshold = $lockout
                } elseif ($lockout -is [string] -and $lockout -match '(\d+)') {
                    $scoringContext.domainInfo.lockoutThreshold = [int]$matches[1]
                }
            }

            # Password complexity - pwdProperties is a bitmask
            # Bit 0 (value 1) = DOMAIN_PASSWORD_COMPLEX
            # Check various property names used in different contexts
            $complexityEnabled = $false

            if ($policyObj.pwdProperties) {
                $pwdProps = $policyObj.pwdProperties
                if ($pwdProps -is [int]) {
                    # Bit 0 = complexity required
                    $complexityEnabled = ($pwdProps -band 1) -eq 1
                } elseif ($pwdProps -is [string] -and $pwdProps -match '^\d+$') {
                    $complexityEnabled = ([int]$pwdProps -band 1) -eq 1
                }
            }

            # Also check explicit PasswordComplexity property (from some checks)
            if ($policyObj.PasswordComplexity) {
                $complexVal = $policyObj.PasswordComplexity
                if ($complexVal -eq $true -or $complexVal -eq 1 -or $complexVal -eq 'Enabled' -or $complexVal -eq 'True') {
                    $complexityEnabled = $true
                }
            }

            # Check for 'Complexity' in string representations
            if ($policyObj.passwordComplexityEnabled -or $policyObj.ComplexityEnabled) {
                $complexityEnabled = $true
            }

            $scoringContext.domainInfo.complexityEnabled = $complexityEnabled

            break  # Found policy, no need to continue
        }
    }

    # If no policy found in findings, use defaults (assume weak policy = higher risk)
    if (-not $scoringContext.domainInfo.maxPwdAgeDays) {
        $scoringContext.domainInfo.maxPwdAgeDays = 0  # 0 = never expires (worst case)
    }

    # ========== NEW: Build findings metadata for JSON-based scoring ==========
    # This eliminates the need for DOM traversal in JavaScript
    # Each entry represents one finding card (SubHeader group)
    $scoringContext.findingCards = @()

    $currentSubHeader = $null
    $currentCategory = $null
    $currentObjectType = $null
    $currentFindings = @()

    foreach ($finding in $AllFindings) {
        if ($finding.Type -eq 'Header') {
            # Flush previous group
            if ($currentSubHeader -and $currentFindings.Count -gt 0) {
                $cardMeta = Build-FindingCardMetadata -Title $currentSubHeader -Category $currentCategory -ObjectType $currentObjectType -Findings $currentFindings -ScoringContext $scoringContext
                if ($cardMeta) {
                    $scoringContext.findingCards += $cardMeta
                }
            }
            $currentSubHeader = $null
            $currentCategory = $null
            $currentObjectType = $null
            $currentFindings = @()
        }
        elseif ($finding.Type -eq 'SubHeader') {
            # Flush previous group
            if ($currentSubHeader -and $currentFindings.Count -gt 0) {
                $cardMeta = Build-FindingCardMetadata -Title $currentSubHeader -Category $currentCategory -ObjectType $currentObjectType -Findings $currentFindings -ScoringContext $scoringContext
                if ($cardMeta) {
                    $scoringContext.findingCards += $cardMeta
                }
            }
            $currentSubHeader = $finding.Text
            $currentObjectType = $finding.ObjectType
            $currentFindings = @()
        }
        else {
            # Content finding
            if ($finding.Category -ne 'Unknown') {
                if (-not $currentCategory) {
                    $currentCategory = ($finding.Category.ToLower() -replace '\s+', '-') -replace '[^a-z0-9\-]', ''
                }
                $currentFindings += $finding
            }
        }
    }

    # Flush last group
    if ($currentSubHeader -and $currentFindings.Count -gt 0) {
        $cardMeta = Build-FindingCardMetadata -Title $currentSubHeader -Category $currentCategory -ObjectType $currentObjectType -Findings $currentFindings -ScoringContext $scoringContext
        if ($cardMeta) {
            $scoringContext.findingCards += $cardMeta
        }
    }

    return $scoringContext
}

<#
.SYNOPSIS
    Builds metadata for a single finding card for JSON-based scoring.
.DESCRIPTION
    Extracts all information needed for score calculation without DOM traversal:
    - Card title, severity, category
    - Object count
    - Account SID (for context lookup)
    - Section name (for display)
#>
function Build-FindingCardMetadata {
    param(
        [string]$Title,
        [string]$Category,
        [string]$ObjectType,
        [array]$Findings,
        [hashtable]$ScoringContext
    )

    # Determine card severity (highest among findings)
    # Determine card severity from findings
    # Priority: Show-Line severity > Object AttributeSeverities
    $cardSeverity = 'note'
    $severityPriority = @{ 'finding' = 4; 'hint' = 3; 'secure' = 2; 'note' = 1; 'standard' = 0 }
    $currentPriority = 1

    foreach ($f in $Findings) {
        if ($f.Type -eq 'Object' -and $f.AttributeSeverities) {
            # Check attribute-level severities for objects
            foreach ($attrSev in $f.AttributeSeverities.Values) {
                $sevLower = $attrSev.ToLower()
                $priority = $severityPriority[$sevLower]
                if ($null -ne $priority -and $priority -gt $currentPriority) {
                    $currentPriority = $priority
                    $cardSeverity = $sevLower
                    if ($cardSeverity -eq 'finding') { break }
                }
            }
        } elseif ($f.Severity) {
            # Check Show-Line severity (Line/KeyValue findings)
            $sevLower = $f.Severity.ToLower()
            $priority = $severityPriority[$sevLower]
            if ($null -ne $priority -and $priority -gt $currentPriority) {
                $currentPriority = $priority
                $cardSeverity = $sevLower
            }
        }
        if ($cardSeverity -eq 'finding') { break }
    }

    # Count objects
    $objectCount = @($Findings | Where-Object { $_.Type -eq 'Object' }).Count
    if ($objectCount -eq 0) { $objectCount = 1 }

    # Find account SID from first object (for context lookup)
    $accountSID = $null
    foreach ($f in $Findings) {
        if ($f.Type -eq 'Object' -and $f.Object) {
            $obj = $f.Object
            if ($obj.objectSid) {
                $accountSID = $obj.objectSid
                break
            } elseif ($obj.distinguishedName) {
                $accountSID = $obj.distinguishedName
                break
            } elseif ($obj.sAMAccountName) {
                $accountSID = $obj.sAMAccountName
                break
            }
        }
    }

    # Get section name from CheckTitle
    $section = if ($Findings.Count -gt 0 -and $Findings[0].CheckTitle) {
        # Use the check's category as section
        $Findings[0].Category
    } else {
        $Category
    }

    # Collect vulnerability tags from objects (e.g., "ESC1", "ESC4" from ADCS templates)
    # These are used by JS scoring to match against findingBaseScores titles
    $vulnTags = @()
    # Collect FindingIds from attribute triggers and line findings
    # Used by JS to look up remediation/impact from findingDefinitions
    $findingIds = @()
    foreach ($f in $Findings) {
        if ($f.Type -eq 'Object' -and $f.Object) {
            $obj = $f.Object
            if ($obj.Vulnerabilities) {
                # Vulnerabilities can be "ESC1, ESC4" (comma-separated string)
                $tags = @($obj.Vulnerabilities -split ',\s*' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                foreach ($tag in $tags) {
                    if ($tag -notin $vulnTags) {
                        $vulnTags += $tag
                    }
                }
            }
            # Extract FindingIds from object attributes via trigger matching
            if ($f.AttributeSeverities) {
                foreach ($attrName in $f.AttributeSeverities.Keys) {
                    $attrSev = $f.AttributeSeverities[$attrName]
                    if ($attrSev -eq 'Finding' -or $attrSev -eq 'Hint') {
                        $attrValue = $obj.$attrName
                        if ($null -ne $attrValue) {
                            $fid = Get-FindingIdForAttribute -Name $attrName -Value $attrValue
                            if ($fid -and $fid -notin $findingIds) {
                                $findingIds += $fid
                            }
                        }
                    }
                }
            }
        } elseif ($f.FindingId -and $f.FindingId -notin $findingIds) {
            # Line/KeyValue findings with explicit FindingId
            $findingIds += $f.FindingId
        }
    }

    return @{
        title = $Title
        severity = $cardSeverity
        category = $Category
        section = $section
        objectCount = $objectCount
        accountSID = $accountSID
        vulnerabilities = $vulnTags
        objectType = $ObjectType
        findingIds = $findingIds
    }
}

<#
.SYNOPSIS
    Gets item count for a group using card logic.
#>
function Get-GroupItemCount {
    param([array]$Findings)

    $objectCount = @($Findings | Where-Object { $_.Type -eq 'Object' }).Count

    if ($objectCount -gt 0) {
        return $objectCount
    } else {
        # No objects = 1 result (cohesive KeyValue/Line result)
        return 1
    }
}

<#
.SYNOPSIS
    Gets the highest severity for a group.
.DESCRIPTION
    Determines the highest severity by checking:
    1. For Objects: Check AttributeSeverities (actual attribute-level analysis)
    2. For Lines/KeyValue: Use the direct Severity property
    Priority: Finding > Hint > Secure > Note
#>
function Get-GroupSeverity {
    param([array]$Findings)

    $severityPriority = @{ 'Finding' = 4; 'Hint' = 3; 'Secure' = 2; 'Note' = 1; 'Standard' = 0 }
    $highestPriority = 0
    $highestSeverity = 'Note'

    foreach ($f in $Findings) {
        # For Objects: Check AttributeSeverities for actual severity
        if ($f.Type -eq 'Object' -and $f.AttributeSeverities) {
            foreach ($attrSev in $f.AttributeSeverities.Values) {
                $priority = $severityPriority[$attrSev]
                if ($null -ne $priority -and $priority -gt $highestPriority) {
                    $highestPriority = $priority
                    $highestSeverity = $attrSev
                    if ($highestSeverity -eq 'Finding') { return 'Finding' }  # Can't get higher
                }
            }
        }
        # For Lines/KeyValue: Use direct Severity (from Show-Line -Class)
        elseif ($f.Severity) {
            $priority = $severityPriority[$f.Severity]
            if ($null -ne $priority -and $priority -gt $highestPriority) {
                $highestPriority = $priority
                $highestSeverity = $f.Severity
                if ($highestSeverity -eq 'Finding') { return 'Finding' }
            }
        }
    }

    return $highestSeverity
}

<#
.SYNOPSIS
    Builds the navigation HTML for the sidebar.
#>
function Build-NavigationHtml {
    param(
        [array]$Categories,
        [array]$Findings
    )

    $nav = [System.Text.StringBuilder]::new()

    # Categories section
    # Calculate total findings across all categories
    $totalCategoryFindings = ($Categories | Measure-Object -Property Count -Sum).Sum
    if (-not $totalCategoryFindings) { $totalCategoryFindings = 0 }

    [void]$nav.AppendLine('<div class="sidebar-section">')
    [void]$nav.AppendLine('    <div class="sidebar-title">Categories</div>')
    [void]$nav.AppendLine('    <a class="nav-item category-filter" data-category="all" href="javascript:void(0)" onclick="filterByCategory(''all'')">')
    [void]$nav.AppendLine('        All Categories')
    [void]$nav.AppendLine("        <span class=`"count`">$totalCategoryFindings</span>")
    [void]$nav.AppendLine('    </a>')

    foreach ($cat in $Categories) {
        $catName = $cat.Name
        $catCount = $cat.Count
        # XSS Protection: Sanitize category ID - only allow alphanumeric and hyphens
        $catId = ($catName.ToLower() -replace '\s+', '-') -replace '[^a-z0-9\-]', ''
        # HTML-encode category name and ID to prevent XSS
        $catNameEncoded = [System.Net.WebUtility]::HtmlEncode($catName)
        $catIdEncoded = ConvertTo-HtmlEncode $catId

        [void]$nav.AppendLine("    <a class=`"nav-item category-filter`" data-category=`"$catIdEncoded`" href=`"javascript:void(0)`" onclick=`"filterByCategory('$catIdEncoded')`">")
        [void]$nav.AppendLine("        $catNameEncoded")
        [void]$nav.AppendLine("        <span class=`"count`">$catCount</span>")
        [void]$nav.AppendLine("    </a>")
    }

    [void]$nav.AppendLine('</div>')

    return $nav.ToString()
}

<#
.SYNOPSIS
    Builds the findings sections HTML following the console output structure.
.DESCRIPTION
    Processes findings in order, using Header/SubHeader entries to structure
    the output similar to what the user sees on the console.

    The category for each section is derived from the first content finding's
    Category property, which matches the navigation categories.
#>
function Build-FindingSectionsHtml {
    param(
        [array]$Findings
    )

    $sections = [System.Text.StringBuilder]::new()

    $currentHeader = $null
    $currentSubHeader = $null
    $currentSubHeaderObjectType = $null  # Track ObjectType from SubHeader
    $currentFindings = [System.Collections.ArrayList]::new()
    $currentCategory = $null
    $sectionStarted = $false
    $cardIndex = 0  # Tracks index into scoringContext.findingCards

    # Process findings in order (they are collected in console output order)
    foreach ($finding in $Findings) {

        if ($finding.Type -eq 'Header') {
            # Close previous section if exists
            if ($sectionStarted) {
                # Close previous subheader card if exists
                if ($currentSubHeader -and $currentFindings.Count -gt 0) {
                    $cardHtml = Build-FindingCardHtml -Title $currentSubHeader -Findings $currentFindings -Category $currentCategory -ObjectType $currentSubHeaderObjectType -CardIndex $cardIndex
                    $cardIndex++
                    [void]$sections.AppendLine($cardHtml)
                }
                [void]$sections.AppendLine("    </div>")
                [void]$sections.AppendLine("</section>")
            }

            # Start new section (but don't output HTML yet - need category from first finding)
            $currentHeader = $finding.Text -replace '^\++\s*|\s*\++$', ''  # Remove +++++ decorations
            $currentCategory = $null  # Will be set from first content finding
            $currentSubHeader = $null
            $currentSubHeaderObjectType = $null
            $currentFindings = [System.Collections.ArrayList]::new()
            $sectionStarted = $false
        }
        elseif ($finding.Type -eq 'SubHeader') {
            # Close previous subheader card if exists
            if ($currentSubHeader -and $currentFindings.Count -gt 0) {
                $cardHtml = Build-FindingCardHtml -Title $currentSubHeader -Findings $currentFindings -Category $currentCategory -ObjectType $currentSubHeaderObjectType -CardIndex $cardIndex
                $cardIndex++
                [void]$sections.AppendLine($cardHtml)
            }

            # Start new subheader group - capture ObjectType if present
            $currentSubHeader = $finding.Text
            $currentSubHeaderObjectType = $finding.ObjectType  # May be $null if not set
            $currentFindings = [System.Collections.ArrayList]::new()
        }
        else {
            # Skip findings with Category="Unknown" (they lack check context)
            if ($finding.Category -eq 'Unknown') {
                continue
            }

            # Content finding - derive category from first one
            if (-not $sectionStarted -and $currentHeader) {
                # Get category from this finding (e.g., "Accounts", "Domain")
                # XSS Protection: Sanitize category - only allow alphanumeric and hyphens
                $currentCategory = ($finding.Category.ToLower() -replace '\s+', '-') -replace '[^a-z0-9\-]', ''
                $sectionId = "cat-$currentCategory"
                $currentCategoryEncoded = ConvertTo-HtmlEncode $currentCategory

                [void]$sections.AppendLine("<section id=`"$sectionId`" class=`"section`" data-category=`"$currentCategoryEncoded`">")
                [void]$sections.AppendLine("    <div class=`"section-header`">")
                [void]$sections.AppendLine("        <div class=`"section-title`">$(ConvertTo-HtmlEncode $currentHeader)</div>")
                [void]$sections.AppendLine("    </div>")
                [void]$sections.AppendLine("    <div class=`"section-content`">")
                $sectionStarted = $true
            }

            # Add finding to current group
            [void]$currentFindings.Add($finding)
        }
    }

    # Close last section
    if ($sectionStarted) {
        if ($currentSubHeader -and $currentFindings.Count -gt 0) {
            $cardHtml = Build-FindingCardHtml -Title $currentSubHeader -Findings $currentFindings -Category $currentCategory -ObjectType $currentSubHeaderObjectType -CardIndex $cardIndex
            $cardIndex++
            [void]$sections.AppendLine($cardHtml)
        }
        [void]$sections.AppendLine("    </div>")
        [void]$sections.AppendLine("</section>")
    }

    return $sections.ToString()
}

<#
.SYNOPSIS
    Builds HTML for a single finding card (subheader group).
#>
function Build-FindingCardHtml {
    param(
        [string]$Title,
        [array]$Findings,
        [string]$Category,
        [string]$ObjectType,  # ObjectType from SubHeader for ObjectTypeDefinitions lookup
        [int]$CardIndex = -1  # Index into scoringContext.findingCards for score calculation
    )

    $card = [System.Text.StringBuilder]::new()

    # Determine card severity from findings
    # Priority: Show-Line severity > Object AttributeSeverities
    $cardSeverity = 'note'
    $severityPriority = @{ 'finding' = 4; 'hint' = 3; 'secure' = 2; 'note' = 1; 'standard' = 0 }
    $currentPriority = 1  # Start with 'note'

    foreach ($f in $Findings) {
        # For Objects: Check AttributeSeverities for actual severity
        if ($f.Type -eq 'Object' -and $f.AttributeSeverities) {
            foreach ($attrSev in $f.AttributeSeverities.Values) {
                $sevLower = $attrSev.ToLower()
                $priority = $severityPriority[$sevLower]
                if ($null -ne $priority -and $priority -gt $currentPriority) {
                    $currentPriority = $priority
                    $cardSeverity = $sevLower
                    if ($cardSeverity -eq 'finding') { break }  # Can't get higher
                }
            }
        }
        # For Lines/KeyValue: Use the Finding's Severity directly (from Show-Line -Class)
        elseif ($f.Severity) {
            $sevLower = $f.Severity.ToLower()
            $priority = $severityPriority[$sevLower]
            if ($null -ne $priority -and $priority -gt $currentPriority) {
                $currentPriority = $priority
                $cardSeverity = $sevLower
            }
        }

        if ($cardSeverity -eq 'finding') { break }  # Can't get higher than finding
    }

    # Count items intelligently:
    # - Objects (AD objects): count each as individual item
    # - KeyValue only (no Objects): this is ONE result (e.g., domain info, password policy)
    # - Lines only: also ONE result
    $objectCount = @($Findings | Where-Object { $_.Type -eq 'Object' }).Count

    # Determine what to display
    $countHtml = if ($objectCount -gt 0) {
        # Has Objects: show count (e.g., "3 item(s)" for 3 Kerberoastable users)
        "<span class=`"finding-count`">$objectCount item(s)</span>"
    } else {
        # No Objects (only KeyValue/Line): this is ONE cohesive result
        "<span class=`"finding-count`">1 result</span>"
    }

    # Use ObjectType for tooltip lookup and card title
    # Priority 1: ObjectType parameter (passed from SubHeader)
    # Priority 2: First object's _adPEASObjectType (fallback)
    $resolvedObjectType = $ObjectType

    # Fallback: Look for _adPEASObjectType in any finding object if not passed
    if (-not $resolvedObjectType) {
        foreach ($f in $Findings) {
            if ($f.Type -eq 'Object' -and $f.Object -and $f.Object._adPEASObjectType) {
                $resolvedObjectType = $f.Object._adPEASObjectType
                break
            }
        }
    }

    # Use ObjectTypeDefinitions.SectionTitle as card title (more professional for HTML report)
    # Console output uses verb-form ("Analyzing..."), HTML uses noun-form ("Domain Password Policy")
    $displayTitle = if ($resolvedObjectType -and $Script:ObjectTypeDefinitions[$resolvedObjectType] -and $Script:ObjectTypeDefinitions[$resolvedObjectType].SectionTitle) {
        $Script:ObjectTypeDefinitions[$resolvedObjectType].SectionTitle
    } else {
        $Title  # Fallback to original title if no SectionTitle exists
    }

    # Get Summary as subtitle from ObjectTypeDefinitions
    $subtitle = if ($resolvedObjectType -and $Script:ObjectTypeDefinitions[$resolvedObjectType] -and $Script:ObjectTypeDefinitions[$resolvedObjectType].Summary) {
        $Script:ObjectTypeDefinitions[$resolvedObjectType].Summary
    } else {
        $null
    }

    # XSS Protection: Encode title for both display and data attribute
    $titleEscaped = ConvertTo-HtmlEncode $displayTitle
    $subtitleEscaped = if ($subtitle) { ConvertTo-HtmlEncode $subtitle } else { $null }
    $titleForAttr = ConvertTo-HtmlEncode $Title  # Keep original for data-check-title lookup
    $objectTypeAttr = if ($resolvedObjectType) { " data-object-type=`"$(ConvertTo-HtmlEncode $resolvedObjectType)`"" } else { "" }

    $helpButtonHtml = "<span class=`"check-help-btn`" data-check-title=`"$titleForAttr`"$objectTypeAttr title=`"Click for more info`">?</span>"

    # XSS Protection: Encode category for data attribute
    $categoryEncoded = ConvertTo-HtmlEncode $Category

    # Generate unique ID for this finding card (for expand/collapse all)
    $findingCardId = "fc-" + [System.Guid]::NewGuid().ToString('N').Substring(0, 8)

    # Add Expand/Collapse All button if there are objects
    $expandCollapseBtn = if ($objectCount -gt 1) {
        "<button class=`"expand-collapse-btn`" onclick=`"event.stopPropagation(); toggleAllObjects('$findingCardId')`" title=`"Expand/Collapse all objects`"><span>&#9654;</span> Expand All</button>"
    } else { "" }

    $cardIndexAttr = if ($CardIndex -ge 0) { " data-card-index=`"$CardIndex`"" } else { "" }
    [void]$card.AppendLine("        <div class=`"finding-card`" id=`"$findingCardId`" data-card-id=`"$findingCardId`" data-severity=`"$cardSeverity`" data-category=`"$categoryEncoded`"$cardIndexAttr>")
    [void]$card.AppendLine("            <div class=`"finding-header`" onclick=`"toggleFinding(this)`">")
    [void]$card.AppendLine("                <input type=`"checkbox`" class=`"finding-checkbox`" onclick=`"event.stopPropagation(); toggleCompleted('$findingCardId', this.checked)`" aria-label=`"Mark as completed`">")
    [void]$card.AppendLine("                <div class=`"finding-severity-bar $cardSeverity`"></div>")
    [void]$card.AppendLine("                <div class=`"finding-content`">")
    [void]$card.AppendLine("                    <div class=`"finding-title-wrapper`"><span class=`"finding-title`">$titleEscaped</span>$helpButtonHtml</div>")
    if ($subtitleEscaped) {
        [void]$card.AppendLine("                    <div class=`"finding-subtitle`">$subtitleEscaped</div>")
    }
    [void]$card.AppendLine("                </div>")
    [void]$card.AppendLine("                <div class=`"finding-meta`">")
    [void]$card.AppendLine("                    $expandCollapseBtn")
    [void]$card.AppendLine("                    $countHtml")
    [void]$card.AppendLine("                    <span class=`"finding-toggle`">&#9660;</span>")
    [void]$card.AppendLine("                </div>")
    [void]$card.AppendLine("            </div>")
    [void]$card.AppendLine("            <div class=`"finding-body`">")

    # Output each finding
    foreach ($finding in $Findings) {
        $severityClass = $finding.Severity.ToLower()

        if ($finding.Type -eq 'Object' -and $finding.Object) {
            # AD Object - full detail card using RenderModel
            # Use cached RenderModel from finding (built during console output) or create new
            $renderModel = if ($finding.RenderModel) { $finding.RenderModel }
                           else { Get-RenderModel -Object $finding.Object }
            $objectHtml = Build-ObjectDetailHtml -Object $finding.Object -Severity $finding.Severity -RenderModel $renderModel
            [void]$card.AppendLine($objectHtml)
        }
        elseif ($finding.Type -eq 'KeyValue' -and $finding.Key) {
            # Key-Value pair with optional tooltip for findings
            $keyHtml = ConvertTo-HtmlEncode $finding.Key
            $valueHtml = ConvertTo-HtmlEncode $finding.Value

            # Check for finding tooltip if this is a Finding or Hint severity
            $findingId = if ($severityClass -eq 'finding' -or $severityClass -eq 'hint') {
                Get-FindingIdForAttribute -Name $finding.Key -Value $finding.Value
            } else { $null }

            # Build value span - with data-finding-id on the value for consistent tooltip behavior
            $valueSpan = if ($findingId) {
                "<span class=`"finding-value`" data-finding-id=`"$findingId`">$valueHtml</span>"
            } else {
                "<span class=`"finding-value`">$valueHtml</span>"
            }

            [void]$card.AppendLine("                <div class=`"finding-item $severityClass`">")
            [void]$card.AppendLine("                    <span class=`"finding-key`">$keyHtml</span>")
            [void]$card.AppendLine("                    $valueSpan")
            [void]$card.AppendLine("                </div>")
        }
        elseif ($finding.Type -eq 'Line' -and $finding.Text) {
            # Single line text with optional tooltip via FindingId
            $textHtml = ConvertTo-HtmlEncode $finding.Text
            $dataAttr = if ($finding.FindingId) { " data-finding-id=`"$($finding.FindingId)`"" } else { "" }
            [void]$card.AppendLine("                <div class=`"finding-item finding-line $severityClass`"$dataAttr>$textHtml</div>")
        }
    }

    [void]$card.AppendLine("            </div>")
    [void]$card.AppendLine("        </div>")

    return $card.ToString()
}

<#
.SYNOPSIS
    Generates a meaningful title for an object card based on object type.
.DESCRIPTION
    Detects the object type and returns an appropriate, descriptive title
    for the collapsed card header. Uses same detection logic as
    Get-ObjectTypeForOrdering in adPEAS-AttributeOrder.ps1.
#>
<#
.SYNOPSIS
    Gets the display title for an object card in the HTML report.
.DESCRIPTION
    Wrapper around the central Get-ObjectTypeTitle function from adPEAS-ObjectTypes.ps1.
    Handles special cases that require object-specific property access.
#>
function Get-ObjectCardTitle {
    param($Object)

    # If no ObjectType set, return UNTAGGED indicator
    # Note: displayName comes before Name because GPOs have Name=GUID but displayName=readable name
    if (-not $Object._adPEASObjectType) {
        $objName = if ($Object.sAMAccountName) { $Object.sAMAccountName }
                   elseif ($Object.displayName) { $Object.displayName }
                   elseif ($Object.Name) { $Object.Name }
                   elseif ($Object.dNSHostName) { $Object.dNSHostName }
                   else { "Unknown" }
        return "[UNTAGGED] $objName"
    }

    $objectType = $Object._adPEASObjectType
    $context = $Object._adPEASContext

    # Helper to get account/object name
    # Note: displayName comes before Name because GPOs have Name=GUID but displayName=readable name
    $objName = if ($Object.sAMAccountName) { $Object.sAMAccountName -replace '\$$' }
               elseif ($Object.displayName) { $Object.displayName }
               elseif ($Object.Name) { $Object.Name }
               elseif ($Object.dNSHostName) { $Object.dNSHostName }
               else { "Object" }

    # Handle special cases that need object-specific property access
    # These cannot be expressed in the simple TitleFormat templates
    switch ($objectType) {
        'EntraConnect' {
            $tenant = if ($Object.entraM365Tenant) { " ($($Object.entraM365Tenant))" } else { "" }
            return "Entra ID Connect: $objName$tenant"
        }
        'Tier0Account' {
            # Only show context if it's not "Unprotected" (that's already clear from the header)
            if ($context -and $context -ne 'Unprotected') {
                return "Tier-0 Account: $objName ($context)"
            }
            return "Tier-0 Account: $objName"
        }
        'OperatorGroup' {
            $grpName = if ($Object.OperatorGroup) { $Object.OperatorGroup } else { $objName }
            return "Operator Group: $grpName"
        }
        'SIDHistory' {
            $ctxInfo = if ($context -eq 'Privileged') { " (Privileged!)" } else { "" }
            return "SID History: $objName$ctxInfo"
        }
        { $_ -in @('GPPCredential', 'SYSVOLCredential') } {
            $credType = if ($Object.credentialType) { $Object.credentialType } else { "Credential" }
            return "Credential ($credType)"
        }
        'LAPSConfiguration' {
            $ouName = if ($Object.ouName) { $Object.ouName } else { $objName }
            return "LAPS Config: $ouName"
        }
        'DomainBasicInfo' {
            $domainName = if ($Object.domainNameDNS) { $Object.domainNameDNS } else { "Domain" }
            return "Domain: $domainName"
        }
        'DomainControllers' {
            $dcList = if ($Object.domainControllers) { @($Object.domainControllers -split "`n") } else { @() }
            $dcCount = $dcList.Count
            return "Domain Controllers ($dcCount)"
        }
        'FineGrainedPasswordPolicy' {
            $psoName = if ($Object.psoName) { $Object.psoName } elseif ($Object.Name) { $Object.Name } else { "PSO" }
            return "Fine-Grained Policy: $psoName"
        }
        'DomainTrust' {
            $trustTarget = if ($Object.trustPartner) { $Object.trustPartner } else { $objName }
            return "Trust: $trustTarget"
        }
        'GPOLocalGroup' {
            $localGrp = if ($Object.localGroup) { $Object.localGroup } else { "Local Group" }
            return "GPO Local Group: $localGrp"
        }
        'GPOScheduledTask' {
            $taskName = if ($Object.taskName) { $Object.taskName } else { "Task" }
            return "Scheduled Task: $taskName"
        }
        'AddComputerRight' {
            $principal = if ($Object.accountName) { $Object.accountName } else { $objName }
            return "Add Computer Right: $principal"
        }
        default {
            # Use central Get-ObjectTypeTitle for all standard cases
            return Get-ObjectTypeTitle -Object $Object
        }
    }
}

<#
.SYNOPSIS
    Builds HTML for an object detail card.
.DESCRIPTION
    Creates object detail HTML with primary attributes visible and extended attributes
    in a collapsible section. Primary attributes are determined by object type to match
    the console output from Get-RenderModel.ps1.
#>
function Build-ObjectDetailHtml {
    param(
        $Object,
        [string]$Severity,
        $RenderModel = $null
    )

    $html = [System.Text.StringBuilder]::new()

    # Detect object type and generate meaningful title
    $objectName = Get-ObjectCardTitle -Object $Object

    # Generate unique ID for this object's extended section
    $objectId = [System.Guid]::NewGuid().ToString('N').Substring(0, 8)

    # Check if title contains DN path (separated by ||)
    $titleHtml = if ($objectName -match '^(.+?)\|\|(.+)$') {
        $mainTitle = ConvertTo-HtmlEncode $matches[1]
        $dnPath = ConvertTo-HtmlEncode $matches[2]
        "$mainTitle <span class=`"object-dn-path`">($dnPath)</span>"
    } else {
        ConvertTo-HtmlEncode $objectName
    }

    # Object cards are collapsed by default, click header to expand
    [void]$html.AppendLine("                <div class=`"object-detail`" id=`"obj-$objectId`">")
    [void]$html.AppendLine("                    <div class=`"object-header`" onclick=`"toggleObjectCard('$objectId')`">")
    [void]$html.AppendLine("                        <span>$titleHtml</span>")
    [void]$html.AppendLine("                        <span class=`"expand-icon`">&#9654;</span>")
    [void]$html.AppendLine("                    </div>")
    [void]$html.AppendLine("                    <div class=`"object-body`">")

    # Use RenderModel if available, otherwise create one
    if (-not $RenderModel) {
        $RenderModel = Get-RenderModel -Object $Object
    }

    # Delegate to Render-HtmlObject (from Render-HtmlObject.ps1)
    $bodyHtml = Render-HtmlObject -Model $RenderModel -ObjectId $objectId -Severity $Severity
    [void]$html.Append($bodyHtml)

    [void]$html.AppendLine("                    </div>")
    [void]$html.AppendLine("                </div>")

    return $html.ToString()
}

# NOTE: Build-AttributeRowHtml and Get-AttributeValueClass have been removed.
# All HTML rendering is now handled by Render-HtmlObject.ps1 via the RenderModel pipeline.

# NOTE: Get-FindingIdForAttribute() is defined in adPEAS-FindingDefinitions.ps1
# It uses the centralized $Script:FindingTriggerIndex for attribute -> FindingId mapping.

<#
.SYNOPSIS
    Returns the HTML template with CSS and JavaScript.
.DESCRIPTION
    During development: Loads templates from separate files (templates/).
    After build: Templates are embedded directly by Build-Release.ps1.
#>
function Get-HTMLTemplate {
    # Try to load from template files (development mode)
    $scriptDir = $PSScriptRoot
    if (-not $scriptDir) {
        # Fallback for when running interactively
        $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    }
    if (-not $scriptDir) {
        $scriptDir = (Get-Location).Path
    }

    $templatesDir = Join-Path $scriptDir "templates"
    $htmlTemplatePath = Join-Path $templatesDir "report-template.html"
    $cssPath = Join-Path $templatesDir "report-styles.css"
    $jsPath = Join-Path $templatesDir "report-scripts.js"

    # Check if template files exist (development mode)
    if ((Test-Path $htmlTemplatePath) -and (Test-Path $cssPath) -and (Test-Path $jsPath)) {
        Write-Log "[Get-HTMLTemplate] Loading templates from separate files (development mode)"

        $htmlTemplate = Get-Content $htmlTemplatePath -Raw -Encoding UTF8
        $cssContent = Get-Content $cssPath -Raw -Encoding UTF8
        $jsContent = Get-Content $jsPath -Raw -Encoding UTF8

        # Replace placeholders with actual content
        $result = $htmlTemplate.Replace('{{CSS_CONTENT}}', $cssContent)
        $result = $result.Replace('{{JS_CONTENT}}', $jsContent)

        return $result
    }

    # Fallback: Return error message if templates not found and not embedded
    Write-Warning "[Get-HTMLTemplate] Template files not found at: $templatesDir"
    Write-Warning "[Get-HTMLTemplate] Either run from source directory or build the project first."
    return $null
}
