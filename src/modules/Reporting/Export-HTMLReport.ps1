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

# Makes a JSON document safe to embed as a JavaScript literal inside a <script> block.
#
# This replaces a function that did the exact opposite. It converted every \uXXXX escape
# back to a raw character, on the premise that ConvertTo-Json escapes characters "which
# display literally in HTML". That premise is wrong: these documents are assigned to a
# const in report-scripts.js, so a JavaScript parser reads them, and \uXXXX is an ordinary
# escape there - the value a script sees is identical either way. What the un-escaping did
# change was the HTML parser's view. Windows PowerShell 5.1, the target runtime, escapes
# "<" as \u003c precisely so that embedded JSON cannot close the surrounding tag; turning
# that back into a raw "<" meant a directory object named "CN=</script><img src=x
# onerror=...>" ended the script block in the generated report. The scoring context is
# built from scan findings, so those strings come out of the directory being audited, and
# the report a consultant hands to a customer must not execute them.
#
# It also collapsed four backslashes to two in the raw JSON text, which is one escape
# level and not a display fix: a UNC path stored as "\\\\server\\share" decodes to
# \\server\share, and after the collapse to \server\share. That silently corrupted every
# path and every escaped DN that reached a tooltip.
#
# Escaping here is idempotent: on PowerShell 5.1 the characters already arrive in \uXXXX
# form and nothing matches, while PowerShell 7 emits them raw and they are escaped now.
function Protect-JsonForScriptBlock {
    param([string]$Json)
    if ([string]::IsNullOrEmpty($Json)) { return $Json }

    # "<" and ">" cannot appear in JSON outside a string value, so replacing them cannot
    # break the grammar. "&" is escaped as well, so the same document stays safe if it is
    # ever embedded somewhere the HTML entity parser runs.
    return $Json.Replace('<', '\u003c').Replace('>', '\u003e').Replace('&', '\u0026')
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
        $generatedDate = (Format-adPEASDate (Get-Date) 'yyyy-MM-dd HH:mm:ss')
        $version = if ($Script:adPEASVersion) { $Script:adPEASVersion } else { "2.0.0" }

        # Use disclaimer from main script (decoded at startup)
        $disclaimer = if ($Script:adPEASDisclaimer) { $Script:adPEASDisclaimer } else { "" }
    }

    process {
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

        # Build navigation HTML. It needs the category counts and nothing else - it used to
        # take the findings as well, which cost a pass over all of them for a parameter the
        # sidebar never read.
        $navHtml = Build-NavigationHtml -Categories $categories

        # Build findings sections HTML (pass all findings to preserve structure)
        $sectionsHtml = Build-FindingSectionsHtml -Findings $findings

        # Build the complete HTML
        $html = Get-HTMLTemplate

        # Critical: verify the template was loaded. This has to throw, not Write-Error and
        # return: 'return' leaves process{}, end{} still runs, and WriteAllText with a null
        # string creates a 0-byte file. Write-Error is non-terminating on top of that, so
        # the callers' try/catch never fires and adPEAS.ps1 goes on to log "HTML report
        # generated" and keeps the path for the summary. Both callers already wrap the call
        # in try/catch, and end{} throws on a failed write for the same reason.
        if (-not $html) {
            throw "[Export-HTMLReport] Failed to load HTML template. Ensure template files exist in 'templates/' directory or build the project first."
        }

        # Export finding definitions as JSON for tooltips
        $findingDefsJson = Protect-JsonForScriptBlock (Export-FindingDefinitionsJson -Minified)

        # Export check descriptions as JSON for help buttons
        $checkDefsJson = Protect-JsonForScriptBlock (Export-CheckDescriptionsJson -Minified)

        # Build scoring context data for context-aware risk calculation
        $scoringContext = Build-ScoringContext -AllFindings $findings
        $scoringContextJson = Protect-JsonForScriptBlock ($scoringContext | ConvertTo-Json -Depth 10 -Compress)

        # Use literal .Replace() for ALL token substitutions, never -replace. The placeholders are
        # literal "{{...}}" strings (no regex needed), and the replacement VALUES are data-derived:
        # any value containing a '$' followed by digits (a SID, a managed-password ID, an account
        # name, a description) is parsed by -replace's replacement engine as a capture-group
        # reference "$<n>", and a long digit run overflows with "Capture group numbers must be less
        # than or equal to Int32.MaxValue", aborting the whole report. HTML-encoding does not help -
        # it does not escape '$'. .Replace() treats both arguments as literal text.
        $html = $html.Replace('{{DOMAIN}}', [string](ConvertTo-HtmlEncode $domain))
        $html = $html.Replace('{{SERVER}}', [string](ConvertTo-HtmlEncode $server))
        $html = $html.Replace('{{USER}}', [string](ConvertTo-HtmlEncode $user))
        $html = $html.Replace('{{GENERATED}}', [string]$generatedDate)
        $html = $html.Replace('{{VERSION}}', [string]$version)
        $html = $html.Replace('{{DEFAULT_THEME}}', [string]$DefaultTheme.ToLower())
        $html = $html.Replace('{{FINDING_COUNT}}', [string]$findingCount)
        $html = $html.Replace('{{HINT_COUNT}}', [string]$hintCount)
        $html = $html.Replace('{{NOTE_COUNT}}', [string]$noteCount)
        $html = $html.Replace('{{SECURE_COUNT}}', [string]$secureCount)
        $html = $html.Replace('{{TOTAL_COUNT}}', [string]$totalCount)
        $html = $html.Replace('{{DISCLAIMER}}', [string](ConvertTo-HtmlEncode $disclaimer))
        $html = $html.Replace('{{NAVIGATION}}', [string]$navHtml)
        $html = $html.Replace('{{FINDINGS_SECTIONS}}', [string]$sectionsHtml)
        # JSON blobs likewise use .Replace() - they contain PowerShell code like "$_" that -replace
        # would interpret as regex capture groups (same failure class as above).
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
function Get-FindingCardGroups {
    [CmdletBinding()]
    param(
        [array]$AllFindings
    )

    # .ToArray() throughout, never @($list): wrapping a generic List in @() throws
    # "Argument types do not match" on current PowerShell, and it would do so only once a
    # group actually had findings in it - i.e. never in an empty-report smoke test.
    $groups = New-Object System.Collections.Generic.List[object]

    $currentSectionIndex = -1
    $currentHeader       = $null
    $currentSubHeader    = $null
    $currentObjectType   = $null
    $currentCategory     = $null
    $currentFindings     = New-Object System.Collections.Generic.List[object]

    foreach ($finding in $AllFindings) {

        if ($finding.Type -eq 'Header') {
            # A group only exists inside a section and under a subheader, and only if
            # something landed in it. The counting loop used to ignore Header entirely, so
            # content between a Header and the next SubHeader was added to the group of the
            # previous section - counted at the top of the report, and rendered nowhere.
            if ($currentHeader -and $currentSubHeader -and $currentFindings.Count -gt 0) {
                [void]$groups.Add([PSCustomObject]@{
                    SectionIndex = $currentSectionIndex
                    Header       = $currentHeader
                    Title        = $currentSubHeader
                    ObjectType   = $currentObjectType
                    Category     = $currentCategory
                    Findings     = $currentFindings.ToArray()
                })
            }

            $currentSectionIndex++
            $currentHeader     = $finding.Text -replace '^\++\s*|\s*\++$', ''  # strip the +++++ decoration
            $currentSubHeader  = $null
            $currentObjectType = $null
            $currentCategory   = $null
            $currentFindings   = New-Object System.Collections.Generic.List[object]
        }
        elseif ($finding.Type -eq 'SubHeader') {
            if ($currentHeader -and $currentSubHeader -and $currentFindings.Count -gt 0) {
                [void]$groups.Add([PSCustomObject]@{
                    SectionIndex = $currentSectionIndex
                    Header       = $currentHeader
                    Title        = $currentSubHeader
                    ObjectType   = $currentObjectType
                    Category     = $currentCategory
                    Findings     = $currentFindings.ToArray()
                })
            }

            $currentSubHeader  = $finding.Text
            $currentObjectType = $finding.ObjectType   # may be $null
            $currentFindings   = New-Object System.Collections.Generic.List[object]
        }
        else {
            # A finding without a Category has no check context, and "Unknown" is what
            # adPEAS puts on disclaimers, connection messages and progress lines. The null
            # test is not redundant: $null -ne 'Unknown'. Findings do not always come from
            # this process - Convert-adPEASReport reads them out of a JSON export, and a
            # file from an older version simply has no Category property.
            if (-not $finding.Category -or $finding.Category -eq 'Unknown') { continue }

            # The section's category comes from its first content finding, which is what
            # both the section id and the sidebar filter are built from.
            if (-not $currentCategory) { $currentCategory = $finding.Category }

            [void]$currentFindings.Add($finding)
        }
    }

    if ($currentHeader -and $currentSubHeader -and $currentFindings.Count -gt 0) {
        [void]$groups.Add([PSCustomObject]@{
            SectionIndex = $currentSectionIndex
            Header       = $currentHeader
            Title        = $currentSubHeader
            ObjectType   = $currentObjectType
            Category     = $currentCategory
            Findings     = $currentFindings.ToArray()
        })
    }

    # Comma: a plain return emits the groups one at a time, and a single group would reach
    # the caller as a bare object whose .Count is empty rather than 1.
    return ,$groups.ToArray()
}

<#
.SYNOPSIS
    Turns a category name into the form used for DOM ids and filter attributes.
.DESCRIPTION
    The result ends up in a section id, in data-category on the section and on every card,
    and in the sidebar's filter call - so it may only carry what an id may carry. The
    sidebar builds the same value from the same input, which is what makes a filter click
    match the sections it is supposed to show.
#>
function ConvertTo-CategorySlug {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$Category
    )

    if (-not $Category) { return $null }
    return (($Category.ToLower() -replace '\s+', '-') -replace '[^a-z0-9\-]', '')
}

<#
.SYNOPSIS
    Counts findings the way the report cards present them.
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

    # One grouping for the whole report: these numbers describe the cards a reader gets to
    # see, card for card. They used to come from a loop of their own that ignored Header,
    # so the summary could count items that were never rendered.
    foreach ($group in (Get-FindingCardGroups -AllFindings $AllFindings)) {
        $groupCount = Get-GroupItemCount -Findings $group.Findings
        $groupSeverity = Get-GroupSeverity -Findings $group.Findings

        $counts[$groupSeverity] += $groupCount

        # The raw category name, because the sidebar shows it; it derives its own id from
        # the same string via ConvertTo-CategorySlug.
        if ($group.Category) {
            if (-not $categoryCounts.ContainsKey($group.Category)) {
                $categoryCounts[$group.Category] = 0
            }
            $categoryCounts[$group.Category] += $groupCount
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
<#
.SYNOPSIS
    Reads a number back out of a password-policy value that was formatted for a human.
.DESCRIPTION
    Get-DomainPasswordPolicy renders its values for display: "14 characters", "90 days",
    "After 5 failed attempts" - and, for the value zero, the word "Disabled", sometimes
    with a parenthetical ("Disabled (Never expires)"). The scoring context needs the
    numbers back.

    The zero case is the reason this exists. Pulling the first digit run out of the string
    works for every value except zero, because "Disabled" has no digits in it - and zero is
    the dangerous state in each of these settings: no minimum password length, passwords
    that never expire, no account lockout at all. Losing exactly those left the scoring
    reading "unknown" for the worst configuration a domain can have.
.OUTPUTS
    [int] the value, or $null when the input carries no number and is not a disabled marker.
#>
function ConvertTo-PolicyNumber {
    param($Value)

    if ($null -eq $Value) { return $null }

    if ($Value -is [int] -or $Value -is [long] -or $Value -is [double]) {
        return [int]$Value
    }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }

    # "Disabled" and "Disabled (Never expires)" both stand for the number zero.
    if ($text -match '^\s*Disabled') { return 0 }

    if ($text -match '(\d+)') { return [int]$Matches[1] }

    return $null
}

function Build-ScoringContext {
    param(
        [array]$AllFindings
    )

    # Rank for the tier upgrade-only comparison below: never let a later, lesser group
    # downgrade a tier already established by an earlier one.
    $tierRank = @{ 'none' = 0; 'tier2' = 1; 'tier1' = 2; 'tier0' = 3 }

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

                    # Classify via the central Test-IsPrivileged categorization
                    # ($Script:PrivilegedRIDSuffixes / $Script:OperatorRIDSuffixes in
                    # adPEAS-SIDs.ps1) instead of an inline regex copy that had drifted
                    # out of sync with it - Group Policy Creator Owners (-520) and Key
                    # Admins/Enterprise Key Admins (-526/-527) are both direct paths to
                    # domain takeover (GPO -> SYSTEM code execution; msDS-KeyCredentialLink
                    # -> Shadow Credentials -> PKINIT -> UnPAC-the-Hash - adPEAS implements
                    # both attacks itself) and are now tier0 like the identity gate already
                    # considered them, not tier2. Cert Publishers (-517) is tier1: it can
                    # write userCertificate but is not a direct takeover without a matching
                    # altSecurityIdentities mapping or template, which the identity gate
                    # already reflects by calling it Operator rather than Privileged.
                    # A bare SID string never touches LDAP (Test-IsPrivileged's
                    # sIDHistory/group-membership phases are gated on
                    # $Script:LdapConnection, unset during offline report generation), so
                    # this is safe to call here.
                    $privCheck = Test-IsPrivileged -Identity $grp.SID
                    $newTier = switch ($privCheck.Category) {
                        'Privileged' { 'tier0' }
                        'Operator'   { 'tier1' }
                        default      { 'tier2' }
                    }
                    if ($tierRank[$newTier] -gt $tierRank[$acctInfo.adminTier]) {
                        $acctInfo.isAdmin = $true
                        $acctInfo.adminTier = $newTier
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
                    # InvariantCulture: the string was written by adPEAS, not typed by the
                    # reader, and the local calendar would read its Gregorian year as a
                    # Buddhist or Hijri one - a password age off by centuries, or a throw.
                    $pwdDate = [datetime]::Parse($obj.pwdLastSet, [System.Globalization.CultureInfo]::InvariantCulture)
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

            # Every one of these three arrives as a string that Get-DomainPasswordPolicy
            # formatted for a human, and for the value zero that string is "Disabled" -
            # "Disabled", "Disabled (Never expires)". A digit match finds nothing in those,
            # so the setting stayed unset in the scoring context and any calculation above
            # it read "unknown" instead of "off". That is backwards: zero is the dangerous
            # state in all three cases - no minimum length, passwords that never expire,
            # and no account lockout at all, which is what makes password spraying work.
            # ConvertTo-PolicyNumber maps the word back to the number it stands for.
            $maxAgeDays = ConvertTo-PolicyNumber -Value $policyObj.maxPwdAge
            if ($null -ne $maxAgeDays) { $scoringContext.domainInfo.maxPwdAgeDays = $maxAgeDays }

            $minLength = ConvertTo-PolicyNumber -Value $policyObj.minPwdLength
            if ($null -ne $minLength) { $scoringContext.domainInfo.minPwdLength = $minLength }

            $lockoutThreshold = ConvertTo-PolicyNumber -Value $policyObj.lockoutThreshold
            if ($null -ne $lockoutThreshold) { $scoringContext.domainInfo.lockoutThreshold = $lockoutThreshold }

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
    # findingCards[N] is read by the card rendered with data-card-index="N", so this array
    # and the cards have to be built from the same grouping. They used to be two loops with
    # slightly different rules; where they disagreed, every card from that point on showed
    # another card's score.
    $scoringContext.findingCards = @()

    foreach ($group in (Get-FindingCardGroups -AllFindings $AllFindings)) {
        $cardMeta = Build-FindingCardMetadata `
            -Title $group.Title `
            -Category (ConvertTo-CategorySlug -Category $group.Category) `
            -ObjectType $group.ObjectType `
            -Findings $group.Findings `
            -ScoringContext $scoringContext

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

    # The severity the JavaScript scoring reads for this card. Same ranking as the badge
    # and the summary count, because all three go through Get-GroupSeverity - this used to
    # be a third copy of that loop, with Hint ranked above Secure.
    $cardSeverity = (Get-GroupSeverity -Findings $Findings).ToLower()

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

    # The section this card reports itself under. The report's "top actions" list displays
    # this string, and its DOM fallback reads the section title - "Accounts" - so this has
    # to be the category as a reader sees it, not the slug the caller passes for ids.
    #
    # The guard used to test CheckTitle and then return Category: a card whose first
    # finding named no check fell through to the slug, so the same list showed "Accounts"
    # and "accounts" next to each other depending on a property that has nothing to do
    # with it. Every finding that reaches a group carries a Category - Get-FindingCardGroups
    # drops the ones that do not - so the fallback is only for a direct call.
    $section = if ($Findings.Count -gt 0 -and $Findings[0].Category) {
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

    # Derived from $Script:SeverityPriority (adPEAS-Types.ps1) rather than restated, so
    # this cannot drift from the ranking the rest of adPEAS uses: Secure outranks Hint - a
    # confirmed-secure section must not be downgraded by a mere Hint elsewhere in it.
    #
    # This function is the single answer to "how severe is this group": the card badge and
    # the scoring metadata call it too. They used to carry their own copy of the loop, with
    # Hint above Secure, so the same group could be counted as Secure in the summary and
    # rendered with a Hint badge right below it.
    #
    # The last entry keeps priority 0, which is what leaves a group of nothing but
    # Standard severities at the 'Note' default instead of promoting it to 'Standard'.
    $severityPriority = @{}
    for ($i = 0; $i -lt $Script:SeverityPriority.Count; $i++) {
        $severityPriority[$Script:SeverityPriority[$i]] = $Script:SeverityPriority.Count - 1 - $i
    }

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
        [array]$Categories
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

        # The same slug the sections carry in data-category - clicking this entry filters
        # on it, so the two have to be derived by the same function and not by two copies
        # of the same expression. It is also what keeps the onclick argument below to
        # [a-z0-9-], i.e. unable to end the JavaScript string literal it sits in.
        $catId = ConvertTo-CategorySlug -Category $catName

        # The report's own encoder, like everywhere else in this file. The sidebar used
        # [System.Net.WebUtility]::HtmlEncode, which also escapes non-ASCII: a localized
        # category name came out as "Dom&#228;nen" in the sidebar and with the umlaut
        # itself in its own section title, in the same UTF-8 document.
        $catNameEncoded = ConvertTo-HtmlEncode $catName
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

    # Same grouping as the counters and the scoring metadata, so a card's index into
    # scoringContext.findingCards is the index of that same group there.
    $cardIndex = 0
    $openSectionIndex = $null

    foreach ($group in (Get-FindingCardGroups -AllFindings $Findings)) {

        $categorySlug = ConvertTo-CategorySlug -Category $group.Category

        if ($group.SectionIndex -ne $openSectionIndex) {
            if ($null -ne $openSectionIndex) {
                [void]$sections.AppendLine("    </div>")
                [void]$sections.AppendLine("</section>")
            }

            $categoryEncoded = ConvertTo-HtmlEncode $categorySlug
            [void]$sections.AppendLine("<section id=`"cat-$categorySlug`" class=`"section`" data-category=`"$categoryEncoded`">")
            [void]$sections.AppendLine("    <div class=`"section-header`">")
            [void]$sections.AppendLine("        <div class=`"section-title`">$(ConvertTo-HtmlEncode $group.Header)</div>")
            [void]$sections.AppendLine("    </div>")
            [void]$sections.AppendLine("    <div class=`"section-content`">")

            $openSectionIndex = $group.SectionIndex
        }

        $cardHtml = Build-FindingCardHtml `
            -Title $group.Title `
            -Findings $group.Findings `
            -Category $categorySlug `
            -ObjectType $group.ObjectType `
            -CardIndex $cardIndex
        $cardIndex++

        [void]$sections.AppendLine($cardHtml)
    }

    if ($null -ne $openSectionIndex) {
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

    # The badge this card shows. Get-GroupSeverity is the one place that ranks a group, so
    # the badge cannot disagree with the summary count above it; lowercased because it goes
    # into a CSS class and a data attribute.
    $cardSeverity = (Get-GroupSeverity -Findings $Findings).ToLower()

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
        # Same name resolution as the tagged path below, trailing '$' included: a computer
        # account read differently depending on whether its check tagged the object.
        $objName = if ($Object.sAMAccountName) { $Object.sAMAccountName -replace '\$$' }
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
            $localGrp = if ($Object.TargetGroup) { $Object.TargetGroup } else { "Local Group" }
            $gpoName = if ($Object.GPOName) { " ($($Object.GPOName))" } else { "" }
            return "GPO Local Group: $localGrp$gpoName"
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
    [void]$html.AppendLine("                        <div class=`"attr-col-resizer`" title=`"Drag to resize the name column`" aria-hidden=`"true`"></div>")

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

#region BUILD:EMBED Get-HTMLTemplate
#
# Build-Release.ps1 replaces everything down to #endregion with a function that
# returns the asset inline. What follows is the development version: it loads the
# same files from templates/, so a dot-sourced run serves identical content.
#
# Marked by region rather than matched against the wording of the doc comment
# below, which is what the build used to do - rewording it broke the match, and
# where the build only warned, the artifact shipped this development version,
# which finds no templates/ directory beside itself and returns nothing.
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
    if (-not $scriptDir -and $MyInvocation.MyCommand.Path) {
        # Fallback for when running interactively.
        #
        # The guard on .Path is what makes the third step below reachable: Split-Path
        # -Parent throws on a null argument rather than returning nothing, so a function
        # that has neither $PSScriptRoot nor an invocation path - one defined in memory
        # rather than dot-sourced from a file - used to die here instead of falling through
        # to the current location.
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
#endregion BUILD:EMBED
