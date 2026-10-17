function Get-GPOLocalGroupMembership {
    <#
    .SYNOPSIS
    Detects GPO-based local group membership assignments.

    .DESCRIPTION
    Analyzes Group Policy Objects for local group membership modifications:
    - Restricted Groups (GptTmpl.inf)
    - Group Policy Preferences Groups (Groups.xml)
    Requires SMB access to \\domain\SYSVOL.

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Get-GPOLocalGroupMembership

    .EXAMPLE
    Get-GPOLocalGroupMembership -Domain "contoso.com" -Credential (Get-Credential)

    .NOTES
    Category: GPO
    Author: Alexander Sturz (@_61106960_)
    Reference:
    - Restricted Groups: https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/jj852219(v=ws.11)
    - Group Policy Preferences: https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn581922(v=ws.11)
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeInactive
    )

    begin {
        Write-Log "[Get-GPOLocalGroupMembership] Starting check"

        # The local groups this check reports a membership assignment for.
        #
        # Five entries used to be in here, and all three parsers filter hard on the table:
        # a Restricted Groups entry or a Group Policy Preferences item naming any other
        # group produced no output at all. The three operator groups are the gap that
        # matters - on a domain controller they are a direct path to the domain, and a
        # policy linked to the Domain Controllers OU that puts a principal in Server
        # Operators is domain compromise in one step, with nothing in the report.
        #
        # Server Operators: may configure services, and a service runs as SYSTEM on the DC.
        # Account Operators: may create and modify users, groups and computers domain-wide.
        # Print Operators: may load printer drivers, which is code as SYSTEM.
        $Script:LocalGroupSIDs = @{
            'S-1-5-32-544' = 'Administrators'
            'S-1-5-32-548' = 'Account Operators'
            'S-1-5-32-549' = 'Server Operators'
            'S-1-5-32-550' = 'Print Operators'
            'S-1-5-32-551' = 'Backup Operators'
            'S-1-5-32-555' = 'Remote Desktop Users'
            'S-1-5-32-556' = 'Network Configuration Operators'
            'S-1-5-32-559' = 'Performance Log Users'
            'S-1-5-32-562' = 'Distributed COM Users'
            'S-1-5-32-574' = 'Certificate Service DCOM Access'
            'S-1-5-32-578' = 'Hyper-V Administrators'
            'S-1-5-32-580' = 'Remote Management Users'
            'S-1-5-32-547' = 'Power Users'
        }

        # The canonical names of the well-known broad groups, so a member is shown the same
        # way whatever language the policy was written in. Whether a member is broad is
        # not decided here but by Test-IsBroadTrustee (Resolve-GroupMemberRisk): this
        # table used to be the test as well, with '-513' beside it, and so Domain
        # Computers, Domain Guests, BUILTIN\Users, Interactive and Network in a local
        # Administrators group did not escalate.
        $Script:RiskySIDs = @{
            'S-1-1-0' = 'Everyone'
            'S-1-5-11' = 'Authenticated Users'
            'S-1-5-7' = 'Anonymous Logon'
            'S-1-5-4' = 'Interactive'
            'S-1-5-2' = 'Network'
            'S-1-5-32-545' = 'Users'
            'S-1-5-32-546' = 'Guests'
        }

        # Base severity per target group (using standard adPEAS severity values)
        # Finding = Critical/High issues, Hint = Medium issues, Note = Low/Info
        $Script:GroupSeverityConfig = @{
            'S-1-5-32-544' = @{ Severity = "Finding"; Risk = "Domain accounts added to local Administrators" }
            # The three operator groups are a Finding rather than a Hint because of what
            # they are on a domain controller, where they are domain-wide rights and not
            # machine-local ones. This check cannot tell from a policy alone which machines
            # it reaches, so the worse of the two readings is the one reported.
            'S-1-5-32-548' = @{ Severity = "Finding"; Risk = "Domain accounts added to Account Operators - on a domain controller this permits creating and modifying users, groups and computers domain-wide" }
            'S-1-5-32-549' = @{ Severity = "Finding"; Risk = "Domain accounts added to Server Operators - on a domain controller this permits configuring services, which run as SYSTEM" }
            'S-1-5-32-550' = @{ Severity = "Finding"; Risk = "Domain accounts added to Print Operators - on a domain controller this permits loading printer drivers, which is code as SYSTEM" }
            'S-1-5-32-551' = @{ Severity = "Hint"; Risk = "Domain accounts added to Backup Operators" }
            'S-1-5-32-555' = @{ Severity = "Hint"; Risk = "Domain accounts added to Remote Desktop Users" }
            'S-1-5-32-556' = @{ Severity = "Hint"; Risk = "Domain accounts added to Network Configuration Operators - permits changing the network configuration, including which DNS server the machine asks" }
            'S-1-5-32-559' = @{ Severity = "Hint"; Risk = "Domain accounts added to Performance Log Users - permits configuring tracing providers, which has been a local escalation path" }
            'S-1-5-32-562' = @{ Severity = "Hint"; Risk = "Domain accounts added to Distributed COM Users - permits launching and activating DCOM objects remotely" }
            'S-1-5-32-574' = @{ Severity = "Hint"; Risk = "Domain accounts added to Certificate Service DCOM Access - permits requesting certificates from the enterprise CA over DCOM" }
            'S-1-5-32-578' = @{ Severity = "Hint"; Risk = "Domain accounts added to Hyper-V Administrators - full control over every virtual machine on the host, which includes its disks" }
            'S-1-5-32-580' = @{ Severity = "Hint"; Risk = "Domain accounts added to Remote Management Users" }
            'S-1-5-32-547' = @{ Severity = "Note"; Risk = "Domain accounts added to Power Users" }
        }
    }

    process {
        try {
            # Connection parameters only. -IncludeInactive belongs to this check and
            # neither callee has a parameter by that name, so splatting $PSBoundParameters
            # failed to bind - a terminating error before any output.
            $connectionParams = @{}
            if ($Domain)     { $connectionParams['Domain']     = $Domain }
            if ($Server)     { $connectionParams['Server']     = $Server }
            if ($Credential) { $connectionParams['Credential'] = $Credential }

            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @connectionParams)) {
                return
            }

            $domainFQDN = $Script:LDAPContext.Domain
            $Script:vulnerableGPOs = @()

            Show-SubHeader "Searching for GPO local group assignments..." -ObjectType "GPOLocalGroup"

            $gpos = Get-DomainGPO @connectionParams

            if (-not $gpos -or @($gpos).Count -eq 0) {
                Show-Line "No GPOs found in domain" -Class Note
                return
            }

            $gpoLinkage = Get-GPOLinkage

            # Which policies have a half switched off, indexed the way a SYSVOL path names
            # them. Get-DomainGPO decodes the flags attribute; nothing used to read it.
            $gpoStatusMap = Get-GPOStatusMap -GPO $gpos

            # Build GPO GUID to name mapping for later lookup
            $gpoNameMap = @{}
            foreach ($gpo in $gpos) {
                $gpoNameMap[$gpo.Name] = $gpo.DisplayName
            }
            $gpoPathMap = Get-GPOPathMap -GPO $gpos

            # Track SYSVOL access status
            $Script:sysvolAccessible = $false

            # SYSVOL Access with Credential Support
            Invoke-SMBAccess -Description "Scanning GPO Groups.xml files" -ScriptBlock {
                $sysvolPath = "\\$($Script:LDAPContext.Server)\SYSVOL\$domainFQDN\Policies"

                if (-not (Test-Path $sysvolPath)) {
                    Write-Log "[Get-GPOLocalGroupMembership] SYSVOL path not accessible: $sysvolPath"
                    return
                }

                $Script:sysvolAccessible = $true

                # Use cached SYSVOL file listing (no redundant SMB directory traversal)
                $gptTmplFiles = Get-CachedSYSVOLFiles -Filter "GptTmpl.inf"

                $totalFiles = @($gptTmplFiles).Count
                $currentIndex = 0
                foreach ($file in $gptTmplFiles) {
                    $currentIndex++
                    if ($totalFiles -gt $Script:ProgressThreshold) { Show-Progress -Activity "Scanning GPO local group assignments" -Current $currentIndex -Total $totalFiles -ObjectName $file.Name }
                    # Extract GPO GUID from path: ...\Policies\{GUID}\Machine\...
                    if ($file.FullName -match '\\Policies\\(\{[^}]+\})\\') {
                        $gpoGUID = $Matches[1]
                        $gpoName = if ($gpoNameMap.ContainsKey($gpoGUID)) { $gpoNameMap[$gpoGUID] } else { $gpoGUID }

                        try {
                            Write-Log "[Get-GPOLocalGroupMembership] Reading: $($file.FullName)"
                            $restrictedGroupsFindings = Parse-RestrictedGroups -FilePath $file.FullName -GPOName $gpoName -GPOGUID $gpoGUID -GPOPath $gpoPathMap[([string]$gpoGUID).ToUpper()]

                            if ($restrictedGroupsFindings) {
                                # $null-guarded, and three-valued. Get-GPOLinkage returns $null
                                # when the linkage could not be resolved, and .ContainsKey on
                                # that throws - inside a try/catch that logs and moves on, so
                                # every finding was dropped and the check closed with "No
                                # vulnerable GPO local group assignments found". A transient
                                # LDAP failure reported the quietest result as the truth.
                                $linkedOUs = $null
                                if ($null -ne $gpoLinkage) {
                                    $linkedOUs = @()
                                    if ($gpoLinkage.ContainsKey($gpoGUID)) {
                                        $linkedOUs = @($gpoLinkage[$gpoGUID])
                                    }
                                }
                                # "Not linked" is what the transformer makes of an empty list,
                                # and that would be a claim the failed lookup cannot support.
                                # Plain assignment, then an override. An "if" whose branch
                                # yields @() writes nothing to the output stream, so
                                # "$x = if (...) { ... } else { $empty }" lands $x as $null -
                                # and @() is precisely the value that means "linked nowhere".
                                $linkedOUsDisplay = $linkedOUs
                                if ($null -eq $linkedOUs) {
                                    $linkedOUsDisplay = 'Unknown - linkage could not be resolved'
                                }

                                # Restricted Groups is a computer-side policy, so the
                                # computer half of the GPO is the one that has to be on.
                                # Where it applies is LinkedOUs' subject, not this one's.
                                $gpoStatus = Get-GPOEffectiveStatus `
                                    -StatusEntry $gpoStatusMap[$gpoGUID] -Scope 'Machine' `
                                    -Link $linkedOUs

                                # Whether those links put a domain controller in the
                                # policy's scope - a fact beside LinkedOUs, no verdict.
                                $gpoDCReach = Get-GPODomainControllerReach -Link $linkedOUs

                                foreach ($finding in $restrictedGroupsFindings) {
                                    $finding | Add-Member -NotePropertyName 'LinkedOUs' -NotePropertyValue $linkedOUsDisplay -Force
                                    $finding | Add-Member -NotePropertyName 'reachesDomainControllers' -NotePropertyValue $gpoDCReach -Force
                                    # Restricted Groups is a computer-side section, so the
                                    # half is Machine - stated per finding because the
                                    # suppression decision reads it from the row now, and
                                    # the GPP branch below answers differently.
                                    $finding | Add-Member -NotePropertyName '_ReachScope' -NotePropertyValue 'Machine' -Force
                                    if ($gpoStatus) {
                                        $finding | Add-Member -NotePropertyName 'GPOStatus' -NotePropertyValue $gpoStatus -Force
                                    }
                                }

                                $Script:vulnerableGPOs += @($restrictedGroupsFindings)
                            }
                        } catch {
                            Write-Log "[Get-GPOLocalGroupMembership] Error parsing $($file.FullName): $_"
                        }
                    }
                }
                if ($totalFiles -gt $Script:ProgressThreshold) { Show-Progress -Activity "Scanning GPO local group assignments" -Completed }

                # Use cached SYSVOL file listing (no redundant SMB directory traversal)
                $groupsXmlFiles = Get-CachedSYSVOLFiles -Filter "Groups.xml"

                $totalXmlFiles = @($groupsXmlFiles).Count
                $currentXmlIndex = 0
                foreach ($file in $groupsXmlFiles) {
                    $currentXmlIndex++
                    if ($totalXmlFiles -gt $Script:ProgressThreshold) { Show-Progress -Activity "Scanning GPP Groups.xml files" -Current $currentXmlIndex -Total $totalXmlFiles -ObjectName $file.Name }
                    # Extract GPO GUID from path: ...\Policies\{GUID}\Machine\...
                    if ($file.FullName -match '\\Policies\\(\{[^}]+\})\\') {
                        $gpoGUID = $Matches[1]
                        $gpoName = if ($gpoNameMap.ContainsKey($gpoGUID)) { $gpoNameMap[$gpoGUID] } else { $gpoGUID }

                        try {
                            Write-Log "[Get-GPOLocalGroupMembership] Reading: $($file.FullName)"
                            $gppGroupsFindings = Parse-GPPGroups -FilePath $file.FullName -GPOName $gpoName -GPOGUID $gpoGUID -GPOPath $gpoPathMap[([string]$gpoGUID).ToUpper()]

                            if ($gppGroupsFindings) {
                                # Same three-valued handling as the Restricted Groups branch
                                # above: $null means the linkage was never resolved, @() means
                                # resolved and linked nowhere, and .ContainsKey on a $null map
                                # throws into the catch below.
                                $linkedOUs = $null
                                if ($null -ne $gpoLinkage) {
                                    $linkedOUs = @()
                                    if ($gpoLinkage.ContainsKey($gpoGUID)) {
                                        $linkedOUs = @($gpoLinkage[$gpoGUID])
                                    }
                                }
                                # Plain assignment, then an override. An "if" whose branch
                                # yields @() writes nothing to the output stream, so
                                # "$x = if (...) { ... } else { $empty }" lands $x as $null -
                                # and @() is precisely the value that means "linked nowhere".
                                $linkedOUsDisplay = $linkedOUs
                                if ($null -eq $linkedOUs) {
                                    $linkedOUsDisplay = 'Unknown - linkage could not be resolved'
                                }

                                # Group Policy Preferences local groups can be deployed from
                                # either half, and the file's path is what says which.
                                $gpoStatus = Get-GPOEffectiveStatus `
                                    -StatusEntry $gpoStatusMap[$gpoGUID] `
                                    -Scope $(if ($file.FullName -match '\\Machine\\') { 'Machine' } else { 'User' }) `
                                    -Link $linkedOUs

                                $gpoDCReach = Get-GPODomainControllerReach -Link $linkedOUs

                                foreach ($finding in $gppGroupsFindings) {
                                    $finding | Add-Member -NotePropertyName 'LinkedOUs' -NotePropertyValue $linkedOUsDisplay -Force
                                    $finding | Add-Member -NotePropertyName 'reachesDomainControllers' -NotePropertyValue $gpoDCReach -Force
                                    # And here the file's path decides, the same way the
                                    # GPOStatus line above is computed.
                                    $finding | Add-Member -NotePropertyName '_ReachScope' `
                                        -NotePropertyValue (Get-GPOHalfFromSource -SourceFile (Get-GPORelativePath -Path $file.FullName)) -Force
                                    if ($gpoStatus) {
                                        $finding | Add-Member -NotePropertyName 'GPOStatus' -NotePropertyValue $gpoStatus -Force
                                    }
                                }

                                $Script:vulnerableGPOs += @($gppGroupsFindings)
                            }
                        } catch {
                            Write-Log "[Get-GPOLocalGroupMembership] Error parsing $($file.FullName): $_"
                        }
                    }
                }
                if ($totalXmlFiles -gt $Script:ProgressThreshold) { Show-Progress -Activity "Scanning GPP Groups.xml files" -Completed }
            }

            # Collect findings from scriptblock (Script scope bridges the child scope boundary)
            $vulnerableGPOs = $Script:vulnerableGPOs
            $Script:vulnerableGPOs = $null

            # Check if SYSVOL was accessible
            $sysvolAccessible = $Script:sysvolAccessible
            $Script:sysvolAccessible = $null

            if (-not $sysvolAccessible) {
                if ((Test-SysvolAccessible) -eq $false) {
                    Show-Line "Skipped - SYSVOL not accessible" -Class Hint
                } else {
                    Show-Line "SYSVOL access failed - cannot analyze GPO local group assignments - SMB access failed (authentication/network issue)" -Class Finding
                }
                return
            }

            if (@($vulnerableGPOs).Count -gt 0) {
                # A local group assignment made by a policy that is not linked or not
                # enabled adds nobody to any group. Held back rather than dropped - see
                # Show-GPOInactiveSummary.
                #
                # Per finding, from the half it came out of. "Machine throughout" claimed
                # that the GPP Groups variant is read from the machine half as well, which
                # contradicted the GPOStatus computation two dozen lines above it: a
                # Preferences item under User\ is applied during user policy processing. A
                # GPO with its user half disabled therefore reported "User configuration
                # disabled" on the row and counted the finding as active, and one with its
                # computer half disabled held back a finding that does apply.
                $split = Split-GPOFindingByReach -Finding $vulnerableGPOs -GPOStatusMap $gpoStatusMap `
                    -GPOLinkage $gpoLinkage -ScopeProperty '_ReachScope'

                $shown = if ($IncludeInactive) { @($vulnerableGPOs) } else { @($split.Active) }

                # Held-back policies first, then the headline for the active ones, then the
                # active ones - the "Found ..." line heads the finding objects, not the
                # dampening block.
                Show-GPOInactiveSummary -Unlinked $split.Unlinked -Disabled $split.Disabled `
                    -Dormant $split.Dormant -Listed:$IncludeInactive

                # The headline takes the most severe assignment that applies, not Finding
                # whatever the rows say. Three assignments to Power Users, each rated Note by
                # this check itself, were announced in red as "vulnerable" - and the HTML
                # card takes its colour from that line.
                $severityRank = @{ 'Note' = 1; 'Hint' = 2; 'Finding' = 3 }
                $headlineClass = 'Note'
                foreach ($candidate in @($shown | Where-Object { @($split.Inactive) -notcontains $_ })) {
                    $candidateSeverity = [string]$candidate.Severity
                    if ($severityRank.ContainsKey($candidateSeverity) -and
                        $severityRank[$candidateSeverity] -gt $severityRank[$headlineClass]) {
                        $headlineClass = $candidateSeverity
                    }
                }

                if (@($shown).Count -gt 0) {
                    if ($headlineClass -eq 'Finding') {
                        Show-Line "Found $(@($shown).Count) vulnerable GPO local group assignment(s)" -Class Finding
                    } else {
                        Show-Line "Found $(@($shown).Count) GPO local group assignment(s)" -Class $headlineClass
                    }
                } else {
                    # Not Secure: the assignments exist, they just apply nowhere. Calling
                    # the domain clean here would be a different statement.
                    Show-Line "No local group assignment is made by a policy that is linked and enabled" -Class Note
                }

                foreach ($finding in $shown) {
                    $finding | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'GPOLocalGroup' -Force

                    # The reason the row is there, on the row. Get-GroupAssignmentSeverity
                    # computes it per target group and names a broad member in it, and it went
                    # to Risk - which $Script:ExcludeAttributes drops, so it reached neither
                    # the console nor a report row. RiskReason is what the scheduled task rows
                    # carry for the same purpose.
                    if ($finding.Risk) {
                        $finding | Add-Member -NotePropertyName 'RiskReason' -NotePropertyValue ([string]$finding.Risk) -Force
                    }

                    if (@($split.Inactive) -contains $finding) {
                        Show-Object $finding -Class Note
                    } else {
                        # The computed severity decides the class. Show-Object defaults to
                        # Standard, so the whole severity pipeline of this module - Finding for
                        # Administrators and the operator groups, Hint for the rest, escalated
                        # by a broad member - ended at the renderer's default, and every
                        # assignment looked alike.
                        $assignmentClass = [string]$finding.Severity
                        if (-not $severityRank.ContainsKey($assignmentClass)) { $assignmentClass = 'Hint' }
                        Show-Object $finding -Class $assignmentClass
                    }
                }
            } else {
                # The count says how many GPOs were looked at, not how many were readable.
                # Without the coverage line a scan that was denied every Policies folder
                # ends on a green "nothing found in N GPOs".
                $groupClass = 'Secure'
                if (Show-SYSVOLCoverageNote) { $groupClass = 'Note' }
                Show-Line "No vulnerable GPO local group assignments found in $(@($gpos).Count) analyzed GPO(s)" -Class $groupClass
            }

        } catch {
            Write-Log "[Get-GPOLocalGroupMembership] Error: $_" -Level Error
            Show-Line "Error during check - GPO local group assignments could not be evaluated: $_" -Class Finding
        }
    }

    end {
        Write-Log "[Get-GPOLocalGroupMembership] Check completed"
    }
}

# Helper Function: Get severity and risk for a group assignment
<#
.SYNOPSIS
    The display name of a target local group, for any BUILTIN group.

.DESCRIPTION
    All three parsers used to gate on $Script:LocalGroupSIDs.ContainsKey() and drop the
    entry otherwise, so a group that is not in the table produced no finding and no note -
    and the next gap in the table would be just as invisible as the operator groups were.

    A BUILTIN group (S-1-5-32-*) that is not in the table is resolved through
    ConvertFrom-SID and reported anyway; Get-GroupAssignmentSeverity gives it a Hint. An
    unresolvable one is reported under its raw SID, which is still enough to look up.

    Anything that is not a BUILTIN group returns $null and is skipped, as before: this
    check is about local group membership, and a domain group on the left-hand side of a
    Restricted Groups entry is a different question.

.PARAMETER SID
    The target group's SID.

.OUTPUTS
    The display name, or $null when the SID is not a BUILTIN group.
#>
function Resolve-LocalGroupTargetName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$SID
    )

    $trimmed = ([string]$SID).Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed)) { return $null }

    if ($Script:LocalGroupSIDs.ContainsKey($trimmed)) {
        return $Script:LocalGroupSIDs[$trimmed]
    }

    if ($trimmed -notmatch '^S-1-5-32-\d+$') { return $null }

    $resolved = $null
    try { $resolved = ConvertFrom-SID -SID $trimmed } catch { $resolved = $null }
    if ($resolved -and $resolved -ne $trimmed) {
        Write-Log "[Resolve-LocalGroupTargetName] Target group $trimmed is not in the table - reported as '$resolved'"
        return [string]$resolved
    }

    Write-Log "[Resolve-LocalGroupTargetName] Target group $trimmed is not in the table and did not resolve to a name"
    return $trimmed
}

function Get-GroupAssignmentSeverity {
    param(
        [string]$GroupSID,
        [array]$RiskyMembers
    )

    $config = $Script:GroupSeverityConfig[$GroupSID]
    if (-not $config) {
        # A group this check has no configuration for: a BUILTIN group outside the curated
        # table, or a custom local group that is reported because of its members. Hint,
        # and it stays Hint even with a broad principal among them - without knowing what
        # the group is, "Everyone was added to it" is a reason to look rather than a
        # verdict.
        #
        # The members are named in the risk text all the same. This path used to return
        # before the escalation block below, so the one line an operator reads never said
        # why the row was there.
        $fallbackRisk = "Domain accounts added to local group"
        if (@($RiskyMembers).Count -gt 0) {
            $fallbackRisk = "$fallbackRisk (includes: $(@($RiskyMembers) -join ', '))"
        }
        return @{ Severity = "Hint"; Risk = $fallbackRisk }
    }

    $severity = $config.Severity
    $risk = $config.Risk

    # Escalate severity if risky members (Everyone, Domain Users, etc.) are present
    # Using standard adPEAS severity values: Note -> Hint -> Finding
    if (@($RiskyMembers).Count -gt 0) {
        $riskyList = $RiskyMembers -join ', '

        # Escalate: Note->Hint, Hint->Finding, Finding stays Finding
        $severity = switch ($severity) {
            "Note"     { "Hint" }
            "Hint"     { "Finding" }
            "Finding"  { "Finding" }
            default    { $severity }
        }

        $risk = "$risk (includes: $riskyList)"
    }

    return @{ Severity = $severity; Risk = $risk }
}

<#
.SYNOPSIS
    Normalizes one Restricted Groups entry to a SID.

.DESCRIPTION
    A [Group Membership] entry may name its principal either as a SID with the GptTmpl.inf
    '*' prefix or as a plain account name. Only the SID form used to be parsed, so a
    name-keyed entry - which the Group Policy editor writes for a group it cannot resolve
    to a SID, and which is common on localized domains - produced no finding at all.

    A name is resolved through ConvertTo-SID so every downstream comparison stays SID based
    and language independent. An unresolvable name is returned unchanged, which simply fails
    the later privileged-group lookup instead of throwing.

.NOTES
    Internal helper function
#>
function Resolve-RestrictedGroupSID {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Identity
    )

    $trimmed = ([string]$Identity).Trim().TrimStart('*').Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed)) { return $trimmed }
    if ($trimmed -match '^S-1-') { return $trimmed }

    try {
        $resolved = ConvertTo-SID -Identity $trimmed
        if ($resolved) {
            Write-Log "[Resolve-RestrictedGroupSID] Resolved name '$trimmed' to $resolved"
            return [string]$resolved
        }
    } catch {
        Write-Log "[Resolve-RestrictedGroupSID] Could not resolve '$trimmed' to a SID: $_"
    }

    return $trimmed
}

<#
.SYNOPSIS
    One member of a group assignment: the name to show, and whether the member is a group
    that holds most of the domain.

.DESCRIPTION
    The three parsers wrote this test three times, each with the private list in
    $Script:RiskySIDs and a '-513' beside it. Test-IsBroadTrustee asks both of the
    project's lists, which is what lets Domain Computers, Domain Guests, BUILTIN\Users,
    Interactive and Network escalate an assignment as Domain Users always did.

    A broad group is shown under its canonical English name; any other member under
    -FallbackName when the caller has one, and otherwise under its resolved name.

.NOTES
    Internal helper function
#>
function Resolve-GroupMemberRisk {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$MemberSID,

        [Parameter(Mandatory = $false)]
        [string]$FallbackName
    )

    $broadRIDNames = @{ '-513' = 'Domain Users'; '-514' = 'Domain Guests'; '-515' = 'Domain Computers' }

    $isBroad = Test-IsBroadTrustee -SID $MemberSID
    $memberName = $null
    if ($Script:RiskySIDs -and $Script:RiskySIDs.ContainsKey($MemberSID)) {
        $memberName = $Script:RiskySIDs[$MemberSID]
    } elseif ($isBroad) {
        $suffix = Test-IsBroadGroupRID -SID $MemberSID
        if ($suffix -and $broadRIDNames.ContainsKey($suffix)) { $memberName = $broadRIDNames[$suffix] }
    }
    if (-not $memberName) {
        $memberName = if ($FallbackName) { $FallbackName } else { ConvertFrom-SID -SID $MemberSID }
    }

    [PSCustomObject]@{ Name = $memberName; IsBroad = [bool]$isBroad }
}

# Helper Function: Parse Restricted Groups (GptTmpl.inf)
function Parse-RestrictedGroups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath,

        [Parameter(Mandatory=$true)]
        [string]$GPOName,

        [Parameter(Mandatory=$true)]
        [string]$GPOGUID,

        # Optional: a GPO whose gPCFileSysPath the directory does not record yields an
        # empty string here, and an empty row is skipped rather than printed blank.
        [Parameter(Mandatory=$false)]
        [string]$GPOPath
    )

    try {
        $content = Get-CachedSYSVOLContent -Path $FilePath
        if (-not $content) { return @() }
        $findings = @()

        if ($content -match '(?s)\[Group Membership\](.*?)(\[|$)') {
            $groupMembershipSection = $Matches[1]
            $lines = $groupMembershipSection -split "`n"

            foreach ($line in $lines) {
                $line = $line.Trim()

                if ($line -match '^\*?(.+?)__Members\s*=\s*(.*)$') {
                    # Variant 1: *LOCAL_GROUP_SID__Members = *SID1, *SID2
                    # The local group is on the LEFT, members are on the RIGHT
                    #
                    # The leading * is optional because real GptTmpl.inf files also key the
                    # entry by group NAME. Requiring the * dropped those lines without a
                    # word, which was a silent detection gap on localized domains.
                    #
                    # (.*) rather than (.+): "*S-1-5-32-544__Members =" with nothing after
                    # it is the authoritative instruction to EMPTY the local
                    # administrators, and it used to match neither branch and vanish. That
                    # is an operational risk and a sabotage mechanism, and it was the one
                    # line in the file that said so.
                    $groupSID = Resolve-RestrictedGroupSID -Identity $Matches[1]

                    # Both sides through the resolver. Only the group was, so a
                    # name-keyed entry like "Administrators__Members = CONTOSO\Domain
                    # Users" left the member as a literal name: $Script:RiskySIDs never
                    # matched it, '-513$' never matched it, $riskyMembers stayed empty and
                    # Get-GroupAssignmentSeverity did not escalate. "Domain Users in
                    # Remote Desktop Users on every machine" came out yellow, with no
                    # coloured member and no finding card. The Memberof branch below
                    # resolved both sides all along.
                    $memberSIDs = $Matches[2] -split ',' |
                        ForEach-Object { Resolve-RestrictedGroupSID -Identity $_ }

                    # Resolve-LocalGroupTargetName rather than a lookup in the table: a
                    # BUILTIN group that is not in the table is reported too, under its
                    # resolved name and as a Hint. The table used to be the gate, so the
                    # next group missing from it would be as invisible as Server Operators
                    # was - and that one is domain compromise on a domain controller.
                    $groupName = Resolve-LocalGroupTargetName -SID $groupSID
                    if ($groupName) {

                        $memberNames = @()
                        $riskyMembers = @()

                        foreach ($memberSID in $memberSIDs) {
                            if ([string]::IsNullOrWhiteSpace($memberSID)) { continue }

                            $memberRisk = Resolve-GroupMemberRisk -MemberSID $memberSID
                            $memberName = $memberRisk.Name
                            if ($memberRisk.IsBroad) { $riskyMembers += $memberName }

                            $memberNames += $memberName
                        }

                        # Get severity from centralized configuration
                        $severityResult = Get-GroupAssignmentSeverity -GroupSID $groupSID -RiskyMembers $riskyMembers

                        # A Members list REPLACES the group on every policy refresh, which
                        # the report never said: the attribute was called MembersAdded and
                        # the risk text read "added to local Administrators" for both
                        # keywords. A list naming one group therefore removes the local
                        # administrator account and Domain Admins from every machine in
                        # scope, and an empty list removes everybody - operationally
                        # relevant, and a persistence and sabotage mechanism too.
                        $membersMode = 'Members (replaces the group on every refresh)'
                        $emptiesGroup = (@($memberNames).Count -eq 0)

                        $finding = [PSCustomObject]@{
                            GPOName = $GPOName
                            GPOGUID = $GPOGUID
                            GPOPath = $GPOPath
                            SourceFile = Get-GPORelativePath -Path $FilePath
                            Type = "Restricted Groups"
                            TargetGroup = $groupName
                            TargetGroupSID = $groupSID
                            Mode = $membersMode
                            MembersAdded = $memberNames
                            MemberSIDs = $memberSIDs
                            RiskyMembers = $riskyMembers
                            Severity = $severityResult.Severity
                            Risk = $severityResult.Risk
                        }

                        if ($emptiesGroup) {
                            $finding | Add-Member -NotePropertyName 'groupEmptied' -NotePropertyValue (
                                "This policy empties $groupName on every machine in scope - the member list is blank, so every existing member is removed at each refresh"
                            ) -Force
                            $finding.Risk = "The policy sets $groupName to an empty list, which removes every member on every machine in scope at the next refresh - including the local administrator account and any domain group that was there."
                        }

                        $findings += $finding
                    }
                }
                elseif ($line -match '^\*?(.+?)__Memberof\s*=\s*(.+)$') {
                    # Variant 2: *DOMAIN_SID__Memberof = *LOCAL_GROUP_SID1, *LOCAL_GROUP_SID2
                    # The account/group being added is on the LEFT, target local groups are on the RIGHT
                    # One finding per target local group (each may have different severity)
                    # The leading * is optional here for the same reason as in variant 1.
                    $memberSID = Resolve-RestrictedGroupSID -Identity $Matches[1]
                    $targetGroupSIDs = $Matches[2] -split ',' |
                        ForEach-Object { Resolve-RestrictedGroupSID -Identity $_ }

                    # Resolve the member name and check if it is itself a risky principal
                    $riskyMembers = @()
                    $memberRisk = Resolve-GroupMemberRisk -MemberSID $memberSID
                    $memberName = $memberRisk.Name
                    if ($memberRisk.IsBroad) { $riskyMembers += $memberName }

                    # Create one finding per target local group
                    foreach ($groupSID in $targetGroupSIDs) {
                        if ([string]::IsNullOrWhiteSpace($groupSID)) { continue }

                        $groupName = Resolve-LocalGroupTargetName -SID $groupSID
                        if ($groupName) {

                            $severityResult = Get-GroupAssignmentSeverity -GroupSID $groupSID -RiskyMembers $riskyMembers

                            $findings += [PSCustomObject]@{
                                GPOName = $GPOName
                                GPOGUID = $GPOGUID
                                GPOPath = $GPOPath
                                SourceFile = Get-GPORelativePath -Path $FilePath
                                Type = "Restricted Groups"
                                TargetGroup = $groupName
                                TargetGroupSID = $groupSID
                                # Memberof only adds, and that difference decides what the
                                # policy does to the members already there.
                                Mode = 'Memberof (adds to the group)'
                                MembersAdded = @($memberName)
                                MemberSIDs = @($memberSID)
                                RiskyMembers = $riskyMembers
                                Severity = $severityResult.Severity
                                Risk = $severityResult.Risk
                            }
                        }
                    }
                }
            }
        }

        return $findings
    } catch {
        Write-Log "[Parse-RestrictedGroups] Error parsing $FilePath : $_"
        return $null
    }
}

# Helper Function: Parse Group Policy Preferences Groups (Groups.xml)
function Parse-GPPGroups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath,

        [Parameter(Mandatory=$true)]
        [string]$GPOName,

        [Parameter(Mandatory=$true)]
        [string]$GPOGUID,

        # Optional: a GPO whose gPCFileSysPath the directory does not record yields an
        # empty string here, and an empty row is skipped rather than printed blank.
        [Parameter(Mandatory=$false)]
        [string]$GPOPath
    )

    try {
        # Use XmlDocument.Load() to honor the XML encoding declaration / BOM.
        # Get-Content defaults to the ANSI code page in Windows PowerShell 5.1,
        # which mojibakes UTF-8 Groups.xml: a localized group name containing an umlaut
        # then decodes into two wrong characters and no longer matches.
        $xmlContent = New-Object System.Xml.XmlDocument
        $xmlContent.Load($FilePath)
        $findings = @()

        $groups = $xmlContent.Groups.Group

        foreach ($group in $groups) {
            # Use groupSid attribute (SID-based, language-independent)
            $groupSID = [string]$group.Properties.groupSid
            $groupNameAttr = [string]$group.Properties.groupName

            # A <Group> element without groupSid used to be dropped where it stood. GPMC
            # writes the attribute for the builtins, but a Groups.xml written by hand, one
            # produced by a migration and every custom local group do not have it - and
            # the Restricted Groups parser has had Resolve-RestrictedGroupSID for exactly
            # this case all along. The asymmetry meant an item adding Everyone to a group
            # called "LocalAdmins" was never read at all.
            if (-not $groupSID -and $groupNameAttr) {
                $groupSID = [string](Resolve-RestrictedGroupSID -Identity $groupNameAttr)
            }

            # Known BUILTIN group, resolved BUILTIN group, or something else entirely.
            $canonicalGroupName = Resolve-LocalGroupTargetName -SID $groupSID
            $targetGroupKnown = [bool]$canonicalGroupName
            if (-not $targetGroupKnown) {
                # Parsed anyway, and held to the end: an item that adds Everyone to a
                # group this check cannot classify is still worth a line, because whether
                # that group is privileged depends on a nesting another policy may well
                # establish - which the old code did not even look for. Without a risky
                # member such an item is dropped at the bottom of this loop.
                $canonicalGroupName = if ($groupNameAttr) { $groupNameAttr } elseif ($groupSID) { $groupSID } else { 'Unknown group' }
            }

            $members = @()
            $memberSIDs = @()
            $riskyMembers = @()
            $removedMembers = @()

            # The item-level semantics, which used to be dropped: action C/R/U/D on the
            # item, and the two flags that clear the group before the members are applied.
            # A Replace item with deleteAllUsers and deleteAllGroups empties the local
            # administrators on every machine in scope and then adds its own list - the
            # report showed only the addition, so the most dangerous half of the
            # configuration ("Domain Admins is removed from the local administrators of
            # every machine in scope") was not in it at all. That is both an operational
            # risk and a classic persistence mechanism.
            $itemAction = [string]$group.Properties.action
            if ([string]::IsNullOrWhiteSpace($itemAction)) { $itemAction = 'U' }
            $itemAction = $itemAction.ToUpper()

            $itemDisabled = ([string]$group.disabled -eq '1')
            $deleteAllUsers = ([string]$group.Properties.deleteAllUsers -eq '1')
            $deleteAllGroups = ([string]$group.Properties.deleteAllGroups -eq '1')

            # A disabled item is never applied, and a Delete item removes the group rather
            # than configuring its membership.
            if ($itemDisabled) { continue }

            if ($group.Properties.Members) {
                foreach ($member in $group.Properties.Members.Member) {
                    # REMOVE is the other half of the configuration and was skipped
                    # silently. It is reported separately below.
                    if ($member.action -eq 'REMOVE') {
                        $removedName = [string]$member.name
                        if ($member.sid -and $Script:RiskySIDs.ContainsKey([string]$member.sid)) {
                            $removedName = $Script:RiskySIDs[[string]$member.sid]
                        } elseif (-not $removedName -and $member.sid) {
                            $removedName = ConvertFrom-SID -SID ([string]$member.sid)
                        }
                        if ($removedName) { $removedMembers += $removedName }
                        continue
                    }

                    # Only process ADD actions
                    if ($member.action -ne 'ADD') { continue }

                    $memberName = $member.name
                    $memberSID = $member.sid

                    # A Member with a name but no SID used to skip the whole risk
                    # classification, so "Domain Users" written without its SID was not
                    # recognised as a risky principal.
                    if (-not $memberSID -and $memberName) {
                        $memberSID = ConvertTo-SID -Identity ([string]$memberName)
                    }

                    # A risky principal is displayed under its canonical English name, not
                    # under the name this XML happens to carry. Groups.xml is written by
                    # whichever console authored it, so Everyone arrives as "Alla" on a
                    # Swedish domain - and the report then named the same principal twice
                    # under two different names, "Alla" in MembersAdded and "Everyone" in
                    # RiskyMembers. Classification is SID based either way; this decides
                    # only which of the two names is shown, and canonicalizing is what lets
                    # the risky entries be recognized inside the member list itself.
                    #
                    # The two Restricted Groups parsers above already name their members
                    # this way; only the preferences parser did not.
                    if ($memberSID) {
                        # Language-independent: decided by SID. A Member element carrying
                        # only a SID gets its resolved name, or the group would look
                        # emptier than it is.
                        $memberRisk = Resolve-GroupMemberRisk -MemberSID ([string]$memberSID) -FallbackName ([string]$memberName)
                        $memberName = $memberRisk.Name
                        if ($memberRisk.IsBroad) { $riskyMembers += $memberName }

                        $memberSIDs += $memberSID
                    }

                    if ($memberName) {
                        $members += $memberName
                    }
                }
            }

            # An item that only removes members, or only clears the group, carries no
            # MembersAdded and used to be dropped here - which is where the removal half
            # of a Replace item disappeared.
            $clearsGroup = ($deleteAllUsers -or $deleteAllGroups)
            if (@($members).Count -eq 0 -and @($removedMembers).Count -eq 0 -and -not $clearsGroup) {
                continue
            }

            # A group that is not a BUILTIN one is only reported when a broad principal is
            # involved - see the note at the top of this loop. Everything else about it is
            # unknowable from one policy.
            if (-not $targetGroupKnown -and @($riskyMembers).Count -eq 0) {
                Write-Log "[Parse-GPPGroups] Item for '$canonicalGroupName' names no BUILTIN group and no broad principal - not reported"
                continue
            }

            # Get severity from centralized configuration
            $severityResult = Get-GroupAssignmentSeverity -GroupSID $groupSID -RiskyMembers $riskyMembers

            $finding = [PSCustomObject]@{
                GPOName = $GPOName
                GPOGUID = $GPOGUID
                GPOPath = $GPOPath
                SourceFile = Get-GPORelativePath -Path $FilePath
                Type = "Group Policy Preferences"
                TargetGroup = $canonicalGroupName
                TargetGroupSID = $groupSID
                Mode = "$itemAction (Create/Replace/Update/Delete)"
                MembersAdded = $members
                MemberSIDs = $memberSIDs
                RiskyMembers = $riskyMembers
                Severity = $severityResult.Severity
                Risk = $severityResult.Risk
            }

            if (@($removedMembers).Count -gt 0) {
                $finding | Add-Member -NotePropertyName 'MembersRemoved' -NotePropertyValue $removedMembers -Force
            }

            if ($clearsGroup) {
                $cleared = @()
                if ($deleteAllUsers)  { $cleared += 'all user members' }
                if ($deleteAllGroups) { $cleared += 'all group members' }
                $finding | Add-Member -NotePropertyName 'groupEmptied' -NotePropertyValue (
                    "This item removes $($cleared -join ' and ') of $canonicalGroupName on every machine in scope before applying its own list"
                ) -Force
            }

            $findings += $finding
        }

        return $findings
    } catch {
        Write-Log "[Parse-GPPGroups] Error parsing $FilePath : $_"
        return $null
    }
}

