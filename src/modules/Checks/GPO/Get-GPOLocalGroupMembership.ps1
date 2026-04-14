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
        [System.Management.Automation.PSCredential]$Credential
    )

    begin {
        Write-Log "[Get-GPOLocalGroupMembership] Starting check"

        # Well-known SIDs for local groups
        $Script:LocalGroupSIDs = @{
            'S-1-5-32-544' = 'Administrators'
            'S-1-5-32-555' = 'Remote Desktop Users'
            'S-1-5-32-580' = 'Remote Management Users'
            'S-1-5-32-551' = 'Backup Operators'
            'S-1-5-32-547' = 'Power Users'
        }

        # Well-known SIDs for risky assignments (Everyone, Authenticated Users, etc.)
        $Script:RiskySIDs = @{
            'S-1-1-0' = 'Everyone'
            'S-1-5-11' = 'Authenticated Users'
            'S-1-5-7' = 'Anonymous Logon'
        }

        # Base severity per target group (using standard adPEAS severity values)
        # Finding = Critical/High issues, Hint = Medium issues, Note = Low/Info
        $Script:GroupSeverityConfig = @{
            'S-1-5-32-544' = @{ Severity = "Finding"; Risk = "Domain accounts added to local Administrators" }
            'S-1-5-32-555' = @{ Severity = "Hint"; Risk = "Domain accounts added to Remote Desktop Users" }
            'S-1-5-32-580' = @{ Severity = "Hint"; Risk = "Domain accounts added to Remote Management Users" }
            'S-1-5-32-551' = @{ Severity = "Hint"; Risk = "Domain accounts added to Backup Operators" }
            'S-1-5-32-547' = @{ Severity = "Note"; Risk = "Domain accounts added to Power Users" }
        }
    }

    process {
        try {
            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @PSBoundParameters)) {
                return
            }

            $domainFQDN = $Script:LDAPContext.Domain
            $Script:vulnerableGPOs = @()

            Show-SubHeader "Searching for GPO local group assignments..." -ObjectType "GPOLocalGroup"

            $gpos = Get-DomainGPO @PSBoundParameters

            if (-not $gpos -or @($gpos).Count -eq 0) {
                Show-Line "No GPOs found in domain" -Class Note
                return
            }

            $gpoLinkage = Get-GPOLinkage

            # Build GPO GUID to name mapping for later lookup
            $gpoNameMap = @{}
            foreach ($gpo in $gpos) {
                $gpoNameMap[$gpo.Name] = $gpo.DisplayName
            }

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
                            $restrictedGroupsFindings = Parse-RestrictedGroups -FilePath $file.FullName -GPOName $gpoName -GPOGUID $gpoGUID

                            if ($restrictedGroupsFindings) {
                                $linkedOUs = @()
                                if ($gpoLinkage.ContainsKey($gpoGUID)) {
                                    $linkedOUs = $gpoLinkage[$gpoGUID]
                                }

                                foreach ($finding in $restrictedGroupsFindings) {
                                    $finding | Add-Member -NotePropertyName 'LinkedOUs' -NotePropertyValue $linkedOUs -Force
                                    $finding | Add-Member -NotePropertyName 'LinkedOUCount' -NotePropertyValue $linkedOUs.Count -Force
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
                            $gppGroupsFindings = Parse-GPPGroups -FilePath $file.FullName -GPOName $gpoName -GPOGUID $gpoGUID

                            if ($gppGroupsFindings) {
                                $linkedOUs = @()
                                if ($gpoLinkage.ContainsKey($gpoGUID)) {
                                    $linkedOUs = $gpoLinkage[$gpoGUID]
                                }

                                foreach ($finding in $gppGroupsFindings) {
                                    $finding | Add-Member -NotePropertyName 'LinkedOUs' -NotePropertyValue $linkedOUs -Force
                                    $finding | Add-Member -NotePropertyName 'LinkedOUCount' -NotePropertyValue $linkedOUs.Count -Force
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
                Show-Line "Found $(@($vulnerableGPOs).Count) vulnerable GPO local group assignment(s)" -Class Finding

                foreach ($finding in $vulnerableGPOs) {
                    $finding | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'GPOLocalGroup' -Force
                    Show-Object $finding
                }
            } else {
                Show-Line "No vulnerable GPO local group assignments found in $(@($gpos).Count) analyzed GPO(s)" -Class Secure
            }

        } catch {
            Write-Log "[Get-GPOLocalGroupMembership] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-GPOLocalGroupMembership] Check completed"
    }
}

# Helper Function: Get severity and risk for a group assignment
function Get-GroupAssignmentSeverity {
    param(
        [string]$GroupSID,
        [array]$RiskyMembers
    )

    $config = $Script:GroupSeverityConfig[$GroupSID]
    if (-not $config) {
        return @{ Severity = "Hint"; Risk = "Domain accounts added to local group" }
    }

    $severity = $config.Severity
    $risk = $config.Risk

    # Escalate severity if risky members (Everyone, Domain Users, etc.) are present
    # Using standard adPEAS severity values: Note → Hint → Finding
    if (@($RiskyMembers).Count -gt 0) {
        $riskyList = $RiskyMembers -join ', '

        # Escalate: Note→Hint, Hint→Finding, Finding stays Finding
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

# Helper Function: Parse Restricted Groups (GptTmpl.inf)
function Parse-RestrictedGroups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath,

        [Parameter(Mandatory=$true)]
        [string]$GPOName,

        [Parameter(Mandatory=$true)]
        [string]$GPOGUID
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

                if ($line -match '^\*(.+?)__Members\s*=\s*(.+)$') {
                    # Variant 1: *LOCAL_GROUP_SID__Members = *SID1, *SID2
                    # The local group is on the LEFT, members are on the RIGHT
                    $groupSID = $Matches[1]
                    $memberSIDs = $Matches[2] -split ',' | ForEach-Object { $_.Trim().TrimStart('*') }

                    if ($Script:LocalGroupSIDs.ContainsKey($groupSID)) {
                        $groupName = $Script:LocalGroupSIDs[$groupSID]

                        $memberNames = @()
                        $riskyMembers = @()

                        foreach ($memberSID in $memberSIDs) {
                            if ([string]::IsNullOrWhiteSpace($memberSID)) { continue }

                            $memberName = ""

                            if ($Script:RiskySIDs.ContainsKey($memberSID)) {
                                $memberName = $Script:RiskySIDs[$memberSID]
                                $riskyMembers += $memberName
                            } elseif ($memberSID -match '-513$') {
                                $memberName = "Domain Users"
                                $riskyMembers += $memberName
                            } else {
                                $memberName = ConvertFrom-SID -SID $memberSID
                            }

                            $memberNames += $memberName
                        }

                        # Get severity from centralized configuration
                        $severityResult = Get-GroupAssignmentSeverity -GroupSID $groupSID -RiskyMembers $riskyMembers

                        $findings += [PSCustomObject]@{
                            GPOName = $GPOName
                            GPOGUID = $GPOGUID
                            Type = "Restricted Groups"
                            TargetGroup = $groupName
                            TargetGroupSID = $groupSID
                            MembersAdded = $memberNames
                            MemberSIDs = $memberSIDs
                            RiskyMembers = $riskyMembers
                            Severity = $severityResult.Severity
                            Risk = $severityResult.Risk
                        }
                    }
                }
                elseif ($line -match '^\*(.+?)__Memberof\s*=\s*(.+)$') {
                    # Variant 2: *DOMAIN_SID__Memberof = *LOCAL_GROUP_SID1, *LOCAL_GROUP_SID2
                    # The account/group being added is on the LEFT, target local groups are on the RIGHT
                    # One finding per target local group (each may have different severity)
                    $memberSID = $Matches[1]
                    $targetGroupSIDs = $Matches[2] -split ',' | ForEach-Object { $_.Trim().TrimStart('*') }

                    # Resolve the member name and check if it is itself a risky principal
                    $memberName = ""
                    $riskyMembers = @()

                    if ($Script:RiskySIDs.ContainsKey($memberSID)) {
                        $memberName = $Script:RiskySIDs[$memberSID]
                        $riskyMembers += $memberName
                    } elseif ($memberSID -match '-513$') {
                        $memberName = "Domain Users"
                        $riskyMembers += $memberName
                    } else {
                        $memberName = ConvertFrom-SID -SID $memberSID
                    }

                    # Create one finding per target local group
                    foreach ($groupSID in $targetGroupSIDs) {
                        if ([string]::IsNullOrWhiteSpace($groupSID)) { continue }

                        if ($Script:LocalGroupSIDs.ContainsKey($groupSID)) {
                            $groupName = $Script:LocalGroupSIDs[$groupSID]

                            $severityResult = Get-GroupAssignmentSeverity -GroupSID $groupSID -RiskyMembers $riskyMembers

                            $findings += [PSCustomObject]@{
                                GPOName = $GPOName
                                GPOGUID = $GPOGUID
                                Type = "Restricted Groups"
                                TargetGroup = $groupName
                                TargetGroupSID = $groupSID
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
        [string]$GPOGUID
    )

    try {
        [xml]$xmlContent = Get-Content -Path $FilePath -ErrorAction Stop
        $findings = @()

        $groups = $xmlContent.Groups.Group

        foreach ($group in $groups) {
            # Use groupSid attribute (SID-based, language-independent)
            $groupSID = $group.Properties.groupSid

            # Skip if no SID or not a target group (use centrally defined SIDs)
            if (-not $groupSID -or -not $Script:LocalGroupSIDs.ContainsKey($groupSID)) {
                continue
            }

            # Get canonical group name from SID
            $canonicalGroupName = $Script:LocalGroupSIDs[$groupSID]

            $members = @()
            $memberSIDs = @()
            $riskyMembers = @()

            if ($group.Properties.Members) {
                foreach ($member in $group.Properties.Members.Member) {
                    # Only process ADD actions
                    if ($member.action -ne 'ADD') { continue }

                    $memberName = $member.name
                    $memberSID = $member.sid

                    if ($memberName) {
                        $members += $memberName
                    }

                    if ($memberSID) {
                        $memberSIDs += $memberSID

                        # Check for risky SIDs (language-independent)
                        if ($Script:RiskySIDs.ContainsKey($memberSID)) {
                            $riskyMembers += $Script:RiskySIDs[$memberSID]
                        } elseif ($memberSID -match '-513$') {
                            # Domain Users (ends with -513)
                            $riskyMembers += "Domain Users"
                        }
                    }
                }
            }

            if (@($members).Count -eq 0) {
                continue
            }

            # Get severity from centralized configuration
            $severityResult = Get-GroupAssignmentSeverity -GroupSID $groupSID -RiskyMembers $riskyMembers

            $findings += [PSCustomObject]@{
                GPOName = $GPOName
                GPOGUID = $GPOGUID
                Type = "Group Policy Preferences"
                TargetGroup = $canonicalGroupName
                TargetGroupSID = $groupSID
                MembersAdded = $members
                MemberSIDs = $memberSIDs
                RiskyMembers = $riskyMembers
                Severity = $severityResult.Severity
                Risk = $severityResult.Risk
            }
        }

        return $findings
    } catch {
        Write-Log "[Parse-GPPGroups] Error parsing $FilePath : $_"
        return $null
    }
}

