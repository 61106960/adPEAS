<#
.SYNOPSIS
    Identifies accounts with password reset rights on OUs containing privileged users.

.DESCRIPTION
    Scans Organizational Units that contain members of privileged groups for principals
    who have password reset extended rights. Password reset rights allow an account to
    reset another user's password without knowing the current password.

    Privileged groups analyzed (SID-based, language-independent):

    Domain Groups:
    - Domain Admins (RID 512)
    - Enterprise Admins (RID 519)
    - Schema Admins (RID 518)
    - Group Policy Creator Owners (RID 520)
    - Key Admins (RID 526)
    - Enterprise Key Admins (RID 527)
    - Cert Publishers (RID 517)

    Built-in Groups:
    - Administrators (S-1-5-32-544)
    - Account Operators (S-1-5-32-548)
    - Server Operators (S-1-5-32-549)
    - Print Operators (S-1-5-32-550)
    - Backup Operators (S-1-5-32-551)
    - Hyper-V Administrators (S-1-5-32-578)
    - Remote Management Users (S-1-5-32-580)

    The module identifies OUs by analyzing where members of these groups are actually located,
    not by guessing OU names. Uses LDAP_MATCHING_RULE_IN_CHAIN (OID 1.2.840.113556.1.4.1941)
    for recursive group membership resolution, finding users in nested groups as well.

.PARAMETER Domain
    Domain to query. Uses current domain if not specified.

.PARAMETER Server
    Domain Controller to query. Uses auto-discovery if not specified.

.PARAMETER Credential
    PSCredential object for authentication.

.PARAMETER IncludeAllOUs
    Analyze all OUs (not just those containing privileged users).

.EXAMPLE
    Get-PasswordResetRights
    Scans OUs containing privileged users for password reset rights.

.EXAMPLE
    Get-PasswordResetRights -IncludeAllOUs
    Scans all OUs in the domain.

.EXAMPLE
    Get-PasswordResetRights -Domain "contoso.com" -Credential (Get-Credential)
    Scans with alternate credentials.

.OUTPUTS
    Findings of non-privileged accounts with password reset rights on critical OUs.

.NOTES
    Category: Rights
    Author: Alexander Sturz (@_61106960_)
#>

function Get-PasswordResetRights {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [switch]$IncludePrivileged,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeAllOUs
    )

    begin {
        Write-Log "[Get-PasswordResetRights] Starting check"
    }

    process {
        try {
            # Build connection parameters (exclude IncludePrivileged and IncludeAllOUs which are not connection parameters)
            $connectionParams = @{}
            if ($Domain) { $connectionParams['Domain'] = $Domain }
            if ($Server) { $connectionParams['Server'] = $Server }
            if ($Credential) { $connectionParams['Credential'] = $Credential }

            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @connectionParams)) {
                return
            }

            $domainSID = $Script:LDAPContext.DomainSID
            $privilegedOUs = @{}  # Hashtable to deduplicate OUs

            Show-SubHeader "Analyzing password reset rights on OUs with privileged users..." -ObjectType "PasswordResetRight"

            if ($IncludeAllOUs) {
                # Analyze all OUs
                $allOUs = Get-DomainObject -LDAPFilter "(objectClass=organizationalUnit)" @connectionParams

                if ($allOUs) {
                    foreach ($ou in $allOUs) {
                        $ouDN = $ou.distinguishedName
                        if (-not $privilegedOUs.ContainsKey($ouDN)) {
                            $privilegedOUs[$ouDN] = [PSCustomObject]@{
                                DN = $ouDN
                                Name = $ou.name
                                Type = "All OUs"
                                PrivilegedUsers = @()
                            }
                        }
                    }
                }
                Write-Log "[Get-PasswordResetRights] Analyzing all $($privilegedOUs.Keys.Count) OUs"
            } else {
                # Find OUs containing members of privileged groups (SID-based)
                # Combine domain-relative RIDs and well-known SIDs into unified list
                $privilegedGroups = @(
                    # Domain-relative groups (RID combined with domain SID)
                    @{ SID = "$domainSID-512"; Name = 'Domain Admins' },
                    @{ SID = "$domainSID-519"; Name = 'Enterprise Admins' },
                    @{ SID = "$domainSID-518"; Name = 'Schema Admins' },
                    @{ SID = "$domainSID-520"; Name = 'Group Policy Creator Owners' },
                    @{ SID = "$domainSID-526"; Name = 'Key Admins' },
                    @{ SID = "$domainSID-527"; Name = 'Enterprise Key Admins' },
                    @{ SID = "$domainSID-517"; Name = 'Cert Publishers' },
                    # Well-known built-in groups (fixed SIDs)
                    @{ SID = 'S-1-5-32-544'; Name = 'Administrators' },
                    @{ SID = 'S-1-5-32-548'; Name = 'Account Operators' },
                    @{ SID = 'S-1-5-32-549'; Name = 'Server Operators' },
                    @{ SID = 'S-1-5-32-550'; Name = 'Print Operators' },
                    @{ SID = 'S-1-5-32-551'; Name = 'Backup Operators' },
                    @{ SID = 'S-1-5-32-578'; Name = 'Hyper-V Administrators' },
                    @{ SID = 'S-1-5-32-580'; Name = 'Remote Management Users' }
                )

                # Process all privileged groups (using LDAP_MATCHING_RULE_IN_CHAIN for recursive lookup)
                foreach ($groupInfo in $privilegedGroups) {
                    $groupSID = $groupInfo.SID
                    $groupName = $groupInfo.Name

                    Write-Log "[Get-PasswordResetRights] Analyzing members of $groupName ($groupSID) (recursive)"

                    # Get group by SID
                    $groupSIDHex = ConvertTo-LDAPSIDHex -SID $groupSID
                    if (-not $groupSIDHex) { continue }

                    # First get the group DN (use [0] to handle referral-chasing returning multiple results)
                    $group = @(Get-DomainObject -LDAPFilter "(objectSid=$groupSIDHex)" @connectionParams)[0]
                    if (-not $group) {
                        Write-Log "[Get-PasswordResetRights] Group $groupName not found"
                        continue
                    }

                    $groupDN = $group.distinguishedName
                    # Escape DN for LDAP filter to prevent injection (RFC 4515)
                    $escapedGroupDN = Escape-LDAPFilterDN -DistinguishedName $groupDN

                    # Get ALL members recursively using LDAP_MATCHING_RULE_IN_CHAIN (OID 1.2.840.113556.1.4.1941)
                    # This finds users who are members directly OR through nested group membership
                    $members = Get-DomainUser -LDAPFilter "(memberOf:1.2.840.113556.1.4.1941:=$escapedGroupDN)" @connectionParams

                    if ($members) {
                        foreach ($member in $members) {
                            $memberDN = $member.distinguishedName
                            $memberName = $member.sAMAccountName

                            # Extract parent OU/Container from member DN
                            if ($memberDN -match '^CN=[^,]+,(.+)$') {
                                $parentDN = $Matches[1]

                                if (-not $privilegedOUs.ContainsKey($parentDN)) {
                                    # Determine if it's an OU or Container
                                    $ouType = if ($parentDN -match '^OU=') { "OU" } else { "Container" }

                                    $privilegedOUs[$parentDN] = [PSCustomObject]@{
                                        DN = $parentDN
                                        Name = ($parentDN -split ',')[0] -replace '^(OU|CN)=', ''
                                        Type = "$ouType containing $groupName member(s)"
                                        PrivilegedUsers = @()
                                    }
                                }

                                # Track which privileged users are in this OU
                                $privilegedOUs[$parentDN].PrivilegedUsers += "$memberName ($groupName)"
                            }
                        }
                    }
                }

                Write-Log "[Get-PasswordResetRights] Found $($privilegedOUs.Keys.Count) OU(s)/Container(s) with privileged users"
            }

            if ($privilegedOUs.Keys.Count -eq 0) {
                Write-Log "[Get-PasswordResetRights] No OUs with privileged users found"
                Show-Line "No OUs with privileged users found to analyze" -Class Note
                return
            }

            $allFindings = @()

            # Analyze each OU for password reset rights
            foreach ($ouDN in $privilegedOUs.Keys) {
                $ouInfo = $privilegedOUs[$ouDN]
                Write-Log "[Get-PasswordResetRights] Analyzing: $($ouInfo.Name) ($ouDN)"

                # Get-OUPermissions uses session context automatically
                $ouPermissions = Get-OUPermissions -DistinguishedName $ouDN -CheckType 'PasswordReset'

                if (-not $ouPermissions -or -not $ouPermissions.Findings) {
                    continue
                }

                # Add findings with OU context
                $allowedSeverities = if ($IncludePrivileged) { @('Critical', 'High', 'Info') } else { @('Critical', 'High') }
                foreach ($finding in $ouPermissions.Findings) {
                    # Filter by severity
                    if ($finding.Severity -notin $allowedSeverities) {
                        continue
                    }

                    # Check if this is an Exchange service group
                    # Exchange groups have by-design permissions that cannot be removed
                    $isExchangeService = $false
                    $exchangeCheck = Test-IsExchangeServiceGroup -Identity $finding.SID
                    if ($exchangeCheck.IsExchangeService) {
                        $isExchangeService = $true
                        Write-Log "[Get-PasswordResetRights] Exchange service group detected: $($finding.Principal)"
                    }

                    # Determine display severity:
                    # - Exchange service groups → 'Attention' (yellow, by-design)
                    # - Privileged accounts (Info from Get-OUPermissions) with -IncludePrivileged → 'Attention' (yellow)
                    # - Non-privileged → original severity (Critical/High)
                    $isPrivilegedAccount = $finding.Severity -eq 'Info'
                    $displaySeverity = if ($isExchangeService) { 'Attention' }
                        elseif ($isPrivilegedAccount) { 'Attention' }
                        else { $finding.Severity }

                    $allFindings += [PSCustomObject]@{
                        OU              = $ouInfo.Name
                        OUType          = $ouInfo.Type
                        DistinguishedName = $ouDN
                        Principal       = $finding.Principal
                        SID             = $finding.SID
                        Right           = $finding.Right
                        Severity        = $displaySeverity
                        Inherited       = $finding.InheritedFrom
                        PrivilegedUsers = $ouInfo.PrivilegedUsers
                        IsExchangeService = $isExchangeService
                        IsPrivilegedAccount = $isPrivilegedAccount
                    }
                }
            }

            if (@($allFindings).Count -eq 0) {
                Show-Line "No dangerous password reset rights detected in $($privilegedOUs.Keys.Count) analyzed OU(s)" -Class Secure
                return
            }

            # Group by principal (each principal may have rights on multiple OUs)
            $groupedByPrincipal = @($allFindings | Group-Object -Property SID)

            # Separate Exchange service groups from other findings for display
            $exchangeFindings = @($groupedByPrincipal | Where-Object { $_.Group[0].IsExchangeService -eq $true })
            $nonExchangeFindings = @($groupedByPrincipal | Where-Object { $_.Group[0].IsExchangeService -ne $true })

            # Display non-Exchange findings as Finding (red)
            if (@($nonExchangeFindings).Count -gt 0) {
                $countText = if ($IncludePrivileged) { "$(@($nonExchangeFindings).Count) account(s)" } else { "$(@($nonExchangeFindings).Count) non-privileged account(s)" }
                Show-Line "Found $countText with password reset rights on OUs containing privileged users" -Class Finding

                foreach ($principalGroup in $nonExchangeFindings) {
                    $sid = $principalGroup.Name
                    $principal = $principalGroup.Group[0].Principal
                    $affectedOUs = @($principalGroup.Group | ForEach-Object { $_.DistinguishedName } | Select-Object -Unique)

                    # Collect all privileged users that could be targeted
                    $targetableUsers = @()
                    foreach ($finding in $principalGroup.Group) {
                        if ($finding.PrivilegedUsers) {
                            $targetableUsers += $finding.PrivilegedUsers
                        }
                    }
                    $targetableUsers = $targetableUsers | Select-Object -Unique

                    # Check if this principal is privileged (for yellow display)
                    $isPriv = $principalGroup.Group[0].IsPrivilegedAccount

                    # Check if this is a well-known SID (S-1-5-X without domain sub-authorities)
                    # Well-known SIDs resolve to unhelpful ForeignSecurityPrincipal objects
                    $isWellKnownSID = $sid -match '^S-1-5-\d+$'

                    # Try to resolve the SID to a full AD object (skip for well-known SIDs)
                    $adObject = $null
                    if (-not $isWellKnownSID) {
                        $sidHex = ConvertTo-LDAPSIDHex -SID $sid
                        if ($sidHex) {
                            $adObject = @(Get-DomainObject -LDAPFilter "(objectSid=$sidHex)" @connectionParams)[0]
                        }
                    }

                    if ($adObject) {
                        $adObject | Add-Member -NotePropertyName 'dangerousRights' -NotePropertyValue "Password Reset (ForceChangePassword)" -Force
                        $adObject | Add-Member -NotePropertyName 'affectedOUs' -NotePropertyValue $affectedOUs -Force
                        if (@($targetableUsers).Count -gt 0) {
                            $adObject | Add-Member -NotePropertyName 'targetablePrivilegedUsers' -NotePropertyValue $targetableUsers -Force
                        }
                        if ($isPriv) {
                            $adObject | Add-Member -NotePropertyName 'dangerousRightsSeverity' -NotePropertyValue 'Hint' -Force
                        }
                        $adObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'PasswordResetRight' -Force
                        Show-Object $adObject
                    } else {
                        # Fallback for well-known SIDs, foreign/deleted principals
                        $resolvedName = if ($isWellKnownSID) { ConvertFrom-SID -SID $sid } else { $principal }
                        $fallbackObject = [PSCustomObject]@{
                            sAMAccountName = $resolvedName
                            objectSid = $sid
                            dangerousRights = "Password Reset (ForceChangePassword)"
                            affectedOUs = $affectedOUs
                        }
                        if (@($targetableUsers).Count -gt 0) {
                            $fallbackObject | Add-Member -NotePropertyName 'targetablePrivilegedUsers' -NotePropertyValue $targetableUsers -Force
                        }
                        if ($isPriv) {
                            $fallbackObject | Add-Member -NotePropertyName 'dangerousRightsSeverity' -NotePropertyValue 'Hint' -Force
                        }
                        $fallbackObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'PasswordResetRight' -Force
                        Show-Object $fallbackObject
                    }
                }
            }

            # Display Exchange service group findings as Hint (yellow) - by-design permissions
            # Only shown with -IncludePrivileged (Exchange groups are privileged by design)
            if ($IncludePrivileged -and @($exchangeFindings).Count -gt 0) {
                Show-Line "Found $(@($exchangeFindings).Count) Exchange service group(s) with password reset rights (by-design, cannot be removed)" -Class Hint

                foreach ($principalGroup in $exchangeFindings) {
                    $sid = $principalGroup.Name
                    $principal = $principalGroup.Group[0].Principal
                    $affectedOUs = @($principalGroup.Group | ForEach-Object { $_.DistinguishedName } | Select-Object -Unique)

                    # Collect all privileged users that could be targeted
                    $targetableUsers = @()
                    foreach ($finding in $principalGroup.Group) {
                        if ($finding.PrivilegedUsers) {
                            $targetableUsers += $finding.PrivilegedUsers
                        }
                    }
                    $targetableUsers = $targetableUsers | Select-Object -Unique

                    # Check if this is a well-known SID (S-1-5-X without domain sub-authorities)
                    $isWellKnownSID = $sid -match '^S-1-5-\d+$'

                    # Try to resolve the SID to a full AD object (skip for well-known SIDs)
                    $adObject = $null
                    if (-not $isWellKnownSID) {
                        $sidHex = ConvertTo-LDAPSIDHex -SID $sid
                        if ($sidHex) {
                            $adObject = @(Get-DomainObject -LDAPFilter "(objectSid=$sidHex)" @connectionParams)[0]
                        }
                    }

                    if ($adObject) {
                        $adObject | Add-Member -NotePropertyName 'dangerousRights' -NotePropertyValue "Password Reset (ForceChangePassword)" -Force
                        $adObject | Add-Member -NotePropertyName 'affectedOUs' -NotePropertyValue $affectedOUs -Force
                        # Mark as Exchange service group for display formatting
                        $adObject | Add-Member -NotePropertyName 'dangerousRightsSeverity' -NotePropertyValue 'Hint' -Force
                        $adObject | Add-Member -NotePropertyName '_isExchangeGroup' -NotePropertyValue $true -Force
                        if (@($targetableUsers).Count -gt 0) {
                            $adObject | Add-Member -NotePropertyName 'targetablePrivilegedUsers' -NotePropertyValue $targetableUsers -Force
                        }
                        $adObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'PasswordResetRight' -Force
                        Show-Object $adObject
                    } else {
                        # Fallback for well-known SIDs, foreign/deleted principals
                        $resolvedName = if ($isWellKnownSID) { ConvertFrom-SID -SID $sid } else { $principal }
                        $fallbackObject = [PSCustomObject]@{
                            sAMAccountName = $resolvedName
                            objectSid = $sid
                            dangerousRights = "Password Reset (ForceChangePassword)"
                            affectedOUs = $affectedOUs
                            dangerousRightsSeverity = 'Hint'
                        }
                        if (@($targetableUsers).Count -gt 0) {
                            $fallbackObject | Add-Member -NotePropertyName 'targetablePrivilegedUsers' -NotePropertyValue $targetableUsers -Force
                        }
                        $fallbackObject | Add-Member -NotePropertyName '_isExchangeGroup' -NotePropertyValue $true -Force
                        $fallbackObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'PasswordResetRight' -Force
                        Show-Object $fallbackObject
                    }
                }
            }

            # If no non-Exchange findings were displayed (and Exchange is hidden without -IncludePrivileged)
            if (@($nonExchangeFindings).Count -eq 0 -and (-not $IncludePrivileged -or @($exchangeFindings).Count -eq 0)) {
                Show-Line "No dangerous password reset rights detected in $($privilegedOUs.Keys.Count) analyzed OU(s)" -Class Secure
            }

        } catch {
            Write-Log "[Get-PasswordResetRights] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-PasswordResetRights] Analysis completed"
    }
}
