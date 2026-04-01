<#
.SYNOPSIS
    Identifies dangerous permissions on Organizational Units across the domain.

.DESCRIPTION
    Scans all OUs in the domain for critical permissions that could lead to privilege escalation or lateral movement:

    - GenericAll (Full Control) - Non-privileged accounts
    - Password Reset Rights - Ability to reset user passwords
    - Account Control Modification - Change userAccountControl flags
    - Group Membership Control - Modify group memberships
    - SPN Modification - Set servicePrincipalName (Kerberoasting prep)
    - Script Path Modification - Change logon scripts (code execution)
    - Delegation Rights - Configure constrained/unconstrained delegation
    - Object Creation - Create new users/computers
    - GPO Linking - Link malicious GPOs
    Focuses on non-privileged accounts having these rights (privileged accounts are expected to have high permissions and generate lower severity findings).

.PARAMETER Domain
    Domain to query. Uses current domain if not specified.

.PARAMETER Server
    Domain Controller to query. Uses auto-discovery if not specified.

.PARAMETER Credential
    PSCredential object for authentication.

.PARAMETER ExcludeInherited
    Only analyze explicit ACEs (exclude inherited permissions).

.PARAMETER CheckType
    Specific check types to perform. Default: All critical checks.

.EXAMPLE
    Get-DangerousOUPermissions
    Scans all OUs in current domain for dangerous permissions.

.EXAMPLE
    Get-DangerousOUPermissions -Domain "contoso.com" -Credential (Get-Credential)
    Scans with alternate credentials.

.EXAMPLE
    Get-DangerousOUPermissions -CheckType 'PasswordReset','GenericAll' -ExcludeInherited
    Only checks for password reset and full control rights, excluding inherited ACEs.

.OUTPUTS
    Hashtable with:
    - FindingsDetected: Boolean
    - Findings: Array of dangerous permission findings
    - Summary: Statistics by check type and severity

.NOTES
    Category: Rights
    Author: Alexander Sturz (@_61106960_)
#>

function Get-DangerousOUPermissions {
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
        [switch]$ExcludeInherited,

        [Parameter(Mandatory=$false)]
        [ValidateSet(
            'All',
            'GenericAll',
            'GenericWrite',
            'WriteDacl',
            'WriteOwner',
            'PasswordReset',
            'AccountControl',
            'GroupMembership',
            'SPNModification',
            'ScriptPath',
            'Delegation',
            'LAPS',
            'ObjectCreation',
            'GPOLinking'
        )]
        [string[]]$CheckType = @('All')
    )

    begin {
        Write-Log "[Get-DangerousOUPermissions] Starting check"
    }

    process {
        try {
            # Build connection parameters (exclude IncludePrivileged, ExcludeInherited and CheckType which are not connection parameters)
            $connectionParams = @{}
            if ($Domain) { $connectionParams['Domain'] = $Domain }
            if ($Server) { $connectionParams['Server'] = $Server }
            if ($Credential) { $connectionParams['Credential'] = $Credential }

            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @connectionParams)) {
                return
            }

            Show-SubHeader "Analyzing OU permissions..." -ObjectType "DangerousOUPermission"

            # Get all OUs in the domain using Get-DomainObject
            $OUs = Get-DomainObject -LDAPFilter "(objectClass=organizationalUnit)" @connectionParams

            if (-not $OUs -or @($OUs).Count -eq 0) {
                Write-Log "[Get-DangerousOUPermissions] No Organizational Units found"
                Show-Line "No dangerous OU permissions detected" -Class Note
                return
            }

            Write-Log "[Get-DangerousOUPermissions] Found $(@($OUs).Count) OU(s) to analyze"

            $allFindings = @()
            $ouCount = 0
            $ouWithFindings = 0

            # Analyze each OU
            $totalOUs = @($OUs).Count
            $currentIndex = 0
            foreach ($ou in $OUs) {
                $currentIndex++
                $ouCount++
                if ($totalOUs -gt $Script:ProgressThreshold) { Show-Progress -Activity "Analyzing OU permissions" -Current $currentIndex -Total $totalOUs -ObjectName $ou.name }
                $ouDN = $ou.distinguishedName
                $ouName = $ou.name

                Write-Log "[Get-DangerousOUPermissions] Analyzing OU ($ouCount/$(@($OUs).Count)): $ouName"

                # Get-OUPermissions uses session context automatically
                $ouParams = @{
                    DistinguishedName = $ouDN
                    CheckType = $CheckType
                }
                if ($ExcludeInherited) { $ouParams['ExcludeInherited'] = $true }

                $ouPermissions = Get-OUPermissions @ouParams

                if (-not $ouPermissions -or -not $ouPermissions.Findings) {
                    continue
                }

                # Filter findings by severity
                # Account Operators (S-1-5-32-548) excluded - they have default OU permissions by design
                $allowedSeverities = if ($IncludePrivileged) { @('Critical', 'High', 'Info') } else { @('Critical', 'High') }
                $dangerousFindings = $ouPermissions.Findings | Where-Object {
                    $_.Severity -in $allowedSeverities -and
                    $_.SID -ne 'S-1-5-32-548'
                }

                if ($dangerousFindings) {
                    $ouWithFindings++

                    foreach ($finding in $dangerousFindings) {
                        # Check if this is an Exchange service group
                        # Exchange groups have by-design permissions that cannot be removed
                        $isExchangeService = $false
                        $exchangeCheck = Test-IsExchangeServiceGroup -Identity $finding.SID
                        if ($exchangeCheck.IsExchangeService) {
                            $isExchangeService = $true
                            Write-Log "[Get-DangerousOUPermissions] Exchange service group detected: $($finding.Principal)"
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
                            OU           = $ouName
                            DistinguishedName = $ouDN
                            CheckType    = $finding.CheckType
                            Right        = $finding.Right
                            Principal    = $finding.Principal
                            SID          = $finding.SID
                            Severity     = $displaySeverity
                            InheritedFrom = $finding.InheritedFrom
                            IsExchangeService = $isExchangeService
                            IsPrivilegedAccount = $isPrivilegedAccount
                        }
                    }
                }
            }
            if ($totalOUs -gt $Script:ProgressThreshold) { Show-Progress -Activity "Analyzing OU permissions" -Completed }

            # Display findings
            if (@($allFindings).Count -eq 0) {
                Show-Line "No dangerous OU permissions detected in $(@($OUs).Count) analyzed OU(s)" -Class Secure
                return
            }

            # Group findings by Principal first (show account once, then all OUs)
            $groupedByPrincipal = @($allFindings | Group-Object -Property SID)

            # Separate Exchange service groups from other findings for display
            $exchangeFindings = @($groupedByPrincipal | Where-Object { $_.Group[0].IsExchangeService -eq $true })
            $nonExchangeFindings = @($groupedByPrincipal | Where-Object { $_.Group[0].IsExchangeService -ne $true })

            # Batch resolve all unique SIDs to AD objects (avoids N+1 LDAP queries in display loops)
            $sidObjectMap = @{}
            $allUniqueSIDs = @($groupedByPrincipal | ForEach-Object { $_.Name } | Sort-Object -Unique)
            $resolvableSIDs = @($allUniqueSIDs | Where-Object { $_ -notmatch '^S-1-5-\d+$' })

            if ($resolvableSIDs.Count -gt 0) {
                $totalSIDs = $resolvableSIDs.Count
                $currentSIDIndex = 0
                foreach ($resolveSID in $resolvableSIDs) {
                    $currentSIDIndex++
                    if ($totalSIDs -gt $Script:ProgressThreshold) {
                        Show-Progress -Activity "Resolving account details" -Current $currentSIDIndex -Total $totalSIDs
                    }
                    $sidHex = ConvertTo-LDAPSIDHex -SID $resolveSID
                    if ($sidHex) {
                        $obj = @(Get-DomainObject -LDAPFilter "(objectSid=$sidHex)" @connectionParams)[0]
                        if ($obj) { $sidObjectMap[$resolveSID] = $obj }
                    }
                }
                if ($totalSIDs -gt $Script:ProgressThreshold) {
                    Show-Progress -Activity "Resolving account details" -Completed
                }
            }

            # Display non-Exchange findings as Finding (red)
            if (@($nonExchangeFindings).Count -gt 0) {
                $countText = if ($IncludePrivileged) { "$(@($nonExchangeFindings).Count) account(s)" } else { "$(@($nonExchangeFindings).Count) non-privileged account(s)" }
                Show-Line "Found $countText with dangerous OU permissions in $ouWithFindings OU(s)" -Class Finding

                foreach ($principalGroup in $nonExchangeFindings) {
                    $sid = $principalGroup.Name
                    $principal = $principalGroup.Group[0].Principal
                    $ouFindings = $principalGroup.Group

                    # Collect all OUs and rights for this principal
                    $affectedOUs = @()
                    $dangerousRightsList = @()
                    $inheritanceSources = @()
                    foreach ($finding in $ouFindings) {
                        $ouEntry = $finding.DistinguishedName
                        if ($affectedOUs -notcontains $ouEntry) {
                            $affectedOUs += $ouEntry
                        }
                        if ($dangerousRightsList -notcontains $finding.Right) {
                            $dangerousRightsList += $finding.Right
                        }
                        if ($finding.InheritedFrom -and $inheritanceSources -notcontains $finding.InheritedFrom) {
                            $inheritanceSources += $finding.InheritedFrom
                        }
                    }

                    $isWellKnownSID = $sid -match '^S-1-5-\d+$'
                    $adObject = if ($sidObjectMap.ContainsKey($sid)) { $sidObjectMap[$sid] } else { $null }
                    $isPriv = $ouFindings[0].IsPrivilegedAccount

                    if ($adObject) {
                        $adObject | Add-Member -NotePropertyName 'dangerousRights' -NotePropertyValue $dangerousRightsList -Force
                        $adObject | Add-Member -NotePropertyName 'affectedOUs' -NotePropertyValue $affectedOUs -Force
                        if (@($inheritanceSources).Count -gt 0) {
                            $adObject | Add-Member -NotePropertyName 'inheritedFrom' -NotePropertyValue $inheritanceSources -Force
                        }
                        if ($isPriv) {
                            $adObject | Add-Member -NotePropertyName 'dangerousRightsSeverity' -NotePropertyValue 'Hint' -Force
                        }
                        $adObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'DangerousOUPermission' -Force
                        Show-Object $adObject
                    } else {
                        $resolvedName = if ($isWellKnownSID) { ConvertFrom-SID -SID $sid } else { $principal }
                        $fallbackObject = [PSCustomObject]@{
                            sAMAccountName = $resolvedName
                            objectSid = $sid
                            dangerousRights = $dangerousRightsList
                            affectedOUs = $affectedOUs
                        }
                        if (@($inheritanceSources).Count -gt 0) {
                            $fallbackObject | Add-Member -NotePropertyName 'inheritedFrom' -NotePropertyValue $inheritanceSources -Force
                        }
                        if ($isPriv) {
                            $fallbackObject | Add-Member -NotePropertyName 'dangerousRightsSeverity' -NotePropertyValue 'Hint' -Force
                        }
                        $fallbackObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'DangerousOUPermission' -Force
                        Show-Object $fallbackObject
                    }
                }
            }

            # Display Exchange service group findings as Hint (yellow) - by-design permissions
            # Only shown with -IncludePrivileged (Exchange groups are privileged by design)
            if ($IncludePrivileged -and @($exchangeFindings).Count -gt 0) {
                Show-Line "Found $(@($exchangeFindings).Count) Exchange service group(s) with OU permissions (by-design, cannot be removed)" -Class Hint

                foreach ($principalGroup in $exchangeFindings) {
                    $sid = $principalGroup.Name
                    $principal = $principalGroup.Group[0].Principal
                    $ouFindings = $principalGroup.Group

                    $affectedOUs = @()
                    $dangerousRightsList = @()
                    $inheritanceSources = @()
                    foreach ($finding in $ouFindings) {
                        $ouEntry = $finding.DistinguishedName
                        if ($affectedOUs -notcontains $ouEntry) {
                            $affectedOUs += $ouEntry
                        }
                        if ($dangerousRightsList -notcontains $finding.Right) {
                            $dangerousRightsList += $finding.Right
                        }
                        if ($finding.InheritedFrom -and $inheritanceSources -notcontains $finding.InheritedFrom) {
                            $inheritanceSources += $finding.InheritedFrom
                        }
                    }

                    $isWellKnownSID = $sid -match '^S-1-5-\d+$'
                    $adObject = if ($sidObjectMap.ContainsKey($sid)) { $sidObjectMap[$sid] } else { $null }

                    if ($adObject) {
                        $adObject | Add-Member -NotePropertyName 'dangerousRights' -NotePropertyValue $dangerousRightsList -Force
                        $adObject | Add-Member -NotePropertyName 'affectedOUs' -NotePropertyValue $affectedOUs -Force
                        if (@($inheritanceSources).Count -gt 0) {
                            $adObject | Add-Member -NotePropertyName 'inheritedFrom' -NotePropertyValue $inheritanceSources -Force
                        }
                        $adObject | Add-Member -NotePropertyName 'dangerousRightsSeverity' -NotePropertyValue 'Hint' -Force
                        $adObject | Add-Member -NotePropertyName '_isExchangeGroup' -NotePropertyValue $true -Force
                        $adObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'DangerousOUPermission' -Force
                        Show-Object $adObject
                    } else {
                        $resolvedName = if ($isWellKnownSID) { ConvertFrom-SID -SID $sid } else { $principal }
                        $fallbackObject = [PSCustomObject]@{
                            sAMAccountName = $resolvedName
                            objectSid = $sid
                            dangerousRights = $dangerousRightsList
                            affectedOUs = $affectedOUs
                            dangerousRightsSeverity = 'Hint'
                        }
                        if (@($inheritanceSources).Count -gt 0) {
                            $fallbackObject | Add-Member -NotePropertyName 'inheritedFrom' -NotePropertyValue $inheritanceSources -Force
                        }
                        $fallbackObject | Add-Member -NotePropertyName '_isExchangeGroup' -NotePropertyValue $true -Force
                        $fallbackObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'DangerousOUPermission' -Force
                        Show-Object $fallbackObject
                    }
                }
            }

            # If no non-Exchange findings were displayed (and Exchange is hidden without -IncludePrivileged)
            if (@($nonExchangeFindings).Count -eq 0 -and (-not $IncludePrivileged -or @($exchangeFindings).Count -eq 0)) {
                Show-Line "No dangerous OU permissions detected in $(@($OUs).Count) analyzed OU(s)" -Class Secure
            }

        } catch {
            Write-Log "[Get-DangerousOUPermissions] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-DangerousOUPermissions] Analysis completed"
    }
}
