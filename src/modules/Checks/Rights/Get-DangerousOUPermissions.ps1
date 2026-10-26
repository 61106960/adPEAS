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
    - Key Credential Write - Add a key to msDS-KeyCredentialLink (Shadow Credentials)
    - Script Path Modification - Change logon scripts (code execution)
    - Delegation Rights - Configure constrained/unconstrained delegation
    - Object Creation - Create new users/computers, or delegated Managed Service Accounts
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
            'KeyCredentialLink',
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

            Show-SubHeader "Analyzing OU and container permissions..." -ObjectType "DangerousOUPermission"

            # The organizational units, and the containers directly under the domain root.
            #
            # CN=Users and CN=Computers are containers rather than organizational units, and
            # in a great many domains they hold most of the accounts - everything nobody
            # deliberately moved. A delegation granting GenericAll over CN=Users used to be
            # invisible here while the same delegation one OU further along was reported.
            $OUs = @(Get-DomainObject -LDAPFilter "(objectClass=organizationalUnit)" @connectionParams) +
                   @(Get-PrincipalContainer @connectionParams)

            if (@($OUs).Count -eq 0) {
                Write-Log "[Get-DangerousOUPermissions] No organizational units or containers found"
                # Say what actually happened. "No dangerous OU permissions detected" here
                # claimed a result for a scan that never examined a single object.
                Show-Line "No organizational units or containers returned - permissions were not evaluated" -Class Note
                return
            }

            Write-Log "[Get-DangerousOUPermissions] Found $(@($OUs).Count) OU(s) and container(s) to analyze"

            # Whether a finding is just a built-in operator group creating what it may
            # create by design. Only that combination - the group, the CheckType and the
            # class - so anything else those groups hold is still reported.
            function Test-IsDefaultObjectCreation {
                param([Parameter(Mandatory = $true)]$Finding)

                if ($Finding.CheckType -ne 'ObjectCreation') { return $false }
                $creatorSID = [string]$Finding.SID
                if (-not $creatorSID) { return $false }
                if (-not $Script:DefaultObjectCreators.ContainsKey($creatorSID)) { return $false }

                # The class off the finding, not out of its sentence.
                $class = if ($Finding.PSObject.Properties['CreatableClass']) { [string]$Finding.CreatableClass } else { '' }
                if (-not $class) { return $false }

                return (@($Script:DefaultObjectCreators[$creatorSID]) -contains $class)
            }

            $allFindings = @()
            $ouCount = 0
            $unreadOUs = @()
            # Delegations an explicit Deny ACE cancels. Get-OUPermissions drops them
            # now rather than reporting access nobody has, and the total is named in
            # the conclusion: a Deny is a fragile control, so a reader who knows the
            # delegation exists should not have to wonder why it is missing.
            $neutralisedByDeny = 0

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

                # An OU whose descriptor could not be read has no findings either, and
                # the conclusion below used to count it as analyzed. Only an explicit
                # $false counts as unread: a result without the property did not come
                # through Get-OUPermissions' own return paths, and inventing a failure
                # for it would be as wrong as the silence this replaces.
                if (-not $ouPermissions -or $ouPermissions.Read -eq $false) {
                    $unreadOUs += $ouDN
                }

                if ($ouPermissions -and $ouPermissions.NeutralisedByDeny) {
                    $neutralisedByDeny += [int]$ouPermissions.NeutralisedByDeny
                }

                if (-not $ouPermissions -or -not $ouPermissions.Findings) {
                    continue
                }

                # Medium belongs in this list. Get-OUPermissions rates the gPLink
                # delegation and CreateChild on user and group as Medium, so dropping that
                # severity meant this module's own documentation ("GPO Linking - Link
                # malicious GPOs") and the OU_PERM_GPLINK definition described a finding
                # the report could not contain. "Manage Group Policy links" is the second
                # most common delegation the ADUC wizard writes, and it leads to code
                # execution on every machine below the OU; creating an account in a
                # privileged OU is the other half of that loss.
                #
                # LAPS, CredentialRoaming and BitLocker are taken out instead: each has a
                # module of its own - Get-LAPSPermissions, Get-CredentialRoaming and
                # Get-BitLockerRecoveryKeyAccess - which reports them with the context this
                # one cannot give, above all whether the confidential flag lets the right
                # work at all.
                $allowedSeverities = if ($IncludePrivileged) { @('Critical', 'High', 'Medium', 'Info') } else { @('Critical', 'High', 'Medium') }
                $ownModuleCheckTypes = @('LAPS', 'CredentialRoaming', 'BitLocker')

                # Account Operators hold CreateChild and DeleteChild on user, group and
                # computer by default, inherited from the domain root. That one
                # combination is filtered, and nothing else: the old filter dropped every
                # finding carrying this SID, whatever the right and whether the ACE was
                # explicit or inherited, and it did so under -IncludePrivileged as well.
                # An explicit GenericAll, WriteDacl or Reset Password for Account
                # Operators on a Tier-0 OU is no default, and it is an escalation path in
                # every pentest.
                $dangerousFindings = $ouPermissions.Findings | Where-Object {
                    $_.Severity -in $allowedSeverities -and
                    $_.CheckType -notin $ownModuleCheckTypes -and
                    -not (Test-IsDefaultObjectCreation -Finding $_)
                }

                if ($dangerousFindings) {
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
                        # - Exchange service groups -> 'Attention' (yellow, by-design)
                        # - Privileged accounts (Info from Get-OUPermissions) with -IncludePrivileged -> 'Attention' (yellow)
                        # - Non-privileged -> original severity (Critical/High)
                        $isPrivilegedAccount = $finding.Severity -eq 'Info'
                        $displaySeverity = if ($isExchangeService) { 'Attention' }
                            elseif ($isPrivilegedAccount) { 'Attention' }
                            else { $finding.Severity }

                        $entry = [PSCustomObject]@{
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
                        # The element the right is about, for Select-OUStrongestFinding below,
                        # and where it is set, for Format-OUPermissionLocation.
                        foreach ($elementField in @('_ElementClass', '_ElementSelf', '_ElementChildren', '_ElementDirectOnly', '_SourceDN')) {
                            if ($finding.PSObject.Properties[$elementField]) {
                                $entry | Add-Member -NotePropertyName $elementField -NotePropertyValue $finding.$elementField -Force
                            }
                        }
                        $allFindings += $entry
                    }
                }
            }
            if ($totalOUs -gt $Script:ProgressThreshold) { Show-Progress -Activity "Analyzing OU permissions" -Completed }

            # How many were really examined, and the class the clean conclusion deserves.
            # Both conclusion lines below used to name the full OU count and stay Secure
            # whatever was readable.
            $readOUs = $totalOUs - @($unreadOUs).Count
            $readScope = Format-OUContainerCount -DistinguishedName @(@($OUs | ForEach-Object { [string]$_.distinguishedName }) | Where-Object { $unreadOUs -notcontains $_ })
            $coverageIncomplete = Show-OUPermissionsCoverageNote -UnreadOUs $unreadOUs -TotalOUs $totalOUs
            $conclusionClass = 'Secure'
            if ($coverageIncomplete) { $conclusionClass = 'Note' }

            # Said once, before the findings, because it applies to the whole scan and
            # not to any one OU. Note rather than Secure: the delegation is still in
            # the DACL, and removing the Deny ACE is all it takes to make it effective.
            if ($neutralisedByDeny -gt 0) {
                Show-Line "$neutralisedByDeny delegation(s) are cancelled by an explicit Deny ACE for the same trustee and are not reported as access" -Class Note
            }

            # Display findings
            if (@($allFindings).Count -eq 0) {
                if ($totalOUs -gt 0 -and $readOUs -le 0) {
                    Show-Line "OU permissions were not evaluated - no security descriptor could be read" -Class Note
                } else {
                    Show-Line "No dangerous OU permissions detected in the $readScope analyzed" -Class $conclusionClass
                }
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

                # The places the accounts below hold their rights, and no others. This used
                # to count every OU with any finding, so one where only an Exchange service
                # group holds rights - hidden without -IncludePrivileged, and on a line of its
                # own with it - was counted for accounts that hold nothing there: a single
                # delegation on one OU read "in 5 OU(s) and 8 container(s)" (measured).
                $findingOUDNs = @($nonExchangeFindings | ForEach-Object { $_.Group } |
                    ForEach-Object { [string]$_.DistinguishedName } | Select-Object -Unique)
                Show-Line "Found $countText with dangerous OU permissions in $(Format-OUContainerCount -DistinguishedName $findingOUDNs)" -Class Finding

                foreach ($principalGroup in $nonExchangeFindings) {
                    $sid = $principalGroup.Name
                    $principal = $principalGroup.Group[0].Principal
                    # The strongest right per element, OU by OU: one Full Control ACE used
                    # to read as GenericAll, GenericWrite, WriteDacl, WriteOwner and Reset
                    # Password. Per OU before the merge, so a right that is the strongest on
                    # one OU is not lost to a stronger one on another.
                    $ouFindings = @($principalGroup.Group | Group-Object -Property DistinguishedName |
                        ForEach-Object { Select-OUStrongestFinding -Finding $_.Group })

                    # Collect all rights for this principal, and the places they are set:
                    # every OU used to be listed, the one an ACE is set on and every OU that
                    # inherits it alike, with the sources in a separate row at the end.
                    $dangerousRightsList = @()
                    foreach ($finding in $ouFindings) {
                        if ($dangerousRightsList -notcontains $finding.Right) {
                            $dangerousRightsList += $finding.Right
                        }
                    }
                    $affectedOUs = @(Format-OUPermissionLocation -Finding $ouFindings -DomainDN $Script:LDAPContext.DomainDN)
                    $inheritanceSources = @(Get-UntaggedInheritanceSource -Finding $ouFindings)

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
                        Show-Object $adObject -Class $(if ([string]$adObject.dangerousRightsSeverity -in @('Expected', 'Attention', 'Hint')) { 'Hint' } else { 'Finding' })
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
                        Show-Object $fallbackObject -Class $(if ([string]$fallbackObject.dangerousRightsSeverity -in @('Expected', 'Attention', 'Hint')) { 'Hint' } else { 'Finding' })
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
                    $ouFindings = @($principalGroup.Group | Group-Object -Property DistinguishedName |
                        ForEach-Object { Select-OUStrongestFinding -Finding $_.Group })

                    $dangerousRightsList = @()
                    foreach ($finding in $ouFindings) {
                        if ($dangerousRightsList -notcontains $finding.Right) {
                            $dangerousRightsList += $finding.Right
                        }
                    }
                    $affectedOUs = @(Format-OUPermissionLocation -Finding $ouFindings -DomainDN $Script:LDAPContext.DomainDN)
                    $inheritanceSources = @(Get-UntaggedInheritanceSource -Finding $ouFindings)

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
                        Show-Object $adObject -Class Hint
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
                        Show-Object $fallbackObject -Class Hint
                    }
                }
            }

            # If no non-Exchange findings were displayed (and Exchange is hidden without -IncludePrivileged)
            if (@($nonExchangeFindings).Count -eq 0 -and (-not $IncludePrivileged -or @($exchangeFindings).Count -eq 0)) {
                Show-Line "No dangerous OU permissions detected in the $readScope analyzed" -Class $conclusionClass
            }

        } catch {
            # Say so on the console, not only in the log. Logging alone made an aborted
            # check indistinguishable from a domain with nothing to report: the section
            # simply ended, and an empty section reads as a clean one. Same wording as
            # the catch in Get-DangerousACLs.
            Write-Log "[Get-DangerousOUPermissions] Error: $_" -Level Error
            Show-Line "Error during check - OU permissions could not be evaluated: $_" -Class Finding
        }
    }

    end {
        Write-Log "[Get-DangerousOUPermissions] Analysis completed"
    }
}

<#
.SYNOPSIS
    Keeps the strongest right per element out of the findings of one principal on one OU.

.DESCRIPTION
    Get-OUPermissions tests every right of an ACE on its own, so one "Full Control on
    descendant user objects" ACE came out as GenericAll, GenericWrite, WriteDacl,
    WriteOwner and Reset Password - five rows for one grant, and eleven for a delegation
    the ADUC wizard writes in two ACEs. A finding is dropped when another finding of the
    set holds a right that contains it, on an element that contains its own:

    - GenericAll contains every right reported here but the ownership of the OU, which is
      no right at all.
    - GenericWrite contains WriteProperty and Self on all properties and every attribute
      write and validated write.
    - WriteProperty on all properties contains every attribute write and validated write.

    An element contains another when it names every class or the same class, reaches the
    object itself and the children wherever the other one does, and is not limited to the
    direct children unless the other one is too. The same right on a strictly larger
    element contains the smaller one, where the check type names a single right.

    Conservative by construction: a finding Get-OUPermissions did not tag with an element
    is neither dropped nor drops anything, and a class the containing finding does not
    name keeps the finding.

.PARAMETER Finding
    The findings of one principal on one OU.

.OUTPUTS
    The findings no other finding contains, in their original order, written one by one.
#>
function Select-OUStrongestFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Finding
    )

    $attributeWrites = @('AccountControl', 'GroupMembership', 'SPNModification', 'DNSHostName',
                         'KeyCredentialLink', 'ScriptPath', 'Delegation', 'GPOLinking')
    # $null: every check type but Ownership.
    $containedTypes = @{
        GenericAll       = $null
        GenericWrite     = @(@('WritePropertyAll', 'SelfAll') + $attributeWrites)
        WritePropertyAll = $attributeWrites
    }
    # The check types that name one right each. Only for these does a finding of the same
    # type on a larger element contain the smaller one: ObjectCreation covers every class
    # that may be created, GPOLinking gPLink and gPOptions, and so on.
    $singleRightTypes = @('GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner',
                          'WritePropertyAll', 'SelfAll', 'PasswordReset')

    $all = @($Finding | Where-Object { $_ })
    $kept = foreach ($candidate in $all) {
        $isContained = $false
        # The owner of the OU is never tagged - it is no ACE - so it is never dropped.
        if ($candidate.PSObject.Properties['_ElementClass']) {
            foreach ($other in $all) {
                if ([object]::ReferenceEquals($other, $candidate)) { continue }
                if (-not $other.PSObject.Properties['_ElementClass']) { continue }

                $otherType = [string]$other.CheckType
                $sameType = ($otherType -eq [string]$candidate.CheckType)
                if ($sameType) {
                    if ($singleRightTypes -notcontains $otherType) { continue }
                } else {
                    if (-not $containedTypes.ContainsKey($otherType)) { continue }
                    $types = $containedTypes[$otherType]
                    if ($null -ne $types -and $types -notcontains [string]$candidate.CheckType) { continue }
                }

                # The element of $other has to contain the element of $candidate.
                if ($other._ElementClass -and $other._ElementClass -ne $candidate._ElementClass) { continue }
                if ($candidate._ElementSelf -and -not $other._ElementSelf) { continue }
                if ($candidate._ElementChildren -and -not $other._ElementChildren) { continue }
                if ($other._ElementDirectOnly -and -not $candidate._ElementDirectOnly) { continue }

                # The same right contains itself only on a strictly larger element - two
                # equal ones would otherwise drop each other.
                if ($sameType -and
                    $other._ElementClass -eq $candidate._ElementClass -and
                    [bool]$other._ElementSelf -eq [bool]$candidate._ElementSelf -and
                    [bool]$other._ElementChildren -eq [bool]$candidate._ElementChildren -and
                    [bool]$other._ElementDirectOnly -eq [bool]$candidate._ElementDirectOnly) { continue }

                $isContained = $true
                break
            }
        }
        if (-not $isContained) { $candidate }
    }
    # One by one, not as one array: the caller collects them across OUs with @(), and an
    # array written as a single object would arrive there as one element.
    $kept
}

<#
.SYNOPSIS
    Names the places a principal's OU rights are set, with how many objects inherit each.

.DESCRIPTION
    affectedOUs used to list every OU a right turned up in, so one delegation on an OU
    high in the tree came out as every OU below it - hundreds of lines, with the place it
    is set lost among them and named only in a separate inheritedFrom row at the end.

    Get-OUPermissions tags each finding with _SourceDN: the object an explicit ACE is set
    on, the source Get-ACEInheritanceSource found for an inherited one, or $null where it
    found none. One line per source, then:

    - "<DN> (set here)", or "(set here, inherited by N OU(s) below)" with the objects that
      inherit it - counted by Format-OUContainerCount, so a container is not called an OU;
    - "<DN> (domain root, inherited by N OU(s))" for a right set on the domain object;
    - "<DN> (inherited, source not found)" for an inherited right without a source.

    A finding without the tag - the owner of an OU, which is no ACE - is listed by the DN
    it was found on, as before.

.PARAMETER Finding
    The findings of one principal, OU by OU.

.PARAMETER DomainDN
    The DN of the domain object.

.OUTPUTS
    The lines, one by one.
#>
function Format-OUPermissionLocation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Finding,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$DomainDN
    )

    $sources = [ordered]@{}
    $unknown = @()
    $plain = @()
    foreach ($item in @($Finding | Where-Object { $_ })) {
        $foundOn = [string]$item.DistinguishedName
        if (-not $item.PSObject.Properties['_SourceDN']) {
            if ($plain -notcontains $foundOn) { $plain += $foundOn }
            continue
        }
        $sourceDN = [string]$item._SourceDN
        if (-not $sourceDN) {
            if ($unknown -notcontains $foundOn) { $unknown += $foundOn }
            continue
        }
        if (-not $sources.Contains($sourceDN)) { $sources[$sourceDN] = @() }
        if ($sources[$sourceDN] -notcontains $foundOn) { $sources[$sourceDN] += $foundOn }
    }

    foreach ($sourceDN in @($sources.Keys)) {
        $inheritors = @($sources[$sourceDN] | Where-Object { $_ -ne $sourceDN })
        if ($DomainDN -and $sourceDN -eq $DomainDN) {
            "$sourceDN (domain root, inherited by $(Format-OUContainerCount -DistinguishedName $inheritors))"
        } elseif ($inheritors.Count -gt 0) {
            "$sourceDN (set here, inherited by $(Format-OUContainerCount -DistinguishedName $inheritors) below)"
        } else {
            "$sourceDN (set here)"
        }
    }
    foreach ($foundOn in $unknown) {
        "$foundOn (inherited, source not found)"
    }
    foreach ($foundOn in $plain) {
        if (-not $sources.Contains($foundOn)) { $foundOn }
    }
}

<#
.SYNOPSIS
    The inheritance sources of the findings that carry no source DN.

.DESCRIPTION
    The inheritedFrom row, kept for findings Get-OUPermissions did not tag with _SourceDN.
    For tagged ones Format-OUPermissionLocation names the source on the affectedOUs line,
    and a separate row would say it a second time.

.PARAMETER Finding
    The findings of one principal.

.OUTPUTS
    The distinct InheritedFrom texts, one by one.
#>
function Get-UntaggedInheritanceSource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Finding
    )

    $seen = @()
    foreach ($item in @($Finding | Where-Object { $_ })) {
        if ($item.PSObject.Properties['_SourceDN']) { continue }
        if ($item.InheritedFrom -and $seen -notcontains $item.InheritedFrom) {
            $seen += $item.InheritedFrom
            $item.InheritedFrom
        }
    }
}