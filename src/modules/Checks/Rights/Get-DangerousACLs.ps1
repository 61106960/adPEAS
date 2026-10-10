function Get-DangerousACLs {
    <#
    .SYNOPSIS
    Detects dangerous ACL permissions on the Domain root object.

    .DESCRIPTION
    Analyzes Access Control Lists (ACLs) on the Domain root object for dangerous permissions that allow privilege escalation to Domain Admin:

    - DCSync Rights (DS-Replication-Get-Changes + DS-Replication-Get-Changes-All)
    - GenericAll (Full Control)
    - GenericWrite (Write all properties)
    - WriteDacl (Modify permissions)
    - WriteOwner (Take ownership)
    Focuses on NON-privileged accounts with these rights (privilege escalation vector).

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Get-DangerousACLs

    .EXAMPLE
    Get-DangerousACLs -Domain "contoso.com" -Credential (Get-Credential)

    .NOTES
    Category: Rights
    Author: Alexander Sturz (@_61106960_)
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
        [switch]$IncludePrivileged
    )

    begin {
        Write-Log "[Get-DangerousACLs] Starting check"
    }

    process {
        try {
            # Build connection parameters (exclude IncludePrivileged which is not a connection parameter)
            $connectionParams = @{}
            if ($Domain) { $connectionParams['Domain'] = $Domain }
            if ($Server) { $connectionParams['Server'] = $Server }
            if ($Credential) { $connectionParams['Credential'] = $Credential }

            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @connectionParams)) {
                return
            }

            $domainDN = $Script:LDAPContext.DomainDN

            # ===== Step 1: Get Domain Root ACLs using Get-ObjectACL =====
            Show-SubHeader "Analyzing Domain root ACLs..." -ObjectType "DangerousACL"

            Write-Log "[Get-DangerousACLs] Domain DN: $domainDN"

            # Use Get-ObjectACL with DangerousOnly filter for efficient ACL analysis
            $aclResult = Get-ObjectACL -DistinguishedName $domainDN -DangerousOnly -AllowOnly @connectionParams

            if (-not $aclResult) {
                Show-Line "Failed to retrieve ACLs for domain root" -Class Note
                return
            }

            Write-Log "[Get-DangerousACLs] Retrieved $($aclResult.ACECount) dangerous ACEs"

            # ===== Step 2: Analyze ACEs =====
            # Only analyze ACEs that grant FULL permissions on the domain object

            $dcsyncAccounts = @{}
            $dangerousRightsAccounts = @()

            # Object-specific ACEs on the domain object that hand the domain over. Named
            # by their resolved ObjectTypeName, which Get-ObjectACL supplies for both an
            # attribute and an extended right.
            # DS-Replication-Synchronize and DS-Replication-Manage-Topology are
            # deliberately absent: they move replication around without reading anything
            # out of it.
            $criticalDomainObjectTypes = @(
                'GP-Link',
                'Reanimate-Tombstones',
                'DS-Install-Replica',
                'Migrate-SID-History',
                'Change-Rid-Master',
                'Change-PDC',
                'Change-Infrastructure-Master',
                'Change-Domain-Master',
                'Change-Schema-Master'
            )

            foreach ($ace in $aclResult.ACEs) {
                $trusteeSID = $ace.TrusteeSID
                $trusteeName = $ace.Trustee
                $objectType = $ace.ObjectType
                $inheritedObjectType = $ace.InheritedObjectType

                # Skip ACEs with InheritedObjectType - they only apply to child objects, not the domain root
                if ($inheritedObjectType -and $inheritedObjectType -ne '' -and $inheritedObjectType -ne '00000000-0000-0000-0000-000000000000') {
                    Write-Log "[Get-DangerousACLs] Skipping child-only ACE: Trustee=$trusteeName, InheritedType=$inheritedObjectType"
                    continue
                }

                # ===== Check for DCSync Rights =====
                $hasDCSync = $false
                foreach ($right in $ace.RightsRaw) {
                    if ($right -match 'DS-Replication-Get-Changes') {
                        if (-not $dcsyncAccounts.ContainsKey($trusteeSID)) {
                            $dcsyncAccounts[$trusteeSID] = @{
                                SID = $trusteeSID
                                Name = $trusteeName
                                Rights = @()
                            }
                        }
                        $dcsyncAccounts[$trusteeSID].Rights += $right
                        $hasDCSync = $true
                    }
                }

                # ===== Check for Dangerous Generic Rights =====
                if (-not $hasDCSync) {
                    $isObjectSpecific = ($objectType -and $objectType -ne '' -and $objectType -ne '00000000-0000-0000-0000-000000000000')

                    if ($isObjectSpecific) {
                        # An object-specific ACE used to be skipped outright, which is
                        # right for most of them and wrong for these: GP-Link is the
                        # attribute that links a GPO to the domain object, so write access
                        # to it is code execution on every machine in the domain, domain
                        # controllers included, and the rest are the documented
                        # domain-takeover extended rights on the domain object itself.
                        if ($criticalDomainObjectTypes -contains $ace.ObjectTypeName) {
                            # An extended-right ACE already carries the resolved name in
                            # RightsRaw, so naming it twice would read as a repetition.
                            $objectRight = $ace.Rights
                            if ($ace.RightsRaw -notcontains $ace.ObjectTypeName) {
                                $objectRight = "$($ace.Rights) ($($ace.ObjectTypeName))"
                            }

                            $dangerousRightsAccounts += [PSCustomObject]@{
                                SID = $trusteeSID
                                Name = $trusteeName
                                Rights = @($objectRight)
                            }
                        } else {
                            Write-Log "[Get-DangerousACLs] Skipping object-specific ACE: Trustee=$trusteeName, ObjectType=$objectType ($($ace.ObjectTypeName))"
                        }
                        continue
                    }

                    # WriteProperty is in the list and was not. GenericWrite is the mask
                    # 0x00020028, so a plain WriteProperty ACE does not satisfy the subset
                    # test for it and carried only 'WriteProperty' - and with no ObjectType
                    # that ACE grants write access to every property of the domain object:
                    # gPLink links a GPO to the whole domain, ms-DS-MachineAccountQuota and
                    # minPwdLength are two more.
                    #
                    # Self deliberately stays out. The only validated write the domain
                    # object defines is Validated-MS-DS-Behavior-Version, so the holder can
                    # raise the domain functional level and nothing else - disruptive, but
                    # not a takeover, and a red line for it would be the louder error.
                    $dangerousRights = @($ace.RightsRaw | Where-Object {
                        $_ -in @('GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner', 'WriteProperty')
                    })

                    if (@($dangerousRights).Count -gt 0) {
                        $dangerousRightsAccounts += [PSCustomObject]@{
                            SID = $trusteeSID
                            Name = $trusteeName
                            Rights = $dangerousRights
                        }
                    }

                    # 'ExtendedRight' with no ObjectType is CONTROL_ACCESS over every
                    # extended right of the domain object, DS-Replication-Get-Changes and
                    # -All included: that is full DCSync rather than something next to it.
                    # The branch above matches the resolved right names and never sees this
                    # form - Get-ObjectACL resolves no name for an empty GUID - so the
                    # single most dangerous ACE in a domain produced no finding at all.
                    # A GenericAll ACE carries ExtendedRight inside its mask and is
                    # already reported above as full control, which is the stronger
                    # statement; adding it here as well would read as two separate
                    # backdoors for one ACE.
                    if (($ace.RightsRaw -contains 'ExtendedRight') -and ($ace.RightsRaw -notcontains 'GenericAll')) {
                        if (-not $dcsyncAccounts.ContainsKey($trusteeSID)) {
                            $dcsyncAccounts[$trusteeSID] = @{
                                SID = $trusteeSID
                                Name = $trusteeName
                                Rights = @()
                            }
                        }
                        $dcsyncAccounts[$trusteeSID].Rights += @(
                            'All-Extended-Rights',
                            'DS-Replication-Get-Changes',
                            'DS-Replication-Get-Changes-All'
                        )
                    }
                }
            }

            # ===== Step 3: Collect non-privileged findings =====
            $dcsyncFindings = @()
            $dangerousRightsFindings = @()

            # Process DCSync accounts
            if ($dcsyncAccounts.Count -gt 0) {
                foreach ($sid in $dcsyncAccounts.Keys) {
                    $account = $dcsyncAccounts[$sid]
                    $rights = $account.Rights
                    $accountName = $account.Name

                    # Check if account has BOTH required rights for DCSync
                    $hasGetChanges = $rights -contains 'DS-Replication-Get-Changes'
                    $hasGetChangesAll = $rights -contains 'DS-Replication-Get-Changes-All'
                    $hasGetChangesFiltered = $rights -contains 'DS-Replication-Get-Changes-In-Filtered-Set'

                    $canDCSync = $hasGetChanges -and $hasGetChangesAll

                    # A trustee holding only one of the two replication rights used to
                    # disappear completely: the ACE marked itself as DCSync-handled, which
                    # took it out of the generic branch, and the output below needs the
                    # pair. Reporting it as DCSync would be wrong - that is what the pair
                    # is for - so it goes into the generic block, where the trustee gate
                    # and the severity are the same as for every other right on this
                    # object, and the text says what the holder can actually do.
                    if (-not $canDCSync -and ($hasGetChanges -or $hasGetChangesAll -or $hasGetChangesFiltered)) {
                        $partialText = "$(@($rights | Select-Object -Unique) -join ', ') - inert without DS-Replication-Get-Changes, one ACE short of DCSync"
                        if ($hasGetChanges) {
                            # Not inert at all: this one replicates the whole directory
                            # except the secrets, every security descriptor included.
                            $partialText = "$(@($rights | Select-Object -Unique) -join ', ') - replicates the directory except secrets, one right short of DCSync"
                        }

                        $dangerousRightsAccounts += [PSCustomObject]@{
                            SID = $sid
                            Name = $accountName
                            Rights = @($partialText)
                        }
                    }

                    if ($canDCSync) {
                        $rightsDisplay = "DS-Replication-Get-Changes, DS-Replication-Get-Changes-All"
                        if ($hasGetChangesFiltered) {
                            $rightsDisplay += ", DS-Replication-Get-Changes-In-Filtered-Set"
                        }
                        if ($rights -contains 'All-Extended-Rights') {
                            # Say where it came from. The ACE grants every extended right
                            # at once rather than the two named ones, and the remediation
                            # is a different one: there is a single ACE to remove.
                            $rightsDisplay = "All Extended Rights (grants DS-Replication-Get-Changes and DS-Replication-Get-Changes-All)"
                        }

                        # Determine severity
                        $severity = 'Finding'

                        if (-not $IncludePrivileged) {
                            # Use scope-based check for DCSync rights
                            $scopeResult = Test-IsExpectedInScope -Identity $sid -Scope 'DCSync' -ReturnDetails

                            if ($scopeResult.Severity -eq 'Expected') {
                                Write-Log "[Get-DangerousACLs] DCSync rights (expected): $accountName - $($scopeResult.Reason)"
                                continue
                            }

                            if ($scopeResult.Severity -eq 'Attention') {
                                Write-Log "[Get-DangerousACLs] DCSync rights (attention): $accountName - $($scopeResult.Reason) - skipped (use -IncludePrivileged to include)"
                                continue
                            }

                            $severity = $scopeResult.Severity
                        } else {
                            # -IncludePrivileged: Show ALL accounts, but mark privileged ones for yellow display
                            $scopeResult = Test-IsExpectedInScope -Identity $sid -Scope 'DCSync' -ReturnDetails
                            $severity = $scopeResult.Severity
                            Write-Log "[Get-DangerousACLs] IncludePrivileged: Including DCSync $accountName ($sid) with severity $severity"
                        }

                        $dcsyncFindings += [PSCustomObject]@{
                            Name = $accountName
                            SID = $sid
                            Rights = $rightsDisplay
                            Severity = $severity
                        }
                    }
                }
            }

            # Process dangerous generic rights
            if (@($dangerousRightsAccounts).Count -gt 0) {
                $groupedAccounts = $dangerousRightsAccounts | Group-Object -Property SID

                foreach ($group in $groupedAccounts) {
                    $sid = $group.Name
                    $accountName = $group.Group[0].Name
                    $allRights = @()

                    foreach ($item in $group.Group) {
                        $allRights += $item.Rights
                    }

                    $allRights = $allRights | Select-Object -Unique
                    $rightsDisplay = $allRights -join ', '

                    # Determine severity
                    $severity = 'Finding'

                    if (-not $IncludePrivileged) {
                        # Use scope-based check for Domain Root ACL rights
                        $scopeResult = Test-IsExpectedInScope -Identity $sid -Scope 'DomainRootACL' -ReturnDetails

                        if ($scopeResult.Severity -eq 'Expected') {
                            Write-Log "[Get-DangerousACLs] Dangerous rights (expected): $accountName - $rightsDisplay - $($scopeResult.Reason)"
                            continue
                        }

                        if ($scopeResult.Severity -eq 'Attention') {
                            Write-Log "[Get-DangerousACLs] Dangerous rights (attention): $accountName - $rightsDisplay - $($scopeResult.Reason) - skipped (use -IncludePrivileged to include)"
                            continue
                        }

                        $severity = $scopeResult.Severity
                    } else {
                        # -IncludePrivileged: Show ALL accounts, but mark privileged ones for yellow display
                        $scopeResult = Test-IsExpectedInScope -Identity $sid -Scope 'DomainRootACL' -ReturnDetails
                        $severity = $scopeResult.Severity
                        Write-Log "[Get-DangerousACLs] IncludePrivileged: Including $accountName ($sid) with severity $severity"
                    }

                    $dangerousRightsFindings += [PSCustomObject]@{
                        Name = $accountName
                        SID = $sid
                        Rights = $rightsDisplay
                        Severity = $severity
                    }
                }
            }

            # ===== Step 4: Output findings with full AD objects =====
            # DCSync findings
            if (@($dcsyncFindings).Count -gt 0) {
                $countText = if ($IncludePrivileged) { "$(@($dcsyncFindings).Count) account(s)" } else { "$(@($dcsyncFindings).Count) non-privileged account(s)" }
                Show-Line "Found $countText with DCSync rights" -Class Finding

                foreach ($finding in $dcsyncFindings) {
                    # Try to resolve the SID to a full AD object (user or group)
                    $sidHex = ConvertTo-LDAPSIDHex -SID $finding.SID
                    $adObject = $null

                    if ($sidHex) {
                        $adObject = @(Get-DomainObject -LDAPFilter "(objectSid=$sidHex)" @connectionParams)[0]
                    }

                    if ($adObject) {
                        $adObject | Add-Member -NotePropertyName 'dangerousRights' -NotePropertyValue $finding.Rights -Force
                        $adObject | Add-Member -NotePropertyName 'dangerousRightsSeverity' -NotePropertyValue $finding.Severity -Force
                        $adObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'DangerousACL' -Force
                        Show-Object $adObject
                    } else {
                        # Create synthetic object for unresolvable SIDs (e.g., foreign domain principals)
                        $syntheticObject = [PSCustomObject]@{
                            sAMAccountName = $finding.Name
                            objectSid = $finding.SID
                            objectClass = 'foreignSecurityPrincipal'
                            dangerousRights = $finding.Rights
                            dangerousRightsSeverity = $finding.Severity
                        }
                        $syntheticObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'DangerousACL' -Force
                        Show-Object $syntheticObject
                    }
                }
            }

            # Dangerous rights findings
            if (@($dangerousRightsFindings).Count -gt 0) {
                $countText = if ($IncludePrivileged) { "$(@($dangerousRightsFindings).Count) account(s)" } else { "$(@($dangerousRightsFindings).Count) non-privileged account(s)" }
                Show-Line "Found $countText with dangerous rights on domain root" -Class Finding

                foreach ($finding in $dangerousRightsFindings) {
                    # Try to resolve the SID to a full AD object (user or group)
                    $sidHex = ConvertTo-LDAPSIDHex -SID $finding.SID
                    $adObject = $null

                    if ($sidHex) {
                        $adObject = @(Get-DomainObject -LDAPFilter "(objectSid=$sidHex)" @connectionParams)[0]
                    }

                    if ($adObject) {
                        $adObject | Add-Member -NotePropertyName 'dangerousRights' -NotePropertyValue $finding.Rights -Force
                        $adObject | Add-Member -NotePropertyName 'dangerousRightsSeverity' -NotePropertyValue $finding.Severity -Force
                        $adObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'DangerousACL' -Force
                        Show-Object $adObject
                    } else {
                        # Create synthetic object for unresolvable SIDs (e.g., foreign domain principals)
                        $syntheticObject = [PSCustomObject]@{
                            sAMAccountName = $finding.Name
                            objectSid = $finding.SID
                            objectClass = 'foreignSecurityPrincipal'
                            dangerousRights = $finding.Rights
                            dangerousRightsSeverity = $finding.Severity
                        }
                        $syntheticObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'DangerousACL' -Force
                        Show-Object $syntheticObject
                    }
                }
            }

            if (@($dcsyncFindings).Count -eq 0 -and @($dangerousRightsFindings).Count -eq 0) {
                Show-Line "No dangerous ACLs detected on domain root" -Class Secure
            }

        } catch {
            # Say so on the console, not only in the log. Logging alone made an aborted
            # check indistinguishable from a domain with nothing to report: both produced
            # no objects and no message at all.
            Write-Log "[Get-DangerousACLs] Error: $_" -Level Error
            Show-Line "Error during check - domain root ACLs could not be evaluated: $_" -Class Finding
        }
    }

    end {
        Write-Log "[Get-DangerousACLs] Check completed"
    }
}

