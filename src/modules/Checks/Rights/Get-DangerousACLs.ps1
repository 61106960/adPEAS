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
                    # Skip if ObjectType is set - this means the right only applies to a specific attribute/extended right
                    if ($objectType -and $objectType -ne '' -and $objectType -ne '00000000-0000-0000-0000-000000000000') {
                        Write-Log "[Get-DangerousACLs] Skipping object-specific ACE: Trustee=$trusteeName, ObjectType=$objectType"
                        continue
                    }

                    $dangerousRights = @($ace.RightsRaw | Where-Object {
                        $_ -in @('GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner')
                    })

                    if (@($dangerousRights).Count -gt 0) {
                        $dangerousRightsAccounts += [PSCustomObject]@{
                            SID = $trusteeSID
                            Name = $trusteeName
                            Rights = $dangerousRights
                        }
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

                    if ($canDCSync) {
                        $rightsDisplay = "DS-Replication-Get-Changes, DS-Replication-Get-Changes-All"
                        if ($hasGetChangesFiltered) {
                            $rightsDisplay += ", DS-Replication-Get-Changes-In-Filtered-Set"
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
            Write-Log "[Get-DangerousACLs] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-DangerousACLs] Check completed"
    }
}

