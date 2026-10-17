function Get-CriticalObjectACLs {
    <#
    .SYNOPSIS
    Detects non-privileged control over the schema, the partitions container, the RID
    and infrastructure role objects and the sites.

    .DESCRIPTION
    Four objects the forest and the domain run on, each with a role of its own:

    - the schema naming context head (Schema Master): who controls it can add or change
      classes and attributes, among them the default security descriptor every new object
      of a class receives
    - CN=Partitions in the configuration naming context (Domain Naming Master): the
      cross-references that define the naming contexts of the forest
    - CN=RID Manager$ under CN=System (RID Master): the pool every security identifier of
      the domain is cut from
    - CN=Infrastructure (Infrastructure Master)

    And every site under CN=Sites: a Group Policy Object linked to a site applies to every
    computer in it, domain controllers included, and the site lives in the configuration
    naming context, out of reach of the OU and domain root checks.

    For each, a trustee that is not Tier-0 is reported when it owns the object, holds
    GenericAll, GenericWrite, WriteDacl, WriteOwner or an unrestricted WriteProperty on it,
    holds the role's transfer right (Change-Schema-Master, Change-Domain-Master,
    Change-Rid-Master, Change-Infrastructure-Master) or all extended rights, or - on the
    RID Manager - may write rIDAvailablePool, or on a site gPLink. Operators count as not Tier-0 here: an
    Account Operator with WriteDacl on the schema is an escalation, not a delegation.

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Get-CriticalObjectACLs

    .EXAMPLE
    Get-CriticalObjectACLs -Domain "contoso.com" -Credential (Get-Credential)

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
        [System.Management.Automation.PSCredential]$Credential
    )

    begin {
        Write-Log "[Get-CriticalObjectACLs] Starting check"
    }

    process {
        try {
            if (-not (Ensure-LDAPConnection @PSBoundParameters)) {
                return
            }

            Show-SubHeader "Analyzing the ACLs of the schema, the partitions container, the role objects and the sites..." -ObjectType "CriticalObjectACL"

            $targets = @()
            if ($Script:LDAPContext.SchemaNamingContext) {
                $targets += @{ DN = [string]$Script:LDAPContext.SchemaNamingContext; Label = 'Schema'; Role = 'Change-Schema-Master'
                               Meaning = 'may change the schema - classes, attributes and the default security descriptor of every new object' }
            }
            if ($Script:LDAPContext.ConfigurationNamingContext) {
                $targets += @{ DN = "CN=Partitions,$($Script:LDAPContext.ConfigurationNamingContext)"; Label = 'Partitions container'; Role = 'Change-Domain-Master'
                               Meaning = 'may change the cross-references that define the naming contexts of the forest' }
            }
            # rIDAvailablePool, the attribute the RID Master allocates pools from (Microsoft,
            # RID-Available-Pool attribute).
            $targets += @{ DN = "CN=RID Manager`$,CN=System,$($Script:LDAPContext.DomainDN)"; Label = 'RID Manager'; Role = 'Change-Rid-Master'
                           Attribute = @{ Guid = '66171888-8f3c-11d0-afda-00c04fd930c9'; Name = 'rIDAvailablePool' }
                           Meaning = 'may take the RID master role or exhaust the RID pool every new security identifier of the domain is cut from' }
            $targets += @{ DN = "CN=Infrastructure,$($Script:LDAPContext.DomainDN)"; Label = 'Infrastructure object'; Role = 'Change-Infrastructure-Master'
                           Meaning = 'may take the infrastructure master role' }

            # And the sites. A GPO linked to a site applies to every computer in it, domain
            # controllers included, and the site object lives in the configuration naming
            # context - out of reach of the OU and domain root checks.
            $unread = @()
            $sitesUnread = $false
            if ($Script:LDAPContext.ConfigurationNamingContext) {
                $sites = $null
                try {
                    $sites = @(Get-DomainObject -LDAPFilter '(objectClass=site)' -SearchBase "CN=Sites,$($Script:LDAPContext.ConfigurationNamingContext)" -Properties 'distinguishedName', 'name' @PSBoundParameters)
                } catch {
                    Write-Log "[Get-CriticalObjectACLs] The sites could not be enumerated: $_"
                    $sitesUnread = $true
                }
                foreach ($site in @($sites)) {
                    if (-not $site -or -not $site.distinguishedName) { continue }
                    $targets += @{ DN = [string]$site.distinguishedName; Label = "Site $($site.name)"; Role = $null
                                   Attribute = @{ Guid = 'f30e3bbe-9ff0-11d1-b603-0000f80367c1'; Name = 'gPLink' }
                                   Meaning = 'may link a Group Policy Object to the site - it applies to every computer in the site, domain controllers included' }
                }
            }

            $noGuid = '00000000-0000-0000-0000-000000000000'

            $findings = @()
            foreach ($target in $targets) {
                $aclResult = Get-ObjectACL -DistinguishedName $target.DN -DangerousOnly -AllowOnly @PSBoundParameters
                if (-not $aclResult) {
                    $unread += $target.Label
                    continue
                }

                # Rights per trustee, so a trustee with several ACEs is one row.
                $rightsBySID = [ordered]@{}
                $nameBySID = @{}
                if ($aclResult.OwnerSID) {
                    $rightsBySID[[string]$aclResult.OwnerSID] = @('Owner')
                    $nameBySID[[string]$aclResult.OwnerSID] = $(if ($aclResult.Owner) { [string]$aclResult.Owner } else { [string]$aclResult.OwnerSID })
                }
                foreach ($ace in @($aclResult.ACEs)) {
                    # Only what applies to the object itself: not inherit-only. A class named
                    # for inheritance does not take the ACE off this object (MS-DTYP, ACE) -
                    # the access check skips INHERIT_ONLY_ACE and nothing else.
                    if (-not (Test-ACEAppliesToSelf -ACE $ace)) { continue }

                    $granted = @()
                    $objectType = [string]$ace.ObjectType
                    if (-not $objectType -or $objectType -eq $noGuid) {
                        $granted += @($ace.RightsRaw | Where-Object { $_ -in @('GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner', 'WriteProperty') })
                        # CONTROL_ACCESS with no object type is every extended right, the
                        # role transfer among them. Full control says that already, and an
                        # object without a role has no extended right that matters here.
                        if ($target.Role -and @($ace.RightsRaw) -contains 'ExtendedRight' -and @($ace.RightsRaw) -notcontains 'GenericAll') {
                            $granted += 'All extended rights'
                        }
                    } elseif ($target.Role -and $ace.ObjectTypeName -eq $target.Role) {
                        $granted += $target.Role
                    } elseif ($objectType -ieq $target.Attribute.Guid -and @($ace.RightsRaw) -contains 'WriteProperty') {
                        $granted += "WriteProperty ($($target.Attribute.Name))"
                    }
                    if ($granted.Count -eq 0) { continue }

                    $sid = [string]$ace.TrusteeSID
                    if (-not $rightsBySID.Contains($sid)) {
                        $rightsBySID[$sid] = @()
                        $nameBySID[$sid] = $(if ($ace.Trustee) { [string]$ace.Trustee } else { $sid })
                    }
                    $rightsBySID[$sid] = @($rightsBySID[$sid]) + $granted
                }

                foreach ($sid in @($rightsBySID.Keys)) {
                    # Tier-0 holds these by default; an operator does not and counts.
                    if ((Test-IsPrivileged -Identity $sid).Category -eq 'Privileged') { continue }

                    $rightsText = "$(@($rightsBySID[$sid] | Select-Object -Unique) -join ', ') - $($target.Meaning)"
                    if (Test-IsBroadTrustee -SID $sid) { $rightsText = "$rightsText - granted to a broad group so every member holds it" }
                    $findings += [PSCustomObject]@{
                        Trustee              = $nameBySID[$sid]
                        TrusteeSID           = $sid
                        criticalObject       = "$($target.Label) ($($target.DN))"
                        criticalObjectRights = $rightsText
                    }
                }
            }

            foreach ($label in $unread) {
                Show-Line "The ACL of the $label could not be read - not checked" -Class Note
            }
            if ($sitesUnread) {
                Show-Line "The sites could not be enumerated - their ACLs were not checked" -Class Note
            }

            if ($findings.Count -gt 0) {
                Show-Line "Found $($findings.Count) non-Tier-0 principal(s) with control over the schema, the partitions container, a role object or a site" -Class Finding
                foreach ($finding in $findings) {
                    $finding | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'CriticalObjectACL' -Force
                    Show-Object $finding -Class Finding
                }
            } elseif ($unread.Count -eq 0 -and -not $sitesUnread) {
                Show-Line "No principal outside Tier-0 controls the schema, the partitions, the RID Manager, the infrastructure object or a site" -Class Secure
            }

        } catch {
            Write-Log "[Get-CriticalObjectACLs] Error: $_" -Level Error
            Show-Line "Error during check - the ACLs of the schema, partitions, role objects and sites could not be evaluated: $_" -Class Finding
        }
    }

    end {
        Write-Log "[Get-CriticalObjectACLs] Check completed"
    }
}
