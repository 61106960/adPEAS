<#
.SYNOPSIS
    The explicit entries on computer objects that give a principal outside Tier-0 control
    over the computer.

.DESCRIPTION
    The other way to control a computer object, next to owning it: an ACE someone put on
    the object itself. Inherited entries come from an OU delegation, which the OU permission
    check reports where it is defined.

    The default security descriptor of the computer class writes explicit entries of its
    own (Microsoft, Computer class): full control for Domain Admins, Account Operators and
    SYSTEM, and for CREATOR OWNER - resolved to the creator - all extended rights, the
    User-Account-Restrictions property set and the validated writes. So the owner, the
    creator (mS-DS-CreatorSID), the CREATOR OWNER and SELF placeholders and Tier-0 including
    the operators are left out, and what remains was added by someone.

    Counted on the object itself (not inherit-only, and either for every class or for
    computer objects): GenericAll, GenericWrite, WriteDacl, WriteOwner, WriteProperty on
    every attribute, all extended rights, the password reset right, and WriteProperty on
    msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD), msDS-KeyCredentialLink (shadow
    credentials), servicePrincipalName and dNSHostName.

.PARAMETER Computers
    Computer objects carrying the converted nTSecurityDescriptor, OwnerSID and
    mS-DS-CreatorSID - the bulk result of Get-NonDefaultComputerOwners.

.OUTPUTS
    PSCustomObject per computer and trustee: Computer, distinguishedName, Trustee,
    TrusteeSID and explicitRights.

.NOTES
    Internal helper function
#>
function Get-ComputerExplicitRight {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        $Computers
    )

    $watchedAttributes = @{
        '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79' = 'msDS-AllowedToActOnBehalfOfOtherIdentity'
        '5b47d60f-6090-40b2-9f37-2a4de88f3063' = 'msDS-KeyCredentialLink'
        'f3a64788-5306-11d1-a9c5-0000f80367c1' = 'servicePrincipalName'
        '72e39547-7b18-11d1-adef-00c04fd8d5cd' = 'dNSHostName'
    }
    $passwordResetGuid = '00299570-246d-11d0-a768-00aa006e0529'
    $computerClassGuid = 'bf967a86-0de6-11d0-a285-00aa003049e2'
    # CREATOR OWNER and SELF: placeholders the default descriptor writes.
    $placeholderSIDs = @('S-1-3-0', 'S-1-5-10')
    $privilegedBySID = @{}

    foreach ($computer in @($Computers)) {
        if (-not $computer) { continue }
        $descriptor = $computer.nTSecurityDescriptor
        if (-not $descriptor -or -not $descriptor.ACEs) { continue }
        $ownerSID = [string]$computer.OwnerSID
        $creatorSID = [string]$computer.'mS-DS-CreatorSID'

        $rightsBySID = [ordered]@{}
        $nameBySID = @{}
        foreach ($ace in @($descriptor.ACEs)) {
            if ($ace.Type -ne 'Allow' -or $ace.IsInherited) { continue }
            if ($ace.InheritedObjectType -and $ace.InheritedObjectType -ine $computerClassGuid) { continue }
            if (-not (Test-ACEAppliesToSelf -ACE $ace)) { continue }

            $sid = [string]$ace.SID
            if (-not $sid -or $placeholderSIDs -contains $sid -or $sid -eq $ownerSID -or $sid -eq $creatorSID) { continue }

            $rights = [string]$ace.Rights
            $objectType = ([string]$ace.ObjectType).ToLowerInvariant()
            $granted = @()
            if (-not $objectType) {
                foreach ($right in @('GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner', 'WriteProperty')) {
                    if ($rights -match "\b$right\b") { $granted += $right }
                }
                if ($rights -match '\bExtendedRight\b' -and $rights -notmatch '\bGenericAll\b') { $granted += 'All extended rights' }
            } elseif ($objectType -eq $passwordResetGuid -and $rights -match '\bExtendedRight\b') {
                $granted += 'Password reset'
            } elseif ($watchedAttributes.ContainsKey($objectType) -and $rights -match '\bWriteProperty\b') {
                $granted += "WriteProperty ($($watchedAttributes[$objectType]))"
            }
            if ($granted.Count -eq 0) { continue }

            # Tier-0 and the operators hold these by default - Account Operators on every
            # computer object. One classification per trustee, not per object.
            if (-not $privilegedBySID.ContainsKey($sid)) {
                $privilegedBySID[$sid] = [bool](Test-IsPrivileged -Identity $sid -IncludeOperators).IsPrivileged
            }
            if ($privilegedBySID[$sid]) { continue }

            if (-not $rightsBySID.Contains($sid)) {
                $rightsBySID[$sid] = @()
                $nameBySID[$sid] = $(if ($ace.Name) { [string]$ace.Name } else { $sid })
            }
            $rightsBySID[$sid] = @($rightsBySID[$sid]) + $granted
        }

        $dn = [string]@($computer.distinguishedName)[0]
        $computerName = $dn
        if ($dn -match '^CN=((?:[^,\\]|\\.)+),') { $computerName = $Matches[1] -replace '\\(.)', '$1' }
        foreach ($sid in @($rightsBySID.Keys)) {
            [PSCustomObject]@{
                Computer          = $computerName
                distinguishedName = $dn
                Trustee           = $nameBySID[$sid]
                TrusteeSID        = $sid
                explicitRights    = (@($rightsBySID[$sid] | Select-Object -Unique) -join ', ')
            }
        }
    }
}

function Get-NonDefaultComputerOwners {
    <#
    .SYNOPSIS
    Identifies computer accounts whose owner is not one of the expected defaults, and the
    explicit permissions on computer objects that give a principal outside Tier-0 control.

    .DESCRIPTION
    The owner of an AD object holds implicit WriteDACL: it can grant itself any right on the
    object, and on a computer that means writing msDS-AllowedToActOnBehalfOfOtherIdentity or
    msDS-KeyCredentialLink and taking local SYSTEM on the machine. So the owner of every
    computer account is worth knowing.

    Two things decide how much a finding is worth, and the check reports both.

    Whether the owner is also the creator. A workstation joined by a helpdesk technician
    using their own account leaves that technician as owner - ordinary, and in a real domain
    it is most of the list. mS-DS-CreatorSID records who created the account, so ownership
    that was changed to somebody else AFTER creation can be told apart from the join. That
    is the case worth looking at: it does not happen by itself.

    Whether the account is disabled. Disabled accounts are included on purpose. Ownership
    survives the disable, and the owner can re-enable the account, set its password and take
    it over - the path is one step longer, not closed. They are marked rather than dropped,
    so the reader can weigh them.

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .PARAMETER OPSEC
    Skip this check - it enumerates every computer account in the domain.

    .EXAMPLE
    Get-NonDefaultComputerOwners

    .EXAMPLE
    Get-NonDefaultComputerOwners -Domain "contoso.com" -Credential (Get-Credential)

    .NOTES
    Category: Computer
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
        [switch]$OPSEC
    )

    begin {
        Write-Log "[Get-NonDefaultComputerOwners] Starting check"

        # Enough to decide and to explain; the full objects are read only for the findings
        $FilterProperties = @('distinguishedName', 'userAccountControl', 'mS-DS-CreatorSID')
    }

    process {
        try {
            # Build connection parameters (exclude OPSEC which Ensure-LDAPConnection doesn't accept)
            $connectionParams = @{}
            if ($Domain) { $connectionParams['Domain'] = $Domain }
            if ($Server) { $connectionParams['Server'] = $Server }
            if ($Credential) { $connectionParams['Credential'] = $Credential }

            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @connectionParams)) {
                return
            }

            Show-SubHeader "Searching for computers with non-default owners or explicit permissions..." -ObjectType "NonDefaultComputerOwner"

            # OPSEC mode: Skip heavy-load enumeration
            if ($OPSEC) {
                Show-Line "OPSEC mode: Skipping computer owner enumeration (would check all computers)" -Class "Hint"
                return
            }

            # Step 1: Bulk-load every computer with owner info in a single LDAP query.
            # -ShowOwner adds nTSecurityDescriptor to the query and extracts Owner/OwnerSID
            # clientside. Disabled accounts are included: ownership survives the disable and
            # the owner can turn the account back on.
            $computersWithOwner = @(Get-DomainComputer -ShowOwner -Properties $FilterProperties @connectionParams |
                Test-AccountActivity -IncludeDetails)

            Write-Log "[Get-NonDefaultComputerOwners] Found $($computersWithOwner.Count) computers, filtering non-default owners clientside..."

            $nonDefaultOwners = @()
            $currentIndex = 0
            $totalComputers = $computersWithOwner.Count

            # Owner and OwnerSID only exist when nTSecurityDescriptor came back with an
            # owner in it. A computer whose descriptor the caller may not read carries
            # neither, and used to be skipped without a counter, a warning or a trace in
            # the report - while the Secure line below claimed every computer had been
            # looked at. Ownership of a computer object is a takeover path, so that is the
            # most expensive place to pass an unread object off as a clean one.
            $unreadableOwners = 0

            foreach ($computer in $computersWithOwner) {
                $currentIndex++

                # Progress indicator for large computer counts
                if ($totalComputers -gt 50) {
                    Show-Progress -Activity "Checking computer owners" -Current $currentIndex -Total $totalComputers
                }

                if (-not $computer.OwnerSID) {
                    $unreadableOwners++
                    Write-Log "[Get-NonDefaultComputerOwners] No owner in the security descriptor of '$($computer.distinguishedName)' - not evaluated"
                }

                # Check if owner is non-default (clientside, no LDAP)
                if ($computer.OwnerSID -and -not (Test-IsDefaultOwner -SID $computer.OwnerSID)) {
                    $dn = if ($computer.distinguishedName -is [array]) { $computer.distinguishedName[0] } else { $computer.distinguishedName }
                    # Nothing can be read back without a DN, and the phantom entries a
                    # global catalog returns do not carry one
                    if ([string]::IsNullOrWhiteSpace($dn)) { continue }

                    $creatorSID = if ($computer.'mS-DS-CreatorSID') { "$($computer.'mS-DS-CreatorSID')" } else { $null }

                    $nonDefaultOwners += [PSCustomObject]@{
                        DN         = $dn
                        Owner      = $computer.Owner
                        OwnerSID   = $computer.OwnerSID
                        CreatorSID = $creatorSID
                        IsEnabled  = $computer.ActivityDetails.IsEnabled
                    }
                }
            }

            # Clear progress bar
            if ($totalComputers -gt 50) {
                Show-Progress -Activity "Checking computer owners" -Completed
            }

            Write-Log "[Get-NonDefaultComputerOwners] Found $($nonDefaultOwners.Count) computer(s) with non-default owners, loading full objects..."

            # Step 2: Read the full objects for the findings, batched. One query per finding
            # meant a domain with three hundred of them paid three hundred round-trips.
            $findingByDN = @{}
            foreach ($finding in $nonDefaultOwners) {
                $findingByDN[$finding.DN.ToLowerInvariant()] = $finding
            }

            $nonDefaultOwnerComputers = @()
            $dnFilters = @(ConvertTo-LDAPDNFilter -DistinguishedName @($nonDefaultOwners.DN))
            # What kind of principal each owner is, resolved once per distinct SID.
            #
            # A computer account owning a computer object is the cluster pattern: the
            # cluster name object creates the virtual computer objects of its roles and
            # owns them afterwards. Without that distinction every clustered environment
            # gets one takeover finding per virtual object - a finding against a state
            # somebody chose on purpose. A group owner is a delegation, and a user or a
            # service account is the case this check exists for.
            #
            # Per distinct owner, not per computer: where one delegated account joined
            # three thousand machines, that is one lookup rather than three thousand.
            $ownerKindBySID = @{}
            foreach ($ownerSID in @(@($nonDefaultOwners | ForEach-Object { $_.OwnerSID }) | Select-Object -Unique)) {
                if (-not $ownerSID) { continue }

                # A machine-local authority is a hash of a name on some computer and is
                # not a directory object anywhere - asking for it costs a global catalog
                # timeout per SID and answers nothing. See ConvertFrom-SID.
                if ("$ownerSID" -match '^S-1-5-(\d+)-\d+' -and $Script:MachineLocalSIDAuthorities -and $Script:MachineLocalSIDAuthorities.ContainsKey($Matches[1])) {
                    $ownerKindBySID[$ownerSID] = 'Machine-local service principal - not a directory object'
                    continue
                }

                $ownerObject = $null
                try {
                    $ownerObject = @(Get-DomainObject -Identity $ownerSID -Properties 'objectClass', 'sAMAccountName' @connectionParams)[0]
                } catch {
                    Write-Log "[Get-NonDefaultComputerOwners] Could not classify owner $ownerSID : $_"
                }

                if (-not $ownerObject) {
                    # Not resolvable is not harmless: a SID that answers nowhere is what a
                    # deleted principal or one from an untrusted domain looks like.
                    $ownerKindBySID[$ownerSID] = 'Unknown - the SID does not resolve in this directory'
                    continue
                }

                $ownerClasses = @($ownerObject.objectClass)
                $ownerKindBySID[$ownerSID] = if ($ownerClasses -icontains 'msDS-GroupManagedServiceAccount') {
                    'Group managed service account'
                } elseif ($ownerClasses -icontains 'msDS-ManagedServiceAccount') {
                    'Standalone managed service account'
                } elseif ($ownerClasses -icontains 'computer') {
                    'Computer account - a cluster name object owns the virtual computer objects it creates'
                } elseif ($ownerClasses -icontains 'group') {
                    'Group - whoever is a member of it owns this computer'
                } elseif ($ownerClasses -icontains 'user') {
                    'User account'
                } else {
                    "Object class $(@($ownerClasses) | Select-Object -Last 1)"
                }
            }

            $filterIndex = 0
            foreach ($dnFilter in $dnFilters) {
                $filterIndex++
                if ($dnFilters.Count -gt 1) {
                    Show-Progress -Activity "Loading computer details" -Current $filterIndex -Total $dnFilters.Count
                }

                foreach ($fullComputer in @(Get-DomainComputer -LDAPFilter $dnFilter @connectionParams)) {
                    $key = "$($fullComputer.distinguishedName)".ToLowerInvariant()
                    $finding = $findingByDN[$key]
                    if (-not $finding) { continue }

                    $fullComputer | Add-Member -NotePropertyName 'Owner' -NotePropertyValue $finding.Owner -Force
                    $fullComputer | Add-Member -NotePropertyName 'OwnerSID' -NotePropertyValue $finding.OwnerSID -Force

                    # What the owner is, not just who. The remediation differs: a cluster
                    # name object is left alone, a group is emptied or re-pointed, a user
                    # account is the one to take the ownership back from.
                    if ($finding.OwnerSID -and $ownerKindBySID.ContainsKey($finding.OwnerSID)) {
                        $ownerKindText = $ownerKindBySID[$finding.OwnerSID]

                        # Self-ownership is a computer account owning a computer object,
                        # and it is not the cluster pattern: this machine owns its OWN
                        # object, so it can rewrite its own DACL. Printing the cluster
                        # sentence on it would excuse the one case that deserves none.
                        $ownSID = "$($fullComputer.objectSid)"
                        if ($ownSID -and $ownSID -eq "$($finding.OwnerSID)") {
                            $ownerKindText = 'The computer owns its own object - it can rewrite its own DACL'
                        }

                        $fullComputer | Add-Member -NotePropertyName 'ownerKind' -NotePropertyValue $ownerKindText -Force
                    }

                    # Who created the account, and whether that is still who owns it. Without
                    # this the ordinary MAQ join and a deliberately re-assigned owner look
                    # exactly alike, and in a real domain the first drowns the second.
                    if ($finding.CreatorSID) {
                        $creatorName = ConvertFrom-SID -SID $finding.CreatorSID
                        $fullComputer | Add-Member -NotePropertyName 'creator' -NotePropertyValue $(
                            if ($creatorName) { $creatorName } else { $finding.CreatorSID }) -Force
                        $fullComputer | Add-Member -NotePropertyName 'creatorSID' -NotePropertyValue $finding.CreatorSID -Force

                        if ($finding.CreatorSID -eq $finding.OwnerSID) {
                            $fullComputer | Add-Member -NotePropertyName 'ownerIsCreator' -NotePropertyValue 'True - the account was joined by this principal' -Force
                        } else {
                            $fullComputer | Add-Member -NotePropertyName 'ownerIsCreator' -NotePropertyValue 'False - ownership was re-assigned after the account was created' -Force
                            $fullComputer | Add-Member -NotePropertyName 'ownershipChanged' -NotePropertyValue 'The owner is not the principal that created this account. Ownership does not change by itself: somebody with the rights to do it took control of this computer object.' -Force
                        }
                    } else {
                        # No mS-DS-CreatorSID: created by a member of the administrators, or
                        # by a domain controller. Say so rather than implying the creator and
                        # the owner match.
                        $fullComputer | Add-Member -NotePropertyName 'ownerIsCreator' -NotePropertyValue 'Unknown - the object records no creator' -Force
                    }

                    if ($false -eq $finding.IsEnabled) {
                        $fullComputer | Add-Member -NotePropertyName 'accountDisabled' -NotePropertyValue 'The account is disabled, but the owner can re-enable it and set its password' -Force
                    }

                    $nonDefaultOwnerComputers += $fullComputer
                }
            }

            if ($dnFilters.Count -gt 1) {
                Show-Progress -Activity "Loading computer details" -Completed
            }

            # Output results
            if (@($nonDefaultOwnerComputers).Count -gt 0) {
                $reassigned = @($nonDefaultOwnerComputers | Where-Object { $_.PSObject.Properties['ownershipChanged'] }).Count
                $reassignedInfo = if ($reassigned -gt 0) { ", $reassigned of them owned by somebody other than the creator" } else { "" }
                Show-Line "Found $(@($nonDefaultOwnerComputers).Count) computer(s) with non-default owners$($reassignedInfo):" -Class "Finding"

                # Counted on a line of its own rather than subtracted from the number
                # above it: these objects really do have a non-default owner, and a
                # reader deciding where to look needs to know which part of the list is
                # a cluster owning what it built.
                $clusterOwned = @($nonDefaultOwnerComputers | Where-Object {
                    $_.PSObject.Properties['ownerKind'] -and "$($_.ownerKind)" -like 'Computer account*' }).Count
                if ($clusterOwned -gt 0) {
                    Show-Line "$clusterOwned of them are owned by a computer account, which is how a cluster owns the objects it creates" -Class "Note"
                }

                foreach ($computer in $nonDefaultOwnerComputers) {
                    $computer | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'NonDefaultComputerOwner' -Force
                    Show-Object $computer -Class Finding
                }
            } elseif ($unreadableOwners -ge $totalComputers -and $totalComputers -gt 0) {
                Show-Line "Computer ownership was not evaluated - no security descriptor carried an owner" -Class "Note"
            } elseif ($unreadableOwners -gt 0) {
                Show-Line "The computers whose owner could be read all have default owners ($unreadableOwners of $totalComputers carried no owner in their security descriptor)" -Class "Note"
            } else {
                Show-Line "All computers have default owners" -Class "Secure"
            }

            # Said next to the finding as well, not only in place of it: a scan that found
            # three non-default owners and could not read a hundred more descriptors is
            # not the same result as one that read all of them.
            if ($unreadableOwners -gt 0 -and @($nonDefaultOwnerComputers).Count -gt 0) {
                Show-Line "$unreadableOwners of $totalComputers computer object(s) carried no owner in their security descriptor and were not evaluated" -Class "Finding"
            }

            # And the other way to control a computer object: an entry someone put on it,
            # read from the descriptors the query above already brought back. A descriptor
            # that could not be read is counted above.
            $explicitFindings = @(Get-ComputerExplicitRight -Computers $computersWithOwner)
            if ($explicitFindings.Count -gt 0) {
                Show-Line "Found $($explicitFindings.Count) explicit permission(s) on computer objects held outside Tier-0:" -Class "Finding"
                foreach ($explicitFinding in $explicitFindings) {
                    $explicitFinding | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'ComputerObjectACL' -Force
                    Show-Object $explicitFinding -Class Finding
                }
            }

        } catch {
            # Say so on the console, not only in the log - an aborted check is otherwise
            # indistinguishable from a domain with nothing to report.
            Write-Log "[Get-NonDefaultComputerOwners] Error: $_" -Level Error
            Show-Line "Error during check - computer ownership could not be evaluated: $_" -Class "Finding"
        }
    }

    end {
        Write-Log "[Get-NonDefaultComputerOwners] Check completed"
    }
}
