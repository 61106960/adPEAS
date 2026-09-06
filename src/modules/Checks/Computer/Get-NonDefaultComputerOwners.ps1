function Get-NonDefaultComputerOwners {
    <#
    .SYNOPSIS
    Identifies computer accounts whose owner is not one of the expected defaults.

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

            Show-SubHeader "Searching for computers with non-default owners..." -ObjectType "NonDefaultComputerOwner"

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

            foreach ($computer in $computersWithOwner) {
                $currentIndex++

                # Progress indicator for large computer counts
                if ($totalComputers -gt 50) {
                    Show-Progress -Activity "Checking computer owners" -Current $currentIndex -Total $totalComputers
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

                foreach ($computer in $nonDefaultOwnerComputers) {
                    $computer | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'NonDefaultComputerOwner' -Force
                    Show-Object $computer
                }
            } else {
                Show-Line "All computers have default owners" -Class "Secure"
            }

        } catch {
            Write-Log "[Get-NonDefaultComputerOwners] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-NonDefaultComputerOwners] Check completed"
    }
}
