function Get-NonDefaultComputerOwners {
    <#
    .SYNOPSIS
    Identifies computer accounts with non-default owners.

    .DESCRIPTION
    Enumerates all computer accounts and checks if the owner of the security descriptor is different from the expected default (Domain Admins).

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

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
                Show-Line "OPSEC mode: Skipping computer owner enumeration (would check all enabled computers)" -Class "Hint"
                return
            }

            # Step 1: Bulk-load all enabled computers with owner info in a single LDAP query
            # -ShowOwner adds nTSecurityDescriptor to the query and extracts Owner/OwnerSID clientside
            # -Properties 'distinguishedName' keeps network traffic minimal (only DN + nTSecurityDescriptor)
            $computersWithOwner = @(Get-DomainComputer -Enabled -ShowOwner -Properties 'distinguishedName' @connectionParams)

            Write-Log "[Get-NonDefaultComputerOwners] Found $($computersWithOwner.Count) enabled computers, filtering non-default owners clientside..."

            $nonDefaultOwnerComputers = @()
            $nonDefaultOwnerDNs = @()
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

                    $nonDefaultOwnerDNs += [PSCustomObject]@{
                        DN = $dn
                        Owner = $computer.Owner
                        OwnerSID = $computer.OwnerSID
                    }
                }
            }

            # Clear progress bar
            if ($totalComputers -gt 50) {
                Show-Progress -Activity "Checking computer owners" -Completed
            }

            Write-Log "[Get-NonDefaultComputerOwners] Found $($nonDefaultOwnerDNs.Count) computer(s) with non-default owners, loading full objects..."

            # Step 2: Only for findings, fetch full computer objects for Show-Object display
            $totalFindings = $nonDefaultOwnerDNs.Count
            $currentIndex = 0
            foreach ($finding in $nonDefaultOwnerDNs) {
                $currentIndex++
                if ($totalFindings -gt $Script:ProgressThreshold) {
                    Show-Progress -Activity "Loading computer details" -Current $currentIndex -Total $totalFindings
                }

                $fullComputer = @(Get-DomainComputer -Identity $finding.DN @connectionParams)[0]

                if ($fullComputer) {
                    # Add owner info to computer object for display
                    $fullComputer | Add-Member -NotePropertyName 'Owner' -NotePropertyValue $finding.Owner -Force
                    $fullComputer | Add-Member -NotePropertyName 'OwnerSID' -NotePropertyValue $finding.OwnerSID -Force
                    $nonDefaultOwnerComputers += $fullComputer
                }
            }

            if ($totalFindings -gt $Script:ProgressThreshold) {
                Show-Progress -Activity "Loading computer details" -Completed
            }

            # Output results
            if (@($nonDefaultOwnerComputers).Count -gt 0) {
                Show-Line "Found $(@($nonDefaultOwnerComputers).Count) computer(s) with non-default owners:" -Class "Finding"

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
