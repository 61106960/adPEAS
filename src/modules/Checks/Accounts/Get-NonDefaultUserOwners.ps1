function Get-NonDefaultUserOwners {
    <#
    .SYNOPSIS
    Identifies user accounts with non-default owners.

    .DESCRIPTION
    Enumerates all user accounts and checks if the owner of the security descriptor is different from the expected default (Domain Admins).

    Non-default ownership can indicate:
    - User created by a non-admin (e.g., via delegation)
    - Ownership changed post-creation
    - Potential for privilege escalation (owner has implicit control)

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .PARAMETER IncludeHealthMailboxes
    Include Exchange Health Mailboxes in output. By default, these are filtered out as they are
    expected to be owned by the Exchange server that created them.

    .EXAMPLE
    Get-NonDefaultUserOwners

    .EXAMPLE
    Get-NonDefaultUserOwners -Domain "contoso.com" -Credential (Get-Credential)

    .EXAMPLE
    Get-NonDefaultUserOwners -IncludeHealthMailboxes

    .NOTES
    Category: Accounts
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
        [switch]$IncludeHealthMailboxes,

        [Parameter(Mandatory=$false)]
        [switch]$OPSEC
    )

    begin {
        Write-Log "[Get-NonDefaultUserOwners] Starting check"
    }

    process {
        try {
            # Build connection parameters (exclude IncludeHealthMailboxes which is not a connection parameter)
            $connectionParams = @{}
            if ($Domain) { $connectionParams['Domain'] = $Domain }
            if ($Server) { $connectionParams['Server'] = $Server }
            if ($Credential) { $connectionParams['Credential'] = $Credential }

            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @connectionParams)) {
                return
            }

            Show-SubHeader "Searching for users with non-default owners..." -ObjectType "NonDefaultOwner"

            # OPSEC mode: Skip heavy-load enumeration
            if ($OPSEC) {
                Show-Line "OPSEC mode: Skipping user owner enumeration (would check all enabled users)" -Class "Hint"
                return
            }

            # Step 1: Bulk-load all enabled users with owner info in a single LDAP query
            # -ShowOwner adds nTSecurityDescriptor to the query and extracts Owner/OwnerSID clientside
            # -Properties 'distinguishedName' keeps network traffic minimal (only DN + nTSecurityDescriptor)
            $usersWithOwner = @(Get-DomainUser -Enabled -ShowOwner -Properties 'distinguishedName' @connectionParams)

            Write-Log "[Get-NonDefaultUserOwners] Found $($usersWithOwner.Count) enabled users, filtering non-default owners clientside..."

            $nonDefaultOwnerUsers = @()
            $nonDefaultOwnerDNs = @()
            $filteredHealthMailboxes = 0
            $currentIndex = 0
            $totalUsers = $usersWithOwner.Count

            foreach ($user in $usersWithOwner) {
                $currentIndex++

                # Progress indicator for large user counts
                if ($totalUsers -gt 50) {
                    Show-Progress -Activity "Checking user owners" -Current $currentIndex -Total $totalUsers
                }

                # Check if owner is non-default (clientside, no LDAP)
                if ($user.OwnerSID -and -not (Test-IsDefaultOwner -SID $user.OwnerSID)) {
                    $dn = if ($user.distinguishedName -is [array]) { $user.distinguishedName[0] } else { $user.distinguishedName }

                    # Filter Exchange Health Mailboxes by default (check DN pattern early to avoid unnecessary full-load)
                    if (-not $IncludeHealthMailboxes) {
                        if ($dn -like '*,CN=Monitoring Mailboxes,CN=Microsoft Exchange System Objects,*') {
                            $filteredHealthMailboxes++
                            Write-Log "[Get-NonDefaultUserOwners] Filtered Exchange Health Mailbox: $dn"
                            continue
                        }
                    }

                    $nonDefaultOwnerDNs += [PSCustomObject]@{
                        DN = $dn
                        Owner = $user.Owner
                        OwnerSID = $user.OwnerSID
                    }
                }
            }

            # Clear progress bar
            if ($totalUsers -gt 50) {
                Show-Progress -Activity "Checking user owners" -Completed
            }

            Write-Log "[Get-NonDefaultUserOwners] Found $($nonDefaultOwnerDNs.Count) user(s) with non-default owners, loading full objects..."

            # Step 2: Only for findings, fetch full user objects for Show-Object display
            $totalFindings = $nonDefaultOwnerDNs.Count
            $currentIndex = 0
            foreach ($finding in $nonDefaultOwnerDNs) {
                $currentIndex++
                if ($totalFindings -gt $Script:ProgressThreshold) {
                    Show-Progress -Activity "Loading user details" -Current $currentIndex -Total $totalFindings
                }

                $fullUser = @(Get-DomainUser -Identity $finding.DN @connectionParams)[0]

                if ($fullUser) {
                    # HealthMailbox sAMAccountName check (DN pattern already filtered above)
                    if (-not $IncludeHealthMailboxes) {
                        if ($fullUser.sAMAccountName -like 'HealthMailbox*') {
                            $filteredHealthMailboxes++
                            Write-Log "[Get-NonDefaultUserOwners] Filtered Exchange Health Mailbox: $($fullUser.sAMAccountName)"
                            continue
                        }
                    }

                    # Add owner info to user object for display
                    $fullUser | Add-Member -NotePropertyName 'Owner' -NotePropertyValue $finding.Owner -Force
                    $fullUser | Add-Member -NotePropertyName 'OwnerSID' -NotePropertyValue $finding.OwnerSID -Force
                    $nonDefaultOwnerUsers += $fullUser
                }
            }

            if ($totalFindings -gt $Script:ProgressThreshold) {
                Show-Progress -Activity "Loading user details" -Completed
            }

            # Output results
            if (@($nonDefaultOwnerUsers).Count -gt 0) {
                Show-Line "Found $(@($nonDefaultOwnerUsers).Count) user(s) with non-default owners:" -Class Finding

                foreach ($user in $nonDefaultOwnerUsers) {
                    $user | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'NonDefaultOwner' -Force
                    Show-Object $user
                }

            } else {
                if ($filteredHealthMailboxes -gt 0) {
                    Show-Line "All users have default owners (filtered $filteredHealthMailboxes Exchange Health Mailboxes)" -Class Secure
                } else {
                    Show-Line "All users have default owners" -Class Secure
                }
            }

        } catch {
            Write-Log "[Get-NonDefaultUserOwners] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-NonDefaultUserOwners] Check completed"
    }
}
