function Get-AdminReversibleEncryption {
    <#
    .SYNOPSIS
    Detects privileged accounts with "Store Password using Reversible Encryption" enabled.

    .DESCRIPTION
    Identifies privileged user accounts (adminCount=1) where passwords are stored using reversible encryption (ENCRYPTED_TEXT_PWD_ALLOWED flag).

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Get-AdminReversibleEncryption

    .EXAMPLE
    Get-AdminReversibleEncryption -Domain "contoso.com" -Credential (Get-Credential)

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
        [System.Management.Automation.PSCredential]$Credential
    )

    begin {
        Write-Log "[Get-AdminReversibleEncryption] Starting check"
    }

    process {
        try {
            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @PSBoundParameters)) {
                # Return without output to avoid redundant error display
                return
            }

            Show-SubHeader "Searching for accounts with reversible encryption..." -ObjectType "ReversibleEncryption"

            # Every account, not only the privileged ones. Reversible encryption means the
            # cleartext password is recoverable from the domain controller, and that is the
            # same leaked credential on a service account as on an administrator - it was
            # the account's privilege, not its exposure, that used to decide whether anyone
            # was told. The domain-wide switch behind this
            # (DOMAIN_PASSWORD_STORE_CLEARTEXT, and the per-PSO equivalent) is reported by
            # Get-DomainPasswordPolicy; this is the per-account setting.
            $vulnerableAccounts = @(Get-DomainUser -ReversibleEncryption -ShowOwner @PSBoundParameters)

            if ($vulnerableAccounts.Count -gt 0) {
                $totalAccounts = $vulnerableAccounts.Count
                Show-Line "Found $totalAccounts account(s) with reversible password encryption:" -Class Finding

                $currentIndex = 0
                $privilegedCount = 0
                foreach ($user in $vulnerableAccounts) {
                    $currentIndex++

                    # Progress indicator for large account counts
                    if ($totalAccounts -gt $Script:ProgressThreshold) {
                        Show-Progress -Activity "Processing reversible encryption accounts" -Current $currentIndex -Total $totalAccounts -ObjectName $user.sAMAccountName
                    }

                    # Privilege decided by Test-IsPrivileged rather than by adminCount.
                    # That attribute is set by AdminSDHolder and never cleared, so it both
                    # keeps accounts that left the group years ago and misses the groups
                    # AdminSDHolder does not protect - Group Policy Creator Owners among
                    # them, whose members can create and edit Group Policy.
                    $privileged = Test-IsPrivileged -Identity $user -IncludeOperators
                    if ($privileged -and $privileged.IsPrivileged) {
                        $privilegedCount++
                        $user | Add-Member -NotePropertyName 'PrivilegedAccount' `
                            -NotePropertyValue $privileged.Reason -Force
                    }

                    $user | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'ReversibleEncryption' -Force
                    Show-Object $user
                }

                # Clear progress bar
                if ($totalAccounts -gt $Script:ProgressThreshold) {
                    Show-Progress -Activity "Processing reversible encryption accounts" -Completed
                }

                if ($privilegedCount -gt 0) {
                    Show-Line "$privilegedCount of them is/are privileged - the cleartext password of an administrator is recoverable from the DC" -Class Finding
                }
            } else {
                Show-Line "No accounts with reversible password encryption found" -Class Secure
            }

        } catch {
            Write-Log "[Get-AdminReversibleEncryption] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-AdminReversibleEncryption] Check completed"
    }
}
