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

            Show-SubHeader "Searching for privileged accounts with reversible encryption..." -ObjectType "ReversibleEncryption"

            # Query privileged accounts (adminCount=1) with ENCRYPTED_TEXT_PWD_ALLOWED flag
            $vulnerableAccounts = Get-DomainUser -AdminCount -ReversibleEncryption -ShowOwner @PSBoundParameters

            if ($vulnerableAccounts -and @($vulnerableAccounts).Count -gt 0) {
                $totalAccounts = @($vulnerableAccounts).Count
                Show-Line "Found $totalAccounts privileged account(s) with reversible password encryption:" -Class Finding

                $currentIndex = 0
                foreach ($user in $vulnerableAccounts) {
                    $currentIndex++

                    # Progress indicator for large account counts
                    if ($totalAccounts -gt $Script:ProgressThreshold) {
                        Show-Progress -Activity "Processing reversible encryption accounts" -Current $currentIndex -Total $totalAccounts -ObjectName $user.sAMAccountName
                    }

                    $user | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'ReversibleEncryption' -Force
                    Show-Object $user
                }

                # Clear progress bar
                if ($totalAccounts -gt $Script:ProgressThreshold) {
                    Show-Progress -Activity "Processing reversible encryption accounts" -Completed
                }
            } else {
                Show-Line "No privileged accounts with reversible password encryption found" -Class Secure
            }

        } catch {
            Write-Log "[Get-AdminReversibleEncryption] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-AdminReversibleEncryption] Check completed"
    }
}
