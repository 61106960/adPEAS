function Get-PasswordNotRequired {
    <#
    .SYNOPSIS
    Detects enabled user accounts with the PASSWD_NOTREQD flag set.

    .DESCRIPTION
    Identifies enabled user accounts where the "Password Not Required" (PASSWD_NOTREQD, UAC bit 32) flag is set.
    This flag allows the account to have an empty password, bypassing the domain password policy.
    While the flag alone does not guarantee an empty password (a password may have been set later), it indicates a hygiene issue and potential security risk.

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Get-PasswordNotRequired

    .EXAMPLE
    Get-PasswordNotRequired -Domain "contoso.com" -Credential (Get-Credential)

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
        Write-Log "[Get-PasswordNotRequired] Starting check"
    }

    process {
        try {
            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @PSBoundParameters)) {
                return
            }

            Show-SubHeader "Searching for enabled accounts with 'Password Not Required' flag..." -ObjectType "PasswordNotRequired"

            # Query enabled user accounts with PASSWD_NOTREQD flag (UAC bit 32)
            $accounts = Get-DomainUser -Enabled -PasswordNotRequired -ShowOwner @PSBoundParameters

            if ($accounts -and @($accounts).Count -gt 0) {
                $totalAccounts = @($accounts).Count
                Show-Line "Found $totalAccounts enabled account(s) with 'Password Not Required' flag (PASSWD_NOTREQD)" -Class Hint

                $currentIndex = 0
                foreach ($user in $accounts) {
                    $currentIndex++
                    if ($totalAccounts -gt $Script:ProgressThreshold) { Show-Progress -Activity "Processing accounts without password requirement" -Current $currentIndex -Total $totalAccounts -ObjectName $user.sAMAccountName }
                    $user | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'PasswordNotRequired' -Force
                    Show-Object $user
                }
                if ($totalAccounts -gt $Script:ProgressThreshold) { Show-Progress -Activity "Processing accounts without password requirement" -Completed }
            } else {
                Show-Line "No enabled accounts with 'Password Not Required' flag found" -Class Secure
            }

        } catch {
            Write-Log "[Get-PasswordNotRequired] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-PasswordNotRequired] Check completed"
    }
}
