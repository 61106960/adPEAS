function Get-UnconstrainedDelegation {
    <#
    .SYNOPSIS
    Identifies accounts with Unconstrained Delegation enabled.

    .DESCRIPTION
    Detects computer and user accounts configured with Unconstrained Delegation, that allows a service to impersonate any user to any service.

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Get-UnconstrainedDelegation

    .EXAMPLE
    Get-UnconstrainedDelegation -Domain "contoso.com" -Credential (Get-Credential)

    .NOTES
    Category: Delegation
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
        Write-Log "[Get-UnconstrainedDelegation] Starting check"
    }

    process {
        try {
            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @PSBoundParameters)) {
                return
            }

            Show-SubHeader "Searching for accounts with Unconstrained Delegation..." -ObjectType "UnconstrainedDelegation"

            $unconstrainedComputers = @(Get-DomainComputer -Unconstrained -Enabled -ShowOwner @PSBoundParameters)
            $unconstrainedUsers = @(Get-DomainUser -Unconstrained -Enabled -ShowOwner @PSBoundParameters)

            $unconstrainedAccounts = $unconstrainedComputers + $unconstrainedUsers

            if (@($unconstrainedAccounts).Count -eq 0) {
                Show-Line "No accounts with Unconstrained Delegation found (excluding Domain Controllers)" -Class "Secure"
                return
            }

            $totalComputers = @($unconstrainedComputers).Count
            $totalUsers = @($unconstrainedUsers).Count
            $total = @($unconstrainedAccounts).Count

            Show-Line "Found $total account(s) with Unconstrained Delegation ($totalComputers computers, $totalUsers users):" -Class "Finding"

            foreach ($account in $unconstrainedAccounts) {
                # Add type marker for HTML report
                $account | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'UnconstrainedDelegation' -Force
                Show-Object $account
            }

        } catch {
            Write-Log "[Get-UnconstrainedDelegation] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-UnconstrainedDelegation] Check completed"
    }
}
