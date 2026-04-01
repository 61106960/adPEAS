function Get-ResourceBasedConstrainedDelegation {
    <#
    .SYNOPSIS
    Identifies accounts with Resource-Based Constrained Delegation (RBCD) configured.

    .DESCRIPTION
    Detects computer and user accounts configured with Resource-Based Constrained Delegation, a newer delegation model where the target resource controls who can delegate to it.

    RBCD vs. Traditional Constrained Delegation:
    - Traditional: Source (delegating service) defines where it can delegate
    - RBCD: Target (resource) defines who can delegate to it
    - RBCD uses msDS-AllowedToActOnBehalfOfOtherIdentity attribute (Security Descriptor)
    - RBCD doesn't require Domain Admin to configure (can be self-managed)

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Get-ResourceBasedConstrainedDelegation

    .EXAMPLE
    Get-ResourceBasedConstrainedDelegation -Domain "contoso.com" -Credential (Get-Credential)

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
        Write-Log "[Get-ResourceBasedConstrainedDelegation] Starting check"
    }

    process {
        try {
            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @PSBoundParameters)) {
                return
            }

            Show-SubHeader "Searching for accounts with RBCD configured..." -ObjectType "RBCDelegation"

            $rbcdComputers = @(Get-DomainComputer -RBCD -Enabled -ShowOwner @PSBoundParameters)
            $rbcdUsers = @(Get-DomainUser -RBCD -Enabled -ShowOwner @PSBoundParameters)

            # Combine results
            $rbcdAccounts = $rbcdComputers + $rbcdUsers

            if (@($rbcdAccounts).Count -eq 0) {
                Show-Line "No accounts with Resource-Based Constrained Delegation found" -Class "Secure"
                return
            }

            $totalComputers = @($rbcdComputers).Count
            $totalUsers = @($rbcdUsers).Count
            $total = @($rbcdAccounts).Count

            Show-Line "Found $total account(s) with Resource-Based Constrained Delegation ($totalComputers computers, $totalUsers users):" -Class "Finding"

            foreach ($account in $rbcdAccounts) {
                # Add type marker for HTML report
                $account | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'RBCDelegation' -Force
                Show-Object $account
            }

        } catch {
            Write-Log "[Get-ResourceBasedConstrainedDelegation] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-ResourceBasedConstrainedDelegation] Check completed"
    }
}
