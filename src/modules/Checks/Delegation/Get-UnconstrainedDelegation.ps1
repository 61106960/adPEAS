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

            # And the managed service accounts, which are neither of the above.
            # objectCategory is single-valued and carries the most specific class, so a gMSA
            # is CN=ms-DS-Group-Managed-Service-Account and an sMSA
            # CN=ms-DS-Managed-Service-Account: neither matches (objectCategory=person) nor
            # (objectCategory=computer), so both base filters drop them. A gMSA is exactly
            # the kind of account an administrator configures delegation on, and the secure
            # line below spoke for the whole domain while never having looked at one.
            $unconstrainedMSAs = @(Get-DomainUser -GMSA -Unconstrained -Enabled -ShowOwner @PSBoundParameters)

            $unconstrainedAccounts = $unconstrainedComputers + $unconstrainedUsers + $unconstrainedMSAs

            if (@($unconstrainedAccounts).Count -eq 0) {
                Show-Line "No accounts with Unconstrained Delegation found (excluding Domain Controllers)" -Class "Secure"
                return
            }

            $totalComputers = @($unconstrainedComputers).Count
            $totalUsers = @($unconstrainedUsers).Count
            $totalMSAs = @($unconstrainedMSAs).Count
            $total = @($unconstrainedAccounts).Count

            $populations = "$totalComputers computers, $totalUsers users"
            if ($totalMSAs -gt 0) { $populations = "$populations, $totalMSAs managed service accounts" }
            Show-Line "Found $total account(s) with Unconstrained Delegation ($populations):" -Class "Finding"

            foreach ($account in $unconstrainedAccounts) {
                # Add type marker for HTML report
                $account | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'UnconstrainedDelegation' -Force
                if (@($unconstrainedMSAs) -contains $account) {
                    # Named on the row: a reader who sees a delegation finding on something
                    # that is neither a server nor a user account needs to know which it is.
                    $account | Add-Member -NotePropertyName 'accountKind' -NotePropertyValue 'Managed service account' -Force
                }
                Show-Object $account -Class Finding
            }

        } catch {
            Write-Log "[Get-UnconstrainedDelegation] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-UnconstrainedDelegation] Check completed"
    }
}
