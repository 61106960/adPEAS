function Get-ConstrainedDelegation {
    <#
    .SYNOPSIS
    Identifies accounts with Constrained Delegation enabled.

    .DESCRIPTION
    Detects computer and user accounts configured with Constrained Delegation, which allows a service to impersonate users to specific services only.

    Two Types of Constrained Delegation:
    1. Standard Constrained Delegation (msDS-AllowedToDelegateTo attribute)
       - Requires user to authenticate with Kerberos
       - Delegation limited to specific SPNs
    2. Protocol Transition (TRUSTED_TO_AUTH_FOR_DELEGATION flag)
       - Allows delegation without Kerberos authentication from user
       - Service can accept non-Kerberos authentication and still delegate
       - Higher security risk

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Get-ConstrainedDelegation

    .EXAMPLE
    Get-ConstrainedDelegation -Domain "contoso.com" -Credential (Get-Credential)

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
        Write-Log "[Get-ConstrainedDelegation] Starting check"
    }

    process {
        try {
            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @PSBoundParameters)) {
                return
            }

            Show-SubHeader "Searching for accounts with Constrained Delegation..." -ObjectType "ConstrainedDelegation"

            $constrainedComputers = @(Get-DomainComputer -Constrained -Enabled -ShowOwner @PSBoundParameters)
            $constrainedUsers = @(Get-DomainUser -Constrained -Enabled -ShowOwner @PSBoundParameters)

            # Combine results
            $constrainedAccounts = $constrainedComputers + $constrainedUsers

            if (@($constrainedAccounts).Count -eq 0) {
                Show-Line "No accounts with Constrained Delegation found" -Class "Secure"
                return
            }

            # Categorize accounts
            $totalComputers = 0
            $totalUsers = 0
            $totalProtocolTransition = 0

            $totalAccounts = @($constrainedAccounts).Count
            $currentIndex = 0
            foreach ($account in $constrainedAccounts) {
                $currentIndex++
                if ($totalAccounts -gt $Script:ProgressThreshold) { Show-Progress -Activity "Analyzing constrained delegation" -Current $currentIndex -Total $totalAccounts -ObjectName $account.sAMAccountName }
                $isComputer = $account.objectClass -icontains "computer"
                if ($isComputer) {
                    $totalComputers++
                } else {
                    $totalUsers++
                }

                # Check for Protocol Transition (TRUSTED_TO_AUTH_FOR_DELEGATION)
                $uacFlags = $account.userAccountControl
                if ($uacFlags -contains "TRUSTED_TO_AUTH_FOR_DELEGATION") {
                    $totalProtocolTransition++
                }
            }
            if ($totalAccounts -gt $Script:ProgressThreshold) { Show-Progress -Activity "Analyzing constrained delegation" -Completed }

            $total = @($constrainedAccounts).Count

            Show-Line "Found $total account(s) with Constrained Delegation ($totalComputers computers, $totalUsers users, $totalProtocolTransition with Protocol Transition):" -Class "Finding"

            $totalAccounts = @($constrainedAccounts).Count
            $currentIndex = 0
            foreach ($account in $constrainedAccounts) {
                $currentIndex++
                if ($totalAccounts -gt $Script:ProgressThreshold) { Show-Progress -Activity "Analyzing constrained delegation" -Current $currentIndex -Total $totalAccounts -ObjectName $account.sAMAccountName }
                # Add type marker for HTML report
                $account | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'ConstrainedDelegation' -Force
                Show-Object $account
            }
            if ($totalAccounts -gt $Script:ProgressThreshold) { Show-Progress -Activity "Analyzing constrained delegation" -Completed }

        } catch {
            Write-Log "[Get-ConstrainedDelegation] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-ConstrainedDelegation] Check completed"
    }
}
