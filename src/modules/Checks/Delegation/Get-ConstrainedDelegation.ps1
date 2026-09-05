function Get-DelegationTargetHost {
    <#
    .SYNOPSIS
    Returns the host out of an SPN held in msDS-AllowedToDelegateTo.

    .DESCRIPTION
    An SPN is "service/host", optionally followed by ":port" and by "/servicename".
    Only the host part decides whether a delegation target is a Domain Controller,
    so that is all this returns; the caller compares it against the known DC names.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$SPN
    )

    if ([string]::IsNullOrWhiteSpace($SPN)) { return $null }

    $slash = $SPN.IndexOf('/')
    if ($slash -lt 0) { return $null }

    # Not $host - that is the automatic variable holding the PowerShell host object.
    $targetHost = $SPN.Substring($slash + 1)

    # Cut the instance port and the trailing service name, whichever comes first.
    $cut = $targetHost.IndexOfAny([char[]]@(':', '/'))
    if ($cut -ge 0) { $targetHost = $targetHost.Substring(0, $cut) }

    if ([string]::IsNullOrWhiteSpace($targetHost)) { return $null }
    return $targetHost.Trim()
}

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

    Two things raise an account above the rest of the list.

    A target on a Domain Controller is a direct path to Domain Admin, and it is matched
    on the host rather than on the service class. Restricting the service class is not a
    control: S4U2Proxy hands back a ticket encrypted with the target host's account key,
    and every SPN registered to that account shares that key, so a ticket obtained for
    time/DC01 can be rewritten to ldap/DC01 and will decrypt. Delegation to any SPN on a
    Domain Controller is therefore worth as much to an attacker as delegation to ldap.

    An account carrying TRUSTED_TO_AUTH_FOR_DELEGATION with no target list at all is
    reported too. It is not reachable through msDS-AllowedToDelegateTo and so falls
    outside the query above, but the flag still buys a forwardable S4U2Self ticket for
    any user against the account's own services, and set on its own it is far more often
    a leftover or a foothold than a configuration anybody intended.

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

            # Protocol transition with no target list at all. Filtered on the server rather
            # than with Where-Object, and kept apart from the two queries above because
            # msDS-AllowedToDelegateTo is exactly what these accounts do not have.
            $noTargetFilter = '(!(msDS-AllowedToDelegateTo=*))'
            $transitionOnlyComputers = @(Get-DomainComputer -TrustedToAuth -Enabled -ShowOwner -LDAPFilter $noTargetFilter @PSBoundParameters)
            $transitionOnlyUsers = @(Get-DomainUser -TrustedToAuth -Enabled -ShowOwner -LDAPFilter $noTargetFilter @PSBoundParameters)

            foreach ($account in ($transitionOnlyComputers + $transitionOnlyUsers)) {
                $account | Add-Member -NotePropertyName 'DelegationAnomaly' `
                    -NotePropertyValue 'Protocol transition enabled without any delegation target' -Force
            }

            # Combine results
            $constrainedAccounts = $constrainedComputers + $constrainedUsers +
                                   $transitionOnlyComputers + $transitionOnlyUsers

            if (@($constrainedAccounts).Count -eq 0) {
                Show-Line "No accounts with Constrained Delegation found" -Class "Secure"
                return
            }

            # Which delegation targets are Domain Controllers. One query for the whole
            # check, and only the names are read - these objects are never displayed, so
            # -Properties here is the internal-use case, not the display path.
            $dcNames = @{}
            try {
                foreach ($dc in @(Get-DomainComputer -DomainController -Properties 'dNSHostName', 'sAMAccountName', 'name' @PSBoundParameters)) {
                    foreach ($candidate in @($dc.dNSHostName, $dc.name, ($dc.sAMAccountName -replace '\$$', ''))) {
                        if (-not [string]::IsNullOrWhiteSpace($candidate)) {
                            $dcNames[$candidate.Trim()] = $true
                        }
                    }
                }
            } catch {
                Write-Log "[Get-ConstrainedDelegation] Could not enumerate Domain Controllers: $_" -Level Warning
            }

            # A failed DC lookup must not quietly downgrade every finding to "no DC target",
            # which would read as a clean result. Say so instead.
            if ($dcNames.Count -eq 0) {
                Show-Line "Domain Controllers could not be enumerated - delegation targets are not checked against them" -Class "Note"
            } else {
                foreach ($account in $constrainedAccounts) {
                    $targetsOnDC = @(
                        foreach ($spn in @($account.'msDS-AllowedToDelegateTo')) {
                            $targetHost = Get-DelegationTargetHost -SPN $spn
                            if ($targetHost -and $dcNames.ContainsKey($targetHost)) { $spn }
                        }
                    )
                    if ($targetsOnDC.Count -gt 0) {
                        $account | Add-Member -NotePropertyName 'DelegationTargetsOnDC' -NotePropertyValue $targetsOnDC -Force
                    }
                }
            }

            # Categorize accounts
            $totalComputers = 0
            $totalUsers = 0
            $totalProtocolTransition = 0
            $totalOnDC = 0
            $totalNoTarget = 0

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

                if ($account.PSObject.Properties['DelegationTargetsOnDC']) { $totalOnDC++ }
                if ($account.PSObject.Properties['DelegationAnomaly']) { $totalNoTarget++ }
            }
            if ($totalAccounts -gt $Script:ProgressThreshold) { Show-Progress -Activity "Analyzing constrained delegation" -Completed }

            $total = @($constrainedAccounts).Count

            Show-Line "Found $total account(s) with Constrained Delegation ($totalComputers computers, $totalUsers users, $totalProtocolTransition with Protocol Transition):" -Class "Finding"

            # Called out separately because it is the difference between "delegation exists"
            # and "there is a path to Domain Admin here".
            if ($totalOnDC -gt 0) {
                Show-Line "$totalOnDC of them delegate to a Domain Controller - treat these as a direct path to Domain Admin" -Class "Finding"
            }
            if ($totalNoTarget -gt 0) {
                Show-Line "$totalNoTarget carry protocol transition without any delegation target" -Class "Hint"
            }

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
