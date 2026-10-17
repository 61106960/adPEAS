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
            # Neither person nor computer: a managed service account's objectCategory is its
            # own class, so both base filters drop it - and msDS-AllowedToActOnBehalfOf-
            # OtherIdentity on a gMSA is the same delegation as on any other account.
            $rbcdMSAs = @(Get-DomainUser -GMSA -RBCD -Enabled -ShowOwner @PSBoundParameters)

            # Combine results
            $rbcdAccounts = $rbcdComputers + $rbcdUsers + $rbcdMSAs

            if (@($rbcdAccounts).Count -eq 0) {
                Show-Line "No accounts with Resource-Based Constrained Delegation found" -Class "Secure"
                return
            }

            $totalComputers = @($rbcdComputers).Count
            $totalUsers = @($rbcdUsers).Count
            $totalMSAs = @($rbcdMSAs).Count
            $total = @($rbcdAccounts).Count

            $populations = "$totalComputers computers, $totalUsers users"
            if ($totalMSAs -gt 0) { $populations = "$populations, $totalMSAs managed service accounts" }
            Show-Line "Found $total account(s) with Resource-Based Constrained Delegation ($populations):" -Class "Finding"

            # Which of these resources is a domain controller. One query for the whole
            # check, names only - these objects are never displayed.
            #
            # An RBCD entry on a domain controller's own computer account is a path to the
            # whole domain: whoever is listed may ask for a ticket to it as any account,
            # including a Domain Admin. The constrained-delegation check asks the same
            # question about its targets (DelegationTargetsOnDC) and this one did not, so
            # an entry on a file server and an attacker-set entry on a DC carried the same
            # title - "Misconfiguration" - and the same score.
            $dcIdentity = @{}
            try {
                foreach ($dc in @(Get-DomainComputer -DomainController -Properties 'dNSHostName', 'sAMAccountName', 'name' @PSBoundParameters)) {
                    foreach ($candidate in @($dc.dNSHostName, $dc.sAMAccountName, $dc.name)) {
                        if ($candidate) { $dcIdentity[([string]$candidate).Trim().TrimEnd('$').ToLower()] = $true }
                    }
                }
            } catch {
                Write-Log "[Get-ResourceBasedConstrainedDelegation] Domain controllers could not be enumerated: $_" -Level Warning
            }
            if ($dcIdentity.Count -eq 0) {
                Show-Line "Domain Controllers could not be enumerated - RBCD targets are not checked against them" -Class "Note"
            }

            foreach ($account in $rbcdAccounts) {
                # Add type marker for HTML report
                $account | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'RBCDelegation' -Force
                if (@($rbcdMSAs) -contains $account) {
                    $account | Add-Member -NotePropertyName 'accountKind' -NotePropertyValue 'Managed service account' -Force
                }

                # Is the resource itself a domain controller?
                $targetIsDC = $false
                foreach ($targetName in @($account.sAMAccountName, $account.dNSHostName, $account.name)) {
                    if (-not $targetName) { continue }
                    if ($dcIdentity.ContainsKey(([string]$targetName).Trim().TrimEnd('$').ToLower())) { $targetIsDC = $true }
                }
                if ($targetIsDC) {
                    $account | Add-Member -NotePropertyName 'rbcdTarget' -NotePropertyValue (
                        'Domain controller - whoever is listed below can request a ticket to it as any account, including a Domain Admin') -Force
                }

                # And who is listed. The attribute arrives decoded: one name per Allow ACE
                # of the security descriptor, or the sentinel below when the descriptor is
                # there and allows nobody.
                #
                # A descriptor the decoder could not read arrives as the raw byte array.
                # Iterating that yields one "principal" per byte, which is how the first
                # version of this block produced rows called 1, 2, 3 and 4.
                $rawPrincipals = $account.'msDS-AllowedToActOnBehalfOfOtherIdentity'
                $undecoded = ($rawPrincipals -is [byte[]])
                $principals = @()
                if (-not $undecoded) { $principals = @($rawPrincipals | Where-Object { $_ }) }
                $emptyDescriptor = ($principals.Count -eq 1 -and ([string]$principals[0]) -eq '[SD present, no Allow ACEs]')

                $rbcdClass = 'Hint'
                if ($undecoded) {
                    $account | Add-Member -NotePropertyName 'rbcdPrincipalRisk' -NotePropertyValue (
                        'Unknown - the security descriptor could not be decoded, so who may delegate to this resource is not visible here') -Force
                } elseif ($emptyDescriptor) {
                    # A descriptor that allows nobody delegates nothing. It is a leftover of
                    # a removed configuration, and it was reported as a finding.
                    $account | Add-Member -NotePropertyName 'rbcdPrincipalRisk' -NotePropertyValue (
                        'None - the attribute is set and its descriptor allows nobody, which is a leftover rather than a delegation') -Force
                    $rbcdClass = 'Note'
                } else {
                    $risks = @()
                    foreach ($principal in $principals) {
                        $principalText = ([string]$principal).Trim()
                        if (-not $principalText) { continue }

                        # An unresolved SID is a deleted or foreign trustee. Worth naming:
                        # the entry still grants delegation, and nobody can tell from the
                        # report who holds it.
                        if ($principalText -match '^S-1-') {
                            $risks += "${principalText}: unresolved - a deleted or foreign principal that still holds the delegation"
                            continue
                        }

                        $principalSID = $null
                        try { $principalSID = ConvertTo-SID -Identity $principalText @PSBoundParameters } catch { }

                        if ($principalSID -and (Test-IsBroadTrustee -SID ([string]$principalSID))) {
                            # Everyone, Authenticated Users, Domain Users, Domain Computers:
                            # every member may impersonate any account to this resource.
                            $risks += "${principalText}: a broad group - every member of it can impersonate any account to this resource"
                            $rbcdClass = 'Finding'
                            continue
                        }

                        $verdict = $null
                        try {
                            $verdict = Test-IsExpectedInScope -Identity $principalText -Scope 'KerberosDelegation' -ReturnDetails
                        } catch {
                            Write-Log "[Get-ResourceBasedConstrainedDelegation] Scope check failed for '$principalText': $_"
                        }

                        if ($verdict -and $verdict.Severity -eq 'Secure') {
                            $risks += "${principalText}: expected - $($verdict.Reason)"
                        } elseif ($verdict -and $verdict.Severity -eq 'Finding') {
                            $risks += "${principalText}: $($verdict.Reason)"
                            $rbcdClass = 'Finding'
                        } elseif ($verdict -and $verdict.Reason) {
                            $risks += "${principalText}: $($verdict.Reason)"
                        } else {
                            # No verdict available: say that rather than imply one.
                            $risks += "${principalText}: not assessed - the principal could not be resolved"
                        }
                    }

                    if ($risks.Count -gt 0) {
                        $account | Add-Member -NotePropertyName 'rbcdPrincipalRisk' -NotePropertyValue $risks -Force
                    }
                }

                # A domain controller as the resource outranks whatever the principals are.
                if ($targetIsDC) { $rbcdClass = 'Finding' }

                Show-Object $account -Class $rbcdClass
            }

        } catch {
            Write-Log "[Get-ResourceBasedConstrainedDelegation] Error: $_" -Level Error
            Show-Line "Error during check - resource-based constrained delegation could not be evaluated: $_" -Class Finding
        }
    }

    end {
        Write-Log "[Get-ResourceBasedConstrainedDelegation] Check completed"
    }
}
