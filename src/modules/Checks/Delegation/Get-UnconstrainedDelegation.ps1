<#
.SYNOPSIS
    Finds the privileged accounts whose TGT a host with unconstrained delegation receives.

.DESCRIPTION
    A Kerberos logon to a host trusted for unconstrained delegation carries a copy of the
    client's TGT, and the host keeps it. Two things stop the KDC from handing it over: the
    flag "Account is sensitive and cannot be delegated" (NOT_DELEGATED in
    userAccountControl), and membership in Protected Users - which takes effect at domain
    functional level Windows Server 2012 R2 or higher only.

    The candidates are the enabled user and managed service accounts
    Get-PrivilegedAccountFilter selects, operators included, without NOT_DELEGATED: the
    server drops the marked ones. Test-IsPrivileged confirms each, which removes the
    accounts adminCount only remembers. Protected Users is read recursively and by primary
    group, as Get-ProtectedUsersStatus reads it.

    Computer accounts are not asked. A Domain Controller's machine account is the TGT a
    coercion delivers to these hosts, and neither control is meant for a computer account,
    so no answer here would change that.

.PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

.PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

.PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

.OUTPUTS
    PSCustomObject with Exposed - the sAMAccountNames, sorted - and ProtectedUsersCounted:
    whether membership in Protected Users was taken as protection, $null when there was
    no candidate to ask about.

.NOTES
    Internal helper function
#>
function Get-UnconstrainedDelegationExposure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential
    )

    $privilegedFilter = Get-PrivilegedAccountFilter -IncludeOperators @PSBoundParameters
    # NOT_DELEGATED, 0x100000: the KDC never forwards the TGT of an account that has it.
    $candidateFilter = "(&$privilegedFilter(!(userAccountControl:1.2.840.113556.1.4.803:=1048576)))"

    # Users, and the managed service accounts, which are neither person nor computer and
    # fall out of the user query's base filter.
    $candidates = @(Get-DomainUser -Enabled -LDAPFilter $candidateFilter -Properties 'sAMAccountName', 'objectSid' @PSBoundParameters)
    $candidates += @(Get-DomainUser -GMSA -Enabled -LDAPFilter $candidateFilter -Properties 'sAMAccountName', 'objectSid' @PSBoundParameters)

    $protectedUsersCounted = $null
    $protectedSIDs = @{}
    if ($candidates.Count -gt 0) {
        # An unreadable domain object counts as a level below 2012 R2: the members of
        # Protected Users are then reported, and the caller says that the group was not
        # counted.
        $domainObject = @(Get-DomainObject -Identity $Script:LDAPContext.DomainDN -Properties 'msDS-Behavior-Version' @PSBoundParameters)[0]
        $protectedUsersCounted = [int]$domainObject.'msDS-Behavior-Version' -ge 6

        if ($protectedUsersCounted) {
            # Recursively, because Protected Users takes effect through the token and a
            # nested group protects its members, and by primary group, which leaves no
            # member link for the recursive filter to follow.
            $protectedClauses = @('(primaryGroupID=525)')
            $protectedGroup = @(Get-DomainGroup -Identity "$($Script:LDAPContext.DomainSID)-525" -Properties 'distinguishedName' @PSBoundParameters)[0]
            if ($protectedGroup -and $protectedGroup.distinguishedName) {
                $escapedProtectedDN = Escape-LDAPFilterDN -DistinguishedName $protectedGroup.distinguishedName
                $protectedClauses += "(memberOf:1.2.840.113556.1.4.1941:=$escapedProtectedDN)"
            }
            foreach ($protectedObject in @(Get-DomainObject -LDAPFilter ('(|' + ($protectedClauses -join '') + ')') -Properties 'objectSid' @PSBoundParameters)) {
                # A contact can be a member and has no SID.
                if ($protectedObject.objectSid) { $protectedSIDs[$protectedObject.objectSid] = $true }
            }
        }
    }

    $exposed = @()
    foreach ($candidate in $candidates) {
        if ($protectedSIDs.ContainsKey($candidate.objectSid)) { continue }
        if (-not (Test-IsPrivileged -Identity $candidate -IncludeOperators).IsPrivileged) { continue }
        $exposed += $candidate.sAMAccountName
    }

    return [PSCustomObject]@{
        Exposed               = @($exposed | Sort-Object)
        ProtectedUsersCounted = $protectedUsersCounted
    }
}

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

            # Whose TGT these hosts receive. The list above says where a TGT can be
            # collected; a privileged account that logs on to one of these hosts with
            # Kerberos hands it its own, unless the account is marked as sensitive or is in
            # Protected Users.
            try {
                $exposure = Get-UnconstrainedDelegationExposure @PSBoundParameters
                $exposedNames = @($exposure.Exposed)
                if ($exposedNames.Count -gt 0) {
                    $shownNames = @($exposedNames | Select-Object -First 20) -join ', '
                    if ($exposedNames.Count -gt 20) { $shownNames = "$shownNames, ... and $($exposedNames.Count - 20) more" }
                    Show-Line "$($exposedNames.Count) privileged account(s) hand their TGT to these hosts on every Kerberos logon to them - neither marked as sensitive nor in Protected Users: $shownNames" -Class Finding -FindingId 'UNCONSTRAINED_DELEGATION_EXPOSED_ACCOUNTS'
                } else {
                    Show-Line "Every privileged account is marked as sensitive or in Protected Users, so none hands its TGT to these hosts - a coerced Domain Controller's machine account still does" -Class Note
                }
                if ($exposure.ProtectedUsersCounted -eq $false) {
                    Show-Line "Protected Users was not counted as protection - it stops delegation at domain functional level Windows Server 2012 R2 or higher only" -Class Note
                }
            } catch {
                Write-Log "[Get-UnconstrainedDelegation] Privileged account exposure could not be evaluated: $_" -Level Warning
                Show-Line "Privileged accounts could not be checked against these hosts - the sensitive flag and Protected Users were not evaluated" -Class Note
            }

        } catch {
            Write-Log "[Get-UnconstrainedDelegation] Error: $_" -Level Error
            Show-Line "Error during check - unconstrained delegation could not be evaluated: $_" -Class Finding
        }
    }

    end {
        Write-Log "[Get-UnconstrainedDelegation] Check completed"
    }
}
