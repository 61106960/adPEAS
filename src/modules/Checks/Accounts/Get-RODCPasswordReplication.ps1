function Get-RODCPasswordReplication {
    <#
    .SYNOPSIS
    Checks which privileged accounts a read-only Domain Controller may cache the password of.

    .DESCRIPTION
    A read-only Domain Controller holds no secrets of its own choosing. Its password
    replication policy decides which accounts it may cache: msDS-RevealOnDemandGroup on its
    computer object lists who is allowed, msDS-NeverRevealGroup who is denied, and deny
    wins. By default the deny list holds the Denied RODC Password Replication Group -
    Domain Admins, Enterprise Admins, Schema Admins and the other Tier-0 groups - and
    Administrators, Account Operators, Server Operators and Backup Operators. An RODC stands
    where physical security is weakest, so a privileged account whose password it may cache
    is exposed to whoever takes the server.

    For every privileged account - Get-PrivilegedAccountFilter with the operators,
    confirmed by Test-IsPrivileged - the check builds the groups of its token: the
    recursive membership, and the primary group with its own nesting, which leaves no
    member link. These are compared with each RODC's allow and deny list. The check also
    reads msDS-RevealedUsers, the accounts whose secrets the RODC has already received.

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Get-RODCPasswordReplication

    .EXAMPLE
    Get-RODCPasswordReplication -Domain "contoso.com" -Credential (Get-Credential)

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
        Write-Log "[Get-RODCPasswordReplication] Starting check"
    }

    process {
        try {
            if (-not (Ensure-LDAPConnection @PSBoundParameters)) {
                return
            }

            Show-SubHeader "Checking the password replication policy of read-only Domain Controllers..." -ObjectType "RODCPasswordReplication"

            # The Domain Controller definition lives in Get-DomainComputer; a read-only one is
            # the one with PARTIAL_SECRETS_ACCOUNT.
            $rodcs = @(Get-DomainComputer -DomainController @PSBoundParameters | Test-AccountActivity -IsEnabled |
                Where-Object { @($_.userAccountControl) -contains 'PARTIAL_SECRETS_ACCOUNT' })
            if ($rodcs.Count -eq 0) {
                Show-Line "No read-only Domain Controller in this domain - there is no password replication policy to check" -Class Note
                return
            }

            # The privileged accounts, each with the SIDs of its token.
            $privilegedFilter = Get-PrivilegedAccountFilter -IncludeOperators @PSBoundParameters
            $accountProperties = @('sAMAccountName', 'objectSid', 'distinguishedName', 'primaryGroupID')
            $candidates = @(Get-DomainUser -Enabled -LDAPFilter $privilegedFilter -Properties $accountProperties @PSBoundParameters)
            $candidates += @(Get-DomainUser -GMSA -Enabled -LDAPFilter $privilegedFilter -Properties $accountProperties @PSBoundParameters)

            $privileged = @()
            foreach ($candidate in $candidates) {
                if (-not (Test-IsPrivileged -Identity $candidate -IncludeOperators).IsPrivileged) { continue }

                $sid = [string]$candidate.objectSid
                $tokenSIDs = @($sid) + @(Get-RecursiveGroupMembership -IdentitySID $sid -IdentityDN ([string]$candidate.distinguishedName))
                # The primary group is in the token without a member link, so the recursive
                # membership does not return it; its RID is relative to the account's domain.
                if ($candidate.primaryGroupID -and $sid -match '^(S-1-5-21-\d+-\d+-\d+)-\d+$') {
                    $primaryGroupSID = "$($Matches[1])-$($candidate.primaryGroupID)"
                    $tokenSIDs += @($primaryGroupSID) + @(Get-RecursiveGroupMembership -IdentitySID $primaryGroupSID)
                }

                $privileged += [PSCustomObject]@{
                    Name              = [string]$candidate.sAMAccountName
                    DistinguishedName = [string]$candidate.distinguishedName
                    TokenSIDs         = $tokenSIDs
                }
            }

            # The allow and deny lists hold DNs; the token holds SIDs. Every DN once.
            $sidByDN = @{}
            foreach ($rodc in $rodcs) {
                foreach ($dn in (@($rodc.'msDS-RevealOnDemandGroup') + @($rodc.'msDS-NeverRevealGroup'))) {
                    if (-not $dn -or $sidByDN.ContainsKey([string]$dn)) { continue }
                    $listed = @(Get-DomainObject -Identity ([string]$dn) -Properties 'objectSid' @PSBoundParameters)[0]
                    $sidByDN[[string]$dn] = if ($listed -and $listed.objectSid) { [string]$listed.objectSid } else { $null }
                }
            }

            $deniedGroupSID = "$($Script:LDAPContext.DomainSID)-572"

            foreach ($rodc in $rodcs) {
                $rodcName = ([string]$rodc.sAMAccountName).TrimEnd('$')

                $allowed = @{}
                foreach ($dn in @($rodc.'msDS-RevealOnDemandGroup')) {
                    if ($dn -and $sidByDN[[string]$dn]) { $allowed[$sidByDN[[string]$dn]] = $true }
                }
                $denied = @{}
                $unresolvedDenied = 0
                foreach ($dn in @($rodc.'msDS-NeverRevealGroup')) {
                    if (-not $dn) { continue }
                    if ($sidByDN[[string]$dn]) { $denied[$sidByDN[[string]$dn]] = $true } else { $unresolvedDenied++ }
                }

                $exposedNames = @()
                foreach ($account in $privileged) {
                    $isAllowed = @($account.TokenSIDs | Where-Object { $allowed.ContainsKey($_) }).Count -gt 0
                    $isDenied  = @($account.TokenSIDs | Where-Object { $denied.ContainsKey($_) }).Count -gt 0
                    if ($isAllowed -and -not $isDenied) { $exposedNames += $account.Name }
                }

                # msDS-RevealedUsers is DN-Binary, one value per secret attribute received:
                # B:<length>:<hex>:<DN>.
                $revealedDNs = @{}
                foreach ($value in @($rodc.'msDS-RevealedUsers')) {
                    if ("$value" -match '^B:\d+:[0-9A-Fa-f]*:(.+)$') { $revealedDNs[$Matches[1]] = $true }
                }
                $revealedNames = @($privileged | Where-Object { $revealedDNs.ContainsKey($_.DistinguishedName) } | ForEach-Object { $_.Name })

                $issues = 0
                if ($exposedNames.Count -gt 0) {
                    $issues++
                    Show-Line "$rodcName - $($exposedNames.Count) privileged account(s) may have their password cached, allowed and not denied by its password replication policy: $(Format-RODCAccountList $exposedNames)" -Class Finding -FindingId 'RODC_PRIVILEGED_PASSWORD_ALLOWED'
                }
                if ($revealedNames.Count -gt 0) {
                    $issues++
                    Show-Line "$rodcName - the secrets of $($revealedNames.Count) privileged account(s) are cached on it already: $(Format-RODCAccountList $revealedNames)" -Class Finding -FindingId 'RODC_PRIVILEGED_PASSWORD_REVEALED'
                }
                if (-not $denied.ContainsKey($deniedGroupSID)) {
                    $issues++
                    Show-Line "$rodcName - the Denied RODC Password Replication Group is not on its deny list" -Class Hint -FindingId 'RODC_DENIED_GROUP_MISSING'
                }
                if ($unresolvedDenied -gt 0) {
                    $issues++
                    Show-Line "$rodcName - $unresolvedDenied member(s) of its deny list could not be resolved and were not counted" -Class Note
                }
                if ($issues -eq 0) {
                    Show-Line "$rodcName - no privileged account may have its password cached, and none has" -Class Secure
                }
            }

        } catch {
            Write-Log "[Get-RODCPasswordReplication] Error: $_" -Level Error
            Show-Line "Error during check - the password replication policy of the read-only Domain Controllers could not be evaluated: $_" -Class Finding
        }
    }

    end {
        Write-Log "[Get-RODCPasswordReplication] Check completed"
    }
}

<#
.SYNOPSIS
    Joins account names for a line, sorted, with at most twenty spelled out.

.NOTES
    Internal helper function
#>
function Format-RODCAccountList {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$Name
    )

    $sorted = @($Name | Sort-Object)
    $shown = @($sorted | Select-Object -First 20) -join ', '
    if ($sorted.Count -gt 20) { $shown = "$shown, ... and $($sorted.Count - 20) more" }
    return $shown
}
