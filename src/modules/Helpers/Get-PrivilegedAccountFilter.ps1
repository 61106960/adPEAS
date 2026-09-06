<#
.SYNOPSIS
    Builds the LDAP clause that selects the domain's privileged accounts.

.DESCRIPTION
    Several checks want "every privileged account, then look at X on it", and all of them
    used to spell that as adminCount=1. That attribute is a poor definition in both
    directions.

    It over-reports, because AdminSDHolder sets it and never clears it: an account removed
    from Domain Admins years ago still carries adminCount=1. The checks that cared already
    handled this by verifying each candidate with Test-IsPrivileged.

    It under-reports, and nothing handled that. AdminSDHolder protects a fixed list of
    groups, and adPEAS treats groups outside it as privileged - Group Policy Creator Owners
    (RID -520) most obviously, whose members can create and edit Group Policy and never
    receive adminCount at all. The propagation is also periodic, SDProp runs hourly by
    default, so an account added to Domain Admins this morning is not marked yet.

    The clause returned here is the union of the two: membership in one of the privileged
    groups, resolved through LDAP_MATCHING_RULE_IN_CHAIN so nested members count, OR
    adminCount=1 - which stays in, because it catches an account whose group this build
    does not know about. It is a candidate filter, not a verdict: the caller still confirms
    each hit with Test-IsPrivileged, which is what removes the accounts adminCount only
    remembers.

    The group DNs are resolved once and cached for the session; Disconnect-adPEAS clears
    the cache.

.PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

.PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

.PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

.PARAMETER IncludeOperators
    Also select members of the operator groups - Account Operators, Server Operators and
    their kin. They cannot administer the domain outright but can reset passwords or log on
    to domain controllers, which is close enough for most checks.

.OUTPUTS
    String - an LDAP filter clause, ready to hand to -LDAPFilter.

.EXAMPLE
    $privileged = Get-PrivilegedAccountFilter @connectionParams
    Get-DomainUser -ReversibleEncryption -LDAPFilter $privileged @connectionParams

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

function Get-PrivilegedAccountFilter {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeOperators
    )

    process {
        $cacheKey = if ($IncludeOperators) { 'WithOperators' } else { 'PrivilegedOnly' }

        if ($Script:PrivilegedAccountFilterCache -and
            $Script:PrivilegedAccountFilterCache.ContainsKey($cacheKey)) {
            return $Script:PrivilegedAccountFilterCache[$cacheKey]
        }

        $connectionParams = @{}
        if ($PSBoundParameters.ContainsKey('Domain'))     { $connectionParams['Domain'] = $Domain }
        if ($PSBoundParameters.ContainsKey('Server'))     { $connectionParams['Server'] = $Server }
        if ($PSBoundParameters.ContainsKey('Credential')) { $connectionParams['Credential'] = $Credential }

        # adminCount is always part of the union. It is the fallback for a privileged group
        # this build does not list, and the caller's verification removes what it over-reports.
        $clauses = @('(adminCount=1)')

        $ridSuffixes = @($Script:PrivilegedRIDSuffixes)
        if ($IncludeOperators) { $ridSuffixes += @($Script:OperatorRIDSuffixes) }

        # Primary group membership, which memberOf does not express, and which needs no
        # domain SID and no query - so it is built first and survives both of the failures
        # the group resolution below can run into.
        #
        # An account whose primaryGroupID is 512 is a Domain Admin: the RID is in its token.
        # But the group does not list it in "member", the account has no "memberOf" pointing
        # back, and LDAP_MATCHING_RULE_IN_CHAIN therefore cannot see it either. Setting the
        # primary group is a known way to hold privilege out of sight of exactly the
        # enumeration everything else here does. The attribute is indexed, and 513 for a
        # user or 515 for a computer is the default that never appears in this list.
        foreach ($rid in $ridSuffixes) {
            # -500 and -502 are accounts rather than groups, so no primary group points at
            # them and no membership clause is built for them below either.
            if ($rid -in @('-500', '-502')) { continue }
            $clauses += ('(primaryGroupID=' + $rid.TrimStart('-') + ')')
        }

        $domainSID = $Script:LDAPContext['DomainSID']
        if ($domainSID) {
            foreach ($rid in $ridSuffixes) {
                # Only group RIDs produce a membership clause. -500 is the built-in
                # Administrator account and -502 is krbtgt: nobody is a member of either,
                # and asking would cost a query for a guaranteed empty answer.
                if ($rid -in @('-500', '-502')) { continue }

                try {
                    $group = @(Get-DomainGroup -Identity "$domainSID$rid" -Properties 'distinguishedName' @connectionParams)[0]
                } catch {
                    Write-Log "[Get-PrivilegedAccountFilter] Could not resolve group $domainSID$rid : $($_.Exception.Message)"
                    continue
                }

                if (-not $group -or -not $group.distinguishedName) {
                    # Normal rather than exceptional: Schema Admins and Enterprise Admins
                    # exist only in the forest root, so a child domain resolves neither.
                    Write-Log "[Get-PrivilegedAccountFilter] No group for RID $rid in this domain"
                    continue
                }

                # The DN goes through the escaper: a group renamed to something containing
                # a parenthesis or an escaped comma would otherwise produce a filter the
                # server rejects, and the whole clause with it.
                $escapedDN = Escape-LDAPFilterDN -DistinguishedName $group.distinguishedName
                $clauses += "(memberOf:1.2.840.113556.1.4.1941:=$escapedDN)"
            }
        } else {
            Write-Log "[Get-PrivilegedAccountFilter] No domain SID in session - falling back to adminCount alone"
        }

        $filter = '(|' + ($clauses -join '') + ')'
        Write-Log "[Get-PrivilegedAccountFilter] $($clauses.Count) clause(s) for $cacheKey"

        if (-not $Script:PrivilegedAccountFilterCache) {
            $Script:PrivilegedAccountFilterCache = @{}
        }
        $Script:PrivilegedAccountFilterCache[$cacheKey] = $filter

        return $filter
    }
}
