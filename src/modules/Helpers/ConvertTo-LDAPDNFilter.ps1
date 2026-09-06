function ConvertTo-LDAPDNFilter {
    <#
    .SYNOPSIS
    Turns a list of distinguished names into a small number of LDAP OR filters.

    .DESCRIPTION
    Checks routinely work in two passes: a cheap query that decides which objects are
    interesting, then a second read of the full objects for the report. Written the obvious
    way the second pass is one LDAP round-trip per finding, so a domain with three hundred
    findings pays three hundred round-trips for data one query could have returned.

    This builds the filters for that second pass: '(|(distinguishedName=a)(distinguishedName=b)...)',
    split into batches so no single filter grows past what a domain controller will accept.
    Every DN is escaped with Escape-LDAPFilterDN, because a DN carrying '(', ')' or an
    escaped comma - 'CN=Doe\, Jane (Contractor),...' is an ordinary name - otherwise
    produces an invalid filter and the object silently vanishes from the report.

    .PARAMETER DistinguishedName
    The DNs to read. Empty entries are dropped; duplicates are collapsed, since asking for
    the same object twice returns it twice.

    .PARAMETER BatchSize
    How many DNs go into one filter. The default of 50 keeps a filter well under the
    server's parse limits even with long DNs, while turning hundreds of round-trips into a
    handful.

    .OUTPUTS
    Array of LDAP filter strings. Empty array when there is nothing to look up, so the
    caller's foreach simply does not run.

    .EXAMPLE
    foreach ($filter in (ConvertTo-LDAPDNFilter -DistinguishedName $dns)) {
        $objects += @(Get-DomainComputer -LDAPFilter $filter @connectionParams)
    }
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory=$false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$DistinguishedName,

        [Parameter(Mandatory=$false)]
        [ValidateRange(1, 500)]
        [int]$BatchSize = 50
    )

    $seen = @{}
    $unique = @()
    foreach ($dn in @($DistinguishedName)) {
        if ([string]::IsNullOrWhiteSpace($dn)) { continue }
        # DNs are case-insensitive, so two spellings of one DN are one object
        $key = $dn.ToLowerInvariant()
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $unique += $dn
    }

    if ($unique.Count -eq 0) { return @() }

    $filters = @()
    for ($i = 0; $i -lt $unique.Count; $i += $BatchSize) {
        $last = [Math]::Min($i + $BatchSize, $unique.Count) - 1
        $clauses = ''
        foreach ($dn in $unique[$i..$last]) {
            $clauses += ('(distinguishedName=' + (Escape-LDAPFilterDN -DistinguishedName $dn) + ')')
        }
        # A single DN needs no OR wrapper, and the plain equality filter is the one a
        # domain controller can answer straight from the index
        $filters += $(if ($last -eq $i) { $clauses } else { '(|' + $clauses + ')' })
    }

    return $filters
}
