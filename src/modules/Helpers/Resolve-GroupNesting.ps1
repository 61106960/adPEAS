<#
.SYNOPSIS
    Group nesting, resolved: every group an account is in.

.DESCRIPTION
    memberOf and member hold the links written on the two objects, and nothing else. Two
    kinds of membership are missing from them, and both count in a logon token:

    - The primary group. Active Directory keeps it in primaryGroupID, as a RID, and never
      in member - so Domain Users, the primary group of almost every user, lists none of
      them, and no user lists it.
    - Nesting. A group may itself be a member of other groups, to any depth.

    The chains come from LDAP_MATCHING_RULE_IN_CHAIN (1.2.840.113556.1.4.1941), which the
    domain controller evaluates over the whole chain in one query. Which group an entry
    was reached through is read from memberOf of the objects the query returned, so a
    chain can be followed link by link. The rule is evaluated within the domain the query
    runs against: a group in another domain or forest that holds an account through a
    foreign security principal is not found.

    Get-DomainUser -ResolveGroups uses these.

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

<#
.SYNOPSIS
    One entry as a reader sees it: the name and how it was reached.

.DESCRIPTION
    "Server Operators (via Tier1)" or "Domain Users (primary group)". Shared by the
    ToString of the entries and by the memberOfNested transformer, which also sees entries
    that came back from a JSON report and carry no ToString of their own.

.PARAMETER Entry
    An entry with Name, Membership and Via.
#>
function Format-GroupNestingEntry {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$false)]
        [AllowNull()]
        $Entry
    )

    if ($null -eq $Entry) { return '' }
    $name = [string]$Entry.Name
    $via = [string]$Entry.Via

    switch ([string]$Entry.Membership) {
        'Primary group' { return "$name (primary group)" }
        default {
            if ($via) { return "$name (via $via)" }
            return "$name (nested)"
        }
    }
}

<#
.SYNOPSIS
    The SID of an object as a string, from either shape it can arrive in.

.PARAMETER Value
    objectSid as Get-DomainObject returns it: a string, or the byte[] of -Raw.
#>
function ConvertTo-GroupNestingSid {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$false)]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) { return '' }
    if ($Value -is [byte[]]) {
        try { return (New-Object System.Security.Principal.SecurityIdentifier($Value, 0)).Value } catch { return '' }
    }
    $text = [string]$Value
    if ($text -match '^S-1-') { return $text }
    return ''
}

<#
.SYNOPSIS
    The display name of a directory object: name, then sAMAccountName, then its RDN.

.PARAMETER Object
    The object.
#>
function Get-GroupNestingName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$false)]
        [AllowNull()]
        $Object
    )

    if ($null -eq $Object) { return '' }
    if ($Object.name) { return [string]$Object.name }
    if ($Object.sAMAccountName) { return [string]$Object.sAMAccountName }
    $dn = [string]$Object.distinguishedName
    $parsed = Split-LDAPDN -DistinguishedName $dn
    if ($parsed -and $parsed.RDNValue) { return $parsed.RDNValue }
    return $dn
}

<#
.SYNOPSIS
    Builds one entry and gives it the ToString a console list shows.

.PARAMETER Object
    The group the entry is about.

.PARAMETER Membership
    'Nested' or 'Primary group'.

.PARAMETER Via
    The name of the group the entry was reached through, or empty.
#>
function New-GroupNestingEntry {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory=$true)]
        $Object,

        [Parameter(Mandatory=$true)]
        [string]$Membership,

        [Parameter(Mandatory=$false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Via
    )

    $viaValue = if ($Via) { $Via } else { $null }
    $entry = [PSCustomObject]@{
        Name              = Get-GroupNestingName -Object $Object
        Membership        = $Membership
        Via               = $viaValue
        DistinguishedName = [string]$Object.distinguishedName
        SID               = ConvertTo-GroupNestingSid -Value $Object.objectSid
    }
    $entry | Add-Member -MemberType ScriptMethod -Name 'ToString' -Value { Format-GroupNestingEntry -Entry $this } -Force
    return $entry
}

<#
.SYNOPSIS
    The groups an account belongs to that its memberOf does not list: its primary group,
    and every group reached through nesting.

.DESCRIPTION
    The groups of memberOf are not repeated; memberOf and the result together are every
    group of the account in its domain. Nested groups come first, in the order a
    breadth-first walk up from memberOf reaches them, each naming the group it was reached
    through; then the primary group and the groups it is nested in.

.PARAMETER Account
    The account object, with distinguishedName, memberOf, primaryGroupID and objectSid.

.PARAMETER ConnectionParams
    Domain, Server and Credential for Get-DomainObject, where the caller was given them.

.PARAMETER PrimaryGroupCache
    The primary group and the groups it is nested in, by SID, shared across the accounts
    of one call: almost every account has the same primary group.

.OUTPUTS
    One PSCustomObject per group: Name, Membership ('Nested' or 'Primary group'), Via,
    DistinguishedName and SID.
#>
function Resolve-AccountGroupNesting {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory=$true)]
        $Account,

        [Parameter(Mandatory=$false)]
        [hashtable]$ConnectionParams = @{},

        [Parameter(Mandatory=$false)]
        [hashtable]$PrimaryGroupCache = @{}
    )

    $accountDN = [string]$Account.distinguishedName
    if ([string]::IsNullOrWhiteSpace($accountDN)) { return @() }

    $groupProperties = @('distinguishedName', 'name', 'objectSid', 'memberOf')
    $entries = New-Object System.Collections.ArrayList

    # Every group accounted for, by DN. The groups of memberOf go in first, so none of them
    # is listed again; a hashtable compares DNs without case, as the directory does.
    $seen = @{}
    $directDNs = @(@($Account.memberOf) | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    foreach ($directDN in $directDNs) { $seen[$directDN] = $true }

    # Walks up from the given groups along memberOf, within the groups a chain query
    # returned. Breadth first, so every group names the link closest to the account.
    function Add-GroupChain {
        param([object[]]$Start, [hashtable]$ChainByDN)

        $queue = New-Object System.Collections.Queue
        foreach ($startGroup in $Start) { $queue.Enqueue($startGroup) }
        while ($queue.Count -gt 0) {
            $current = $queue.Dequeue()
            $parentDNs = @(@($current.memberOf) | ForEach-Object { [string]$_ } |
                Where-Object { $ChainByDN.ContainsKey($_) } | Sort-Object)
            foreach ($parentDN in $parentDNs) {
                if ($seen.ContainsKey($parentDN)) { continue }
                $seen[$parentDN] = $true
                $parent = $ChainByDN[$parentDN]
                [void]$entries.Add((New-GroupNestingEntry -Object $parent -Membership 'Nested' -Via (Get-GroupNestingName -Object $current)))
                $queue.Enqueue($parent)
            }
        }

        # A group the chain query returned but the walk did not reach - a memberOf that did
        # not arrive whole: the account is still in it.
        foreach ($chainDN in @($ChainByDN.Keys | Sort-Object)) {
            if ($seen.ContainsKey($chainDN)) { continue }
            $seen[$chainDN] = $true
            [void]$entries.Add((New-GroupNestingEntry -Object $ChainByDN[$chainDN] -Membership 'Nested'))
        }
    }

    function Get-GroupChainByDN {
        param([string]$MemberDN)

        $escapedDN = Escape-LDAPFilterDN -DistinguishedName $MemberDN
        $chainByDN = @{}
        foreach ($chainGroup in @(Get-DomainObject -LDAPFilter "(&(objectClass=group)(member:1.2.840.113556.1.4.1941:=$escapedDN))" -Properties $groupProperties @ConnectionParams)) {
            if ($chainGroup -and $chainGroup.distinguishedName) { $chainByDN[[string]$chainGroup.distinguishedName] = $chainGroup }
        }
        return $chainByDN
    }

    # Nesting from the groups of memberOf.
    $accountChain = Get-GroupChainByDN -MemberDN $accountDN
    $directGroups = @($directDNs | Sort-Object | Where-Object { $accountChain.ContainsKey($_) } | ForEach-Object { $accountChain[$_] })
    Add-GroupChain -Start $directGroups -ChainByDN $accountChain

    # The primary group: its SID is the account's domain SID and primaryGroupID.
    $primaryRID = 0
    $accountSID = ConvertTo-GroupNestingSid -Value $Account.objectSid
    if ([int]::TryParse(([string]$Account.primaryGroupID).Trim(), [ref]$primaryRID) -and $primaryRID -gt 0 -and
        $accountSID -match '^(S-1-5-21-\d+-\d+-\d+)-\d+$') {
        $primarySID = "$($Matches[1])-$primaryRID"

        if (-not $PrimaryGroupCache.ContainsKey($primarySID)) {
            $primaryGroup = @(Get-DomainObject -Identity $primarySID -Properties $groupProperties @ConnectionParams | Where-Object { $_ })[0]
            $primaryChain = @{}
            if ($primaryGroup -and $primaryGroup.distinguishedName) {
                $primaryChain = Get-GroupChainByDN -MemberDN ([string]$primaryGroup.distinguishedName)
            }
            $PrimaryGroupCache[$primarySID] = @{ Group = $primaryGroup; Chain = $primaryChain }
        }

        $cached = $PrimaryGroupCache[$primarySID]
        if ($cached.Group) {
            $primaryDN = [string]$cached.Group.distinguishedName
            if (-not $seen.ContainsKey($primaryDN)) {
                $seen[$primaryDN] = $true
                [void]$entries.Add((New-GroupNestingEntry -Object $cached.Group -Membership 'Primary group'))
            }
            Add-GroupChain -Start @($cached.Group) -ChainByDN $cached.Chain
        }
    }

    return @($entries)
}

