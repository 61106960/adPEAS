<#
.SYNOPSIS
    Group nesting, resolved both ways: every group an account is in, and every member a
    group has.

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

    Get-DomainUser -ResolveGroups and Get-DomainGroup -ShowMembers -Recurse use these.

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

<#
.SYNOPSIS
    One entry as a reader sees it: the name and how it was reached.

.DESCRIPTION
    "Server Operators (via Tier1)", "Domain Users (primary group)", "jdoe (via Domain
    Users, primary group)", or the name alone for a direct member. Shared by the ToString
    of the entries and by the memberOfNested transformer, which also sees entries that
    came back from a JSON report and carry no ToString of their own.

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
        'Direct' { return $name }
        'Primary group' {
            # On a member: through the primary group of a nested group, or of the group.
            if ($via) { return "$name (via $via, primary group)" }
            return "$name (primary group)"
        }
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
    The group or member object the entry is about.

.PARAMETER Membership
    'Direct', 'Nested' or 'Primary group'.

.PARAMETER Via
    The name of the group the entry was reached through, or empty.

.PARAMETER WithObjectClass
    Adds ObjectClass, the most specific class of the object - for members, which are not
    all groups.
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
        [string]$Via,

        [Parameter(Mandatory=$false)]
        [switch]$WithObjectClass
    )

    $sid = ConvertTo-GroupNestingSid -Value $Object.objectSid
    $name = Get-GroupNestingName -Object $Object
    $viaValue = if ($Via) { $Via } else { $null }

    if (-not $WithObjectClass) {
        $entry = [PSCustomObject]@{
            Name              = $name
            Membership        = $Membership
            Via               = $viaValue
            DistinguishedName = [string]$Object.distinguishedName
            SID               = $sid
        }
    } else {
        $classes = @(@($Object.objectClass) | Where-Object { $_ })
        $objectClass = if ($classes.Count -gt 0) { [string]$classes[$classes.Count - 1] } else { '' }

        # A foreign security principal is named by its SID; the name it stands for is what
        # a reader needs.
        if ($objectClass -eq 'foreignSecurityPrincipal' -and $sid) {
            $resolvedName = ConvertFrom-SID -SID $sid
            if ($resolvedName -and $resolvedName -ne $sid) { $name = [string]$resolvedName }
        }

        $entry = [PSCustomObject]@{
            Name              = $name
            ObjectClass       = $objectClass
            Membership        = $Membership
            Via               = $viaValue
            DistinguishedName = [string]$Object.distinguishedName
            SID               = $sid
        }
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

<#
.SYNOPSIS
    Every member of a group: direct, through nested groups, and through the primary group
    of the group or of a group nested in it.

.DESCRIPTION
    Direct members come first, then the members of nested groups, in the order a
    breadth-first walk down from the group reaches them - each naming the group that
    holds it. Then the accounts whose primary group is the group or one nested in it,
    which no member attribute lists; an account already found another way keeps that
    entry. Nested groups are members too and are listed with the others.

    Built from both ends of the link. The chain query matches memberOf, and memberOf of
    what it returns gives the links; that does not depend on the member attribute, which
    arrives in ranges on a large group. But memberOf is not readable everywhere - measured
    on a lab domain, a domain user sees it on the foreign security principal of
    Authenticated Users and not on those of INTERACTIVE, IUSR or Enterprise Domain
    Controllers - and an object whose memberOf cannot be read is not matched at all. So
    the member attribute of each group of the chain is read as well, and a DN found there
    and nowhere else is looked up; a foreign security principal is named by the SID its
    DN carries.

.PARAMETER Group
    The group object, with distinguishedName and objectSid.

.PARAMETER ConnectionParams
    Domain, Server and Credential for Get-DomainObject, where the caller was given them.

.OUTPUTS
    One PSCustomObject per member: Name, ObjectClass, Membership ('Direct', 'Nested' or
    'Primary group'), Via, DistinguishedName and SID.
#>
function Resolve-GroupMemberNesting {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory=$true)]
        $Group,

        [Parameter(Mandatory=$false)]
        [hashtable]$ConnectionParams = @{}
    )

    $groupDN = [string]$Group.distinguishedName
    if ([string]::IsNullOrWhiteSpace($groupDN)) { return @() }

    $memberProperties = @('distinguishedName', 'name', 'sAMAccountName', 'objectSid', 'objectClass', 'memberOf', 'member')
    $escapedDN = Escape-LDAPFilterDN -DistinguishedName $groupDN
    $chainMembers = @(Get-DomainObject -LDAPFilter "(memberOf:1.2.840.113556.1.4.1941:=$escapedDN)" -Properties $memberProperties @ConnectionParams |
        Where-Object { $_ -and $_.distinguishedName })

    # Every object known so far by DN, and the groups among them, the group itself included.
    $objectsByDN = @{}
    $groupsByDN = @{}
    $groupsByDN[$groupDN] = $Group
    foreach ($chainMember in $chainMembers) {
        $objectsByDN[[string]$chainMember.distinguishedName] = $chainMember
        if (@($chainMember.objectClass) -contains 'group') { $groupsByDN[[string]$chainMember.distinguishedName] = $chainMember }
    }

    # Who each group holds, from memberOf of what the chain query returned.
    $childrenOf = @{}
    foreach ($chainMember in $chainMembers) {
        foreach ($parentDN in @(@($chainMember.memberOf) | ForEach-Object { [string]$_ })) {
            if (-not $groupsByDN.ContainsKey($parentDN)) { continue }
            if (-not $childrenOf.ContainsKey($parentDN)) { $childrenOf[$parentDN] = New-Object System.Collections.ArrayList }
            [void]$childrenOf[$parentDN].Add($chainMember)
        }
    }

    # And from member of the group itself, for what memberOf did not show. A DN known
    # from nowhere else is looked up once; a foreign security principal needs no lookup,
    # its DN carries its SID.
    function Get-GroupChildren {
        param($Holder)

        # A child named by both sides comes twice; the walk lists each DN once.
        $holderDN = [string]$Holder.distinguishedName
        $children = New-Object System.Collections.ArrayList
        if ($childrenOf.ContainsKey($holderDN)) {
            foreach ($known in $childrenOf[$holderDN]) { [void]$children.Add($known) }
        }

        foreach ($memberValue in @($Holder.member)) {
            $memberDN = [string]$memberValue
            if ([string]::IsNullOrWhiteSpace($memberDN)) { continue }

            if (-not $objectsByDN.ContainsKey($memberDN)) {
                $found = $null
                if ($memberDN -match '^CN=(S-1-[0-9-]+),CN=ForeignSecurityPrincipals,') {
                    $found = [PSCustomObject]@{
                        distinguishedName = $memberDN
                        name              = $Matches[1]
                        objectSid         = $Matches[1]
                        objectClass       = @('top', 'foreignSecurityPrincipal')
                    }
                } else {
                    $found = @(Get-DomainObject -Identity $memberDN -Properties $memberProperties @ConnectionParams | Where-Object { $_ })[0]
                    if (-not $found) { $found = [PSCustomObject]@{ distinguishedName = $memberDN } }
                }
                $objectsByDN[$memberDN] = $found
                if (@($found.objectClass) -contains 'group') { $groupsByDN[$memberDN] = $found }
            }
            [void]$children.Add($objectsByDN[$memberDN])
        }

        return @($children | Sort-Object -Property { [string]$_.distinguishedName })
    }

    $entries = New-Object System.Collections.ArrayList
    # The group itself is seen from the start: in a nesting loop it is its own member.
    $seen = @{}
    $seen[$groupDN] = $true
    $nestedGroups = New-Object System.Collections.ArrayList

    $queue = New-Object System.Collections.Queue
    $queue.Enqueue($Group)
    while ($queue.Count -gt 0) {
        $current = $queue.Dequeue()
        $currentDN = [string]$current.distinguishedName
        $isTop = ($currentDN -eq $groupDN)
        foreach ($child in @(Get-GroupChildren -Holder $current)) {
            $childDN = [string]$child.distinguishedName
            if ($seen.ContainsKey($childDN)) { continue }
            $seen[$childDN] = $true
            if ($isTop) {
                [void]$entries.Add((New-GroupNestingEntry -Object $child -Membership 'Direct' -WithObjectClass))
            } else {
                [void]$entries.Add((New-GroupNestingEntry -Object $child -Membership 'Nested' -Via (Get-GroupNestingName -Object $current) -WithObjectClass))
            }
            if ($groupsByDN.ContainsKey($childDN)) {
                [void]$nestedGroups.Add($child)
                $queue.Enqueue($child)
            }
        }
    }

    # A member the chain query returned but the walk did not reach - a memberOf that did
    # not arrive whole: still a member.
    foreach ($chainMember in @($chainMembers | Sort-Object -Property { [string]$_.distinguishedName })) {
        $memberDN = [string]$chainMember.distinguishedName
        if ($seen.ContainsKey($memberDN)) { continue }
        $seen[$memberDN] = $true
        [void]$entries.Add((New-GroupNestingEntry -Object $chainMember -Membership 'Nested' -WithObjectClass))
        if ($groupsByDN.ContainsKey($memberDN)) { [void]$nestedGroups.Add($chainMember) }
    }

    # Accounts whose primary group is the group or one nested in it. primaryGroupID is a
    # RID of the account's own domain, so a group can be one only for accounts of its own
    # domain - never a builtin group, though one nested in a builtin group can: Domain Users
    # in BUILTIN\Users. Keyed by the full SID, so an account is matched by its domain too.
    $holderBySID = @{}
    foreach ($candidate in @(@($Group) + @($nestedGroups))) {
        $candidateSID = ConvertTo-GroupNestingSid -Value $candidate.objectSid
        if ($candidateSID -match '^S-1-5-21-\d+-\d+-\d+-\d+$' -and -not $holderBySID.ContainsKey($candidateSID)) {
            $holderBySID[$candidateSID] = $candidate
        }
    }

    if ($holderBySID.Count -gt 0) {
        $rids = @($holderBySID.Keys | ForEach-Object { ($_ -split '-')[-1] } | Sort-Object -Property { [int]$_ })
        $ridClauses = ($rids | ForEach-Object { "(primaryGroupID=$_)" }) -join ''
        $primaryFilter = if ($rids.Count -eq 1) { $ridClauses } else { "(|$ridClauses)" }
        $primaryMembers = @(Get-DomainObject -LDAPFilter $primaryFilter -Properties ($memberProperties + @('primaryGroupID')) @ConnectionParams |
            Where-Object { $_ -and $_.distinguishedName })

        foreach ($primaryMember in @($primaryMembers | Sort-Object -Property { [string]$_.distinguishedName })) {
            $memberDN = [string]$primaryMember.distinguishedName
            if ($seen.ContainsKey($memberDN)) { continue }
            $memberSID = ConvertTo-GroupNestingSid -Value $primaryMember.objectSid
            if ($memberSID -notmatch '^(S-1-5-21-\d+-\d+-\d+)-\d+$') { continue }
            $holderSID = "$($Matches[1])-$(([string]$primaryMember.primaryGroupID).Trim())"
            if (-not $holderBySID.ContainsKey($holderSID)) { continue }

            $seen[$memberDN] = $true
            $holder = $holderBySID[$holderSID]
            $via = if ([string]$holder.distinguishedName -ne $groupDN) { Get-GroupNestingName -Object $holder } else { '' }
            [void]$entries.Add((New-GroupNestingEntry -Object $primaryMember -Membership 'Primary group' -Via $via -WithObjectClass))
        }
    }

    return @($entries)
}
