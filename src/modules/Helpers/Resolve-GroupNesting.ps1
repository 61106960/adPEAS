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
    chain can be followed link by link. A domain controller holds its own domain only.
    The Global Catalog holds every domain of the forest, and the universal groups with
    their members - Enterprise Admins and Schema Admins among them, in the forest root.
    The groups of an account are asked of it as well, and the members of a group once one
    of them is of another domain. It holds no members of a global or domain local group
    of another domain: a domain local group there that holds the account is not found,
    and of a global group there that is a member, only the accounts whose primary group
    it is. A group of another forest holds an account through a foreign security
    principal, and is not followed either.

    Get-DomainUser -ResolveGroups and Get-DomainGroup -ShowMembers -Recurse use these.

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

<#
.SYNOPSIS
    One entry as a reader sees it: the name and how it was reached.

.DESCRIPTION
    "Server Operators (via Tier1)", "Domain Users (primary group)", "jdoe (via Domain
    Users, primary group)", "Enterprise Admins (contoso.com, via Tier0)" for an object of
    another domain, or the name alone for a direct member. Shared by the ToString of the
    entries and by the memberOfNested transformer, which also sees entries that came back
    from a JSON report and carry no ToString of their own.

.PARAMETER Entry
    An entry with Name, Membership, Via and, for an object of another domain, Domain.
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

    $qualifiers = @()
    if ($Entry.Domain) { $qualifiers += [string]$Entry.Domain }
    switch ([string]$Entry.Membership) {
        'Direct' { }
        'Primary group' {
            # On a member: through the primary group of a nested group, or of the group.
            if ($via) { $qualifiers += "via $via" }
            $qualifiers += 'primary group'
        }
        default {
            if ($via) { $qualifiers += "via $via" } else { $qualifiers += 'nested' }
        }
    }

    if ($qualifiers.Count -eq 0) { return $name }
    return "$name ($($qualifiers -join ', '))"
}

<#
.SYNOPSIS
    The SID of an object as a string, from either shape it can arrive in.

.PARAMETER Value
    objectSid as Get-DomainObject returns it: a string, or the byte[] of -Raw - which a
    raw Global Catalog answer may wrap in an array of one.
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
    if ($Value -is [array] -and $Value.Count -gt 0 -and $Value[0] -is [byte[]]) { $Value = $Value[0] }
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
    The domain of a DN: its trailing run of DC= components.

.PARAMETER DistinguishedName
    The DN.
#>
function Get-GroupNestingDomainDN {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$DistinguishedName
    )

    if ($DistinguishedName -match '(?i)(?:^|,)(DC=[^,]+(?:,DC=[^,]+)*)$') { return $Matches[1] }
    return ''
}

<#
.SYNOPSIS
    The DNS name of the domain of a DN, where that is not the domain an entry is listed
    for.

.PARAMETER DistinguishedName
    The DN of the object.

.PARAMETER HomeDomainDN
    The DN of the domain the entries are listed for: the account's, or the group's.

.OUTPUTS
    "child.contoso.com", or empty for an object of the home domain.
#>
function Get-GroupNestingForeignDomain {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$DistinguishedName,

        [Parameter(Mandatory=$false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$HomeDomainDN
    )

    $domainDN = Get-GroupNestingDomainDN -DistinguishedName $DistinguishedName
    if ($domainDN -ieq $HomeDomainDN) { return '' }
    return ($domainDN -replace '^DC=', '' -replace ',DC=', '.')
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

.PARAMETER Domain
    The DNS name of the domain of an object outside the account's or the group's own
    domain, or empty.

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
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Domain,

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
            Domain            = if ($Domain) { $Domain } else { $null }
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
            Domain            = if ($Domain) { $Domain } else { $null }
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
    group of the account in its domain, and with a Global Catalog every universal group of
    the forest too. Nested groups come first, in the order a breadth-first walk up from
    memberOf reaches them, each naming the group it was reached through; then the primary
    group and the groups it is nested in; then the groups of other domains, from the
    Global Catalog, each naming its domain.

    A domain controller does not see a link into another domain: memberOf on it lists
    the groups of its own domain only, and its chain query walks only those. The Global
    Catalog holds the universal groups of every domain with their members, so it is asked
    the same two questions - which groups hold the account at all, and which it is
    directly in - for the account and for its primary group.

.PARAMETER Account
    The account object, with distinguishedName, memberOf, primaryGroupID and objectSid.

.PARAMETER ConnectionParams
    Domain, Server and Credential for Get-DomainObject, where the caller was given them.

.PARAMETER PrimaryGroupCache
    The primary group and the groups it is nested in, by SID, shared across the accounts
    of one call: almost every account has the same primary group.

.PARAMETER GlobalCatalog
    The Global Catalog connection, from Get-GCConnection, or $null - the groups of other
    domains are then left out.

.OUTPUTS
    One PSCustomObject per group: Name, Membership ('Nested', 'Primary group', or
    'Direct' for a group of another domain that holds the account itself), Via, Domain
    (the DNS name of another domain, else $null), DistinguishedName and SID.
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
        [hashtable]$PrimaryGroupCache = @{},

        [Parameter(Mandatory=$false)]
        [AllowNull()]
        $GlobalCatalog = $null
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
    $primarySID = $null
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

    if ($GlobalCatalog) {
        $accountDomainDN = Get-GroupNestingDomainDN -DistinguishedName $accountDN

        # The two questions, asked of the Global Catalog: the groups that hold the object
        # through any chain, and the ones it is directly in. -Raw, like the other Global
        # Catalog lookups: the explicit attribute list then works on the GC port.
        function Get-ForestGroupChain {
            param([string]$MemberDN)

            $escapedDN = Escape-LDAPFilterDN -DistinguishedName $MemberDN
            $memberObject = @(Invoke-LDAPSearch -Filter "(distinguishedName=$escapedDN)" -Properties @('distinguishedName', 'memberOf') `
                -LdapConnection $GlobalCatalog -Raw | Where-Object { $_ })[0]
            $chainByDN = @{}
            foreach ($chainGroup in @(Invoke-LDAPSearch -Filter "(&(objectClass=group)(member:1.2.840.113556.1.4.1941:=$escapedDN))" `
                    -Properties @('distinguishedName', 'name', 'objectSid', 'memberOf') -LdapConnection $GlobalCatalog -Raw)) {
                if ($chainGroup -and $chainGroup.distinguishedName) { $chainByDN[[string]$chainGroup.distinguishedName] = $chainGroup }
            }
            $startDNs = @()
            if ($memberObject) {
                $startDNs = @(@($memberObject.memberOf) | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            }
            return @{ StartDNs = $startDNs; Chain = $chainByDN }
        }

        # The same walk as Add-GroupChain, over the whole forest: through the groups the
        # domain controller already gave, which are not listed again, to the rest. That is
        # mostly groups of other domains - and a group of the account's own domain that holds
        # it only through one of theirs: a domain local group with a universal group of
        # another domain in it, a link the domain controller does not see. StartVia names
        # the object the start groups hold, when that is not the account itself.
        function Add-ForestGroupChain {
            param([hashtable]$Forest, [string]$StartVia)

            $chainByDN = $Forest.Chain
            $visited = @{}
            $queue = New-Object System.Collections.Queue

            function Add-ForestEntry {
                param($Group, [string]$Membership, [string]$Via)
                $groupDN = [string]$Group.distinguishedName
                if ($seen.ContainsKey($groupDN)) { return }
                $seen[$groupDN] = $true
                $domainName = Get-GroupNestingForeignDomain -DistinguishedName $groupDN -HomeDomainDN $accountDomainDN
                [void]$entries.Add((New-GroupNestingEntry -Object $Group -Membership $Membership -Via $Via -Domain $domainName))
            }

            foreach ($startDN in @($Forest.StartDNs | Sort-Object)) {
                if (-not $chainByDN.ContainsKey($startDN) -or $visited.ContainsKey($startDN)) { continue }
                $visited[$startDN] = $true
                if ($StartVia) {
                    Add-ForestEntry -Group $chainByDN[$startDN] -Membership 'Nested' -Via $StartVia
                } else {
                    Add-ForestEntry -Group $chainByDN[$startDN] -Membership 'Direct'
                }
                $queue.Enqueue($chainByDN[$startDN])
            }

            while ($queue.Count -gt 0) {
                $current = $queue.Dequeue()
                $parentDNs = @(@($current.memberOf) | ForEach-Object { [string]$_ } |
                    Where-Object { $chainByDN.ContainsKey($_) } | Sort-Object)
                foreach ($parentDN in $parentDNs) {
                    if ($visited.ContainsKey($parentDN)) { continue }
                    $visited[$parentDN] = $true
                    Add-ForestEntry -Group $chainByDN[$parentDN] -Membership 'Nested' -Via (Get-GroupNestingName -Object $current)
                    $queue.Enqueue($chainByDN[$parentDN])
                }
            }

            foreach ($chainDN in @($chainByDN.Keys | Sort-Object)) {
                if ($visited.ContainsKey($chainDN)) { continue }
                Add-ForestEntry -Group $chainByDN[$chainDN] -Membership 'Nested'
            }
        }

        Add-ForestGroupChain -Forest (Get-ForestGroupChain -MemberDN $accountDN)

        if ($primarySID -and $PrimaryGroupCache.ContainsKey($primarySID) -and $PrimaryGroupCache[$primarySID].Group) {
            $cached = $PrimaryGroupCache[$primarySID]
            if (-not $cached.ContainsKey('Forest')) {
                $cached['Forest'] = Get-ForestGroupChain -MemberDN ([string]$cached.Group.distinguishedName)
            }
            Add-ForestGroupChain -Forest $cached.Forest -StartVia (Get-GroupNestingName -Object $cached.Group)
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
    entry. Nested groups are members too and are listed with the others. A member of
    another domain names its domain.

    Built from both ends of the link. The chain query matches memberOf, and memberOf of
    what it returns gives the links; that does not depend on the member attribute, which
    arrives in ranges on a large group. But memberOf is not readable everywhere - measured
    on a lab domain, a domain user sees it on the foreign security principal of
    Authenticated Users and not on those of INTERACTIVE, IUSR or Enterprise Domain
    Controllers - and an object whose memberOf cannot be read is not matched at all. So
    the member attribute of each group of the chain is read as well, and a DN found there
    and nowhere else is looked up; a foreign security principal is named by the SID its
    DN carries.

    A domain controller holds its own domain only: its chain query ends at a member of
    another domain, and it cannot look one up. The first member of another domain the
    walk meets opens the Global Catalog, so a group with none opens nothing. It is asked
    the same chain question, for the whole forest, and looks up what the answer left out.
    It holds the members of a universal group, so the walk goes on through one, back into
    this domain too. It holds no members of a global group of another domain: the group
    is listed, a warning names it, and of its members only the accounts whose primary
    group it is - primaryGroupID it does hold.

.PARAMETER Group
    The group object, with distinguishedName and objectSid.

.PARAMETER ConnectionParams
    Domain, Server and Credential for Get-DomainObject, where the caller was given them.

.OUTPUTS
    One PSCustomObject per member: Name, ObjectClass, Membership ('Direct', 'Nested' or
    'Primary group'), Via, Domain (the DNS name of another domain, else $null),
    DistinguishedName and SID.
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
    $groupDomainDN = Get-GroupNestingDomainDN -DistinguishedName $groupDN

    $memberProperties = @('distinguishedName', 'name', 'sAMAccountName', 'objectSid', 'objectClass', 'memberOf', 'member')
    # And from the Global Catalog groupType: whether it holds the members of a group.
    $forestProperties = $memberProperties + @('groupType')
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

    # Who each group holds, by DN, from memberOf of what a chain query returned.
    $childrenOf = @{}
    function Add-ChildLink {
        param($Object)
        foreach ($parentDN in @(@($Object.memberOf) | ForEach-Object { [string]$_ })) {
            if (-not $childrenOf.ContainsKey($parentDN)) { $childrenOf[$parentDN] = New-Object System.Collections.ArrayList }
            [void]$childrenOf[$parentDN].Add([string]$Object.distinguishedName)
        }
    }
    foreach ($chainMember in $chainMembers) { Add-ChildLink -Object $chainMember }

    # The Global Catalog, once a member of another domain is met. A hashtable, so the
    # functions below can set it. -Raw, like the other Global Catalog lookups: the
    # explicit attribute list then works on the GC port.
    $forest = @{ Asked = $false; Connection = $null; ByDN = @{} }
    function Read-ForestMembers {
        $forest.Asked = $true
        $forest.Connection = Get-GCConnection
        if (-not $forest.Connection) { return }
        foreach ($forestMember in @(Invoke-LDAPSearch -Filter "(memberOf:1.2.840.113556.1.4.1941:=$escapedDN)" -Properties $forestProperties `
                -LdapConnection $forest.Connection -Raw)) {
            $forest.ByDN[[string]$forestMember.distinguishedName] = $forestMember
            Add-ChildLink -Object $forestMember
        }
    }

    # A DN known from nowhere else, looked up once: on a domain controller in the group's
    # own domain, in the Global Catalog in another. A foreign security principal needs no
    # lookup, its DN carries its SID; a DN that does not resolve is kept by its name.
    function Resolve-MemberObject {
        param([string]$MemberDN)

        $found = $null
        if ($MemberDN -match '^CN=(S-1-[0-9-]+),CN=ForeignSecurityPrincipals,') {
            $found = [PSCustomObject]@{
                distinguishedName = $MemberDN
                name              = $Matches[1]
                objectSid         = $Matches[1]
                objectClass       = @('top', 'foreignSecurityPrincipal')
            }
        } elseif (-not (Get-GroupNestingForeignDomain -DistinguishedName $MemberDN -HomeDomainDN $groupDomainDN)) {
            $found = @(Get-DomainObject -Identity $MemberDN -Properties $memberProperties @ConnectionParams | Where-Object { $_ })[0]
        } elseif ($forest.ByDN.ContainsKey($MemberDN)) {
            $found = $forest.ByDN[$MemberDN]
        } elseif ($forest.Connection) {
            $escapedMemberDN = Escape-LDAPFilterDN -DistinguishedName $MemberDN
            $found = @(Invoke-LDAPSearch -Filter "(distinguishedName=$escapedMemberDN)" -Properties $forestProperties -LdapConnection $forest.Connection -Raw)[0]
        }
        if (-not $found) { $found = [PSCustomObject]@{ distinguishedName = $MemberDN } }
        $objectsByDN[$MemberDN] = $found
        if (@($found.objectClass) -contains 'group') { $groupsByDN[$MemberDN] = $found }
    }

    # Who a group holds: the links from memberOf, and member of the group itself, for what
    # memberOf did not show. A child named by both sides comes twice; the walk lists each
    # DN once.
    function Get-GroupChildren {
        param($Holder)

        $memberDNs = @(@($Holder.member) | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        # Before the links are read, so they include the ones the Global Catalog adds.
        if (-not $forest.Asked -and @($memberDNs | Where-Object { Get-GroupNestingForeignDomain -DistinguishedName $_ -HomeDomainDN $groupDomainDN }).Count -gt 0) {
            Read-ForestMembers
        }

        $childDNs = @()
        $holderDN = [string]$Holder.distinguishedName
        if ($childrenOf.ContainsKey($holderDN)) { $childDNs += @($childrenOf[$holderDN]) }
        $childDNs += $memberDNs

        $children = New-Object System.Collections.ArrayList
        foreach ($childDN in $childDNs) {
            if (-not $objectsByDN.ContainsKey($childDN)) { Resolve-MemberObject -MemberDN $childDN }
            [void]$children.Add($objectsByDN[$childDN])
        }
        return @($children | Sort-Object -Property { [string]$_.distinguishedName })
    }

    $entries = New-Object System.Collections.ArrayList
    # Global groups of another domain, whose members the Global Catalog does not hold.
    $unreadGroups = New-Object System.Collections.ArrayList
    function Add-MemberEntry {
        param($Object, [string]$Membership, [string]$Via)

        $memberDomain = Get-GroupNestingForeignDomain -DistinguishedName ([string]$Object.distinguishedName) -HomeDomainDN $groupDomainDN
        [void]$entries.Add((New-GroupNestingEntry -Object $Object -Membership $Membership -Via $Via -Domain $memberDomain -WithObjectClass))

        # groupType 0x8: universal.
        $groupType = [int64]0
        if ($memberDomain -and [int64]::TryParse([string]$Object.groupType, [ref]$groupType) -and -not ($groupType -band 8)) {
            [void]$unreadGroups.Add("$(Get-GroupNestingName -Object $Object) ($memberDomain)")
        }
    }

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
                Add-MemberEntry -Object $child -Membership 'Direct'
            } else {
                Add-MemberEntry -Object $child -Membership 'Nested' -Via (Get-GroupNestingName -Object $current)
            }
            if ($groupsByDN.ContainsKey($childDN)) {
                [void]$nestedGroups.Add($child)
                $queue.Enqueue($child)
            }
        }
    }

    # A member a chain query returned but the walk did not reach - a memberOf that did
    # not arrive whole: still a member.
    foreach ($chainMember in @(@($chainMembers) + @($forest.ByDN.Values) | Sort-Object -Property { [string]$_.distinguishedName })) {
        $memberDN = [string]$chainMember.distinguishedName
        if ($seen.ContainsKey($memberDN)) { continue }
        $seen[$memberDN] = $true
        Add-MemberEntry -Object $chainMember -Membership 'Nested'
        if (@($chainMember.objectClass) -contains 'group') { [void]$nestedGroups.Add($chainMember) }
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

    # Asked where the accounts are: a domain controller for the groups of this domain, the
    # Global Catalog below the domain of each other one.
    $ridsByDomain = @{}
    foreach ($holderSID in @($holderBySID.Keys)) {
        $holderDomainDN = Get-GroupNestingDomainDN -DistinguishedName ([string]$holderBySID[$holderSID].distinguishedName)
        if (-not $ridsByDomain.ContainsKey($holderDomainDN)) { $ridsByDomain[$holderDomainDN] = @() }
        $ridsByDomain[$holderDomainDN] += ($holderSID -split '-')[-1]
    }

    $primaryMembers = @()
    foreach ($holderDomainDN in @($ridsByDomain.Keys | Sort-Object)) {
        $rids = @($ridsByDomain[$holderDomainDN] | Sort-Object -Property { [int]$_ })
        $ridClauses = ($rids | ForEach-Object { "(primaryGroupID=$_)" }) -join ''
        $primaryFilter = if ($rids.Count -eq 1) { $ridClauses } else { "(|$ridClauses)" }
        if ($holderDomainDN -ieq $groupDomainDN) {
            $primaryMembers += @(Get-DomainObject -LDAPFilter $primaryFilter -Properties ($memberProperties + @('primaryGroupID')) @ConnectionParams)
        } else {
            $primaryMembers += @(Invoke-LDAPSearch -Filter $primaryFilter -SearchBase $holderDomainDN -Properties ($forestProperties + @('primaryGroupID')) `
                -LdapConnection $forest.Connection -Raw)
        }
    }

    foreach ($primaryMember in @($primaryMembers | Where-Object { $_ -and $_.distinguishedName } | Sort-Object -Property { [string]$_.distinguishedName })) {
        $memberDN = [string]$primaryMember.distinguishedName
        if ($seen.ContainsKey($memberDN)) { continue }
        $memberSID = ConvertTo-GroupNestingSid -Value $primaryMember.objectSid
        if ($memberSID -notmatch '^(S-1-5-21-\d+-\d+-\d+)-\d+$') { continue }
        $holderSID = "$($Matches[1])-$(([string]$primaryMember.primaryGroupID).Trim())"
        if (-not $holderBySID.ContainsKey($holderSID)) { continue }

        $seen[$memberDN] = $true
        $holder = $holderBySID[$holderSID]
        $via = if ([string]$holder.distinguishedName -ne $groupDN) { Get-GroupNestingName -Object $holder } else { '' }
        Add-MemberEntry -Object $primaryMember -Membership 'Primary group' -Via $via
    }

    if ($unreadGroups.Count -gt 0) {
        Write-Warning ("[Resolve-GroupMemberNesting] Members not read: $($unreadGroups -join ', ') - the Global Catalog holds no members " +
            "of a global group of another domain; listed are only the accounts whose primary group it is.")
    }

    return @($entries)
}
