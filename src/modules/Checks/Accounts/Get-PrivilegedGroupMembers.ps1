function Get-PrivilegedGroupMembers {
    <#
    .SYNOPSIS
    Enumerates members of all privileged Active Directory groups with nested membership analysis.

    .DESCRIPTION
    This check identifies all members in privileged Active Directory groups including:
    - BUILTIN groups (Administrators, Account/Server/Print/Backup Operators, etc.)
    - Domain groups (Domain/Enterprise/Schema Admins, Group Policy Creator Owners, etc.)
    - Dynamic groups (DNS Admins)

    Features:
    - Distinguishes between direct members and nested group membership
    - Tracks nesting level and depth
    - Identifies high-risk nested groups (large membership)
    - Detects deep nesting (>3 levels)
    - Detects Foreign Security Principals (FSPs) from external domains/forests
    - Analyzes AdminSDHolder ACLs for unauthorized permissions
    - Reads the DACL of the privileged groups AdminSDHolder does not protect
      (Show-UnprotectedGroupACL)
    - Checks Pre-Windows 2000 Compatible Access group for dangerous members

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Get-PrivilegedGroupMembers

    .EXAMPLE
    Get-PrivilegedGroupMembers -Domain "contoso.com" -Credential (Get-Credential)

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
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [switch]$IncludePrivileged
    )

    begin {
        Write-Log "[Get-PrivilegedGroupMembers] Starting privileged group enumeration"

        # Built-in privileged groups (well-known SIDs)
        $Script:PrivilegedGroupSIDs = @{
            'S-1-5-32-544' = 'Administrators'
            'S-1-5-32-548' = 'Account Operators'
            'S-1-5-32-549' = 'Server Operators'
            'S-1-5-32-550' = 'Print Operators'
            'S-1-5-32-551' = 'Backup Operators'
            'S-1-5-32-578' = 'Hyper-V Administrators'
            'S-1-5-32-580' = 'Remote Management Users'
        }

        # Domain-specific privileged groups (RIDs)
        $Script:PrivilegedGroupRIDs = @{
            '512' = 'Domain Admins'
            '519' = 'Enterprise Admins'
            '518' = 'Schema Admins'
            '520' = 'Group Policy Creator Owners'
            '526' = 'Key Admins'
            '527' = 'Enterprise Key Admins'
            '517' = 'Cert Publishers'
        }

        # The three domain-controller groups, for the primaryGroupID query ONLY.
        #
        # -516, -521 and -498 are privileged: $Script:PrivilegedRIDSuffixes says so, and
        # $Script:DCSyncPrivilegedRIDSuffixes names -516 and -521 explicitly. This module
        # deliberately does not enumerate them, and that is right - every domain controller
        # is a member of -516, so listing the members would be pages of noise.
        #
        # The interesting case is the other one, and nothing in adPEAS looked for it: a
        # USER account whose primaryGroupID is 516 carries the Domain Controllers SID in its
        # token and therefore every access a DACL grants to domain controllers. It is in no
        # member attribute, it is not a computer, and it survives a review of group
        # memberships untouched.
        $Script:DCPrimaryGroupRIDs = @{
            '516' = 'Domain Controllers'
            '521' = 'Read-only Domain Controllers'
            '498' = 'Enterprise Read-only Domain Controllers'
        }

        # Dynamic groups (no fixed SID - resolve by name)
        $Script:DynamicPrivilegedGroups = @(
            'DnsAdmins'
        )
    }

    process {
        try {
            # Build connection parameters (exclude IncludePrivileged which is not a connection parameter)
            $connectionParams = @{}
            if ($Domain) { $connectionParams['Domain'] = $Domain }
            if ($Server) { $connectionParams['Server'] = $Server }
            if ($Credential) { $connectionParams['Credential'] = $Credential }

            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @connectionParams)) {
                # Return without output to avoid redundant error display
                return
            }

            $AllGroupData = @()
            $TotalUniqueMembers = @{}
            $MembershipPaths = @{}  # Track all paths per member DN
            $Script:AllForeignMembers = @()
            $DomainSID = $Script:LDAPContext.DomainSID
            $domainDN = $Script:LDAPContext.DomainDN

            # ===== Helper Function: Filter GC multi-domain results =====
            # GC port 3268 can return objects from multiple domain partitions
            # (e.g. BUILTIN groups exist in every domain, DnsAdmins by name in parent+child)
            # Always pick only the group from the current domain.
            function Select-LocalDomainGroup {
                param([object]$GroupResult)

                $groups = @($GroupResult)
                if ($groups.Count -le 1) { return $groups | Select-Object -First 1 }

                # Filter to current domain
                if ($domainDN) {
                    $local = $groups | Where-Object { $_.distinguishedName -like "*,$domainDN" }
                    if ($local) {
                        Write-Log "[Get-PrivilegedGroupMembers] GC returned $($groups.Count) results - filtered to current domain"
                        return $local | Select-Object -First 1
                    }
                }

                # Fallback: first result
                Write-Log "[Get-PrivilegedGroupMembers] GC returned $($groups.Count) results - using first"
                return $groups | Select-Object -First 1
            }

            # ===== Helper Function: Recursive Group Member Resolution =====
            function Get-GroupMembersRecursive {
                param(
                    [string]$GroupDN,
                    [string]$GroupName,
                    [int]$NestingLevel = 0,
                    [hashtable]$Visited = @{},
                    [hashtable]$CredentialParams = @{},
                    [string]$MembershipPath = "Direct Member",
                    [object]$GroupObject = $null  # Pass already-fetched group to avoid duplicate query
                )

                # Prevent infinite loops
                # The guard has to describe the current PATH, not everything visited so far. $Visited is
    # a hashtable and goes into every branch by reference: if group A contains both B and C
    # and both contain D, then D is expanded under B, and under C the entry is already there
    # - so the second branch stops with "circular reference detected" on a group that is not
    # a cycle at all. TotalMemberCount per group then undercounts, and the second route by
    # which an account is a Domain Admin is missing from the display, which is the one thing
    # the "how do I get to Domain Admin" section is for. The entry is removed again on the
    # way out, below.
    if ($Visited.ContainsKey($GroupDN)) {
                    Write-Log "[Get-PrivilegedGroupMembers] Circular reference detected: $GroupDN"
                    return @{
                        DirectMembers = @()
                        NestedGroups = @()
                    }
                }
                $Visited[$GroupDN] = $true

                $DirectMembers = @()
                $NestedGroups = @()

                try {
                    # Use passed group object if available, otherwise fetch it
                    $Group = $GroupObject
                    if (-not $Group) {
                        $Group = @(Get-DomainGroup -Identity $GroupDN @CredentialParams)[0]
                        Write-Log "[Get-PrivilegedGroupMembers] Fetched nested group: $GroupName (DN: $GroupDN)"
                    } else {
                        Write-Log "[Get-PrivilegedGroupMembers] Using pre-fetched group: $GroupName (DN: $GroupDN)"
                    }

                    if (-not $Group) {
                        Write-Log "[Get-PrivilegedGroupMembers] WARNING: Group not found by DN: $GroupDN"
                        return @{ DirectMembers = @(); NestedGroups = @() }
                    }

                    $memberAttr = $Group.member
                    $memberCount = if ($memberAttr) { @($memberAttr).Count } else { 0 }
                    Write-Log "[Get-PrivilegedGroupMembers] Group found: True, Member count: $memberCount"

                    if ($memberAttr) {
                        $MemberDNs = @($Group.member)
                        Write-Log "[Get-PrivilegedGroupMembers] Group '$GroupName' has $($MemberDNs.Count) direct members (Nesting Level: $NestingLevel)"

                        foreach ($MemberDN in $MemberDNs) {
                            # Skip empty/null member DNs (can occur with GC multi-domain results)
                            if ([string]::IsNullOrWhiteSpace($MemberDN)) { continue }

                            # Get member object using Get-DomainObject
                            $Member = @(Get-DomainObject -Identity $MemberDN @CredentialParams)[0]

                            # Cross-domain member resolution: If member not found locally and DN belongs
                            # to a different domain (e.g. parent domain user in child domain group),
                            # try resolving via Global Catalog (port 3268/3269)
                            if (-not $Member -and $domainDN -and -not $MemberDN.EndsWith(",$domainDN")) {
                                Write-Log "[Get-PrivilegedGroupMembers] Cross-domain member detected: $MemberDN - trying GC lookup"
                                try {
                                    $gcConn = Get-GCConnection
                                    if ($gcConn) {
                                        # Use Invoke-LDAPSearch with GC connection for full attribute conversion.
                                        # Escape the member DN (may contain '(' ')' '\,' - e.g. "CN=Doe\, Jane (Contractor),...").
                                        $escapedMemberDN = Escape-LDAPFilterDN -DistinguishedName $MemberDN
                                        $Member = @(Invoke-LDAPSearch -Filter "(&(objectClass=*)(distinguishedName=$escapedMemberDN))" -SizeLimit 1 -LdapConnection $gcConn)[0]
                                        if ($Member) {
                                            Write-Log "[Get-PrivilegedGroupMembers] GC resolved cross-domain member: $($Member.distinguishedName)"
                                        }
                                    }
                                } catch {
                                    Write-Log "[Get-PrivilegedGroupMembers] GC lookup failed for $MemberDN : $_"
                                }
                            }

                            if ($Member) {
                                # Check if member is a group
                                if ($Member.objectClass -icontains "group") {
                                    # Nested group - recurse with updated path
                                    $NewPath = if ($MembershipPath -eq "Direct Member") {
                                        "via $($Member.sAMAccountName)"
                                    } else {
                                        "$MembershipPath -> $($Member.sAMAccountName)"
                                    }

                                    # Pass GC-resolved group object for cross-domain groups to avoid
                                    # local partition lookup failure in recursion
                                    $nestedGroupObj = $null
                                    if ($domainDN -and -not $MemberDN.EndsWith(",$domainDN")) {
                                        $nestedGroupObj = $Member  # GC-resolved object with member attribute
                                    }

                                    $NestedResult = Get-GroupMembersRecursive `
                                        -GroupDN $Member.distinguishedName `
                                        -GroupName $Member.sAMAccountName `
                                        -NestingLevel ($NestingLevel + 1) `
                                        -Visited $Visited `
                                        -CredentialParams $CredentialParams `
                                        -MembershipPath $NewPath `
                                        -GroupObject $nestedGroupObj

                                    # Calculate total member count from nested groups
                                    $NestedTotalCount = $NestedResult.DirectMembers.Count +
                                                        ($NestedResult.NestedGroups | Measure-Object -Property TotalMembers -Sum).Sum

                                    $NestedGroups += [PSCustomObject]@{
                                        GroupName = $Member.sAMAccountName
                                        DistinguishedName = $Member.distinguishedName
                                        NestingLevel = $NestingLevel + 1
                                        DirectMembers = $NestedResult.DirectMembers
                                        NestedGroups = $NestedResult.NestedGroups
                                        TotalMembers = $NestedTotalCount
                                    }
                                } else {
                                    # Direct member (user/computer/FSP)
                                    $IsForeignSecurityPrincipal = $Member.objectClass -icontains 'foreignSecurityPrincipal'

                                    if ($IsForeignSecurityPrincipal) {
                                        # Foreign Security Principal - extract SID from CN
                                        $MemberSID = $null
                                        if ($Member.distinguishedName -match '^CN=([^,]+)') {
                                            $MemberSID = $matches[1]
                                        }

                                        # Resolve SID to account name using central function
                                        $ResolvedName = if ($MemberSID) {
                                            ConvertFrom-SID -SID $MemberSID
                                        } else {
                                            "[FOREIGN - Unknown]"
                                        }

                                        # Check if resolution was successful (not same as SID)
                                        $ResolutionSuccessful = ($ResolvedName -ne $MemberSID)

                                        $MemberInfo = [PSCustomObject]@{
                                            Name = $ResolvedName
                                            SAMAccountName = if ($ResolutionSuccessful) { $ResolvedName.Split('\')[1] } else { "[FOREIGN]" }
                                            ObjectClass = "foreignSecurityPrincipal"
                                            DistinguishedName = $Member.distinguishedName
                                            SID = $MemberSID
                                            ResolvedName = if ($ResolutionSuccessful) { $ResolvedName } else { $null }
                                            NestingLevel = $NestingLevel
                                            IsForeign = $true
                                            MembershipPath = $MembershipPath
                                        }
                                    } else {
                                        # Regular member - determine object type from objectClass array
                                        # Priority: gMSA/sMSA > computer > user (most specific first)
                                        $objectClassArray = @($Member.objectClass)
                                        $detectedClass = 'user'  # Default fallback

                                        if ($objectClassArray -icontains 'msDS-GroupManagedServiceAccount') {
                                            $detectedClass = 'msDS-GroupManagedServiceAccount'
                                        }
                                        elseif ($objectClassArray -icontains 'msDS-ManagedServiceAccount') {
                                            $detectedClass = 'msDS-ManagedServiceAccount'
                                        }
                                        elseif ($objectClassArray -icontains 'computer') {
                                            $detectedClass = 'computer'
                                        }
                                        elseif ($objectClassArray -icontains 'user') {
                                            $detectedClass = 'user'
                                        }

                                        # Detect cross-domain members (resolved via GC, DN not in current domain)
                                        $isCrossDomain = ($domainDN -and -not $MemberDN.EndsWith(",$domainDN"))

                                        $MemberInfo = [PSCustomObject]@{
                                            Name = $Member.name
                                            SAMAccountName = $Member.sAMAccountName
                                            ObjectClass = $detectedClass
                                            DistinguishedName = $Member.distinguishedName
                                            SID = $Member.objectSid
                                            NestingLevel = $NestingLevel
                                            IsForeign = $false
                                            IsCrossDomain = $isCrossDomain
                                            GCObject = if ($isCrossDomain) { $Member } else { $null }
                                            MembershipPath = $MembershipPath
                                        }
                                    }

                                    $DirectMembers += $MemberInfo

                                    # Track foreign members for summary
                                    if ($IsForeignSecurityPrincipal) {
                                        $Script:AllForeignMembers += [PSCustomObject]@{
                                            SID = $MemberSID
                                            ResolvedName = $MemberInfo.ResolvedName
                                            PrivilegedGroup = $GroupName
                                            NestingLevel = $NestingLevel
                                        }
                                    }
                                }
                            }
                        }
                    }
                } catch {
                    Write-Log "[Get-PrivilegedGroupMembers] Error resolving members for $GroupDN : $_"
                } finally {
                    # Out of this branch again, so $Visited describes the current path rather
                    # than everything the walk has seen. A real cycle is still caught: an
                    # ancestor of this group is still in the table while we are below it.
                    #
                    # Not memoised on purpose. A group reachable by two routes is expanded
                    # twice now, and the result cannot simply be cached per DN because
                    # NestingLevel and MembershipPath are baked into the objects it returns -
                    # a cache would hand the second route the first route's path, which is
                    # the very thing this fix is about.
                    [void]$Visited.Remove($GroupDN)
                }

                return @{
                    DirectMembers = $DirectMembers
                    NestedGroups = $NestedGroups
                }
            }

            # ===== Helper Function: Collect ALL members including from nested groups =====
            function Get-AllMembersFromResult {
                param(
                    [Parameter(Mandatory)]
                    $Result
                )

                $AllMembers = @()

                # Add direct members
                if ($Result.DirectMembers) {
                    $AllMembers += @($Result.DirectMembers)
                }

                # Recursively add members from nested groups
                if ($Result.NestedGroups) {
                    foreach ($NestedGroup in $Result.NestedGroups) {
                        # Each nested group has DirectMembers and NestedGroups properties
                        if ($NestedGroup.DirectMembers) {
                            $AllMembers += @($NestedGroup.DirectMembers)
                        }
                        if ($NestedGroup.NestedGroups) {
                            # Recurse into deeper nested groups
                            $AllMembers += Get-AllMembersFromResult -Result $NestedGroup
                        }
                    }
                }

                return $AllMembers
            }

            # ===== The groups whose own DACL step 5b reads =====
            # Every privileged group the steps below find, and every group nested into one of
            # them - a nested group passes its membership on, so the right to add a member to
            # it is the right to add one to the group above. Only this domain's partition: the
            # descriptor of a group in another domain is not read over this connection.
            $GroupsForACLReview = [ordered]@{}
            function Add-GroupForACLReview {
                param(
                    [string]$DistinguishedName,
                    [string]$Name,
                    [string]$Source,
                    $NestedGroups
                )
                if ([string]::IsNullOrWhiteSpace($DistinguishedName)) { return }
                if ($domainDN -and -not $DistinguishedName.EndsWith(",$domainDN", [System.StringComparison]::OrdinalIgnoreCase)) { return }
                if (-not $GroupsForACLReview.Contains($DistinguishedName)) {
                    $GroupsForACLReview[$DistinguishedName] = [PSCustomObject]@{
                        DistinguishedName = $DistinguishedName
                        Name              = $Name
                        Source            = $Source
                    }
                }
                foreach ($nestedGroup in @($NestedGroups)) {
                    if (-not $nestedGroup) { continue }
                    Add-GroupForACLReview -DistinguishedName $nestedGroup.DistinguishedName -Name $nestedGroup.GroupName `
                        -Source "nested in $Name" -NestedGroups $nestedGroup.NestedGroups
                }
            }

            # Members of Account Operators, for step 5b: the group class gives Account
            # Operators full control over every group AdminSDHolder does not protect, and
            # whether that matters today depends on whether anybody is in it. $null = the
            # group was not found.
            $accountOperatorMembers = $null

            # ===== STEP 1: Query Domain-Specific Privileged Groups =====
            Show-SubHeader "Searching for privileged group members..." -ObjectType "PrivilegedGroupMember"

            # Build credential params for recursive calls (only relevant params)
            $CredParams = @{}
            if ($PSBoundParameters.ContainsKey('Domain')) { $CredParams['Domain'] = $Domain }
            if ($PSBoundParameters.ContainsKey('Server')) { $CredParams['Server'] = $Server }
            if ($PSBoundParameters.ContainsKey('Credential')) { $CredParams['Credential'] = $Credential }

            # ===== Primary group members, which "member" does not list =====
            #
            # An account whose primaryGroupID is 512 is a Domain Admin - the RID is in its
            # token - but Active Directory does not write that relation into the group's
            # member attribute, and the account carries no memberOf pointing back. The
            # recursion below walks member, so it cannot see these accounts at all, and
            # setting the primary group is a known way to hold privilege out of sight of
            # exactly that kind of enumeration.
            #
            # One query for every privileged group rather than one per group: the RIDs are
            # known and primaryGroupID is indexed. 513 for a user and 515 for a computer are
            # the defaults, and neither is a privileged RID, so nothing ordinary matches.
            $PrimaryGroupMembers = @{}
            # DN -> group name, for the display further down. "(direct)" would be true but
            # misleading: you do not remove such an account from the group, because it is
            # not in the member attribute - you change its primaryGroupID.
            $PrimaryGroupOf = @{}
            try {
                $primaryClauses = ($Script:PrivilegedGroupRIDs.Keys | ForEach-Object { "(primaryGroupID=$_)" }) -join ''
                $primaryFilter = "(|$primaryClauses)"

                foreach ($account in @(Get-DomainObject -LDAPFilter $primaryFilter -Properties 'distinguishedName', 'sAMAccountName', 'name', 'objectSid', 'objectClass', 'primaryGroupID' @CredParams)) {
                    $accountRID = "$($account.primaryGroupID)"
                    if (-not $PrimaryGroupMembers.ContainsKey($accountRID)) {
                        $PrimaryGroupMembers[$accountRID] = @()
                    }
                    $PrimaryGroupMembers[$accountRID] += $account
                }

                $primaryTotal = ($PrimaryGroupMembers.Values | ForEach-Object { @($_).Count } | Measure-Object -Sum).Sum
                if (-not $primaryTotal) { $primaryTotal = 0 }
                Write-Log "[Get-PrivilegedGroupMembers] $primaryTotal account(s) hold a privileged group as their primary group"
            } catch {
                # Not fatal: the member-based enumeration below is the main path, and losing
                # this one costs coverage rather than the whole check.
                Write-Log "[Get-PrivilegedGroupMembers] Primary group query failed: $($_.Exception.Message)" -Level Warning
            }

            foreach ($RID in $Script:PrivilegedGroupRIDs.Keys) {
                try {
                    $GroupSID = "$DomainSID-$RID"
                    $GroupNameEN = $Script:PrivilegedGroupRIDs[$RID]

                    Write-Log "[Get-PrivilegedGroupMembers] Checking group: $GroupNameEN (SID: $GroupSID)"

                    # Find group by SID using Get-DomainGroup
                    $Group = Select-LocalDomainGroup (Get-DomainGroup -Identity $GroupSID @CredParams)

                    if ($Group) {
                        # Use actual sAMAccountName from AD (localized, e.g. "Domaenen-Admins" in German)
                        $GroupName = $Group.sAMAccountName
                        Write-Log "[Get-PrivilegedGroupMembers] Found group: $GroupName ($($Group.distinguishedName))"

                        # Each top-level group gets its own Visited hashtable to avoid cross-contamination
                        # Pass the already-fetched group object to avoid duplicate LDAP query
                        $Result = Get-GroupMembersRecursive -GroupDN $Group.distinguishedName -GroupName $GroupName -CredentialParams $CredParams -Visited @{} -GroupObject $Group
                        Add-GroupForACLReview -DistinguishedName $Group.distinguishedName -Name $GroupName -Source 'privileged group' -NestedGroups $Result.NestedGroups

                        # Fold in the accounts holding this group as their primary group.
                        # They are direct members in every sense that matters - the RID is in
                        # their token - and the path says "Primary group" rather than "Direct
                        # Member", because the latter would send a reader looking for them in
                        # an attribute that does not list them.
                        #
                        # Only this loop needs it: a primaryGroupID is a RID relative to the
                        # domain, so it can never point at a BUILTIN group, which is what the
                        # two loops below enumerate.
                        foreach ($primaryMember in @($PrimaryGroupMembers["$RID"])) {
                            if (-not $primaryMember) { continue }

                            $primaryDN = if ($primaryMember.distinguishedName -is [array]) {
                                $primaryMember.distinguishedName[0]
                            } else {
                                $primaryMember.distinguishedName
                            }

                            # An account can hold the group as its primary group and be listed
                            # in member as well. Counting it twice would inflate the group and
                            # print the account twice.
                            if (@($Result.DirectMembers | ForEach-Object { $_.DistinguishedName }) -contains $primaryDN) {
                                Write-Log "[Get-PrivilegedGroupMembers] $primaryDN is a listed and a primary-group member of $GroupName"
                                continue
                            }

                            $primaryClassArray = @($primaryMember.objectClass)
                            $primaryClass = 'user'
                            if ($primaryClassArray -icontains 'msDS-GroupManagedServiceAccount') {
                                $primaryClass = 'msDS-GroupManagedServiceAccount'
                            } elseif ($primaryClassArray -icontains 'msDS-ManagedServiceAccount') {
                                $primaryClass = 'msDS-ManagedServiceAccount'
                            } elseif ($primaryClassArray -icontains 'computer') {
                                $primaryClass = 'computer'
                            }

                            $Result.DirectMembers += [PSCustomObject]@{
                                Name              = $primaryMember.name
                                SAMAccountName    = $primaryMember.sAMAccountName
                                ObjectClass       = $primaryClass
                                DistinguishedName = $primaryDN
                                SID               = $primaryMember.objectSid
                                NestingLevel      = 0
                                IsForeign         = $false
                                IsCrossDomain     = ($domainDN -and $primaryDN -and -not $primaryDN.EndsWith(",$domainDN"))
                                GCObject          = $null
                                MembershipPath    = 'Primary group'
                            }

                            $PrimaryGroupOf[$primaryDN] = $GroupName
                            Write-Log "[Get-PrivilegedGroupMembers] $GroupName - primary group member: $primaryDN"
                        }

                        $DirectMemberCount = @($Result.DirectMembers).Count
                        $NestedGroupCount = @($Result.NestedGroups).Count
                        $NestedSum = ($Result.NestedGroups | Measure-Object -Property TotalMembers -Sum).Sum
                        if ($null -eq $NestedSum) { $NestedSum = 0 }
                        $TotalMemberCount = $DirectMemberCount + $NestedSum

                        Write-Log "[Get-PrivilegedGroupMembers] $GroupName - Direct: $DirectMemberCount, Nested groups: $NestedGroupCount, Total: $TotalMemberCount"

                        # Track unique members and their paths (including nested group members)
                        $AllMembersFromGroup = Get-AllMembersFromResult -Result $Result
                        foreach ($Member in $AllMembersFromGroup) {
                            $TotalUniqueMembers[$Member.DistinguishedName] = $Member

                            # Track membership path for this group
                            if (-not $MembershipPaths.ContainsKey($Member.DistinguishedName)) {
                                $MembershipPaths[$Member.DistinguishedName] = @()
                            }
                            if ($Member.MembershipPath -notin $MembershipPaths[$Member.DistinguishedName]) {
                                $MembershipPaths[$Member.DistinguishedName] += $Member.MembershipPath
                            }
                        }

                        # Add group data if it has any members (direct or nested)
                        if ($TotalMemberCount -gt 0) {
                            $AllGroupData += [PSCustomObject]@{
                                GroupName = $GroupName
                                GroupSID = $GroupSID
                                GroupType = "Domain"
                                DirectMemberCount = $DirectMemberCount
                                NestedGroupCount = $NestedGroupCount
                                TotalMemberCount = $TotalMemberCount
                                DirectMembers = $Result.DirectMembers
                                NestedGroups = $Result.NestedGroups
                            }
                        }
                    } else {
                        Write-Log "[Get-PrivilegedGroupMembers] Group not found: $GroupNameEN (SID: $GroupSID)"
                    }
                } catch {
                    Write-Warning "[Get-PrivilegedGroupMembers] Error checking group $GroupNameEN : $_"
                }
            }

            # ===== STEP 2: Query Built-in Privileged Groups =====
            foreach ($SID in $Script:PrivilegedGroupSIDs.Keys) {
                try {
                    $GroupNameEN = $Script:PrivilegedGroupSIDs[$SID]
                    Write-Log "[Get-PrivilegedGroupMembers] Checking built-in group: $GroupNameEN (SID: $SID)"

                    $Group = Select-LocalDomainGroup (Get-DomainGroup -Identity $SID @CredParams)

                    if ($Group) {
                        # Use actual sAMAccountName from AD (localized, e.g. "Administratoren" in German)
                        $GroupName = $Group.sAMAccountName
                        Write-Log "[Get-PrivilegedGroupMembers] Found built-in group: $GroupName ($($Group.distinguishedName))"

                        # Each top-level group gets its own Visited hashtable to avoid cross-contamination
                        # Pass the already-fetched group object to avoid duplicate LDAP query
                        $Result = Get-GroupMembersRecursive -GroupDN $Group.distinguishedName -GroupName $GroupName -CredentialParams $CredParams -Visited @{} -GroupObject $Group
                        Add-GroupForACLReview -DistinguishedName $Group.distinguishedName -Name $GroupName -Source 'privileged group' -NestedGroups $Result.NestedGroups

                        $DirectMemberCount = @($Result.DirectMembers).Count
                        $NestedGroupCount = @($Result.NestedGroups).Count
                        $NestedSum = ($Result.NestedGroups | Measure-Object -Property TotalMembers -Sum).Sum
                        if ($null -eq $NestedSum) { $NestedSum = 0 }
                        $TotalMemberCount = $DirectMemberCount + $NestedSum
                        if ($SID -eq 'S-1-5-32-548') { $accountOperatorMembers = $TotalMemberCount }

                        Write-Log "[Get-PrivilegedGroupMembers] $GroupName - Direct: $DirectMemberCount, Nested groups: $NestedGroupCount, Total: $TotalMemberCount"

                        # Track unique members and their paths (including nested group members)
                        $AllMembersFromGroup = Get-AllMembersFromResult -Result $Result
                        foreach ($Member in $AllMembersFromGroup) {
                            $TotalUniqueMembers[$Member.DistinguishedName] = $Member

                            # Track membership path for this group
                            if (-not $MembershipPaths.ContainsKey($Member.DistinguishedName)) {
                                $MembershipPaths[$Member.DistinguishedName] = @()
                            }
                            if ($Member.MembershipPath -notin $MembershipPaths[$Member.DistinguishedName]) {
                                $MembershipPaths[$Member.DistinguishedName] += $Member.MembershipPath
                            }
                        }

                        if ($TotalMemberCount -gt 0) {
                            $AllGroupData += [PSCustomObject]@{
                                GroupName = $GroupName
                                GroupSID = $SID
                                GroupType = "BUILTIN"
                                DirectMemberCount = $DirectMemberCount
                                NestedGroupCount = $NestedGroupCount
                                TotalMemberCount = $TotalMemberCount
                                DirectMembers = $Result.DirectMembers
                                NestedGroups = $Result.NestedGroups
                            }
                        }
                    } else {
                        Write-Log "[Get-PrivilegedGroupMembers] Built-in group not found: $GroupNameEN (SID: $SID)"
                    }
                } catch {
                    Write-Warning "[Get-PrivilegedGroupMembers] Error checking built-in group $GroupNameEN : $_"
                }
            }

            # ===== STEP 3: Query Dynamic Privileged Groups =====
            $domainDN = $Script:LDAPContext.DomainDN
            foreach ($GroupNameDynamic in $Script:DynamicPrivilegedGroups) {
                try {
                    Write-Log "[Get-PrivilegedGroupMembers] Checking dynamic group: $GroupNameDynamic"

                    $Group = Select-LocalDomainGroup (Get-DomainGroup -Identity $GroupNameDynamic @CredParams)

                    if ($Group) {
                        # Use actual sAMAccountName from AD (dynamic groups may have localized names)
                        $GroupName = $Group.sAMAccountName
                        Write-Log "[Get-PrivilegedGroupMembers] Found dynamic group: $GroupName ($($Group.distinguishedName))"

                        # Each top-level group gets its own Visited hashtable to avoid cross-contamination
                        # Pass the already-fetched group object to avoid duplicate LDAP query
                        $Result = Get-GroupMembersRecursive -GroupDN $Group.distinguishedName -GroupName $GroupName -CredentialParams $CredParams -Visited @{} -GroupObject $Group
                        Add-GroupForACLReview -DistinguishedName $Group.distinguishedName -Name $GroupName -Source 'privileged group' -NestedGroups $Result.NestedGroups

                        $DirectMemberCount = @($Result.DirectMembers).Count
                        $NestedGroupCount = @($Result.NestedGroups).Count
                        $NestedSum = ($Result.NestedGroups | Measure-Object -Property TotalMembers -Sum).Sum
                        if ($null -eq $NestedSum) { $NestedSum = 0 }
                        $TotalMemberCount = $DirectMemberCount + $NestedSum

                        Write-Log "[Get-PrivilegedGroupMembers] $GroupName - Direct: $DirectMemberCount, Nested groups: $NestedGroupCount, Total: $TotalMemberCount"

                        # Track unique members and their paths (including nested group members)
                        $AllMembersFromGroup = Get-AllMembersFromResult -Result $Result
                        foreach ($Member in $AllMembersFromGroup) {
                            $TotalUniqueMembers[$Member.DistinguishedName] = $Member

                            # Track membership path for this group
                            if (-not $MembershipPaths.ContainsKey($Member.DistinguishedName)) {
                                $MembershipPaths[$Member.DistinguishedName] = @()
                            }
                            if ($Member.MembershipPath -notin $MembershipPaths[$Member.DistinguishedName]) {
                                $MembershipPaths[$Member.DistinguishedName] += $Member.MembershipPath
                            }
                        }

                        if ($TotalMemberCount -gt 0) {
                            $AllGroupData += [PSCustomObject]@{
                                GroupName = $GroupName
                                GroupSID = $Group.objectSid
                                GroupType = "Dynamic"
                                DirectMemberCount = $DirectMemberCount
                                NestedGroupCount = $NestedGroupCount
                                TotalMemberCount = $TotalMemberCount
                                DirectMembers = $Result.DirectMembers
                                NestedGroups = $Result.NestedGroups
                            }
                        }
                    } else {
                        Write-Log "[Get-PrivilegedGroupMembers] Dynamic group not found: $GroupNameDynamic"
                    }
                } catch {
                    Write-Warning "[Get-PrivilegedGroupMembers] Error checking dynamic group $GroupNameDynamic : $_"
                }
            }

            # The Exchange groups, for step 5b only. Their members are Get-ExchangeInfrastructure's
            # to report; their own DACL is nobody's, and AdminSDHolder does not protect them.
            # Exchange creates them with fixed English names in one OU, so a group is taken only
            # from there - a group of the same name elsewhere is not one of them.
            foreach ($exchangeGroupName in @('Organization Management', 'Exchange Trusted Subsystem', 'Exchange Windows Permissions')) {
                try {
                    $exchangeGroup = Select-LocalDomainGroup (Get-DomainGroup -Identity $exchangeGroupName @CredParams)
                    if ($exchangeGroup -and [string]$exchangeGroup.distinguishedName -match ',OU=Microsoft Exchange Security Groups,') {
                        Add-GroupForACLReview -DistinguishedName $exchangeGroup.distinguishedName -Name $exchangeGroup.sAMAccountName -Source 'Exchange group'
                    }
                } catch {
                    Write-Log "[Get-PrivilegedGroupMembers] Lookup of $exchangeGroupName failed: $_"
                }
            }

            # ===== STEP 4: Build User-Centric View =====
            $TotalGroups = $AllGroupData.Count
            $TotalMembers = $TotalUniqueMembers.Count

            # Count by type for accurate summary message
            $UserCount = 0
            $ComputerCount = 0
            $gMSACount = 0
            # Foreign Security Principals get a count of their own. They used to be added to
            # $UserCount, so "Found 7 user(s) across 5 privileged group(s)" could mean six
            # users and one principal from a trusted domain - and if that principal names a
            # group over there, its members are not enumerated either. The number the
            # section opens with has to be a number the reader can trust.
            $ForeignCount = 0
            $totalMembers = @($TotalUniqueMembers.Values).Count
            $currentIndex = 0

            foreach ($memberData in $TotalUniqueMembers.Values) {
                $currentIndex++

                # Progress indicator for large member counts
                if ($totalMembers -gt $Script:ProgressThreshold) {
                    Show-Progress -Activity "Analyzing privileged members" -Current $currentIndex -Total $totalMembers -ObjectName $memberData.SAMAccountName
                }

                $objClass = $memberData.ObjectClass
                $samName = $memberData.SAMAccountName

                Write-Log "[Get-PrivilegedGroupMembers] Counting member: $samName, ObjectClass: '$objClass'"

                # gMSA and sMSA are service accounts (specific objectClass)
                if ($objClass -ieq 'msDS-GroupManagedServiceAccount' -or $objClass -ieq 'msDS-ManagedServiceAccount') {
                    $gMSACount++
                    Write-Log "[Get-PrivilegedGroupMembers]   -> Counted as gMSA"
                }
                # Computer accounts (regular computers and DCs)
                elseif ($objClass -ieq 'computer') {
                    $ComputerCount++
                    Write-Log "[Get-PrivilegedGroupMembers]   -> Counted as Computer"
                }
                # A principal from a trusted domain or forest. Counted apart from the users:
                # adPEAS resolves the SID to a name but cannot read the object behind it, so
                # it does not know whether that SID names a user or a group over there - and
                # if it is a group, the members this report should have listed are on the
                # other side of the trust and were never enumerated.
                elseif ($objClass -ieq 'foreignSecurityPrincipal') {
                    $ForeignCount++
                    Write-Log "[Get-PrivilegedGroupMembers]   -> Counted as foreign principal"
                }
                # User accounts
                elseif ($objClass -ieq 'user') {
                    $UserCount++
                    Write-Log "[Get-PrivilegedGroupMembers]   -> Counted as User"
                }
                # Fallback: Check sAMAccountName for $ suffix (computer/gMSA indicator)
                elseif ($samName -and $samName.EndsWith('$')) {
                    # Could be computer or gMSA - check for gMSA pattern (often has specific naming)
                    $ComputerCount++
                    Write-Log "[Get-PrivilegedGroupMembers]   -> Counted as Computer ($ suffix fallback)"
                }
                else {
                    # Default to user for unknown types
                    $UserCount++
                    Write-Log "[Get-PrivilegedGroupMembers]   -> Counted as User (default fallback, class was: '$objClass')"
                }
            }

            # Clear progress bar
            if ($totalMembers -gt $Script:ProgressThreshold) {
                Show-Progress -Activity "Analyzing privileged members" -Completed
            }

            Write-Log "[Get-PrivilegedGroupMembers] Count summary: Users=$UserCount, gMSAs=$gMSACount, Computers=$ComputerCount, Foreign=$ForeignCount"

            Write-Log "[Get-PrivilegedGroupMembers] AllGroupData contains $TotalGroups groups:"
            foreach ($gd in $AllGroupData) {
                Write-Log "[Get-PrivilegedGroupMembers]   - $($gd.GroupName) (Type: $($gd.GroupType), Members: $($gd.TotalMemberCount))"
            }
            Write-Log "[Get-PrivilegedGroupMembers] TotalUniqueMembers: $TotalMembers"

            # Build per-member group membership tracking
            $MemberGroupMemberships = @{}  # DN -> @{ Groups = @(); DirectGroups = @(); NestedVia = @{} }

            foreach ($GroupData in $AllGroupData) {
                # Helper function to collect all members from nested groups recursively
                function Get-AllMembersWithPaths {
                    param($Members, $NestedGroups, $TopLevelGroup, $ParentPath = $null)

                    $AllMembers = @()

                    # Add direct members
                    foreach ($Member in $Members) {
                        $AllMembers += [PSCustomObject]@{
                            MemberDN = $Member.DistinguishedName
                            MemberInfo = $Member
                            TopLevelGroup = $TopLevelGroup
                            IsDirect = ($null -eq $ParentPath)
                            NestedVia = $ParentPath
                        }
                    }

                    # Recursively add members from nested groups
                    foreach ($NestedGroup in $NestedGroups) {
                        $NewPath = if ($null -eq $ParentPath) {
                            $NestedGroup.GroupName
                        } else {
                            "$ParentPath -> $($NestedGroup.GroupName)"
                        }

                        $NestedMembers = Get-AllMembersWithPaths -Members $NestedGroup.DirectMembers -NestedGroups $NestedGroup.NestedGroups -TopLevelGroup $TopLevelGroup -ParentPath $NewPath
                        $AllMembers += $NestedMembers
                    }

                    return $AllMembers
                }

                # Collect all members for this top-level group
                $AllMembersFlat = Get-AllMembersWithPaths -Members $GroupData.DirectMembers -NestedGroups $GroupData.NestedGroups -TopLevelGroup $GroupData.GroupName

                foreach ($Entry in $AllMembersFlat) {
                    $dn = $Entry.MemberDN
                    if (-not $MemberGroupMemberships.ContainsKey($dn)) {
                        $MemberGroupMemberships[$dn] = @{
                            MemberInfo = $Entry.MemberInfo
                            Groups = @()
                            DirectGroups = @()
                            NestedPaths = @{}
                        }
                    }

                    # Track group membership
                    if ($Entry.TopLevelGroup -notin $MemberGroupMemberships[$dn].Groups) {
                        $MemberGroupMemberships[$dn].Groups += $Entry.TopLevelGroup
                    }

                    if ($Entry.IsDirect) {
                        if ($Entry.TopLevelGroup -notin $MemberGroupMemberships[$dn].DirectGroups) {
                            $MemberGroupMemberships[$dn].DirectGroups += $Entry.TopLevelGroup
                        }
                    } else {
                        if (-not $MemberGroupMemberships[$dn].NestedPaths.ContainsKey($Entry.TopLevelGroup)) {
                            $MemberGroupMemberships[$dn].NestedPaths[$Entry.TopLevelGroup] = @()
                        }
                        if ($Entry.NestedVia -notin $MemberGroupMemberships[$dn].NestedPaths[$Entry.TopLevelGroup]) {
                            $MemberGroupMemberships[$dn].NestedPaths[$Entry.TopLevelGroup] += $Entry.NestedVia
                        }
                    }
                }
            }

            # Show Found message BEFORE user data
            if ($TotalMembers -gt 0) {
                # Build summary message with accurate counts by type
                $summaryParts = @()
                if ($UserCount -gt 0) {
                    $summaryParts += "$UserCount user(s)"
                }
                if ($gMSACount -gt 0) {
                    $summaryParts += "$gMSACount gMSA(s)"
                }
                if ($ComputerCount -gt 0) {
                    $summaryParts += "$ComputerCount computer(s)"
                }
                if ($ForeignCount -gt 0) {
                    $summaryParts += "$ForeignCount foreign principal(s)"
                }
                $summaryText = $summaryParts -join ", "
                Show-Line "Found $summaryText across $TotalGroups privileged group(s):" -Class Finding
            }

            # What those foreign principals are, said once. $Script:AllForeignMembers was
            # filled in the recursion under the comment "Track foreign members for summary"
            # and then read nowhere - the summary it was collected for did not exist. A SID
            # from across a trust can name a group as easily as a user, and in that case the
            # members this section is about are on the other side and were not enumerated.
            # Grouped by SID, not one row per collected entry. The recursion appends to
            # $Script:AllForeignMembers once per path it reaches the principal on, so a
            # principal that is a member of two privileged groups - or of one group through
            # two routes - was in there twice, and the count above it said two where
            # $ForeignCount, which counts unique members, said one. One line per principal,
            # naming every group it reaches.
            if (@($Script:AllForeignMembers).Count -gt 0) {
                $foreignBySID = @{}
                foreach ($foreign in $Script:AllForeignMembers) {
                    $foreignSID = [string]$foreign.SID
                    if (-not $foreignSID) { continue }
                    if (-not $foreignBySID.ContainsKey($foreignSID)) {
                        $foreignName = [string]$foreign.ResolvedName
                        if (-not $foreignName) { $foreignName = $foreignSID }
                        $foreignBySID[$foreignSID] = [PSCustomObject]@{
                            Name   = $foreignName
                            Groups = @()
                        }
                    }
                    $foreignGroup = [string]$foreign.PrivilegedGroup
                    if ($foreignGroup -and $foreignBySID[$foreignSID].Groups -notcontains $foreignGroup) {
                        $foreignBySID[$foreignSID].Groups += $foreignGroup
                    }
                }

                if ($foreignBySID.Count -gt 0) {
                    Show-Line "$($foreignBySID.Count) of them come from a trusted domain - adPEAS cannot read the object behind the SID, so a group there is not expanded:" -Class Hint
                    foreach ($foreignSID in ($foreignBySID.Keys | Sort-Object)) {
                        $entry = $foreignBySID[$foreignSID]
                        Show-Line "  $($entry.Name) in $(@($entry.Groups) -join ', ')" -Class Hint
                    }
                }
            }

            # Output each unique member with full user object
            foreach ($dn in $MemberGroupMemberships.Keys) {
                $MemberData = $MemberGroupMemberships[$dn]
                $BasicInfo = $MemberData.MemberInfo

                # Get full user object for Show-Object
                $FullUserObject = $null

                if ($BasicInfo.IsForeign) {
                    # Foreign Security Principal - create display object
                    $FullUserObject = [PSCustomObject]@{
                        sAMAccountName = if ($BasicInfo.ResolvedName) { "[FOREIGN] $($BasicInfo.ResolvedName)" } else { "[FOREIGN] $($BasicInfo.SID)" }
                        distinguishedName = $BasicInfo.DistinguishedName
                        objectSid = $BasicInfo.SID
                        objectClass = "foreignSecurityPrincipal"
                    }
                } elseif ($BasicInfo.IsCrossDomain -and $BasicInfo.GCObject) {
                    # Cross-domain member resolved via GC - use GC object directly
                    # (local Get-DomainUser/Computer would fail because DN is in another partition)
                    $FullUserObject = $BasicInfo.GCObject
                    Write-Log "[Get-PrivilegedGroupMembers] Using GC-resolved object for cross-domain member: $($BasicInfo.SAMAccountName)"
                } else {
                    # Get full user/computer object with all attributes
                    $FullUserObject = @(Get-DomainUser -Identity $dn @CredParams)[0]

                    if (-not $FullUserObject) {
                        # Might be a computer - try Get-DomainComputer
                        $FullUserObject = @(Get-DomainComputer -Identity $dn @CredParams)[0]
                    }

                    if (-not $FullUserObject) {
                        # Might be a gMSA or other special account type - try Get-DomainObject
                        # gMSAs have objectClass=msDS-GroupManagedServiceAccount, not user/computer
                        $FullUserObject = @(Get-DomainObject -Identity $dn @CredParams)[0]
                    }

                    if (-not $FullUserObject) {
                        # Fallback to basic info
                        $FullUserObject = [PSCustomObject]@{
                            sAMAccountName = $BasicInfo.SAMAccountName
                            distinguishedName = $BasicInfo.DistinguishedName
                        }
                    }
                }

                # Remove memberOf from object to avoid duplication with privilegedGroups
                # The privilegedGroups property below shows the relevant group memberships
                if ($FullUserObject.PSObject.Properties['memberOf']) {
                    $FullUserObject.PSObject.Properties.Remove('memberOf')
                }

                # Build privilege groups with SID for tier classification
                # SID lookup directly from $AllGroupData (no separate hashtable needed)
                $GroupEntries = @()
                foreach ($grp in $MemberData.Groups) {
                    # Find SID from AllGroupData by group name
                    $grpData = $AllGroupData | Where-Object { $_.GroupName -eq $grp } | Select-Object -First 1
                    $grpSID = if ($grpData) { $grpData.GroupSID } else { $null }

                    $displayText = if ($PrimaryGroupOf[$dn] -eq $grp) {
                        # Not "(direct)": this account is not in the group's member
                        # attribute at all, and the fix is a different one.
                        "$grp (primary group)"
                    } elseif ($grp -in $MemberData.DirectGroups) {
                        "$grp (direct)"
                    } else {
                        $nestedPath = $MemberData.NestedPaths[$grp] -join ", "
                        "$grp (via $nestedPath)"
                    }
                    $GroupEntries += [PSCustomObject]@{
                        Name = $grp
                        SID = $grpSID
                        DisplayText = $displayText
                    }
                }
                # Add privilegedGroups as array property - Show-Object will format with proper alignment
                $FullUserObject | Add-Member -NotePropertyName 'privilegedGroups' -NotePropertyValue $GroupEntries -Force
                $FullUserObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'PrivilegedGroupMember' -Force

                # Pass complete object to Show-Object (includes privilegedGroups)
                # Use -Class Hint: Privileged accounts are informational, not a finding per se
                # Individual problematic attributes (DONT_EXPIRE_PASSWORD, etc.) still show as Finding
                Show-Object $FullUserObject -Class Hint

                # Add blank line between accounts for readability
                Show-EmptyLine
            }

            # Show group summary if no members found
            if ($TotalMembers -eq 0) {
                Show-Line "No members found in privileged groups" -Class Note
            }

            # ===== Accounts that are not computers but hold a DC group as primary =====
            #
            # Its own block rather than part of the enumeration above, because the groups
            # themselves stay out: -516 holds every domain controller and listing it would
            # bury everything else. What is asked here is the inverse - who holds one of
            # these as their PRIMARY group without being a computer.
            try {
                $dcPrimaryClauses = ($Script:DCPrimaryGroupRIDs.Keys | ForEach-Object { "(primaryGroupID=$_)" }) -join ''
                $dcPrimaryFilter = "(|$dcPrimaryClauses)"
                $dcPrimaryFindings = @()

                foreach ($dcAccount in @(Get-DomainObject -LDAPFilter $dcPrimaryFilter -Properties 'distinguishedName', 'sAMAccountName', 'name', 'objectSid', 'objectClass', 'primaryGroupID' @CredParams)) {
                    # A computer with primaryGroupID 516 is a domain controller doing what
                    # domain controllers do. Only the accounts that are not computers are a
                    # finding here - the class decides, not the name.
                    if (@($dcAccount.objectClass) -icontains 'computer') { continue }

                    $dcRID = "$($dcAccount.primaryGroupID)"
                    if (-not $Script:DCPrimaryGroupRIDs.ContainsKey($dcRID)) { continue }

                    $dcAccount | Add-Member -NotePropertyName 'primaryGroupIsDCGroup' -NotePropertyValue (
                        "$($Script:DCPrimaryGroupRIDs[$dcRID]) (RID $dcRID)") -Force
                    $dcAccount | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'PrivilegedGroupMember' -Force
                    $dcPrimaryFindings += $dcAccount
                }

                if (@($dcPrimaryFindings).Count -gt 0) {
                    Show-Line "$(@($dcPrimaryFindings).Count) account(s) that are not computers hold a domain controller group as their primary group:" -Class Finding
                    foreach ($dcFinding in $dcPrimaryFindings) {
                        Show-Object $dcFinding -Class Finding
                    }
                }
            } catch {
                # Coverage, not a reason to lose the rest of the check.
                Write-Log "[Get-PrivilegedGroupMembers] Primary-group query for the DC groups failed: $($_.Exception.Message)" -Level Warning
            }

            # ===== STEP 5: Check AdminSDHolder ACLs =====
            Show-SubHeader "Checking AdminSDHolder ACLs..." -ObjectType "AdminSDHolderACL"

            $AdminSDHolderFindings = @()
            $DomainDN = $Script:LDAPContext.DomainDN
            $AdminSDHolderDN = "CN=AdminSDHolder,CN=System,$DomainDN"

            try {
                # Use auth-agnostic LDAP pipeline (works with Kerberos PTT, SimpleBind, etc.)
                $AdminSDHolderObj = @(Get-DomainObject -Identity $AdminSDHolderDN -Properties 'nTSecurityDescriptor' -Raw @connectionParams)[0]
                if (-not $AdminSDHolderObj -or -not $AdminSDHolderObj.nTSecurityDescriptor) {
                    Write-Log "[Get-PrivilegedGroupMembers] Could not retrieve AdminSDHolder security descriptor" -Level Error
                    throw "AdminSDHolder security descriptor not available"
                }

                $sdBytes = $AdminSDHolderObj.nTSecurityDescriptor
                $SecurityDescriptor = New-Object System.DirectoryServices.ActiveDirectorySecurity
                $SecurityDescriptor.SetSecurityDescriptorBinaryForm($sdBytes)

                if ($SecurityDescriptor) {
                    # Uses central privileged check from Test-IsPrivileged.ps1

                    # The dangerous rights of each trustee, gathered over all of its ACEs
                    $trusteeRights = [ordered]@{}

                    # GetAccessRules with SecurityIdentifier, not .Access. .Access asks for
                    # the rules as NTAccount, which makes the local machine name-resolve
                    # every SID and silently drops the ones it cannot. Against a domain
                    # this host is not joined to that is every domain principal, so the
                    # AdminSDHolder DACL came back holding only built-in identities - and
                    # a dangerous ACE on AdminSDHolder is a persistence mechanism that has
                    # to be seen.
                    $AdminSDHolderRules = $SecurityDescriptor.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])

                    foreach ($ACE in $AdminSDHolderRules) {
                        if ($ACE.AccessControlType -ne 'Allow' -or $ACE.IsInherited) { continue }

                        # Get SID - IdentityReference may be SecurityIdentifier or NTAccount
                        $TrusteeSID = $null
                        $identRef = $ACE.IdentityReference
                        if ($identRef -is [System.Security.Principal.SecurityIdentifier]) {
                            $TrusteeSID = $identRef.Value
                        } else {
                            # NTAccount - use ConvertTo-SID for cross-domain support
                            $TrusteeSID = ConvertTo-SID -Identity $identRef.Value
                        }
                        if (-not $TrusteeSID) { continue }

                        # An inherit-only ACE grants nothing on AdminSDHolder, and nothing on
                        # the objects SDProp copies it onto - it reaches only their children.
                        #
                        # An InheritedObjectType does not take an ACE off the object either:
                        # it names the class of the children that may inherit the ACE (MS-DTYP,
                        # ACE), and the access check reads the ObjectType alone and skips only
                        # INHERIT_ONLY_ACE. "This object and descendant user objects" is full
                        # control over AdminSDHolder and, copied by SDProp, over every
                        # protected group and account. This skipped every ACE with a class.
                        if (([string]$ACE.PropagationFlags) -match 'InheritOnly') {
                            Write-Log "[Get-PrivilegedGroupMembers] Skipping inherit-only ACE on AdminSDHolder: Trustee=$TrusteeSID"
                            continue
                        }

                        # Check for dangerous permissions
                        $objectType = $ACE.ObjectType

                        # Test-ADRightsMask (adPEAS-GUIDs.ps1) expands generic access bits
                        # (GA/GR/GW/GX) before testing and requires an exact match for GenericAll,
                        # not just an overlap - a raw "-band" against $ACE.ActiveDirectoryRights
                        # would miss an ACE that grants full control only via the GA generic bit
                        # (e.g. the RBCD-style "O:BAD:(A;;GA;;;<sid>)" form), GenericAll included.
                        # Also, GenericAll only applies to the whole object if ObjectType is empty.
                        $HasGenericAll = (Test-ADRightsMask -Rights $ACE.ActiveDirectoryRights -Has ([System.DirectoryServices.ActiveDirectoryRights]::GenericAll)) -and
                                         (-not $objectType -or $objectType -eq [Guid]::Empty)

                        # WriteDacl (0x40000) and WriteOwner (0x80000) - only if ObjectType is empty
                        $HasWriteDacl = (Test-ADRightsMask -Rights $ACE.ActiveDirectoryRights -Has ([System.DirectoryServices.ActiveDirectoryRights]::WriteDacl)) -and
                                        (-not $objectType -or $objectType -eq [Guid]::Empty)
                        $HasWriteOwner = (Test-ADRightsMask -Rights $ACE.ActiveDirectoryRights -Has ([System.DirectoryServices.ActiveDirectoryRights]::WriteOwner)) -and
                                         (-not $objectType -or $objectType -eq [Guid]::Empty)

                        # The rights that add a MEMBER without controlling the object, which
                        # the three above do not cover. This is the heaviest consequence an
                        # ACE on AdminSDHolder can have: SDProp writes this descriptor onto
                        # every adminCount=1 object hourly, so one of these here means the
                        # trustee may add itself to Domain Admins, Enterprise Admins, Schema
                        # Admins and every other protected group - and keep that right,
                        # because a right granted here is the one that survives SDProp.
                        #
                        # Three forms, and the ObjectType decides which is which:
                        #   WriteProperty on the member GUID  - write the attribute directly
                        #   WriteProperty with no ObjectType  - write every attribute
                        #   Self on the member GUID           - the "add/remove self as
                        #                                       member" validated write
                        # GenericWrite with no ObjectType expands to WriteProperty over all
                        # attributes, which includes member; Test-ADRightsMask expands the
                        # generic bits, so it is caught by the WriteProperty test.
                        $memberGUID = $Script:PropertyGUIDs['member']
                        $objectTypeIsMember = ($objectType -and $memberGUID -and $objectType -eq $memberGUID)
                        $objectTypeIsEmpty = (-not $objectType -or $objectType -eq [Guid]::Empty)

                        $HasWriteMember = (Test-ADRightsMask -Rights $ACE.ActiveDirectoryRights -Has ([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty)) -and
                                          ($objectTypeIsMember -or $objectTypeIsEmpty)
                        $HasSelfMember = (Test-ADRightsMask -Rights $ACE.ActiveDirectoryRights -Has ([System.DirectoryServices.ActiveDirectoryRights]::Self)) -and
                                         ($objectTypeIsMember -or $objectTypeIsEmpty)

                        # The rights that take over the protected ACCOUNTS, which the member
                        # rights above do not cover: SDProp writes this descriptor onto every
                        # protected user as well, so a write on one of these attributes here
                        # is that write on every administrator. Named attributes only - a
                        # WriteProperty without an ObjectType is already the member line
                        # above, and GenericAll covers everything.
                        #   msDS-KeyCredentialLink - add a key and authenticate as the account
                        #   servicePrincipalName   - give the account an SPN and roast it
                        #   altSecurityIdentities  - map a certificate onto the account (ESC14)
                        #   userAccountControl     - switch off pre-authentication or the
                        #                            password requirement (directly or through
                        #                            the User-Account-Restrictions set)
                        # and the extended right to reset the password, which an ACE with no
                        # ObjectType grants along with every other extended right.
                        $hasWriteProperty = Test-ADRightsMask -Rights $ACE.ActiveDirectoryRights -Has ([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty)
                        $hasExtendedRight = Test-ADRightsMask -Rights $ACE.ActiveDirectoryRights -Has ([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight)
                        $HasWriteKeyCredential = $hasWriteProperty -and $objectType -and ($objectType -eq $Script:PropertyGUIDs['msDS-KeyCredentialLink'])
                        $HasWriteSPN = $hasWriteProperty -and $objectType -and ($objectType -eq $Script:PropertyGUIDs['servicePrincipalName'])
                        $HasWriteAltSecurity = $hasWriteProperty -and $objectType -and ($objectType -eq $Script:PropertyGUIDs['altSecurityIdentities'])
                        $HasWriteAccountControl = $hasWriteProperty -and $objectType -and (
                            ($objectType -eq $Script:PropertyGUIDs['userAccountControl']) -or
                            ($objectType -eq $Script:PropertySetGUIDs['User-Account-Restrictions']))
                        $resetPasswordGUID = [Guid]$Script:ExtendedRightsAliases['ForceChangePassword']
                        $HasResetPassword = $hasExtendedRight -and ($objectTypeIsEmpty -or ($objectType -eq $resetPasswordGUID))

                        $HasDangerousPermission = $HasGenericAll -or $HasWriteDacl -or $HasWriteOwner -or
                                                  $HasWriteMember -or $HasSelfMember -or
                                                  $HasWriteKeyCredential -or $HasWriteSPN -or $HasWriteAltSecurity -or
                                                  $HasWriteAccountControl -or $HasResetPassword

                        if (-not $HasDangerousPermission) { continue }

                        # Collected per trustee and judged once, below. The descriptor hands
                        # the ACEs back in an order nobody controls - measured, it re-sorts
                        # them on load - and the loop used to take the first dangerous ACE of
                        # a trustee and skip the others, so which of its rights the row named
                        # depended on that order.
                        if (-not $trusteeRights.Contains($TrusteeSID)) {
                            $trusteeRights[$TrusteeSID] = @{
                                GenericAll = $false; WriteDacl = $false; WriteOwner = $false
                                WriteMember = $false; SelfMember = $false; KeyCredential = $false
                                SPN = $false; AltSecurity = $false; AccountControl = $false
                                ResetPassword = $false; AllExtendedRights = $false
                            }
                        }
                        $collected = $trusteeRights[$TrusteeSID]
                        if ($HasGenericAll) { $collected.GenericAll = $true }
                        if ($HasWriteDacl) { $collected.WriteDacl = $true }
                        if ($HasWriteOwner) { $collected.WriteOwner = $true }
                        if ($HasWriteMember) { $collected.WriteMember = $true }
                        if ($HasSelfMember) { $collected.SelfMember = $true }
                        if ($HasWriteKeyCredential) { $collected.KeyCredential = $true }
                        if ($HasWriteSPN) { $collected.SPN = $true }
                        if ($HasWriteAltSecurity) { $collected.AltSecurity = $true }
                        if ($HasWriteAccountControl) { $collected.AccountControl = $true }
                        if ($HasResetPassword) {
                            if ($objectTypeIsEmpty) { $collected.AllExtendedRights = $true } else { $collected.ResetPassword = $true }
                        }
                    }

                    # The rights some trustees hold here by design: Key Admins and Enterprise
                    # Key Admins write msDS-KeyCredentialLink for Windows Hello for Business
                    # (DefaultRightHolders of the DomainRootACL scope). Left out of the row, so
                    # a right of theirs that is not by design is reported on its own.
                    $holderTable = $Script:SecurityScopes['DomainRootACL'].DefaultRightHolders

                    foreach ($TrusteeSID in @($trusteeRights.Keys)) {
                        $collected = $trusteeRights[$TrusteeSID]

                        $defaultRights = @()
                        if ($holderTable) {
                            $holderRID = Get-SIDRIDSuffix -SID $TrusteeSID
                            if ($holderTable.ContainsKey($TrusteeSID)) { $defaultRights = @($holderTable[$TrusteeSID]) }
                            elseif ($holderRID -and $holderTable.ContainsKey($holderRID)) { $defaultRights = @($holderTable[$holderRID]) }
                        }

                        # Each right by name and by what it does. Named for the consequence
                        # rather than for the bit, because that is what a reader has to see:
                        # this propagates to every protected group and account.
                        #
                        # Only GenericAll, WriteDacl and WriteOwner when GenericAll is on the
                        # row: full control over the whole object expands to every right
                        # below, so listing them beside it says the same thing several times.
                        $entries = New-Object System.Collections.ArrayList
                        if ($collected.GenericAll) { [void]$entries.Add(@('GenericAll', 'GenericAll')) }
                        if ($collected.WriteDacl) { [void]$entries.Add(@('WriteDacl', 'WriteDacl')) }
                        if ($collected.WriteOwner) { [void]$entries.Add(@('WriteOwner', 'WriteOwner')) }
                        if (-not $collected.GenericAll) {
                            if ($collected.WriteMember) { [void]$entries.Add(@('member', 'WriteProperty on member - may add a member to every protected group')) }
                            if ($collected.SelfMember) { [void]$entries.Add(@('Self-Membership', 'Self on member - may add itself to every protected group')) }
                            if ($collected.KeyCredential) { [void]$entries.Add(@('msDS-KeyCredentialLink', 'WriteProperty on msDS-KeyCredentialLink - may add a key credential to every protected account and log on as it')) }
                            if ($collected.SPN) { [void]$entries.Add(@('servicePrincipalName', 'WriteProperty on servicePrincipalName - may give every protected account an SPN and roast its password')) }
                            if ($collected.AltSecurity) { [void]$entries.Add(@('altSecurityIdentities', 'WriteProperty on altSecurityIdentities - may map a certificate onto every protected account')) }
                            if ($collected.AccountControl) { [void]$entries.Add(@('userAccountControl', 'WriteProperty on userAccountControl - may turn off pre-authentication or the password requirement on every protected account')) }
                            if ($collected.AllExtendedRights) {
                                [void]$entries.Add(@('User-Force-Change-Password', 'All extended rights - may reset the password of every protected account'))
                            } elseif ($collected.ResetPassword) {
                                # Not "Reset password ...": OU_PERM_PASSWORD_RESET matches that
                                # text, scores higher and describes an OU delegation.
                                [void]$entries.Add(@('User-Force-Change-Password', 'Password reset right - may reset the password of every protected account'))
                            }
                        }

                        $reported = @($entries | Where-Object { $defaultRights -notcontains $_[0] })
                        if (@($reported).Count -eq 0) {
                            Write-Log "[Get-PrivilegedGroupMembers] AdminSDHolder: $TrusteeSID holds only its default rights"
                            continue
                        }
                        $Permissions = @($reported | ForEach-Object { $_[1] })

                        # Resolve name for display
                        $TrusteeName = ConvertFrom-SID -SID $TrusteeSID

                        # Determine severity
                        $severity = 'Finding'

                        if (-not $IncludePrivileged) {
                            # Use scope-based check for Domain Root ACL (AdminSDHolder has same expectations)
                            $scopeResult = Test-IsExpectedInScope -Identity $TrusteeSID -Scope 'DomainRootACL' -ReturnDetails

                            if ($scopeResult.Severity -eq 'Expected') {
                                Write-Log "[Get-PrivilegedGroupMembers] AdminSDHolder expected: $TrusteeName - $($scopeResult.Reason)"
                                continue
                            }

                            if ($scopeResult.Severity -eq 'Attention') {
                                Write-Log "[Get-PrivilegedGroupMembers] AdminSDHolder attention: $TrusteeName - $($scopeResult.Reason) - skipped (use -IncludePrivileged to include)"
                                continue
                            }

                            $severity = $scopeResult.Severity
                        } else {
                            # -IncludePrivileged: Show ALL accounts, but mark privileged ones for yellow display
                            $scopeResult = Test-IsExpectedInScope -Identity $TrusteeSID -Scope 'DomainRootACL' -ReturnDetails
                            $severity = $scopeResult.Severity
                            Write-Log "[Get-PrivilegedGroupMembers] IncludePrivileged: Including AdminSDHolder $TrusteeName ($TrusteeSID) with severity $severity"
                        }

                        $finding = [PSCustomObject]@{
                            Name = $TrusteeName
                            Trustee = $TrusteeName
                            TrusteeSID = $TrusteeSID
                            dangerousRights = $Permissions
                        }
                        if ($severity -in @('Expected', 'Attention')) {
                            $finding | Add-Member -NotePropertyName 'dangerousRightsSeverity' -NotePropertyValue 'Hint' -Force
                        }
                        $finding | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'AdminSDHolderACL' -Force
                        $AdminSDHolderFindings += $finding

                        Show-Object $finding -Class $(if ([string]$finding.dangerousRightsSeverity -in @('Expected', 'Attention', 'Hint')) { 'Hint' } else { 'Finding' })
                    }

                    # Two questions, and the loop above answers only the first.
                    #
                    # "What does SDProp propagate" is about the EXPLICIT Allow ACEs: those
                    # are the descriptor that gets written onto every protected object, and
                    # that is why the loop skips inherited and Deny.
                    #
                    # "Who can change AdminSDHolder itself" is a different question with a
                    # different answer. A GenericAll inherited onto CN=AdminSDHolder from
                    # CN=System or from the domain root is enough to rewrite the template,
                    # and the domain root is covered by Get-DangerousACLs while CN=System is
                    # covered by nobody. Said as its own line, because the remediation is a
                    # different one - the ACE has to be removed at the parent.
                    $inheritedControllers = @()
                    $denyTrustees = @()
                    foreach ($ACE in $AdminSDHolderRules) {
                        $identRef = $ACE.IdentityReference
                        $aceSID = if ($identRef -is [System.Security.Principal.SecurityIdentifier]) {
                            $identRef.Value
                        } else {
                            ConvertTo-SID -Identity $identRef.Value
                        }
                        if (-not $aceSID) { continue }

                        if ($ACE.AccessControlType -eq 'Deny') {
                            # A Deny on AdminSDHolder is itself worth a look: it can hide the
                            # template from the very administrators who would audit it.
                            $denyName = ConvertFrom-SID -SID $aceSID
                            if (-not $denyName) { $denyName = $aceSID }
                            if ($denyTrustees -notcontains $denyName) { $denyTrustees += $denyName }
                            continue
                        }

                        if (-not $ACE.IsInherited) { continue }
                        # An inherited copy for another class than AdminSDHolder's arrives
                        # inherit-only and grants nothing here.
                        if (([string]$ACE.PropagationFlags) -match 'InheritOnly') { continue }

                        $inheritedType = $ACE.ObjectType
                        $inheritedEmpty = (-not $inheritedType -or $inheritedType -eq [Guid]::Empty)
                        $controls = (
                            (Test-ADRightsMask -Rights $ACE.ActiveDirectoryRights -Has ([System.DirectoryServices.ActiveDirectoryRights]::GenericAll)) -or
                            (Test-ADRightsMask -Rights $ACE.ActiveDirectoryRights -Has ([System.DirectoryServices.ActiveDirectoryRights]::WriteDacl)) -or
                            (Test-ADRightsMask -Rights $ACE.ActiveDirectoryRights -Has ([System.DirectoryServices.ActiveDirectoryRights]::WriteOwner))
                        ) -and $inheritedEmpty
                        if (-not $controls) { continue }

                        # The four default holders of full control on everything are not a
                        # finding here either - same gate as above.
                        $inheritedScope = Test-IsExpectedInScope -Identity $aceSID -Scope 'DomainRootACL' -ReturnDetails
                        if ($inheritedScope.Severity -in @('Expected', 'Attention')) { continue }

                        $inheritedName = ConvertFrom-SID -SID $aceSID
                        if (-not $inheritedName) { $inheritedName = $aceSID }
                        if ($inheritedControllers -notcontains $inheritedName) { $inheritedControllers += $inheritedName }
                    }

                    # The owner of AdminSDHolder may rewrite its DACL whatever the DACL says,
                    # and the rewritten template is copied onto every protected object within
                    # the hour. Not asked before; the four default owners - Administrators,
                    # SYSTEM, Domain Admins, Enterprise Admins - are expected, as on the domain
                    # object.
                    $holderOwnerSID = $null
                    try { $holderOwnerSID = $SecurityDescriptor.GetOwner([System.Security.Principal.SecurityIdentifier]).Value } catch {
                        Write-Log "[Get-PrivilegedGroupMembers] Could not read the AdminSDHolder owner: $_"
                    }
                    if ($holderOwnerSID) {
                        $ownerScope = Test-IsExpectedInScope -Identity $holderOwnerSID -Scope 'DomainRootACL' -ReturnDetails
                        if ($ownerScope.Severity -notin @('Expected', 'Attention')) {
                            $ownerName = ConvertFrom-SID -SID $holderOwnerSID
                            if (-not $ownerName) { $ownerName = $holderOwnerSID }
                            $ownerFinding = [PSCustomObject]@{
                                Name = $ownerName
                                Trustee = $ownerName
                                TrusteeSID = $holderOwnerSID
                                dangerousRights = @('Owner of AdminSDHolder - may rewrite the template SDProp copies onto every protected group and account')
                                _adPEASObjectType = 'AdminSDHolderACL'
                            }
                            $AdminSDHolderFindings += $ownerFinding
                            Show-Object $ownerFinding -Class Finding
                        }
                    }

                    if (@($inheritedControllers).Count -gt 0) {
                        Show-Line "$(@($inheritedControllers).Count) principal(s) can rewrite AdminSDHolder through an inherited ACE - remove it at the parent:" -Class Finding
                        foreach ($controller in $inheritedControllers) {
                            Show-Line "  $controller" -Class Finding
                        }
                    }

                    if (@($denyTrustees).Count -gt 0) {
                        Show-Line "$(@($denyTrustees).Count) Deny ACE trustee(s) on AdminSDHolder - a Deny here can hide the template from the people who audit it:" -Class Hint
                        foreach ($denied in $denyTrustees) {
                            Show-Line "  $denied" -Class Hint
                        }
                    }
                }
                $adminSDHolderRead = $true
            } catch {
                Write-Log "[Get-PrivilegedGroupMembers] Error checking AdminSDHolder: $_" -Level Error
                $adminSDHolderRead = $false
            }

            if (-not $adminSDHolderRead) {
                # Without this branch a failed read fell through to the Secure message
                # below, so a blind check was indistinguishable from a clean one.
                Show-Line "AdminSDHolder could not be read - its ACLs were not evaluated" -Class Finding
            }
            elseif (@($AdminSDHolderFindings).Count -eq 0) {
                Show-Line "AdminSDHolder ACLs are secure" -Class Secure
            }

            # ===== STEP 5b: The DACL of the privileged groups AdminSDHolder does not protect =====
            # Its own try: a failure here must not read as clean, and must not take the steps
            # around it with it.
            try {
                Show-UnprotectedGroupACL -Groups @($GroupsForACLReview.Values) -IncludePrivileged:$IncludePrivileged `
                    -ConnectionParams $connectionParams -AccountOperatorMembers $accountOperatorMembers
            } catch {
                Write-Log "[Get-PrivilegedGroupMembers] Group ACL analysis failed: $_" -Level Error
                Show-Line "Error during the group ACL analysis - the privileged groups AdminSDHolder does not protect could not be evaluated: $_" -Class Finding
            }

            # ===== STEP 6: Check Pre-Windows 2000 Compatible Access =====
            Show-SubHeader "Checking Pre-Windows 2000 Compatible Access group..." -ObjectType "PreWindows2000Access"

            $PreWin2000Findings = @()
            $PreWin2000Unresolved = @()
            $preWin2000Read = $false
            # Use Well-Known SID S-1-5-32-554 for language-independent lookup
            $PreWin2000SID = 'S-1-5-32-554'

            try {
                $PreWin2000Group = Select-LocalDomainGroup (Get-DomainGroup -Identity $PreWin2000SID @CredParams)

                if ($PreWin2000Group) { $preWin2000Read = $true }

                if ($PreWin2000Group -and $PreWin2000Group.member) {
                    foreach ($MemberDN in @($PreWin2000Group.member)) {
                        if ([string]::IsNullOrWhiteSpace($MemberDN)) { continue }

                        # The SID out of the DN first, and only then a query. A well-known
                        # principal added to a domain group becomes a
                        # foreignSecurityPrincipal whose CN *is* its SID, so the lookup is
                        # not needed at all - and the module already reads FSPs this way
                        # where it walks the privileged groups above.
                        $MemberSID = $null
                        if ($MemberDN -match '^CN=(S-1-[0-9-]+?)(?:,|$)') {
                            $MemberSID = $Matches[1]
                        }

                        if (-not $MemberSID) {
                            # The other place AD keeps these: CN=WellKnown Security
                            # Principals under the Configuration partition, where the
                            # objects are named by their display name rather than by SID.
                            # That is a different naming context, and a subtree search
                            # under the domain DN does not reach it - so the search base
                            # comes from the member's own DN. Without it the lookup
                            # returned nothing, the member was skipped in silence, and the
                            # check reported a clean group.
                            $memberParams = @{}
                            foreach ($key in $CredParams.Keys) { $memberParams[$key] = $CredParams[$key] }
                            if ($MemberDN -match ',(CN=Configuration,.+)$') {
                                $memberParams['SearchBase'] = $Matches[1]
                            }

                            $MemberObj = @(Get-DomainObject -Identity $MemberDN @memberParams)[0]
                            if ($MemberObj -and $MemberObj.objectSid) {
                                $MemberSID = [string]$MemberObj.objectSid
                            }
                        }

                        if (-not $MemberSID) {
                            $PreWin2000Unresolved += $MemberDN
                            Write-Log "[Get-PrivilegedGroupMembers] Pre-Windows 2000 member could not be resolved to a SID: $MemberDN" -Level Warning
                            continue
                        }

                        # The central lists, not a private copy of three of them. The copy
                        # knew Everyone, Anonymous Logon and Authenticated Users, so
                        # Domain Users - the ordinary result of installing the domain with
                        # pre-Windows 2000 compatible permissions - was reported as
                        # "No dangerous members".
                        if (-not (Test-IsBroadTrustee -SID $MemberSID)) { continue }

                        $MemberName = ConvertFrom-SID -SID $MemberSID
                        if ([string]::IsNullOrWhiteSpace($MemberName)) { $MemberName = $MemberSID }

                        # Name carries the card title ({Name} in the ObjectType's
                        # TitleFormat). Without it the title resolved to
                        # "Pre-Windows 2000 Compatible Access: Unknown", because none of
                        # the properties Get-ObjectTypeTitle looks for were present.
                        $finding = [PSCustomObject]@{
                            Name       = $MemberName
                            MemberName = $MemberName
                            MemberSID  = $MemberSID
                        }

                        # One of two statements, each on an attribute of its own. The
                        # object used to carry Severity = 'Critical' or 'High', which are
                        # not adPEAS severity classes: META_SEVERITY_PASSTHROUGH matches
                        # only Finding, Hint, Note and Secure, so the row stayed colourless
                        # and named no finding card for one of the classic legacy findings
                        # there is.
                        # Three cases, because three different things are true. The
                        # value is the member name: the sentence these attributes used to
                        # carry is the card's Description word for word, so the console
                        # was repeating the tooltip in 160 characters.
                        $memberClass = 'Finding'
                        if ($MemberSID -eq 'S-1-5-7') {
                            # No credentials at all - the strongest of the three.
                            $finding | Add-Member -NotePropertyName 'prewin2000AnonymousMember' -NotePropertyValue $MemberName -Force
                        } elseif ($MemberSID -eq 'S-1-5-11') {
                            # The Microsoft default: still pre-populated in new forests on
                            # Server 2022 and 2025, and removing it breaks ADFS 3.0
                            # WebForms and Cisco ISE among others. Hardening worth doing,
                            # with dependencies to check first - not a finding against the
                            # configuration as shipped.
                            $finding | Add-Member -NotePropertyName 'prewin2000DefaultMember' -NotePropertyValue $MemberName -Force
                            $memberClass = 'Hint'
                        } else {
                            # Everyone, or anyone added by hand. The legacy mode.
                            $finding | Add-Member -NotePropertyName 'prewin2000BroadMember' -NotePropertyValue $MemberName -Force
                        }

                        $finding | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'PreWindows2000Access' -Force
                        $PreWin2000Findings += $finding

                        Show-Line "$MemberName is a member" -Class $memberClass

                        # The object was built, counted and never shown, so it reached
                        # neither the console nor the HTML report: the only trace of this
                        # finding anywhere was the single line above.
                        Show-Object $finding -Class $memberClass
                    }
                }

                if (-not $preWin2000Read) {
                    # A failed read used to fall through to the Secure message below, so a
                    # blind check looked exactly like a clean one.
                    Show-Line "Pre-Windows 2000 Compatible Access group could not be read - its membership was not assessed" -Class Finding
                }
                elseif (@($PreWin2000Findings).Count -eq 0 -and @($PreWin2000Unresolved).Count -eq 0) {
                    Show-Line "No dangerous members in Pre-Windows 2000 Compatible Access group" -Class Secure
                }

                if (@($PreWin2000Unresolved).Count -gt 0) {
                    Show-Line "$(@($PreWin2000Unresolved).Count) member(s) of Pre-Windows 2000 Compatible Access could not be resolved to a SID and were not assessed" -Class Hint
                }
            } catch {
                Write-Log "[Get-PrivilegedGroupMembers] Error checking Pre-Windows 2000 Compatible Access: $_" -Level Error
                Show-Line "Pre-Windows 2000 Compatible Access group could not be read - its membership was not assessed" -Class Finding
            }

        } catch {
            Write-Log "[Get-PrivilegedGroupMembers] Error: $_" -Level Error
            Show-Line "Error during check - privileged group memberships could not be evaluated: $_" -Class Finding
        }
    }

    end {
        Write-Log "[Get-PrivilegedGroupMembers] Privileged group enumeration completed"
    }
}

<#
.SYNOPSIS
    Reports who may change a privileged group that AdminSDHolder does not protect.

.DESCRIPTION
    Step 5b of Get-PrivilegedGroupMembers (review accounts 22, user decision 2026-10-16).
    AdminSDHolder protects a fixed set of groups - Microsoft lists Account Operators,
    Administrators, Backup Operators, Domain Admins, Domain Controllers, Enterprise Admins,
    Enterprise Key Admins, Key Admins, Print Operators, Read-only Domain Controllers,
    Replicator, Schema Admins and Server Operators - and SDProp resets their DACL to its
    template every hour, which is why step 5 reads the template. Every other group keeps
    whatever ACEs it is given, and several of them are privileged in all but name: DnsAdmins
    can load code into the DNS service on the domain controllers, Group Policy Creator
    Owners create policy, the Exchange groups hold rights on the domain, and a group nested
    into one of them passes its membership on.

    Which groups are unprotected is measured, not listed: SDProp sets adminCount=1 on every
    group it protects, so the groups without it are read. adminCount is never cleared, so a
    group that was protected once and is no longer keeps a stale 1 and is not read here.

    The rights that take a group over: writing its member attribute (WriteProperty on member
    or on every attribute, which GenericWrite includes), the Self-Membership validated write,
    WriteDacl, WriteOwner, GenericAll, and owning it. Explicit and inherited ACEs alike - both
    apply to the group itself - but not an inherit-only one, and not an Allow that an
    explicit Deny for the same trustee cancels completely. Who counts as expected is decided
    by the same gate as the AdminSDHolder step, and an Exchange service group's rights are
    by design, as in the other ACL checks.

    One holder is reported apart: Account Operators. The default security descriptor of the
    group class grants them full control - (A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO) on
    learn.microsoft.com, adschema - so they control every group AdminSDHolder does not
    protect, in every domain, by design. Listed per group that would be the same finding in
    every report; it is said once instead, as a hint while the group has members and a note
    while it is empty.

.PARAMETER Groups
    The groups to read: DistinguishedName, Name and Source ("privileged group", "nested in
    <group>", "Exchange group").

.PARAMETER IncludePrivileged
    Also list the expected and privileged holders, as hints.

.PARAMETER ConnectionParams
    Domain/Server/Credential hashtable, passed through unchanged.

.PARAMETER AccountOperatorMembers
    How many members Account Operators has, or $null when the group was not found.
#>
function Show-UnprotectedGroupACL {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        [object[]]$Groups,

        [Parameter(Mandatory=$false)]
        [switch]$IncludePrivileged,

        [Parameter(Mandatory=$false)]
        [hashtable]$ConnectionParams = @{},

        [Parameter(Mandatory=$false)]
        [AllowNull()]
        $AccountOperatorMembers
    )

    Show-SubHeader "Checking the ACLs of privileged groups AdminSDHolder does not protect..." -ObjectType 'PrivilegedGroupACL'

    $accountOperatorsSID = 'S-1-5-32-548'
    $memberGUID = $Script:PropertyGUIDs['member']

    # Per trustee: the rights it holds, and on which groups.
    $byTrustee = [ordered]@{}
    $examinedGroups = @()
    $unreadGroups = @()
    $accountOperatorGroups = @()
    $suppressed = @{}

    foreach ($group in @($Groups)) {
        if (-not $group -or -not $group.DistinguishedName) { continue }

        $groupObject = $null
        try {
            $groupObject = @(Get-DomainObject -Identity $group.DistinguishedName -Properties 'nTSecurityDescriptor', 'adminCount' -Raw @ConnectionParams)[0]
        } catch {
            Write-Log "[Get-PrivilegedGroupMembers] Could not read $($group.DistinguishedName): $_"
        }
        if (-not $groupObject -or -not $groupObject.nTSecurityDescriptor) {
            $unreadGroups += $group.Name
            continue
        }

        # Protected: step 5 read its template.
        if ("$($groupObject.adminCount)" -eq '1') { continue }

        $descriptor = New-Object System.DirectoryServices.ActiveDirectorySecurity
        try {
            $descriptor.SetSecurityDescriptorBinaryForm([byte[]]$groupObject.nTSecurityDescriptor)
        } catch {
            Write-Log "[Get-PrivilegedGroupMembers] Could not parse the descriptor of $($group.DistinguishedName): $_"
            $unreadGroups += $group.Name
            continue
        }
        $examinedGroups += $group.Name

        # SecurityIdentifier, not .Access - see the AdminSDHolder step.
        $rules = @($descriptor.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
        $denyRules = @($rules | Where-Object { $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny })

        # Trustee SID -> the rights it holds on this group, and whether any came by inheritance.
        $onThisGroup = [ordered]@{}

        foreach ($ace in $rules) {
            if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
            if (([string]$ace.PropagationFlags) -match 'InheritOnly') { continue }

            $trusteeSID = $ace.IdentityReference.Value
            # SELF and CREATOR OWNER: the group itself cannot sign in, and the creator's
            # rights are the owner's, which is read below.
            if ($trusteeSID -in @('S-1-5-10', 'S-1-3-0')) { continue }
            if ($denyRules.Count -gt 0 -and (Test-ACEFullyDenied -ACE $ace -DenyACEs $denyRules)) { continue }

            $objectType = $ace.ObjectType
            $objectTypeIsEmpty = (-not $objectType -or $objectType -eq [Guid]::Empty)
            $objectTypeIsMember = ($objectType -and $memberGUID -and $objectType -eq $memberGUID)

            # Test-ADRightsMask expands the generic bits, GenericWrite into WriteProperty
            # over every attribute among them - see the AdminSDHolder step.
            $rights = @()
            if ((Test-ADRightsMask -Rights $ace.ActiveDirectoryRights -Has ([System.DirectoryServices.ActiveDirectoryRights]::GenericAll)) -and $objectTypeIsEmpty) {
                # Full control says everything below; listing them beside it would turn one
                # ACE into five rows that say the same.
                $rights += 'GenericAll'
            } else {
                if ((Test-ADRightsMask -Rights $ace.ActiveDirectoryRights -Has ([System.DirectoryServices.ActiveDirectoryRights]::WriteDacl)) -and $objectTypeIsEmpty) {
                    $rights += 'WriteDacl'
                }
                if ((Test-ADRightsMask -Rights $ace.ActiveDirectoryRights -Has ([System.DirectoryServices.ActiveDirectoryRights]::WriteOwner)) -and $objectTypeIsEmpty) {
                    $rights += 'WriteOwner'
                }
                if ((Test-ADRightsMask -Rights $ace.ActiveDirectoryRights -Has ([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty)) -and ($objectTypeIsMember -or $objectTypeIsEmpty)) {
                    $rights += 'WriteProperty on member - may add a member to the group'
                }
                if ((Test-ADRightsMask -Rights $ace.ActiveDirectoryRights -Has ([System.DirectoryServices.ActiveDirectoryRights]::Self)) -and ($objectTypeIsMember -or $objectTypeIsEmpty)) {
                    $rights += 'Self on member - may add itself to the group'
                }
            }
            if ($rights.Count -eq 0) { continue }

            if (-not $onThisGroup.Contains($trusteeSID)) {
                $onThisGroup[$trusteeSID] = [PSCustomObject]@{ Rights = @(); Inherited = $false }
            }
            foreach ($right in $rights) {
                if ($onThisGroup[$trusteeSID].Rights -notcontains $right) { $onThisGroup[$trusteeSID].Rights += $right }
            }
            if ($ace.IsInherited) { $onThisGroup[$trusteeSID].Inherited = $true }
        }

        # The owner may rewrite the DACL whatever it says - the same as WriteDacl.
        $ownerSID = $null
        try { $ownerSID = $descriptor.GetOwner([System.Security.Principal.SecurityIdentifier]).Value } catch { $ownerSID = $null }
        if ($ownerSID) {
            if (-not $onThisGroup.Contains($ownerSID)) {
                $onThisGroup[$ownerSID] = [PSCustomObject]@{ Rights = @(); Inherited = $false }
            }
            $onThisGroup[$ownerSID].Rights += 'Owner of the group - may rewrite its DACL'
        }

        foreach ($trusteeSID in @($onThisGroup.Keys)) {
            $held = $onThisGroup[$trusteeSID]

            if ($trusteeSID -eq $accountOperatorsSID) {
                $accountOperatorGroups += $group.Name
                if (-not $IncludePrivileged) { continue }
                $severity = 'Attention'
            } else {
                # The AdminSDHolder step's gate: the default holders of everything, and the
                # members of those groups, are expected.
                $scopeResult = Test-IsExpectedInScope -Identity $trusteeSID -Scope 'DomainRootACL' -ReturnDetails
                $severity = $scopeResult.Severity
                if ($severity -notin @('Expected', 'Attention')) {
                    $exchangeCheck = Test-IsExchangeServiceGroup -Identity $trusteeSID
                    if ($exchangeCheck -and $exchangeCheck.IsExchangeService) { $severity = 'Attention' }
                }
                if ($severity -in @('Expected', 'Attention') -and -not $IncludePrivileged) {
                    $suppressed[$trusteeSID] = $true
                    continue
                }
            }

            if (-not $byTrustee.Contains($trusteeSID)) {
                $byTrustee[$trusteeSID] = [PSCustomObject]@{ Rights = @(); Groups = @(); Severity = $severity }
            }
            $entry = $byTrustee[$trusteeSID]
            foreach ($right in $held.Rights) {
                if ($entry.Rights -notcontains $right) { $entry.Rights += $right }
            }
            $groupText = "$($group.Name) ($($group.Source))"
            if ($held.Inherited) { $groupText += ' - inherited, remove it at the parent' }
            $entry.Groups += $groupText
        }
    }

    if ($examinedGroups.Count -gt 0) {
        Show-Line ("$($examinedGroups.Count) privileged group(s) are outside AdminSDHolder's protection and were read: " +
                   ($examinedGroups -join ', ')) -Class Note
    }

    # Account Operators: the default, said once - see the description.
    if ($accountOperatorGroups.Count -gt 0) {
        $aoText = "Account Operators control $($accountOperatorGroups.Count) of these group(s) through the default every new group gets - a member of Account Operators can make itself a member of each"
        $aoClass = 'Note'
        if ($null -ne $AccountOperatorMembers -and [int]$AccountOperatorMembers -gt 0) {
            $aoText += "; Account Operators has $AccountOperatorMembers member(s)"
            $aoClass = 'Hint'
        } elseif ($null -ne $AccountOperatorMembers) {
            $aoText += '; Account Operators has no members'
        }
        Show-Line $aoText -Class $aoClass -FindingId 'PRIVILEGED_GROUP_ACL'
    }

    $findingRows = @()
    $hintRows = @()
    foreach ($trusteeSID in @($byTrustee.Keys)) {
        $entry = $byTrustee[$trusteeSID]
        $trusteeName = ConvertFrom-SID -SID $trusteeSID
        if (-not $trusteeName) { $trusteeName = $trusteeSID }

        $row = [PSCustomObject]@{
            Name            = $trusteeName
            Trustee         = $trusteeName
            TrusteeSID      = $trusteeSID
            dangerousRights = @($entry.Rights)
            affectedGroups  = @($entry.Groups)
        }
        if ($entry.Severity -in @('Expected', 'Attention')) {
            $row | Add-Member -NotePropertyName 'dangerousRightsSeverity' -NotePropertyValue 'Hint' -Force
            $row | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'PrivilegedGroupACL' -Force
            $hintRows += $row
        } else {
            $row | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'PrivilegedGroupACL' -Force
            $findingRows += $row
        }
    }

    if ($findingRows.Count -gt 0) {
        Show-Line ("Found $($findingRows.Count) principal(s) that can take over a privileged group AdminSDHolder " +
                   "does not protect") -Class Finding -FindingId 'PRIVILEGED_GROUP_ACL'
        foreach ($row in $findingRows) { Show-Object $row -Class Finding }
    }
    if ($hintRows.Count -gt 0) {
        Show-Line "Found $($hintRows.Count) expected or privileged holder(s) of the same rights" -Class Hint
        foreach ($row in $hintRows) { Show-Object $row -Class Hint }
    }

    if ($unreadGroups.Count -gt 0) {
        Show-Line ("$($unreadGroups.Count) group(s) could not be read - who may change them was not evaluated: " +
                   ($unreadGroups -join ', ')) -Class Note
    }

    if ($findingRows.Count -eq 0 -and $hintRows.Count -eq 0) {
        if ($examinedGroups.Count -eq 0) {
            if ($unreadGroups.Count -eq 0) {
                Show-Line "Every privileged group found is protected by AdminSDHolder" -Class Note
            }
            return
        }
        $cleanClass = 'Secure'
        if ($unreadGroups.Count -gt 0) { $cleanClass = 'Note' }
        $cleanText = "No principal beyond the expected ones can change the $($examinedGroups.Count) privileged group(s) AdminSDHolder does not protect"
        if ($suppressed.Count -gt 0) {
            $cleanText += " - $($suppressed.Count) expected or privileged holder(s) hidden, use -IncludePrivileged to see them"
        }
        Show-Line $cleanText -Class $cleanClass
    }
}

