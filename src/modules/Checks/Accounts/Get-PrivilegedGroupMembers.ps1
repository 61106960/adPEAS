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
                                        # Use Invoke-LDAPSearch with GC connection for full attribute conversion
                                        $Member = @(Invoke-LDAPSearch -Filter "(&(objectClass=*)(distinguishedName=$MemberDN))" -SizeLimit 1 -LdapConnection $gcConn)[0]
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
                                        "$MembershipPath ? $($Member.sAMAccountName)"
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

            # ===== STEP 1: Query Domain-Specific Privileged Groups =====
            Show-SubHeader "Searching for privileged group members..." -ObjectType "PrivilegedGroupMember"

            # Build credential params for recursive calls (only relevant params)
            $CredParams = @{}
            if ($PSBoundParameters.ContainsKey('Domain')) { $CredParams['Domain'] = $Domain }
            if ($PSBoundParameters.ContainsKey('Server')) { $CredParams['Server'] = $Server }
            if ($PSBoundParameters.ContainsKey('Credential')) { $CredParams['Credential'] = $Credential }

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

            # ===== STEP 4: Build User-Centric View =====
            $TotalGroups = $AllGroupData.Count
            $TotalMembers = $TotalUniqueMembers.Count

            # Count by type for accurate summary message
            $UserCount = 0
            $ComputerCount = 0
            $gMSACount = 0
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
                # User accounts (including foreignSecurityPrincipal)
                elseif ($objClass -ieq 'user' -or $objClass -ieq 'foreignSecurityPrincipal') {
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

            Write-Log "[Get-PrivilegedGroupMembers] Count summary: Users=$UserCount, gMSAs=$gMSACount, Computers=$ComputerCount"

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
                $summaryText = $summaryParts -join ", "
                Show-Line "Found $summaryText across $TotalGroups privileged group(s):" -Class Finding
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

                    $displayText = if ($grp -in $MemberData.DirectGroups) {
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

                    # Deduplicate by tracking seen SIDs
                    $SeenSIDs = @{}

                    foreach ($ACE in $SecurityDescriptor.Access) {
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

                        # Skip if already processed this SID
                        if ($SeenSIDs.ContainsKey($TrusteeSID)) { continue }

                        # Skip ACEs with InheritedObjectType - they only apply to child objects, not AdminSDHolder itself
                        $inheritedObjectType = $ACE.InheritedObjectType
                        if ($inheritedObjectType -and $inheritedObjectType -ne [Guid]::Empty) {
                            Write-Log "[Get-PrivilegedGroupMembers] Skipping child-only ACE on AdminSDHolder: Trustee=$TrusteeSID"
                            continue
                        }

                        # Check for dangerous permissions
                        $Rights = $ACE.ActiveDirectoryRights
                        $objectType = $ACE.ObjectType

                        # GenericAll in AD is 0xF01FF (983551)
                        # We need to check if the EXACT GenericAll flag is set, not just if some rights overlap
                        # Also, GenericAll only applies to the whole object if ObjectType is empty
                        $GenericAllValue = [int][System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                        $RightsValue = [int]$Rights

                        # Check if GenericAll is explicitly set (not just overlapping bits)
                        # AND ObjectType must be empty (applies to whole object, not specific attribute)
                        $HasGenericAll = (($RightsValue -band $GenericAllValue) -eq $GenericAllValue) -and
                                         (-not $objectType -or $objectType -eq [Guid]::Empty)

                        # WriteDacl (0x40000) and WriteOwner (0x80000) - only if ObjectType is empty
                        $HasWriteDacl = ($Rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl) -and
                                        (-not $objectType -or $objectType -eq [Guid]::Empty)
                        $HasWriteOwner = ($Rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner) -and
                                         (-not $objectType -or $objectType -eq [Guid]::Empty)

                        $HasDangerousPermission = $HasGenericAll -or $HasWriteDacl -or $HasWriteOwner

                        if (-not $HasDangerousPermission) { continue }

                        # Mark as seen
                        $SeenSIDs[$TrusteeSID] = $true

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

                        $Permissions = @()
                        if ($HasGenericAll) { $Permissions += "GenericAll" }
                        if ($HasWriteDacl) { $Permissions += "WriteDacl" }
                        if ($HasWriteOwner) { $Permissions += "WriteOwner" }

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

                        Show-Object $finding
                    }
                }
            } catch {
                Write-Log "[Get-PrivilegedGroupMembers] Error checking AdminSDHolder: $_" -Level Error
            }

            if (@($AdminSDHolderFindings).Count -eq 0) {
                Show-Line "AdminSDHolder ACLs are secure" -Class Secure
            }

            # ===== STEP 6: Check Pre-Windows 2000 Compatible Access =====
            Show-SubHeader "Checking Pre-Windows 2000 Compatible Access group..." -ObjectType "PreWindows2000Access"

            $PreWin2000Findings = @()
            # Use Well-Known SID S-1-5-32-554 for language-independent lookup
            $PreWin2000SID = 'S-1-5-32-554'

            try {
                $PreWin2000Group = Select-LocalDomainGroup (Get-DomainGroup -Identity $PreWin2000SID @CredParams)

                if ($PreWin2000Group -and $PreWin2000Group.member) {
                    $DangerousSIDs = @{
                        'S-1-1-0' = @{ Name = 'Everyone'; Severity = 'Critical' }
                        'S-1-5-7' = @{ Name = 'Anonymous Logon'; Severity = 'Critical' }
                        'S-1-5-11' = @{ Name = 'Authenticated Users'; Severity = 'High' }
                    }

                    foreach ($MemberDN in $PreWin2000Group.member) {
                        $MemberObj = @(Get-DomainObject -Identity $MemberDN @CredParams)[0]

                        if ($MemberObj -and $MemberObj.objectSid) {
                            if ($DangerousSIDs.ContainsKey($MemberObj.objectSid)) {
                                $DangerousInfo = $DangerousSIDs[$MemberObj.objectSid]
                                $finding = [PSCustomObject]@{
                                    MemberName = $DangerousInfo.Name
                                    MemberSID = $MemberObj.objectSid
                                    Severity = $DangerousInfo.Severity
                                }
                                $finding | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'PreWindows2000Access' -Force
                                $PreWin2000Findings += $finding

                                Show-Line "$($DangerousInfo.Name) is a member" -Class Hint
                            }
                        }
                    }
                }

                if (@($PreWin2000Findings).Count -eq 0) {
                    Show-Line "No dangerous members in Pre-Windows 2000 Compatible Access group" -Class Secure
                }
            } catch {
                Write-Log "[Get-PrivilegedGroupMembers] Error checking Pre-Windows 2000 Compatible Access: $_" -Level Error
            }

        } catch {
            Write-Log "[Get-PrivilegedGroupMembers] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-PrivilegedGroupMembers] Privileged group enumeration completed"
    }
}

