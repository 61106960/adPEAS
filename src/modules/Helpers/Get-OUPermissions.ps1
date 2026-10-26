<#
.SYNOPSIS
    Helper function to determine the source of an inherited ACE.

.DESCRIPTION
    Traces the parent container chain to find where an inherited ACE was originally set.
    Loads parent ACLs via Invoke-LDAPSearch (reuses existing LdapConnection).

    The source is the nearest parent with an explicit, inheritable Allow ACE for the same
    trustee that grants at least the rights of the inherited one, for the same object
    type and the same inheritance class, and that reaches this far down. The match used to
    be the trustee and an inheritance flag only, so another explicit ACE of the same
    trustee on a nearer parent was named as the source; and where nothing matched, the
    domain root was named anyway.

.PARAMETER DistinguishedName
    The DN of the object with the inherited ACE.

.PARAMETER ACE
    The ACE to trace.

.OUTPUTS
    PSCustomObject with DN (the source container, $null when not found) and Display
    ("OU=Corp (OU=Corp,DC=...)", "Domain Root (DC=...)", or "Unknown - ..." when not found).
#>
function Get-ACEInheritanceSource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$DistinguishedName,

        [Parameter(Mandatory=$true)]
        $ACE
    )

    try {
        # Get domain DN from context
        $domainDN = $Script:LDAPContext.DomainDN

        # Parse the DN to get parent containers
        # Example: OU=Computers,OU=Corp,DC=contoso,DC=com
        # Parents: OU=Corp,DC=contoso,DC=com -> DC=contoso,DC=com

        $currentDN = $DistinguishedName
        $parents = @()

        # Build list of parent DNs
        while ($currentDN -match '^[^,]+,(.+)$') {
            $parentDN = $Matches[1]
            $parents += $parentDN
            $currentDN = $parentDN

            # Stop at domain root
            if ($parentDN -eq $domainDN) {
                break
            }
        }

        # ACE.IdentityReference is always a SecurityIdentifier (from GetAccessRules with [SecurityIdentifier])
        $aceIdentitySID = $ACE.IdentityReference.Value

        # What the inherited copy carries over from its source unchanged: object type and
        # inheritance class. The empty GUID and no GUID are the same "none".
        $normalizeGuid = {
            param($Value)
            if (-not $Value -or [string]$Value -eq [string][GUID]::Empty) { '' } else { ([string]$Value).ToLowerInvariant() }
        }
        $aceObjType = & $normalizeGuid $ACE.ObjectType
        $aceInheritedType = & $normalizeGuid $ACE.InheritedObjectType
        # Generic bits expanded: the inherited copy carries the mapped rights of a GA in
        # its source, or the GA itself.
        $aceRights = ConvertTo-ExpandedADRightsValue -Rights $ACE.ActiveDirectoryRights

        # Session-level cache for parent ACLs (parent ACLs are identical across all child OUs)
        if (-not $Script:InheritanceACLCache) {
            $Script:InheritanceACLCache = @{}
        }

        # Check each parent starting from immediate parent
        $isImmediateParent = $true
        foreach ($parentDN in $parents) {
            $parentIsImmediate = $isImmediateParent
            $isImmediateParent = $false
            try {
                # Load parent ACL - use cache to avoid redundant LDAP queries
                # Parent ACLs are shared by all child OUs, so caching is highly effective
                $cacheKey = $parentDN.ToLowerInvariant()
                $parentAccessRules = $null

                if ($Script:InheritanceACLCache.ContainsKey($cacheKey)) {
                    $parentAccessRules = $Script:InheritanceACLCache[$cacheKey]
                } else {
                    $parentResult = @(Invoke-LDAPSearch -Filter "(objectClass=*)" -SearchBase $parentDN -Scope Base -Properties 'nTSecurityDescriptor' -Raw)[0]
                    if ($parentResult -and $parentResult.nTSecurityDescriptor) {
                        $parentSdParsed = ConvertTo-AccessRules -SecurityDescriptorBytes $parentResult.nTSecurityDescriptor
                        $parentAccessRules = if ($parentSdParsed) { $parentSdParsed.AccessRules } else { @() }
                    } else {
                        $parentAccessRules = @()
                    }
                    $Script:InheritanceACLCache[$cacheKey] = $parentAccessRules
                }

                if (-not $parentAccessRules -or @($parentAccessRules).Count -eq 0) {
                    continue
                }

                # Look for the explicit ACE on the parent the inherited one is a copy of
                foreach ($parentACE in $parentAccessRules) {
                    # Must be explicit (not inherited) and Allow
                    if ($parentACE.IsInherited) { continue }
                    if ($parentACE.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }

                    # Match by SID (both are SecurityIdentifier - direct string comparison)
                    if ($parentACE.IdentityReference.Value -ne $aceIdentitySID) { continue }

                    # Check inheritance flags - must be set to inherit to children
                    $inheritFlags = $parentACE.InheritanceFlags
                    $canInherit = ($inheritFlags -band [System.Security.AccessControl.InheritanceFlags]::ContainerInherit) -or
                                  ($inheritFlags -band [System.Security.AccessControl.InheritanceFlags]::ObjectInherit)

                    if (-not $canInherit) { continue }

                    # NoPropagateInherit stops the copy at the direct children.
                    if (-not $parentIsImmediate -and ([string]$parentACE.PropagationFlags) -match 'NoPropagateInherit') { continue }

                    # The copy keeps object type and inheritance class, and its rights are
                    # the source's.
                    if ((& $normalizeGuid $parentACE.ObjectType) -ne $aceObjType) { continue }
                    if ((& $normalizeGuid $parentACE.InheritedObjectType) -ne $aceInheritedType) { continue }
                    if (-not (Test-ADRightsMask -Rights $parentACE.ActiveDirectoryRights -Has $aceRights)) { continue }

                    # Found the source - return a friendly name
                    if ($parentDN -eq $domainDN) {
                        return [PSCustomObject]@{ DN = $parentDN; Display = "Domain Root ($domainDN)" }
                    }
                    # Extract the first RDN for display (e.g., "OU=Corp" -> "Corp")
                    $display = $parentDN
                    if ($parentDN -match '^([^=]+)=([^,]+)') {
                        $display = "$($Matches[1])=$($Matches[2]) ($parentDN)"
                    }
                    return [PSCustomObject]@{ DN = $parentDN; Display = $display }
                }

            } catch {
                Write-Log "[Get-ACEInheritanceSource] Error checking parent '$parentDN': $_"
                continue
            }
        }

        # Not found: a parent ACL that could not be read, or a source outside the chain.
        # The domain root used to be named here anyway, as "the most common source" - a
        # guess presented as a fact.
        return [PSCustomObject]@{ DN = $null; Display = 'Unknown - no matching explicit ACE above' }

    } catch {
        Write-Log "[Get-ACEInheritanceSource] Error: $_"
        return [PSCustomObject]@{ DN = $null; Display = 'Unknown - no matching explicit ACE above' }
    }
}

<#
.SYNOPSIS
    Analyzes ACLs on Organizational Units to identify critical permissions.

.DESCRIPTION
    Universal ACL analysis module that checks for various dangerous permissions on OUs:
    - GenericAll (Full Control)
    - Password Reset Rights
    - Account Control Modification (userAccountControl, SPN, scriptPath)
    - Group Membership Control
    - Delegation Rights (Constrained, RBCD)
    - LAPS Password Access
    - Object Creation/Deletion Rights
    - GPO Linking Rights

    Returns principals (users/groups) who have these permissions.

.PARAMETER DistinguishedName
    The distinguished name of the OU to analyze.

.PARAMETER CheckType
    Type of permission check to perform. Valid values:
    - All (default): All checks
    - GenericAll: Full Control rights
    - PasswordReset: Password reset extended rights
    - AccountControl: userAccountControl write access
    - GroupMembership: member attribute write access
    - SPNModification: servicePrincipalName write access
    - KeyCredentialLink: msDS-KeyCredentialLink write access (Shadow Credentials)
    - ScriptPath: scriptPath write access
    - Delegation: Delegation attribute write access
    - LAPS: LAPS password read access
    - CredentialRoaming: read access to the Credential Roaming attributes on user objects
      (ms-PKI-DPAPIMasterKeys, ms-PKI-AccountCredentials, ms-PKI-RoamingTimeStamp). These
      findings additionally carry GrantsControlAccess, because a confidential attribute
      needs READ_PROPERTY and CONTROL_ACCESS while a non-confidential one needs only the
      former - and only the caller knows which the schema says.
    - BitLocker: read access to msFVE-RecoveryPassword on the msFVE-RecoveryInformation
      objects below the computers. These findings carry GrantsRead and GrantsControlAccess,
      for the same reason as CredentialRoaming, and an ACE carrying either half is reported.
    - ObjectCreation: CreateChild rights
    - GPOLinking: gPLink write access

.PARAMETER ExcludeInherited
    Only analyze explicit ACEs (exclude inherited permissions).

.EXAMPLE
    Get-OUPermissions -DistinguishedName "OU=Workstations,DC=contoso,DC=com"
    Performs all checks on the specified OU.

.EXAMPLE
    Get-OUPermissions -DistinguishedName "OU=Users,DC=contoso,DC=com" -CheckType 'PasswordReset'
    Checks only for password reset rights.

.EXAMPLE
    Get-OUPermissions -DistinguishedName "OU=Servers,DC=contoso,DC=com" -CheckType 'LAPS' -ExcludeInherited
    Checks for LAPS read rights, excluding inherited permissions.

.OUTPUTS
    PSCustomObject with:
    - OU: Distinguished name
    - Findings: Array of permission findings with CheckType, Right, Principals, Severity

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

<#
.SYNOPSIS
    Answers whether a Deny ACE in the same DACL cancels an Allow ACE completely.
.DESCRIPTION
    Deny ACEs were skipped rather than counted. In the canonical DACL order a Deny
    precedes the Allow entries and wins for the same right and the same trustee, so a
    delegation a Deny neutralises is not access anybody has - and reporting it is the
    finding type that loses an argument with the person who hardened the domain.

    Deliberately conservative. True is returned only when ONE Deny ACE for the same
    trustee SID covers every right bit the Allow grants, carries the same ObjectType or
    an empty one, is limited to the same object class or to none, and reaches at least
    as far as the Allow does. Several Deny ACEs are not unioned, and an Allow that is
    only partly denied stays a finding: a false negative here hides real access, which
    is worse than the false positive it would replace.

    The reach test is the same ContainerInherit/ObjectInherit and InheritOnly pair the
    caller uses for the Allow side - a Deny that does not apply where the Allow applies
    denies nothing there.
.PARAMETER ACE
    The Allow ACE under test.
.PARAMETER DenyACEs
    The Deny ACEs of the same security descriptor.
#>
function Test-ACEFullyDenied {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $ACE,
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] $DenyACEs
    )

    # Through ConvertTo-ExpandedADRightsValue, not the raw enum: a mask written with a
    # generic bit ("(A;;GA;;;<sid>)") has no named value, and a raw comparison would
    # miss that a Deny covers it.
    $allowMask = ConvertTo-ExpandedADRightsValue -Rights $ACE.ActiveDirectoryRights
    if (-not $allowMask) { return $false }

    $ci = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit
    $oi = [System.Security.AccessControl.InheritanceFlags]::ObjectInherit

    $allowSelf = -not ((([string]$ACE.PropagationFlags)) -match 'InheritOnly')
    $allowKids = ($ACE.InheritanceFlags -band $ci) -or ($ACE.InheritanceFlags -band $oi)

    foreach ($deny in $DenyACEs) {
        if ($deny.IdentityReference.Value -ne $ACE.IdentityReference.Value) { continue }

        # An inherited Deny is evaluated after every explicit ACE, so it takes nothing from
        # an Allow written on this object - it cancelled that delegation all the same.
        if ($deny.IsInherited -and -not $ACE.IsInherited) { continue }

        # ObjectType limits a Deny to one attribute or one extended right. An empty
        # GUID means all of them, which covers whatever the Allow names.
        $denyObjectType = $deny.ObjectType
        $denyCoversEveryRight = (-not $denyObjectType) -or ($denyObjectType -eq [GUID]::Empty)
        if (-not $denyCoversEveryRight -and ($denyObjectType -ne $ACE.ObjectType)) { continue }

        # InheritedObjectType limits it to one object class, same reasoning.
        $denyClass = $deny.InheritedObjectType
        $denyCoversEveryClass = (-not $denyClass) -or ($denyClass -eq [GUID]::Empty)
        if (-not $denyCoversEveryClass -and ($denyClass -ne $ACE.InheritedObjectType)) { continue }

        $denySelf = -not ((([string]$deny.PropagationFlags)) -match 'InheritOnly')
        if ($allowSelf -and -not $denySelf) { continue }

        $denyKids = ($deny.InheritanceFlags -band $ci) -or ($deny.InheritanceFlags -band $oi)
        if ($allowKids -and -not $denyKids) { continue }

        $denyMask = ConvertTo-ExpandedADRightsValue -Rights $deny.ActiveDirectoryRights
        if (-not $denyMask) { continue }
        if (($allowMask -band $denyMask) -eq $allowMask) { return $true }
    }

    return $false
}

function Get-OUPermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$DistinguishedName,

        [Parameter(Mandatory=$false)]
        [ValidateSet(
            'All',
            'GenericAll',
            'GenericWrite',
            'WriteDacl',
            'WriteOwner',
            'PasswordReset',
            'AccountControl',
            'GroupMembership',
            'SPNModification',
            'DNSHostName',
            'KeyCredentialLink',
            'ScriptPath',
            'Delegation',
            'LAPS',
            'CredentialRoaming',
            'BitLocker',
            'ObjectCreation',
            'GPOLinking',
            'Ownership'
        )]
        [string[]]$CheckType = @('All'),

        [Parameter(Mandatory=$false)]
        [switch]$ExcludeInherited
    )

    begin {
        Write-Log "[Get-OUPermissions] Analyzing ACL for OU: $DistinguishedName"

        # Use central GUID definitions from adPEAS-GUIDs.ps1
        # $Script:PropertyGUIDs - Property GUIDs (Name -> GUID)
        # Get-ExtendedRightGUID - Extended Right lookup (Name -> GUID)

        # Use central PropertyGUIDs directly (already Name -> GUID format)
        $PropertyGUIDs = $Script:PropertyGUIDs

        # Schema Class GUIDs for InheritedObjectType checks
        $SchemaClassGUIDs = $Script:SchemaClassGUIDs

        # Track if this is a full scan (All check types) for cross-module caching
        $isFullScan = $CheckType -contains 'All'

        # Expand 'All' to all check types. This list has to stay complete: only a full scan
        # writes the cross-module cache, and a later narrow call filters that cache by
        # CheckType. A type missing here would therefore come back with zero findings from
        # a cache hit - a silent pass rather than an error.
        if ($isFullScan) {
            $CheckType = @(
                'GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner',
                'PasswordReset', 'AccountControl', 'GroupMembership',
                'SPNModification', 'DNSHostName', 'KeyCredentialLink', 'ScriptPath', 'Delegation', 'LAPS',
                'CredentialRoaming', 'BitLocker', 'ObjectCreation', 'GPOLinking', 'Ownership'
            )
        }
    }

    process {
        # Internal helper - caller must ensure LDAP connection exists
        if (-not $Script:LdapConnection -or -not $Script:LDAPContext) {
            Write-Log "[Get-OUPermissions] No LDAP connection - returning null"
            return $null
        }

        try {
            # Cross-module result cache: Get-DangerousOUPermissions runs first with -CheckType All,
            # then Get-LAPSPermissions and Get-PasswordResetRights can reuse cached results
            if (-not $Script:OUPermissionsCache) {
                $Script:OUPermissionsCache = @{}
            }

            $cacheKey = $DistinguishedName.ToLowerInvariant()

            if ($Script:OUPermissionsCache.ContainsKey($cacheKey)) {
                $cached = $Script:OUPermissionsCache[$cacheKey]
                # Filter cached full-scan results for requested CheckType
                $filteredFindings = @($cached.Findings | Where-Object { $_.CheckType -in $CheckType })
                Write-Log "[Get-OUPermissions] Cache hit for OU: $DistinguishedName ($(@($filteredFindings).Count) findings for requested types)"
                return [PSCustomObject]@{
                    OU       = $DistinguishedName
                    Findings = $filteredFindings
                    Read     = $true
                }
            }

            Write-Log "[Get-OUPermissions] Analyzing: $DistinguishedName"

            # Load nTSecurityDescriptor via Invoke-LDAPSearch (uses existing $Script:LdapConnection)
            # -Raw returns byte[] instead of ConvertFrom-SecurityDescriptor (we need native ACE objects)
            $ouResult = @(Invoke-LDAPSearch -Filter "(objectClass=*)" -SearchBase $DistinguishedName -Scope Base -Properties 'nTSecurityDescriptor' -Raw)[0]

            # Read = $false rather than $null on every failure path. A caller cannot tell
            # "nothing found" from "nothing read" out of an empty finding list, and all
            # three callers phrased the first one as a Secure line naming the full OU
            # count as analyzed: a scan that was denied every descriptor in the domain
            # read as a clean domain.
            if (-not $ouResult -or -not $ouResult.nTSecurityDescriptor) {
                Write-Log "[Get-OUPermissions] Failed to read nTSecurityDescriptor for OU: $DistinguishedName"
                return [PSCustomObject]@{ OU = $DistinguishedName; Findings = $null; Read = $false }
            }

            # Parse nTSecurityDescriptor into AccessRules via shared helper
            $sdParsed = ConvertTo-AccessRules -SecurityDescriptorBytes $ouResult.nTSecurityDescriptor
            if (-not $sdParsed) {
                Write-Log "[Get-OUPermissions] Failed to parse nTSecurityDescriptor for OU: $DistinguishedName"
                return [PSCustomObject]@{ OU = $DistinguishedName; Findings = $null; Read = $false }
            }
            $AccessRules = $sdParsed.AccessRules

            # The Deny entries of this descriptor, for Test-ACEFullyDenied below. They
            # were in $AccessRules all along and the loop threw them away, so a
            # delegation that an explicit Deny cancels was reported as access.
            $denyACEs = @($AccessRules | Where-Object {
                $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny
            })
            $neutralisedByDeny = 0

            $Findings = @()

            # The owner, before the ACE loop and once per OU - it is not an ACE, which is
            # why the loop below never saw it. $sdParsed.OwnerSID was parsed two screens
            # above and discarded, so an OU owned by somebody who is not a default owner
            # produced no finding at all. That is the BloodHound Owns path: the owner can
            # write itself any ACE on the OU and have it inherited down to every object
            # inside.
            #
            # Owner checks existed in the project, but only for user and computer objects
            # (Get-NonDefaultUserOwners, Get-NonDefaultComputerOwners). OUs, containers and
            # the domain object had none.
            if ($CheckType -contains 'Ownership' -and $sdParsed.OwnerSID) {
                if (-not (Test-IsDefaultOwner -SID $sdParsed.OwnerSID)) {
                    $ownerName = ConvertFrom-SID -SID $sdParsed.OwnerSID
                    if (-not $ownerName) { $ownerName = $sdParsed.OwnerSID }
                    # .IsPrivileged, which is the property the per-ACE severity below asks
                    # for. Category -eq 'Privileged' would be a second way of asking one
                    # question, and the two do not agree: Account Operators answers
                    # Category 'Operator' with IsPrivileged false.
                    $ownerPrivileged = (Test-IsPrivileged -Identity $sdParsed.OwnerSID).IsPrivileged

                    $Findings += [PSCustomObject]@{
                        CheckType     = "Ownership"
                        # Same wording decision as the domain root: a string containing
                        # "WriteDacl" matches that pattern on dangerousRights and would
                        # take the wrong card.
                        Right         = "Owner of the OU"
                        Principal     = $ownerName
                        SID           = $sdParsed.OwnerSID
                        # Info is this module's word for "privileged, shown only with
                        # -IncludePrivileged", not for "harmless".
                        Severity      = $(if ($ownerPrivileged) { "Info" } else { "Critical" })
                        InheritedFrom = $null
                    }
                }
            }

            # Analyze each ACE
            foreach ($ACE in $AccessRules) {
                # Skip Deny ACEs (we only care about Allow)
                if ($ACE.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
                    continue
                }

                # An Allow a Deny cancels completely grants nothing, so none of the
                # checks below has anything to report about it. Tested once here
                # rather than at each of the emit sites: the condition is a property
                # of the ACE, not of the individual right, and only a Deny covering
                # the whole mask qualifies.
                if ($denyACEs.Count -gt 0 -and (Test-ACEFullyDenied -ACE $ACE -DenyACEs $denyACEs)) {
                    Write-Log "[Get-OUPermissions] ACE neutralised by an explicit Deny for the same trustee: $($ACE.IdentityReference.Value) on $DistinguishedName"
                    $neutralisedByDeny++
                    continue
                }

                # Skip inherited ACEs if requested
                if ($ExcludeInherited -and $ACE.IsInherited) {
                    continue
                }

                # IdentityReference is always a SecurityIdentifier (guaranteed by GetAccessRules above)
                $TrusteeSID = $ACE.IdentityReference.Value
                $TrusteeName = ConvertFrom-SID -SID $TrusteeSID
                if (-not $TrusteeName) {
                    $TrusteeName = $TrusteeSID
                }

                # Skip ACEs with empty SID (can occur with orphaned/deleted principals)
                if ([string]::IsNullOrEmpty($TrusteeSID)) {
                    Write-Log "[Get-OUPermissions] Skipping ACE with empty SID on OU: $DistinguishedName"
                    continue
                }

                # Use context-specific filtering for OUs
                # SELF and Creator Owner are NORMAL on OUs (self-modification) - skip completely
                # Broad groups (Authenticated Users, Pre-Win2000) have default "All Properties" read - skip only those
                $expectedCheck = Test-IsExpectedACLIdentity -SID $TrusteeSID -Context 'OU'
                if ($expectedCheck.Skip) {
                    # Complete skip - these are expected entries (SELF, Creator Owner)
                    continue
                }
                # Track if this identity should only have "All Properties" findings filtered
                $skipAllPropertiesOnly = $expectedCheck.SkipAllPropertiesOnly

                # Determine severity using central function with recursive group membership check
                # Create an object with SID and name so Test-IsPrivileged can check Exchange groups by name
                # Extract just the name part (remove DOMAIN\ prefix if present)
                $nameOnly = $TrusteeName
                if ($TrusteeName -match '^[^\\]+\\(.+)$') {
                    $nameOnly = $Matches[1]
                }
                $identityObject = [PSCustomObject]@{
                    objectSid = $TrusteeSID
                    sAMAccountName = $nameOnly
                }
                $IsPrivileged = (Test-IsPrivileged -Identity $identityObject).IsPrivileged

                # Track inheritance source
                # Windows ACLs don't provide direct "inherited from" info, but we can determine the source
                # by examining the ACL inheritance chain. For OUs, inherited permissions typically come from:
                # 1. Direct parent OU/container
                # 2. Domain root (most common for domain-wide delegations)
                $InheritedFrom = $null
                # Where the ACE is set: this object for an explicit one, the source found
                # above for an inherited one, $null where none was found.
                $aceSourceDN = $DistinguishedName
                if ($ACE.IsInherited) {
                    # Determine the inheritance source by checking the propagation
                    # Inherited ACEs on OUs typically come from the domain root or parent OUs
                    # We'll trace back to find the source
                    $inheritanceSource = Get-ACEInheritanceSource -DistinguishedName $DistinguishedName -ACE $ACE
                    $InheritedFrom = $inheritanceSource.Display
                    $aceSourceDN = $inheritanceSource.DN
                }

                # Get ObjectType and InheritedObjectType for scope checking
                # ObjectType = which property/right is affected
                # InheritedObjectType = which object CLASS the ACE applies to (User, Computer, etc.)
                $objectType = $ACE.ObjectType
                $inheritedObjectType = $ACE.InheritedObjectType

                # Pre-calculate common right checks (performance optimization - used by multiple checks)
                # Test-ADRightsMask (adPEAS-GUIDs.ps1) expands generic access bits (GA/GR/GW/GX)
                # before testing - a raw "-band" against $ACE.ActiveDirectoryRights would miss a
                # right granted only via a generic bit, GenericAll included (see its own header).
                $HasWriteProperty = Test-ADRightsMask -Rights $ACE.ActiveDirectoryRights -Has ([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty)
                # Hoisted: the blanket-Self block below runs before the branches that
                # used to compute this for themselves. They still do, harmlessly - the
                # call is idempotent and leaving it there keeps each branch readable.
                $HasSelf = Test-ADRightsMask -Rights $ACE.ActiveDirectoryRights -Has ([System.DirectoryServices.ActiveDirectoryRights]::Self)
                $IsAllProperties = ($objectType -eq [GUID]::Empty) -or (-not $objectType)

                # InheritedObjectType checks - determines which object class this ACE applies to
                # Empty/null = applies to ALL object types
                # Specific GUID = applies only to that object class
                $IsAllObjectTypes = (-not $inheritedObjectType -or $inheritedObjectType -eq [GUID]::Empty)
                $AppliesToUsers = $IsAllObjectTypes -or ($inheritedObjectType -eq $SchemaClassGUIDs['user'])
                $AppliesToComputers = $IsAllObjectTypes -or ($inheritedObjectType -eq $SchemaClassGUIDs['computer'])
                $AppliesToGroups = $IsAllObjectTypes -or ($inheritedObjectType -eq $SchemaClassGUIDs['group'])

                # Inheritance scope. InheritedObjectType above says which object CLASS an
                # ACE reaches; these two say whether it reaches this object, its children,
                # or both. Neither was read, so an ACE that grants nothing here was
                # reported here: a WriteProperty on 'member' with no inheritance flags
                # applies to this OU's own 'member' attribute, and an organizationalUnit
                # has none - AD rejects the write and adPEAS called it a group takeover.
                #
                # The field is InheritanceFlags, not InheritanceType: an
                # ActiveDirectoryAccessRule has no InheritanceType, so a gate reading it
                # would be $null -ne "None" and therefore always true - a gate that looks
                # like one and is not. ContainerInherit -bor ObjectInherit is the same
                # test Get-ACEInheritanceSource already makes on the parent ACE above.
                #
                # Suppressing here loses nothing: Get-DangerousOUPermissions enumerates
                # every organizationalUnit plus the principal containers, and Windows
                # clears InheritOnly on the copy it propagates, so a descendants-only ACE
                # is reported at the descendant it actually applies to.
                $AppliesToSelf = -not (([string]$ACE.PropagationFlags) -match 'InheritOnly')
                $AppliesToChildren = ($ACE.InheritanceFlags -band [System.Security.AccessControl.InheritanceFlags]::ContainerInherit) -or
                                     ($ACE.InheritanceFlags -band [System.Security.AccessControl.InheritanceFlags]::ObjectInherit)

                # A right that is a takeover of the container and of its children alike is
                # not suppressed, only located: GenericAll with InheritOnly is full control
                # of every descendant and none of this OU, and used to read as the latter.
                #
                # NoPropagateInherit stops the inheritance one level down: the copy a
                # direct child receives has its inheritance flags cleared. Such an ACE
                # reaches this container's direct children and nothing below them, and it
                # read like a delegation on the whole subtree. Rights on child objects
                # reach children by definition, so for them only that limit is news.
                # Without ContainerInherit or ObjectInherit the flag means nothing, and
                # GetAccessRules reports it as None there even where the raw descriptor
                # carries it (measured) - so the flag alone is the test.
                $isNoPropagate = ([string]$ACE.PropagationFlags) -match 'NoPropagateInherit'
                $inheritanceNote = ''
                if ($isNoPropagate -and $AppliesToSelf) { $inheritanceNote = ' (this object and its direct children only)' }
                elseif ($isNoPropagate) { $inheritanceNote = ' (direct children only)' }
                elseif (-not $AppliesToSelf) { $inheritanceNote = ' (descendants only)' }
                $childReachNote = if ($isNoPropagate) { ' (direct children only)' } else { '' }

                # Every finding from here to the end of this loop body comes from this ACE;
                # the end of the body tags them with the element they are about.
                $aceFindingStart = @($Findings).Count

                # If WriteProperty on ALL properties, create ONE generic finding instead of 6+ individual ones
                # This prevents duplicate findings like: userAccountControl, member, SPN, scriptPath, Delegation x2, gPLink
                if ($HasWriteProperty -and $IsAllProperties -and ($CheckType -contains 'AccountControl' -or
                    $CheckType -contains 'GroupMembership' -or $CheckType -contains 'SPNModification' -or
                    $CheckType -contains 'ScriptPath' -or $CheckType -contains 'Delegation' -or
                    $CheckType -contains 'GPOLinking' -or $CheckType -contains 'KeyCredentialLink')) {

                    # Skip broad groups with expected "All Properties" access
                    if (-not $skipAllPropertiesOnly) {
                        # Determine scope based on InheritedObjectType
                        $scopeInfo = if ($IsAllObjectTypes) {
                            ""
                        } else {
                            $targetClass = Get-SchemaClassName -GUID $inheritedObjectType
                            if ($targetClass) { " on $targetClass objects" } else { "" }
                        }

                        $Severity = if ($IsPrivileged) { "Info" } else { "Critical" }
                        $Findings += [PSCustomObject]@{
                            CheckType     = "WritePropertyAll"
                            Right         = "WriteProperty (All Properties)$scopeInfo$inheritanceNote"
                            Principal     = $TrusteeName
                            SID           = $TrusteeSID
                            Severity      = $Severity
                            InheritedFrom = $InheritedFrom
                        }
                    }
                }

                # A Self ACE with no ObjectType grants EVERY validated write at once -
                # Self-Membership, Validated-SPN, Validated-DNS-Host-Name - and fell
                # through every gate. The three Self branches further down each require
                # -not $IsAllProperties because they identify their right by its GUID, and
                # the blanket-WriteProperty block above requires $HasWriteProperty, which a
                # mask of 0x8 does not satisfy. So the broadest form of the right produced
                # nothing while each narrow form produced a finding.
                #
                # The common superset is already covered: GenericWrite is 0x00020028 and
                # carries the Self bit, and its branch requires $IsAllProperties. What was
                # missing is Self on its own, which is what "all validated writes" in the
                # delegation wizard writes.
                #
                # One finding rather than three, for the reason the blanket WriteProperty
                # gives: emitting one per validated write would report the same delegation
                # three times. Severity follows the worst of them - joining a privileged
                # group through Self-Membership.
                if ($HasSelf -and $IsAllProperties -and $AppliesToChildren -and
                    ($CheckType -contains 'GroupMembership' -or $CheckType -contains 'SPNModification' -or
                     $CheckType -contains 'DNSHostName')) {

                    $scopeInfo = if ($IsAllObjectTypes) {
                        ""
                    } else {
                        $targetClass = Get-SchemaClassName -GUID $inheritedObjectType
                        if ($targetClass) { " on $targetClass objects" } else { "" }
                    }

                    $Severity = if ($IsPrivileged) { "Info" } else { "High" }
                    $Findings += [PSCustomObject]@{
                        CheckType     = "SelfAll"
                        Right         = "Self (All Validated Writes)$scopeInfo$inheritanceNote"
                        Principal     = $TrusteeName
                        SID           = $TrusteeSID
                        Severity      = $Severity
                        InheritedFrom = $InheritedFrom
                    }
                }

                # Check 1: GenericAll (Full Control)
                if ($CheckType -contains 'GenericAll') {
                    # GenericAll only applies to the whole object if ObjectType is empty. The
                    # generic-bit expansion and the exact-match test both live in Test-ADRightsMask.
                    $HasFullGenericAll = (Test-ADRightsMask -Rights $ACE.ActiveDirectoryRights -Has ([System.DirectoryServices.ActiveDirectoryRights]::GenericAll)) -and $IsAllProperties
                    if ($HasFullGenericAll) {
                        # Determine scope based on InheritedObjectType
                        $scopeInfo = if ($IsAllObjectTypes) {
                            ""  # No suffix for all objects
                        } else {
                            $targetClass = Get-SchemaClassName -GUID $inheritedObjectType
                            if ($targetClass) { " on $targetClass objects" } else { "" }
                        }

                        $Severity = if ($IsPrivileged) { "Info" } else { "Critical" }
                        $Findings += [PSCustomObject]@{
                            CheckType     = "GenericAll"
                            Right         = "GenericAll (Full Control)$scopeInfo$inheritanceNote"
                            Principal     = $TrusteeName
                            SID           = $TrusteeSID
                            Severity      = $Severity
                            InheritedFrom = $InheritedFrom
                        }
                    }
                }

                # Check 1b: GenericWrite (includes WriteProperty, WriteSelf, WritePropertyExtended)
                # GenericWrite = 0x00020028 - dangerous because it includes WriteProperty on all attributes
                if ($CheckType -contains 'GenericWrite') {
                    $HasGenericWrite = (Test-ADRightsMask -Rights $ACE.ActiveDirectoryRights -Has ([System.DirectoryServices.ActiveDirectoryRights]::GenericWrite)) -and $IsAllProperties
                    if ($HasGenericWrite) {
                        $scopeInfo = if ($IsAllObjectTypes) {
                            ""
                        } else {
                            $targetClass = Get-SchemaClassName -GUID $inheritedObjectType
                            if ($targetClass) { " on $targetClass objects" } else { "" }
                        }

                        $Severity = if ($IsPrivileged) { "Info" } else { "High" }
                        $Findings += [PSCustomObject]@{
                            CheckType     = "GenericWrite"
                            Right         = "GenericWrite$scopeInfo$inheritanceNote"
                            Principal     = $TrusteeName
                            SID           = $TrusteeSID
                            Severity      = $Severity
                            InheritedFrom = $InheritedFrom
                        }
                    }
                }

                # Check 1c: WriteDacl (can modify ACL = effectively full control)
                #
                # Only from an ACE that names no ObjectType, as for GenericAll above: an
                # object ACE applies to the node of the object type list its GUID names
                # (MS-DTYP 2.5.3.2), so the WriteDacl and WriteOwner bits of GenericAll scoped
                # to a class grant nothing on the object. Exchange setup writes exactly that -
                # GenericAll on the msExchDynamicDistributionList class for Exchange Trusted
                # Subsystem, inherited by every OU - and it was reported as WriteDacl and
                # WriteOwner on all of them.
                if ($CheckType -contains 'WriteDacl') {
                    $HasWriteDacl = (Test-ADRightsMask -Rights $ACE.ActiveDirectoryRights -Has ([System.DirectoryServices.ActiveDirectoryRights]::WriteDacl)) -and $IsAllProperties

                    if ($HasWriteDacl) {
                        $scopeInfo = if ($IsAllObjectTypes) {
                            ""
                        } else {
                            $targetClass = Get-SchemaClassName -GUID $inheritedObjectType
                            if ($targetClass) { " on $targetClass objects" } else { "" }
                        }

                        $Severity = if ($IsPrivileged) { "Info" } else { "Critical" }
                        $Findings += [PSCustomObject]@{
                            CheckType     = "WriteDacl"
                            Right         = "WriteDacl (Modify Permissions)$scopeInfo$inheritanceNote"
                            Principal     = $TrusteeName
                            SID           = $TrusteeSID
                            Severity      = $Severity
                            InheritedFrom = $InheritedFrom
                        }
                    }
                }

                # Check 1d: WriteOwner (can take ownership = effectively full control)
                if ($CheckType -contains 'WriteOwner') {
                    $HasWriteOwner = (Test-ADRightsMask -Rights $ACE.ActiveDirectoryRights -Has ([System.DirectoryServices.ActiveDirectoryRights]::WriteOwner)) -and $IsAllProperties

                    if ($HasWriteOwner) {
                        $scopeInfo = if ($IsAllObjectTypes) {
                            ""
                        } else {
                            $targetClass = Get-SchemaClassName -GUID $inheritedObjectType
                            if ($targetClass) { " on $targetClass objects" } else { "" }
                        }

                        $Severity = if ($IsPrivileged) { "Info" } else { "Critical" }
                        $Findings += [PSCustomObject]@{
                            CheckType     = "WriteOwner"
                            Right         = "WriteOwner (Take Ownership)$scopeInfo$inheritanceNote"
                            Principal     = $TrusteeName
                            SID           = $TrusteeSID
                            Severity      = $Severity
                            InheritedFrom = $InheritedFrom
                        }
                    }
                }

                # Check 2: Password Reset Rights
                # Note: Password reset only applies to User objects, so we check InheritedObjectType
                if ($CheckType -contains 'PasswordReset') {
                    $HasExtendedRight = Test-ADRightsMask -Rights $ACE.ActiveDirectoryRights -Has ([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight)

                    if ($HasExtendedRight -and $AppliesToUsers -and $AppliesToChildren) {
                        # Check for Reset Password extended right (using central GUID lookup)
                        $passwordResetGUID = Get-ExtendedRightGUID -Name 'User-Force-Change-Password'
                        if ($ACE.ObjectType -eq $passwordResetGUID -or $ACE.ObjectType -eq [GUID]::Empty) {
                            $Severity = if ($IsPrivileged) { "Info" } else { "Critical" }
                            $Findings += [PSCustomObject]@{
                                CheckType     = "PasswordReset"
                                Right         = "Reset Password (Extended Right)$childReachNote"
                                Principal     = $TrusteeName
                                SID           = $TrusteeSID
                                Severity      = $Severity
                                InheritedFrom = $InheritedFrom
                            }
                        }
                    }
                }

                # Check 3: Account Control (userAccountControl or User-Account-Restrictions Property Set)
                # Note: GUID::Empty is handled by generic "WriteProperty (All Properties)" above
                # userAccountControl exists on User AND Computer objects
                # User-Account-Restrictions Property Set (4c164200-...) includes UAC and is commonly delegated
                if ($CheckType -contains 'AccountControl') {
                    if ($HasWriteProperty -and -not $IsAllProperties -and ($AppliesToUsers -or $AppliesToComputers) -and $AppliesToChildren) {
                        # Check direct userAccountControl attribute
                        if ($ACE.ObjectType -eq $PropertyGUIDs['userAccountControl']) {
                            $Severity = if ($IsPrivileged) { "Info" } else { "Critical" }
                            $Findings += [PSCustomObject]@{
                                CheckType     = "AccountControl"
                                Right         = "WriteProperty (userAccountControl)$childReachNote"
                                Principal     = $TrusteeName
                                SID           = $TrusteeSID
                                Severity      = $Severity
                                InheritedFrom = $InheritedFrom
                            }
                        }
                        # Check User-Account-Restrictions Property Set (includes UAC, pwdLastSet, accountExpires, etc.)
                        elseif ($ACE.ObjectType -eq $Script:PropertySetGUIDs['User-Account-Restrictions']) {
                            $Severity = if ($IsPrivileged) { "Info" } else { "Critical" }
                            $Findings += [PSCustomObject]@{
                                CheckType     = "AccountControl"
                                Right         = "WriteProperty (User-Account-Restrictions)$childReachNote"
                                Principal     = $TrusteeName
                                SID           = $TrusteeSID
                                Severity      = $Severity
                                InheritedFrom = $InheritedFrom
                            }
                        }
                    }
                }

                # Check 4: Group Membership (member attribute)
                # Note: GUID::Empty is handled by generic "WriteProperty (All Properties)" above
                # member attribute exists only on Group objects
                if ($CheckType -contains 'GroupMembership') {
                    if ($HasWriteProperty -and -not $IsAllProperties -and $AppliesToGroups -and $AppliesToChildren) {
                        if ($ACE.ObjectType -eq $PropertyGUIDs['member']) {
                            $Severity = if ($IsPrivileged) { "Info" } else { "High" }
                            $Findings += [PSCustomObject]@{
                                CheckType     = "GroupMembership"
                                Right         = "WriteProperty (member)$childReachNote"
                                Principal     = $TrusteeName
                                SID           = $TrusteeSID
                                Severity      = $Severity
                                InheritedFrom = $InheritedFrom
                            }
                        }
                    }

                    # Check the Self right carrying the Self-Membership validated write.
                    # AD reuses the schemaIDGUID of 'member' as the rightsGUID of that
                    # validated write, so the GUID alone does not say which of the two an
                    # ACE grants - the ACE type does. Self lets the trustee add itself to
                    # the group and nobody else: a narrower right than WriteProperty on
                    # 'member', the same escalation if the group is privileged.
                    $HasSelf = Test-ADRightsMask -Rights $ACE.ActiveDirectoryRights -Has ([System.DirectoryServices.ActiveDirectoryRights]::Self)
                    if ($HasSelf -and -not $IsAllProperties -and $AppliesToGroups -and $AppliesToChildren) {
                        if ($ACE.ObjectType -eq $PropertyGUIDs['member']) {
                            $Severity = if ($IsPrivileged) { "Info" } else { "High" }
                            $Findings += [PSCustomObject]@{
                                CheckType     = "GroupMembership"
                                Right         = "Self (Self-Membership)$childReachNote"
                                Principal     = $TrusteeName
                                SID           = $TrusteeSID
                                Severity      = $Severity
                                InheritedFrom = $InheritedFrom
                            }
                        }
                    }
                }

                # Check 5: SPN Modification (servicePrincipalName or Validated-SPN)
                # Note: GUID::Empty is handled by generic "WriteProperty (All Properties)" above
                # servicePrincipalName exists on User AND Computer objects
                # Validated-SPN (f3a64788-...) is commonly used for SPN delegation via Self right
                if ($CheckType -contains 'SPNModification') {
                    # Check WriteProperty on servicePrincipalName attribute
                    if ($HasWriteProperty -and -not $IsAllProperties -and ($AppliesToUsers -or $AppliesToComputers) -and $AppliesToChildren) {
                        if ($ACE.ObjectType -eq $PropertyGUIDs['servicePrincipalName']) {
                            $Severity = if ($IsPrivileged) { "Info" } else { "High" }
                            $Findings += [PSCustomObject]@{
                                CheckType     = "SPNModification"
                                Right         = "WriteProperty (servicePrincipalName)$childReachNote"
                                Principal     = $TrusteeName
                                SID           = $TrusteeSID
                                Severity      = $Severity
                                InheritedFrom = $InheritedFrom
                            }
                        }
                        # Also check for WriteProperty on Validated-SPN GUID
                        # Note: This is unusual - WriteProperty on a Validated Write GUID effectively
                        # grants direct SPN modification without validation. Report as servicePrincipalName.
                        elseif ($ACE.ObjectType -eq $Script:ValidatedWriteGUIDs['Validated-SPN']) {
                            $Severity = if ($IsPrivileged) { "Info" } else { "High" }
                            $Findings += [PSCustomObject]@{
                                CheckType     = "SPNModification"
                                Right         = "WriteProperty (servicePrincipalName)$childReachNote"
                                Principal     = $TrusteeName
                                SID           = $TrusteeSID
                                Severity      = $Severity
                                InheritedFrom = $InheritedFrom
                            }
                        }
                    }
                    # Check Self right with Validated-SPN (validated write)
                    $HasSelf = Test-ADRightsMask -Rights $ACE.ActiveDirectoryRights -Has ([System.DirectoryServices.ActiveDirectoryRights]::Self)
                    if ($HasSelf -and -not $IsAllProperties -and ($AppliesToUsers -or $AppliesToComputers) -and $AppliesToChildren) {
                        if ($ACE.ObjectType -eq $Script:ValidatedWriteGUIDs['Validated-SPN']) {
                            $Severity = if ($IsPrivileged) { "Info" } else { "High" }
                            $Findings += [PSCustomObject]@{
                                CheckType     = "SPNModification"
                                Right         = "Self (Validated-SPN)$childReachNote"
                                Principal     = $TrusteeName
                                SID           = $TrusteeSID
                                Severity      = $Severity
                                InheritedFrom = $InheritedFrom
                            }
                        }
                    }
                }

                # Check 5b: DNS Host Name Modification (dNSHostName or DNS-Host-Name-Attributes Property Set)
                # Note: GUID::Empty is handled by generic "WriteProperty (All Properties)" above
                # dNSHostName exists on Computer objects - modification can enable machine account attacks
                # DNS-Host-Name-Attributes Property Set includes dNSHostName
                # Validated-DNS-Host-Name is commonly used for delegation via Self right
                if ($CheckType -contains 'DNSHostName') {
                    # Check WriteProperty on dNSHostName attribute
                    if ($HasWriteProperty -and -not $IsAllProperties -and $AppliesToComputers -and $AppliesToChildren) {
                        if ($ACE.ObjectType -eq $PropertyGUIDs['dNSHostName']) {
                            $Severity = if ($IsPrivileged) { "Info" } else { "High" }
                            $Findings += [PSCustomObject]@{
                                CheckType     = "DNSHostName"
                                Right         = "WriteProperty (dNSHostName)$childReachNote"
                                Principal     = $TrusteeName
                                SID           = $TrusteeSID
                                Severity      = $Severity
                                InheritedFrom = $InheritedFrom
                            }
                        }
                        # Check for DNS-Host-Name-Attributes Property Set
                        elseif ($ACE.ObjectType -eq $Script:PropertySetGUIDs['DNS-Host-Name-Attributes']) {
                            $Severity = if ($IsPrivileged) { "Info" } else { "High" }
                            $Findings += [PSCustomObject]@{
                                CheckType     = "DNSHostName"
                                Right         = "WriteProperty (DNS-Host-Name-Attributes)$childReachNote"
                                Principal     = $TrusteeName
                                SID           = $TrusteeSID
                                Severity      = $Severity
                                InheritedFrom = $InheritedFrom
                            }
                        }
                        # Check for WriteProperty on Validated-DNS-Host-Name GUID
                        # Note: This is unusual - WriteProperty on a Validated Write GUID effectively
                        # grants direct dNSHostName modification without validation. Report as dNSHostName.
                        elseif ($ACE.ObjectType -eq $Script:ValidatedWriteGUIDs['Validated-DNS-Host-Name']) {
                            $Severity = if ($IsPrivileged) { "Info" } else { "High" }
                            $Findings += [PSCustomObject]@{
                                CheckType     = "DNSHostName"
                                Right         = "WriteProperty (dNSHostName)$childReachNote"
                                Principal     = $TrusteeName
                                SID           = $TrusteeSID
                                Severity      = $Severity
                                InheritedFrom = $InheritedFrom
                            }
                        }
                    }
                    # Check Self right with Validated-DNS-Host-Name (validated write)
                    $HasSelf = Test-ADRightsMask -Rights $ACE.ActiveDirectoryRights -Has ([System.DirectoryServices.ActiveDirectoryRights]::Self)
                    if ($HasSelf -and -not $IsAllProperties -and $AppliesToComputers -and $AppliesToChildren) {
                        if ($ACE.ObjectType -eq $Script:ValidatedWriteGUIDs['Validated-DNS-Host-Name']) {
                            $Severity = if ($IsPrivileged) { "Info" } else { "High" }
                            $Findings += [PSCustomObject]@{
                                CheckType     = "DNSHostName"
                                Right         = "Self (Validated-DNS-Host-Name)$childReachNote"
                                Principal     = $TrusteeName
                                SID           = $TrusteeSID
                                Severity      = $Severity
                                InheritedFrom = $InheritedFrom
                            }
                        }
                    }
                }

                # Check 5c: Shadow Credentials (msDS-KeyCredentialLink)
                # Note: GUID::Empty is handled by generic "WriteProperty (All Properties)" above
                # A key the trustee writes into the attribute lets it authenticate as the user
                # or computer with PKINIT, without the password and across every password
                # reset. No check asked who may write it: the SHADOW_CREDENTIALS card said the
                # ACL checks report it, and this is where they now do. Key Admins and Enterprise
                # Key Admins hold the right on the domain by design and are privileged, so they
                # come out as Info like every other privileged holder.
                if ($CheckType -contains 'KeyCredentialLink') {
                    if ($HasWriteProperty -and -not $IsAllProperties -and ($AppliesToUsers -or $AppliesToComputers) -and $AppliesToChildren) {
                        if ($ACE.ObjectType -eq $PropertyGUIDs['msDS-KeyCredentialLink']) {
                            $Severity = if ($IsPrivileged) { "Info" } else { "High" }
                            $Findings += [PSCustomObject]@{
                                CheckType     = "KeyCredentialLink"
                                Right         = "WriteProperty (msDS-KeyCredentialLink)$childReachNote"
                                Principal     = $TrusteeName
                                SID           = $TrusteeSID
                                Severity      = $Severity
                                InheritedFrom = $InheritedFrom
                            }
                        }
                    }
                }

                # Check 6: Script Path (scriptPath)
                # Note: GUID::Empty is handled by generic "WriteProperty (All Properties)" above
                # scriptPath exists only on User objects
                if ($CheckType -contains 'ScriptPath') {
                    if ($HasWriteProperty -and -not $IsAllProperties -and $AppliesToUsers -and $AppliesToChildren) {
                        if ($ACE.ObjectType -eq $PropertyGUIDs['scriptPath']) {
                            $Severity = if ($IsPrivileged) { "Info" } else { "High" }
                            $Findings += [PSCustomObject]@{
                                CheckType     = "ScriptPath"
                                Right         = "WriteProperty (scriptPath)$childReachNote"
                                Principal     = $TrusteeName
                                SID           = $TrusteeSID
                                Severity      = $Severity
                                InheritedFrom = $InheritedFrom
                            }
                        }
                    }
                }

                # Check 7: Delegation Rights
                # Note: GUID::Empty is handled by generic "WriteProperty (All Properties)" above
                # Delegation attributes exist on User AND Computer objects
                if ($CheckType -contains 'Delegation') {
                    if ($HasWriteProperty -and -not $IsAllProperties -and ($AppliesToUsers -or $AppliesToComputers) -and $AppliesToChildren) {
                        # msDS-AllowedToDelegateTo (Constrained Delegation)
                        if ($ACE.ObjectType -eq $PropertyGUIDs['msDS-AllowedToDelegateTo']) {
                            $Severity = if ($IsPrivileged) { "Info" } else { "High" }
                            $Findings += [PSCustomObject]@{
                                CheckType     = "Delegation"
                                Right         = "WriteProperty (msDS-AllowedToDelegateTo)$childReachNote"
                                Principal     = $TrusteeName
                                SID           = $TrusteeSID
                                Severity      = $Severity
                                InheritedFrom = $InheritedFrom
                            }
                        }

                        # msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD)
                        if ($ACE.ObjectType -eq $PropertyGUIDs['msDS-AllowedToActOnBehalfOfOtherIdentity']) {
                            $Severity = if ($IsPrivileged) { "Info" } else { "High" }
                            $Findings += [PSCustomObject]@{
                                CheckType     = "Delegation"
                                Right         = "WriteProperty (msDS-AllowedToActOnBehalfOfOtherIdentity)$childReachNote"
                                Principal     = $TrusteeName
                                SID           = $TrusteeSID
                                Severity      = $Severity
                                InheritedFrom = $InheritedFrom
                            }
                        }
                    }
                }

                # Check 8: LAPS Password Access
                # Note: LAPS attributes are only on Computer objects, so we check InheritedObjectType
                if ($CheckType -contains 'LAPS') {

                    # GenericAll is a composite mask (0xf01ff) that already contains the
                    # ReadProperty and ExtendedRight bits, so a bare overlap test against it
                    # matches almost any right. Testing for overlap made every harmless Allow
                    # ACE without an ObjectType - ReadControl, Delete, ListChildren - come back
                    # as an "All Properties includes LAPS" finding. Test-ADRightsMask requires
                    # every bit of GenericAll to be present, the same way check 2 tests it - and
                    # also expands a GA-granted-via-generic-bit ACE first, which a raw -band on
                    # $ACE.ActiveDirectoryRights would miss entirely (see its own header).
                    $HasReadProperty = Test-ADRightsMask -Rights $ACE.ActiveDirectoryRights -Has ([System.DirectoryServices.ActiveDirectoryRights]::ReadProperty)
                    $HasGenericAll = Test-ADRightsMask -Rights $ACE.ActiveDirectoryRights -Has ([System.DirectoryServices.ActiveDirectoryRights]::GenericAll)
                    $HasExtendedRight = Test-ADRightsMask -Rights $ACE.ActiveDirectoryRights -Has ([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight)

                    if (($HasReadProperty -or $HasGenericAll -or $HasExtendedRight) -and $AppliesToComputers -and $AppliesToChildren) {
                        # LAPS permissions on OUs can be configured in several ways:
                        # 1. Specific property read: ObjectType = LAPS-Property-GUID (most common for delegated LAPS read)
                        # 2. All properties read: ObjectType = Empty GUID (GenericAll or full ReadProperty)
                        # 3. Extended Right for Control Access (Windows LAPS specific)
                        #
                        # We need to check all scenarios to catch LAPS read permissions

                        # Use different variable name to avoid collision with $IsAllProperties
                        $lapsIsAllProperties = $IsAllProperties
                        $lapsPropertyFound = $false

                        # Whether this ACE carries CONTROL_ACCESS, which the caller needs to
                        # judge an all-properties read. The LAPS password attributes are
                        # confidential in the schema, and MS-ADTS requires READ_PROPERTY
                        # *and* CONTROL_ACCESS for such an attribute - which is why
                        # Set-AdmPwdReadPasswordPermission writes two ACEs. A bare "read all
                        # properties" delegation therefore does not reach the password,
                        # while this check reported every one of them as "LAPS Password
                        # Read" at finding severity: a helpdesk or monitoring delegation on
                        # a computer OU came out as "can read every local administrator
                        # password in this OU". GenericAll contains CONTROL_ACCESS, so it
                        # defeats the flag on its own. Carried per ACE, the same way the
                        # Credential Roaming block below does it.
                        $lapsGrantsControlAccess = ($HasGenericAll -or $HasExtendedRight)

                        # Legacy LAPS (ms-Mcs-AdmPwd). GUID from $Script:PropertyGUIDs.
                        $legacyLAPSMatch = ($ACE.ObjectType -and $ACE.ObjectType.Guid -eq $PropertyGUIDs['ms-Mcs-AdmPwd'].Guid)
                        if ($legacyLAPSMatch) {
                            $Severity = if ($IsPrivileged) { "Info" } else { "Medium" }
                            $Findings += [PSCustomObject]@{
                                CheckType     = "LAPS"
                                Right         = "ReadProperty (ms-Mcs-AdmPwd - Legacy LAPS)$childReachNote"
                                Principal     = $TrusteeName
                                SID           = $TrusteeSID
                                Severity      = $Severity
                                InheritedFrom = $InheritedFrom
                                GrantsControlAccess = $lapsGrantsControlAccess
                            }
                            $lapsPropertyFound = $true
                        }

                        # Windows LAPS - Encrypted Password (most common). The GUID comes from
                        # $Script:PropertyGUIDs and is deliberately not repeated here.
                        $encPwdMatch = ($ACE.ObjectType -and $ACE.ObjectType.Guid -eq $PropertyGUIDs['msLAPS-EncryptedPassword'].Guid)
                        if ($encPwdMatch) {
                            $Severity = if ($IsPrivileged) { "Info" } else { "Medium" }
                            $Findings += [PSCustomObject]@{
                                CheckType     = "LAPS"
                                Right         = "ReadProperty (msLAPS-EncryptedPassword - Windows LAPS)$childReachNote"
                                Principal     = $TrusteeName
                                SID           = $TrusteeSID
                                Severity      = $Severity
                                InheritedFrom = $InheritedFrom
                                GrantsControlAccess = $lapsGrantsControlAccess
                            }
                            $lapsPropertyFound = $true
                        }

                        # Windows LAPS - Encrypted Password History. GUID from
                        # $Script:PropertyGUIDs, as above.
                        $encHistMatch = ($ACE.ObjectType -and $ACE.ObjectType.Guid -eq $PropertyGUIDs['msLAPS-EncryptedPasswordHistory'].Guid)
                        if ($encHistMatch) {
                            $Severity = if ($IsPrivileged) { "Info" } else { "Medium" }
                            $Findings += [PSCustomObject]@{
                                CheckType     = "LAPS"
                                Right         = "ReadProperty (msLAPS-EncryptedPasswordHistory - Windows LAPS)$childReachNote"
                                Principal     = $TrusteeName
                                SID           = $TrusteeSID
                                Severity      = $Severity
                                InheritedFrom = $InheritedFrom
                                GrantsControlAccess = $lapsGrantsControlAccess
                            }
                            $lapsPropertyFound = $true
                        }

                        # Windows LAPS - Plain Password (unencrypted mode)
                        # GUID: 35eb61e8-0ae2-4e1a-b60f-f6aa82d54867
                        $plainPwdMatch = ($ACE.ObjectType -and $ACE.ObjectType.Guid -eq $PropertyGUIDs['msLAPS-Password'].Guid)
                        if ($plainPwdMatch) {
                            $Severity = if ($IsPrivileged) { "Info" } else { "Medium" }
                            $Findings += [PSCustomObject]@{
                                CheckType     = "LAPS"
                                Right         = "ReadProperty (msLAPS-Password - Windows LAPS)$childReachNote"
                                Principal     = $TrusteeName
                                SID           = $TrusteeSID
                                Severity      = $Severity
                                InheritedFrom = $InheritedFrom
                                GrantsControlAccess = $lapsGrantsControlAccess
                            }
                            $lapsPropertyFound = $true
                        }

                        # Windows LAPS - Current Password Version (less critical but indicates LAPS access)
                        # GUID: 5d848c52-82d7-4014-867b-714b3e4b6685
                        $versionMatch = ($ACE.ObjectType -and $ACE.ObjectType.Guid -eq $PropertyGUIDs['msLAPS-CurrentPasswordVersion'].Guid)
                        if ($versionMatch) {
                            $Severity = if ($IsPrivileged) { "Info" } else { "Low" }
                            $Findings += [PSCustomObject]@{
                                CheckType     = "LAPS"
                                Right         = "ReadProperty (msLAPS-CurrentPasswordVersion - Windows LAPS)$childReachNote"
                                Principal     = $TrusteeName
                                SID           = $TrusteeSID
                                Severity      = $Severity
                                InheritedFrom = $InheritedFrom
                                GrantsControlAccess = $lapsGrantsControlAccess
                            }
                            $lapsPropertyFound = $true
                        }

                        # Windows LAPS - Password Expiration Time (less critical but indicates LAPS access)
                        # GUID: ec38fa45-104d-4ede-b3b1-4620e8594575
                        $expTimeMatch = ($ACE.ObjectType -and $ACE.ObjectType.Guid -eq $PropertyGUIDs['msLAPS-PasswordExpirationTime'].Guid)
                        if ($expTimeMatch) {
                            $Severity = if ($IsPrivileged) { "Info" } else { "Low" }
                            $Findings += [PSCustomObject]@{
                                CheckType     = "LAPS"
                                Right         = "ReadProperty (msLAPS-PasswordExpirationTime - Windows LAPS)$childReachNote"
                                Principal     = $TrusteeName
                                SID           = $TrusteeSID
                                Severity      = $Severity
                                InheritedFrom = $InheritedFrom
                                GrantsControlAccess = $lapsGrantsControlAccess
                            }
                            $lapsPropertyFound = $true
                        }

                        # All Properties (GenericAll or ReadProperty with Empty GUID) - covers all LAPS types
                        # Only add if:
                        # 1. Not already caught by specific LAPS property checks above
                        # 2. NOT a broad group/legacy compat group (they have default "All Properties" read)
                        #    These groups should only be flagged if they have SPECIFIC LAPS property rights
                        if ($lapsIsAllProperties -and -not $lapsPropertyFound -and -not $skipAllPropertiesOnly) {
                            $Severity = if ($IsPrivileged) { "Info" } else { "Medium" }

                            # Name what the ACE carries instead of asserting that it
                            # includes LAPS. Whether it does depends on the confidential
                            # flag, and that is the caller's question - the text used to
                            # answer it here with "includes LAPS".
                            $lapsAllPropsRight = 'ReadProperty (All Properties)'
                            if ($HasGenericAll) {
                                $lapsAllPropsRight = 'GenericAll (All Properties)'
                            } elseif ($lapsGrantsControlAccess) {
                                $lapsAllPropsRight = 'ReadProperty + ControlAccess (All Properties)'
                            }

                            $Findings += [PSCustomObject]@{
                                CheckType     = "LAPS"
                                Right         = $lapsAllPropsRight
                                Principal     = $TrusteeName
                                SID           = $TrusteeSID
                                Severity      = $Severity
                                InheritedFrom = $InheritedFrom
                                GrantsControlAccess = $lapsGrantsControlAccess
                            }
                        }
                    }
                }

                # Check 8b: Credential Roaming read rights on user objects
                #
                # Credential Roaming stores a user's private keys and DPAPI master keys in
                # attributes on their user object. A delegated read of those is the one way a
                # principal gets at another user's private key without touching a password,
                # and it is the kind of right a delegation wizard hands out by accident.
                #
                # Two booleans travel with each finding instead of one verdict, because
                # whether the right actually grants read depends on the schema. Marked
                # confidential (searchFlags bit 7), an attribute needs READ_PROPERTY *and*
                # CONTROL_ACCESS; without the flag, READ_PROPERTY alone is enough. Only the
                # caller knows the flag, so the decision is left to it - and the two are
                # reported per ACE so that a principal holding them in two separate ACEs is
                # still judged correctly once the caller ORs them per principal.
                if ($CheckType -contains 'CredentialRoaming') {

                    # Test-ADRightsMask rather than -band, for the reason given in the LAPS
                    # block: GenericAll is a composite mask that overlaps nearly everything,
                    # and a right granted only through a generic bit is invisible to a raw
                    # overlap test.
                    $crHasRead          = Test-ADRightsMask -Rights $ACE.ActiveDirectoryRights -Has ([System.DirectoryServices.ActiveDirectoryRights]::ReadProperty)
                    $crHasGenericAll    = Test-ADRightsMask -Rights $ACE.ActiveDirectoryRights -Has ([System.DirectoryServices.ActiveDirectoryRights]::GenericAll)
                    $crHasControlAccess = Test-ADRightsMask -Rights $ACE.ActiveDirectoryRights -Has ([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight)

                    # CONTROL_ACCESS belongs in the gate, not only in the verdict. An ACE
                    # that carries it alone, scoped to one of these attributes, is the other
                    # half of the confidential-attribute pair - and the READ_PROPERTY half
                    # usually needs no delegation at all, because the default ACL already
                    # gives every authenticated user a blanket read of all properties. So a
                    # CONTROL_ACCESS-only ACE is in practice a complete grant, and gating it
                    # out would have missed exactly the delegation Microsoft's own
                    # instructions for confidential attributes produce.
                    if (($crHasRead -or $crHasGenericAll -or $crHasControlAccess) -and $AppliesToUsers -and $AppliesToChildren) {

                        # GenericAll carries CONTROL_ACCESS, so it defeats the confidential
                        # flag on its own.
                        $crControlAccess = ($crHasGenericAll -or $crHasControlAccess)

                        # Attribute GUID -> what a read of it yields. The timestamp is only a
                        # date and is rated Low so that it drops out of a default report,
                        # while still showing up for anybody who asks for everything: on its
                        # own it says somebody ran a Credential Roaming delegation.
                        $crAttributes = @(
                            @{ Name = 'ms-PKI-DPAPIMasterKeys'
                               Note = 'DPAPI master keys'
                               Severity = 'High' }
                            @{ Name = 'ms-PKI-AccountCredentials'
                               Note = 'private keys and certificates'
                               Severity = 'High' }
                            @{ Name = 'ms-PKI-RoamingTimeStamp'
                               Note = 'roaming timestamp'
                               Severity = 'Low' }
                        )

                        # The label names what the ACE actually carries rather than assuming
                        # ReadProperty. A CONTROL_ACCESS-only ACE printed as "ReadProperty"
                        # would send a reader looking for a permission that is not there.
                        $crRightPrefix = if ($crHasGenericAll) {
                            'GenericAll'
                        } elseif (($crHasRead -or $crHasGenericAll) -and $crHasControlAccess) {
                            'ReadProperty + ControlAccess'
                        } elseif ($crHasRead) {
                            'ReadProperty'
                        } else {
                            'ControlAccess'
                        }

                        $crPropertyFound = $false
                        foreach ($crAttribute in $crAttributes) {
                            $crGuid = $PropertyGUIDs[$crAttribute.Name]
                            if ($ACE.ObjectType -and $crGuid -and $ACE.ObjectType.Guid -eq $crGuid.Guid) {
                                $Severity = if ($IsPrivileged) { "Info" } else { $crAttribute.Severity }
                                $Findings += [PSCustomObject]@{
                                    CheckType           = "CredentialRoaming"
                                    Right               = "$crRightPrefix ($($crAttribute.Name) - $($crAttribute.Note))$childReachNote"
                                    Principal           = $TrusteeName
                                    SID                 = $TrusteeSID
                                    Severity            = $Severity
                                    InheritedFrom       = $InheritedFrom
                                    GrantsControlAccess = $crControlAccess
                                }
                                $crPropertyFound = $true
                            }
                        }

                        # All Properties, same treatment as LAPS: reported only when no
                        # specific attribute matched, and never for the broad groups whose
                        # default ACE is a blanket read of everything. That blanket read is
                        # what the confidential flag exists to cut off, and reporting it here
                        # would duplicate the caller's own schema verdict for every OU.
                        #
                        # A read is required here even though the gate accepts CONTROL_ACCESS
                        # alone. An unscoped CONTROL_ACCESS ACE is "all extended rights",
                        # which says nothing about Credential Roaming in particular; it is
                        # Get-DangerousACLs' business, and claiming it under this CheckType
                        # would attribute a generic grant to this one attribute set.
                        if ($IsAllProperties -and ($crHasRead -or $crHasGenericAll) -and
                            -not $crPropertyFound -and -not $skipAllPropertiesOnly) {
                            $Severity = if ($IsPrivileged) { "Info" } else { "High" }
                            $Findings += [PSCustomObject]@{
                                CheckType           = "CredentialRoaming"
                                Right               = "$crRightPrefix (All Properties - includes the roaming attributes)$childReachNote"
                                Principal           = $TrusteeName
                                SID                 = $TrusteeSID
                                Severity            = $Severity
                                InheritedFrom       = $InheritedFrom
                                GrantsControlAccess = $crControlAccess
                            }
                        }
                    }
                }

                # Check 8c: read rights on the BitLocker recovery password
                #
                # The recovery password is not an attribute of the computer. It sits on an
                # msFVE-RecoveryInformation object below the computer, two levels under the
                # container whose descriptor this reads, so an ACE reaches it only when it is
                # inherited (ContainerInherit), is not stopped at the computers
                # (NoPropagateInherit leaves the computer a copy without inheritance flags),
                # and is not limited to another class: InheritedObjectType empty or
                # msFVE-RecoveryInformation. An ACE limited to the computer class becomes
                # effective on the computer and never on the object below it.
                #
                # The attribute is confidential in the shipped schema (searchFlags 0x298), so
                # a read needs READ_PROPERTY *and* CONTROL_ACCESS. Whether the flag is still
                # set is the caller's question, and the two halves can sit in two ACEs, so
                # each finding says which half it carries instead of a verdict. Unlike the
                # Credential Roaming block, CONTROL_ACCESS alone is reported in the
                # all-extended-rights case as well: the shipped default security descriptor
                # of the class grants the object to Domain Admins and SYSTEM only, so nobody
                # else holds the read half by default, and the caller needs both halves of a
                # principal to decide anything.
                #
                # Nor are the broad groups exempted from the all-properties case, as they are
                # there and for LAPS. A blanket read is the default ACL of a user object; on a
                # recovery object it is not, so a broad read reaching one was granted by
                # somebody - and only the confidential flag then stands between every user
                # and every recovery password.
                if ($CheckType -contains 'BitLocker') {

                    # Test-ADRightsMask rather than -band, for the reason given in the LAPS
                    # block above. It also expands GenericAll - written as a GA generic bit or
                    # as the full mask - into the bits it contains, so full control answers
                    # yes to both halves on its own and needs no term of its own below; it
                    # only decides the label.
                    $blHasRead          = Test-ADRightsMask -Rights $ACE.ActiveDirectoryRights -Has ([System.DirectoryServices.ActiveDirectoryRights]::ReadProperty)
                    $blHasGenericAll    = Test-ADRightsMask -Rights $ACE.ActiveDirectoryRights -Has ([System.DirectoryServices.ActiveDirectoryRights]::GenericAll)
                    $blHasControlAccess = Test-ADRightsMask -Rights $ACE.ActiveDirectoryRights -Has ([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight)

                    $blAppliesToRecovery = $IsAllObjectTypes -or ($inheritedObjectType -eq $SchemaClassGUIDs['msFVE-RecoveryInformation'])

                    if (($blHasRead -or $blHasControlAccess) -and
                        $blAppliesToRecovery -and $AppliesToChildren -and -not $isNoPropagate) {

                        $blTarget = $null
                        $blPasswordGuid = $PropertyGUIDs['msFVE-RecoveryPassword']
                        if ($ACE.ObjectType -and $blPasswordGuid -and $ACE.ObjectType.Guid -eq $blPasswordGuid.Guid) {
                            $blTarget = 'msFVE-RecoveryPassword'
                        } elseif ($IsAllProperties) {
                            # No ObjectType: every property for the read half, every extended
                            # right for the control half - the recovery password among them.
                            $blTarget = 'all extended rights - includes the recovery password'
                            if ($blHasRead) {
                                $blTarget = 'all properties - includes the recovery password'
                            }
                        }

                        if ($blTarget) {
                            # Named after what the ACE carries. "GenericAll" is avoided on
                            # purpose: a dangerousRights value containing it takes the
                            # GenericAll card, and "Full control" tells a reader the same.
                            $blRightPrefix = 'ControlAccess'
                            if ($blHasGenericAll) {
                                $blRightPrefix = 'Full control'
                            } elseif ($blHasRead -and $blHasControlAccess) {
                                $blRightPrefix = 'ReadProperty + ControlAccess'
                            } elseif ($blHasRead) {
                                $blRightPrefix = 'ReadProperty'
                            }

                            $Severity = if ($IsPrivileged) { "Info" } else { "High" }
                            $Findings += [PSCustomObject]@{
                                CheckType           = "BitLocker"
                                Right               = "$blRightPrefix ($blTarget)"
                                Principal           = $TrusteeName
                                SID                 = $TrusteeSID
                                Severity            = $Severity
                                InheritedFrom       = $InheritedFrom
                                GrantsRead          = $blHasRead
                                GrantsControlAccess = $blHasControlAccess
                            }
                        }
                    }
                }

                # Check 9: Object Creation Rights
                # ObjectType specifies WHICH object class can be created (User, Computer, Group, etc.)
                if ($CheckType -contains 'ObjectCreation') {

                    $HasCreateChild = Test-ADRightsMask -Rights $ACE.ActiveDirectoryRights -Has ([System.DirectoryServices.ActiveDirectoryRights]::CreateChild)
                    if ($HasCreateChild -and $AppliesToSelf) {
                        # Determine what can be created based on ObjectType
                        # Empty ObjectType = "All Objects" (but may be limited by other mechanisms)
                        # Specific GUID = specific object class (User, Computer, Group, etc.)
                        $createTarget = if ($IsAllProperties) {
                            "All Objects"
                        } else {
                            # Try to resolve the schema class name
                            $className = Get-SchemaClassName -GUID $objectType
                            if ($className) {
                                # Verbatim, not title-cased. These are schema names:
                                # ToTitleCase lowercases everything after the first letter
                                # of a word unless the whole word is uppercase, so
                                # inetOrgPerson came out as Inetorgperson and
                                # msDS-ManagedServiceAccount as Msds-Managedserviceaccount -
                                # names that exist in no schema and that a reader cannot
                                # search for.
                                $className
                            } else {
                                # Unknown GUID - show as-is
                                $objectType.ToString()
                            }
                        }

                        # Severity: Creating computers is more critical (can be used for RBCD attacks)
                        # "All Objects" includes Computer, so also High severity
                        # A delegated Managed Service Account is a computer subclass, and its
                        # creator owns it: paired with an account the creator can write to, it
                        # receives that account's group memberships and keys from a Windows
                        # Server 2025 KDC. It was Medium, like a user or a group.
                        $Severity = if ($IsPrivileged) {
                            "Info"
                        } elseif ($objectType -eq $SchemaClassGUIDs['computer'] -or
                                  $objectType -eq $SchemaClassGUIDs['msDS-DelegatedManagedServiceAccount'] -or
                                  $IsAllProperties) {
                            "High"  # Computer creation enables RBCD attacks
                        } else {
                            "Medium"
                        }

                        $Findings += [PSCustomObject]@{
                            CheckType     = "ObjectCreation"
                            Right         = "CreateChild ($createTarget)$inheritanceNote"
                            # The class itself, beside the sentence that names it. The
                            # caller decides whether a built-in may create it, and that
                            # decision must not come from parsing the text above.
                            CreatableClass = $createTarget
                            Principal     = $TrusteeName
                            SID           = $TrusteeSID
                            Severity      = $Severity
                            InheritedFrom = $InheritedFrom
                        }
                    }
                }

                # Check 10: GPO Linking Rights
                # Note: GUID::Empty is handled by generic "WriteProperty (All Properties)" above
                # gPLink is an attribute of the OU itself, NOT child objects, so the question
                # is whether the ACE applies to this OU: not inherit-only. A class named for
                # inheritance does not take it off the OU - it names the children that may
                # inherit the ACE (MS-DTYP, ACE), and the access check skips INHERIT_ONLY_ACE
                # and nothing else. An inherited copy for another class arrives inherit-only.
                # The class used to be required to be organizationalUnit, which dropped
                # "this object and descendant user objects" although it grants the write here.
                if ($CheckType -contains 'GPOLinking') {
                    if ($HasWriteProperty -and -not $IsAllProperties -and $AppliesToSelf) {
                        if ($ACE.ObjectType -eq $PropertyGUIDs['gPLink']) {
                            $Severity = if ($IsPrivileged) { "Info" } else { "Medium" }
                            $Findings += [PSCustomObject]@{
                                CheckType     = "GPOLinking"
                                Right         = "WriteProperty (gPLink)$inheritanceNote"
                                Principal     = $TrusteeName
                                SID           = $TrusteeSID
                                Severity      = $Severity
                                InheritedFrom = $InheritedFrom
                            }
                        } elseif ($ACE.ObjectType -eq $PropertyGUIDs['gPOptions']) {
                            # The other half of "Manage Group Policy links": gPOptions is
                            # where the OU blocks inheritance, and with it every GPO linked
                            # above that is not enforced - a security baseline linked at the
                            # domain stops applying to everything below.
                            $Severity = if ($IsPrivileged) { "Info" } else { "Medium" }
                            $Findings += [PSCustomObject]@{
                                CheckType     = "GPOLinking"
                                Right         = "WriteProperty (gPOptions)$inheritanceNote"
                                Principal     = $TrusteeName
                                SID           = $TrusteeSID
                                Severity      = $Severity
                                InheritedFrom = $InheritedFrom
                            }
                        }
                    }
                }

                # The element each finding of this ACE is about: the class its inheritance
                # names ('' for every class), and whether it reaches this object, its
                # children, and only the direct ones. Select-OUStrongestFinding reads it to
                # show the strongest right per element; the other callers ignore it. And
                # where the ACE is set, which Get-DangerousOUPermissions reads to name the
                # places a right is set instead of every OU that inherits it.
                $elementClass = if ($IsAllObjectTypes) { '' } else { ([string]$inheritedObjectType).ToLowerInvariant() }
                for ($findingIndex = $aceFindingStart; $findingIndex -lt @($Findings).Count; $findingIndex++) {
                    $Findings[$findingIndex] | Add-Member -NotePropertyName '_SourceDN' -NotePropertyValue $aceSourceDN -Force
                    $Findings[$findingIndex] | Add-Member -NotePropertyName '_ElementClass' -NotePropertyValue $elementClass -Force
                    $Findings[$findingIndex] | Add-Member -NotePropertyName '_ElementSelf' -NotePropertyValue ([bool]$AppliesToSelf) -Force
                    $Findings[$findingIndex] | Add-Member -NotePropertyName '_ElementChildren' -NotePropertyValue ([bool]$AppliesToChildren) -Force
                    $Findings[$findingIndex] | Add-Member -NotePropertyName '_ElementDirectOnly' -NotePropertyValue ([bool]$isNoPropagate) -Force
                }
            }

            $result = [PSCustomObject]@{
                OU       = $DistinguishedName
                Findings = $Findings
                Read     = $true
                # How many ACEs an explicit Deny cancelled. The caller says so in its
                # conclusion rather than leaving the reader to wonder why a delegation
                # they know about is missing - a Deny is a fragile control, and one
                # removed ACE brings the access back.
                NeutralisedByDeny = $neutralisedByDeny
            }

            # Cache full-scan results for cross-module reuse
            if ($isFullScan) {
                $Script:OUPermissionsCache[$cacheKey] = $result
            }

            return $result

        } catch {
            Write-Log "[Get-OUPermissions] Error analyzing OU '$DistinguishedName': $_"
            return [PSCustomObject]@{ OU = $DistinguishedName; Findings = $null; Read = $false }
        }
    }

    end {
        Write-Log "[Get-OUPermissions] ACL analysis completed"
    }
}


<#
.SYNOPSIS
    Emits a line about the OUs whose security descriptor could not be read, if there are
    any.

.DESCRIPTION
    Get-OUPermissions answers with Read = $false when it could not read or parse an OU's
    nTSecurityDescriptor. Its callers used to see only an empty finding list, which they
    could not tell apart from an OU with nothing on it, and their conclusion named the
    full OU count as analyzed - a scan denied every descriptor in the domain read as a
    clean domain.

    Writes nothing when every OU was read, so a caller can place it unconditionally in
    front of its own conclusion. Returns $true when coverage was incomplete, which lets a
    caller downgrade a "Secure" conclusion to a "Note": a green line must not be printed
    over objects whose permissions were never seen. Same contract as
    Show-SYSVOLCoverageNote.

.PARAMETER UnreadOUs
    Distinguished names of the OUs and containers that could not be read.

.PARAMETER TotalOUs
    How many were meant to be analyzed, for the "N of M" in the message.

.OUTPUTS
    Boolean - $true if at least one OU could not be read.
#>
function Show-OUPermissionsCoverageNote {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$UnreadOUs,

        [Parameter(Mandatory = $true)]
        [int]$TotalOUs
    )

    # @($null) is a one-element array in PowerShell, so an unset list would otherwise
    # report one unreadable OU that does not exist.
    $unread = @($UnreadOUs | Where-Object { $_ })
    if ($unread.Count -eq 0) { return $false }

    Show-Line "The security descriptor of $($unread.Count) of $TotalOUs object(s) could not be read - the result below is incomplete" -Class Finding
    foreach ($unreadDN in ($unread | Select-Object -First 10)) {
        Show-Line "  not read: $unreadDN" -Class Hint
    }
    if ($unread.Count -gt 10) {
        Show-Line "  ... and $($unread.Count - 10) more" -Class Hint
    }

    return $true
}
