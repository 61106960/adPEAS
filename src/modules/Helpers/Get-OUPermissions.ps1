<#
.SYNOPSIS
    Helper function to determine the source of an inherited ACE.

.DESCRIPTION
    Traces the parent container chain to find where an inherited ACE was originally set.
    Loads parent ACLs via Invoke-LDAPSearch (reuses existing LdapConnection).
    Returns the distinguished name of the source container (e.g., domain root).

.PARAMETER DistinguishedName
    The DN of the object with the inherited ACE.

.PARAMETER ACE
    The ACE to trace.

.OUTPUTS
    String: Distinguished name of the inheritance source, or "Inherited" if source cannot be determined.
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

        # Session-level cache for parent ACLs (parent ACLs are identical across all child OUs)
        if (-not $Script:InheritanceACLCache) {
            $Script:InheritanceACLCache = @{}
        }

        # Check each parent starting from immediate parent
        foreach ($parentDN in $parents) {
            try {
                # Load parent ACL — use cache to avoid redundant LDAP queries
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

                # Look for matching explicit ACE on parent
                # We use relaxed matching: same identity + explicit + similar rights
                foreach ($parentACE in $parentAccessRules) {
                    # Must be explicit (not inherited) and Allow
                    if ($parentACE.IsInherited) { continue }
                    if ($parentACE.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }

                    # Match by SID (both are SecurityIdentifier — direct string comparison)
                    if ($parentACE.IdentityReference.Value -ne $aceIdentitySID) { continue }

                    # Relaxed matching: Check if the parent ACE could be the source
                    # The inherited ACE may have different rights due to inheritance flags
                    # Key indicators: same identity + explicit + inheritable

                    # Check inheritance flags - must be set to inherit to children
                    $inheritFlags = $parentACE.InheritanceFlags
                    $canInherit = ($inheritFlags -band [System.Security.AccessControl.InheritanceFlags]::ContainerInherit) -or
                                  ($inheritFlags -band [System.Security.AccessControl.InheritanceFlags]::ObjectInherit)

                    if (-not $canInherit) { continue }

                    # Additional check: ObjectType should match (the right being granted)
                    # Skip this check if either ObjectType is Empty GUID (means "all properties/rights")
                    # GUID::Empty is truthy in PowerShell, so we must check explicitly
                    $aceObjType = $ACE.ObjectType
                    $parentObjType = $parentACE.ObjectType
                    if ($aceObjType -and $aceObjType -ne [GUID]::Empty -and
                        $parentObjType -and $parentObjType -ne [GUID]::Empty) {
                        if ($aceObjType -ne $parentObjType) { continue }
                    }

                    # Found the source - return a friendly name
                    if ($parentDN -eq $domainDN) {
                        return "Domain Root ($domainDN)"
                    } else {
                        # Extract the first RDN for display (e.g., "OU=Corp" -> "Corp")
                        $rdnMatch = $parentDN -match '^([^=]+)=([^,]+)'
                        if ($rdnMatch) {
                            $rdnType = $Matches[1]
                            $rdnValue = $Matches[2]
                            return "$rdnType=$rdnValue ($parentDN)"
                        }
                        return $parentDN
                    }
                }

            } catch {
                Write-Log "[Get-ACEInheritanceSource] Error checking parent '$parentDN': $_"
                continue
            }
        }

        # Couldn't determine exact source - but if the ACE is inherited,
        # it MUST come from somewhere in the parent chain
        # Default to domain root as the most common source for domain-wide delegations
        if ($parents -contains $domainDN) {
            return "Domain Root ($domainDN)"
        }

        return "Inherited"

    } catch {
        Write-Log "[Get-ACEInheritanceSource] Error: $_"
        return "Inherited"
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
    - ScriptPath: scriptPath write access
    - Delegation: Delegation attribute write access
    - LAPS: LAPS password read access
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
            'ScriptPath',
            'Delegation',
            'LAPS',
            'ObjectCreation',
            'GPOLinking'
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

        # Expand 'All' to all check types
        if ($isFullScan) {
            $CheckType = @(
                'GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner',
                'PasswordReset', 'AccountControl', 'GroupMembership',
                'SPNModification', 'DNSHostName', 'ScriptPath', 'Delegation', 'LAPS',
                'ObjectCreation', 'GPOLinking'
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
                }
            }

            Write-Log "[Get-OUPermissions] Analyzing: $DistinguishedName"

            # Load nTSecurityDescriptor via Invoke-LDAPSearch (uses existing $Script:LdapConnection)
            # -Raw returns byte[] instead of ConvertFrom-SecurityDescriptor (we need native ACE objects)
            $ouResult = @(Invoke-LDAPSearch -Filter "(objectClass=*)" -SearchBase $DistinguishedName -Scope Base -Properties 'nTSecurityDescriptor' -Raw)[0]

            if (-not $ouResult -or -not $ouResult.nTSecurityDescriptor) {
                Write-Log "[Get-OUPermissions] Failed to read nTSecurityDescriptor for OU: $DistinguishedName"
                return $null
            }

            # Parse nTSecurityDescriptor into AccessRules via shared helper
            $sdParsed = ConvertTo-AccessRules -SecurityDescriptorBytes $ouResult.nTSecurityDescriptor
            if (-not $sdParsed) {
                Write-Log "[Get-OUPermissions] Failed to parse nTSecurityDescriptor for OU: $DistinguishedName"
                return $null
            }
            $AccessRules = $sdParsed.AccessRules

            $Findings = @()

            # Analyze each ACE
            foreach ($ACE in $AccessRules) {
                # Skip Deny ACEs (we only care about Allow)
                if ($ACE.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
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
                if ($ACE.IsInherited) {
                    # Determine the inheritance source by checking the propagation
                    # Inherited ACEs on OUs typically come from the domain root or parent OUs
                    # We'll trace back to find the source
                    $InheritedFrom = Get-ACEInheritanceSource -DistinguishedName $DistinguishedName -ACE $ACE
                }

                # Get ObjectType and InheritedObjectType for scope checking
                # ObjectType = which property/right is affected
                # InheritedObjectType = which object CLASS the ACE applies to (User, Computer, etc.)
                $objectType = $ACE.ObjectType
                $inheritedObjectType = $ACE.InheritedObjectType

                # Pre-calculate common right checks (performance optimization - used by multiple checks)
                $HasWriteProperty = $ACE.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                $IsAllProperties = ($objectType -eq [GUID]::Empty) -or (-not $objectType)

                # InheritedObjectType checks - determines which object class this ACE applies to
                # Empty/null = applies to ALL object types
                # Specific GUID = applies only to that object class
                $IsAllObjectTypes = (-not $inheritedObjectType -or $inheritedObjectType -eq [GUID]::Empty)
                $AppliesToUsers = $IsAllObjectTypes -or ($inheritedObjectType -eq $SchemaClassGUIDs['user'])
                $AppliesToComputers = $IsAllObjectTypes -or ($inheritedObjectType -eq $SchemaClassGUIDs['computer'])
                $AppliesToGroups = $IsAllObjectTypes -or ($inheritedObjectType -eq $SchemaClassGUIDs['group'])

                # If WriteProperty on ALL properties, create ONE generic finding instead of 6+ individual ones
                # This prevents duplicate findings like: userAccountControl, member, SPN, scriptPath, Delegation x2, gPLink
                if ($HasWriteProperty -and $IsAllProperties -and ($CheckType -contains 'AccountControl' -or
                    $CheckType -contains 'GroupMembership' -or $CheckType -contains 'SPNModification' -or
                    $CheckType -contains 'ScriptPath' -or $CheckType -contains 'Delegation' -or
                    $CheckType -contains 'GPOLinking')) {

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
                            Right         = "WriteProperty (All Properties)$scopeInfo"
                            Principal     = $TrusteeName
                            SID           = $TrusteeSID
                            Severity      = $Severity
                            InheritedFrom = $InheritedFrom
                        }
                    }
                }

                # Check 1: GenericAll (Full Control)
                if ($CheckType -contains 'GenericAll') {
                    # GenericAll in AD is 0xF01FF (983551)
                    # We need to check if ALL bits of GenericAll are set, not just some overlap
                    # GenericAll only applies to the whole object if ObjectType is empty
                    $GenericAllValue = [int][System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                    $RightsValue = [int]$ACE.ActiveDirectoryRights

                    $HasFullGenericAll = (($RightsValue -band $GenericAllValue) -eq $GenericAllValue) -and $IsAllProperties
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
                            Right         = "GenericAll (Full Control)$scopeInfo"
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
                    $GenericWriteValue = [int][System.DirectoryServices.ActiveDirectoryRights]::GenericWrite
                    $RightsValue = [int]$ACE.ActiveDirectoryRights

                    $HasGenericWrite = (($RightsValue -band $GenericWriteValue) -eq $GenericWriteValue) -and $IsAllProperties
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
                            Right         = "GenericWrite$scopeInfo"
                            Principal     = $TrusteeName
                            SID           = $TrusteeSID
                            Severity      = $Severity
                            InheritedFrom = $InheritedFrom
                        }
                    }
                }

                # Check 1c: WriteDacl (can modify ACL = effectively full control)
                if ($CheckType -contains 'WriteDacl') {
                    $HasWriteDacl = $ACE.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl

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
                            Right         = "WriteDacl (Modify Permissions)$scopeInfo"
                            Principal     = $TrusteeName
                            SID           = $TrusteeSID
                            Severity      = $Severity
                            InheritedFrom = $InheritedFrom
                        }
                    }
                }

                # Check 1d: WriteOwner (can take ownership = effectively full control)
                if ($CheckType -contains 'WriteOwner') {
                    $HasWriteOwner = $ACE.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner

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
                            Right         = "WriteOwner (Take Ownership)$scopeInfo"
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
                    $HasExtendedRight = $ACE.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight

                    if ($HasExtendedRight -and $AppliesToUsers) {
                        # Check for Reset Password extended right (using central GUID lookup)
                        $passwordResetGUID = Get-ExtendedRightGUID -Name 'User-Force-Change-Password'
                        if ($ACE.ObjectType -eq $passwordResetGUID -or $ACE.ObjectType -eq [GUID]::Empty) {
                            $Severity = if ($IsPrivileged) { "Info" } else { "Critical" }
                            $Findings += [PSCustomObject]@{
                                CheckType     = "PasswordReset"
                                Right         = "Reset Password (Extended Right)"
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
                    if ($HasWriteProperty -and -not $IsAllProperties -and ($AppliesToUsers -or $AppliesToComputers)) {
                        # Check direct userAccountControl attribute
                        if ($ACE.ObjectType -eq $PropertyGUIDs['userAccountControl']) {
                            $Severity = if ($IsPrivileged) { "Info" } else { "Critical" }
                            $Findings += [PSCustomObject]@{
                                CheckType     = "AccountControl"
                                Right         = "WriteProperty (userAccountControl)"
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
                                Right         = "WriteProperty (User-Account-Restrictions)"
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
                    if ($HasWriteProperty -and -not $IsAllProperties -and $AppliesToGroups) {
                        if ($ACE.ObjectType -eq $PropertyGUIDs['member']) {
                            $Severity = if ($IsPrivileged) { "Info" } else { "High" }
                            $Findings += [PSCustomObject]@{
                                CheckType     = "GroupMembership"
                                Right         = "WriteProperty (member)"
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
                    if ($HasWriteProperty -and -not $IsAllProperties -and ($AppliesToUsers -or $AppliesToComputers)) {
                        if ($ACE.ObjectType -eq $PropertyGUIDs['servicePrincipalName']) {
                            $Severity = if ($IsPrivileged) { "Info" } else { "High" }
                            $Findings += [PSCustomObject]@{
                                CheckType     = "SPNModification"
                                Right         = "WriteProperty (servicePrincipalName)"
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
                                Right         = "WriteProperty (servicePrincipalName)"
                                Principal     = $TrusteeName
                                SID           = $TrusteeSID
                                Severity      = $Severity
                                InheritedFrom = $InheritedFrom
                            }
                        }
                    }
                    # Check Self right with Validated-SPN (validated write)
                    $HasSelf = $ACE.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::Self
                    if ($HasSelf -and -not $IsAllProperties -and ($AppliesToUsers -or $AppliesToComputers)) {
                        if ($ACE.ObjectType -eq $Script:ValidatedWriteGUIDs['Validated-SPN']) {
                            $Severity = if ($IsPrivileged) { "Info" } else { "High" }
                            $Findings += [PSCustomObject]@{
                                CheckType     = "SPNModification"
                                Right         = "Self (Validated-SPN)"
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
                    if ($HasWriteProperty -and -not $IsAllProperties -and $AppliesToComputers) {
                        if ($ACE.ObjectType -eq $PropertyGUIDs['dNSHostName']) {
                            $Severity = if ($IsPrivileged) { "Info" } else { "High" }
                            $Findings += [PSCustomObject]@{
                                CheckType     = "DNSHostName"
                                Right         = "WriteProperty (dNSHostName)"
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
                                Right         = "WriteProperty (DNS-Host-Name-Attributes)"
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
                                Right         = "WriteProperty (dNSHostName)"
                                Principal     = $TrusteeName
                                SID           = $TrusteeSID
                                Severity      = $Severity
                                InheritedFrom = $InheritedFrom
                            }
                        }
                    }
                    # Check Self right with Validated-DNS-Host-Name (validated write)
                    $HasSelf = $ACE.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::Self
                    if ($HasSelf -and -not $IsAllProperties -and $AppliesToComputers) {
                        if ($ACE.ObjectType -eq $Script:ValidatedWriteGUIDs['Validated-DNS-Host-Name']) {
                            $Severity = if ($IsPrivileged) { "Info" } else { "High" }
                            $Findings += [PSCustomObject]@{
                                CheckType     = "DNSHostName"
                                Right         = "Self (Validated-DNS-Host-Name)"
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
                    if ($HasWriteProperty -and -not $IsAllProperties -and $AppliesToUsers) {
                        if ($ACE.ObjectType -eq $PropertyGUIDs['scriptPath']) {
                            $Severity = if ($IsPrivileged) { "Info" } else { "High" }
                            $Findings += [PSCustomObject]@{
                                CheckType     = "ScriptPath"
                                Right         = "WriteProperty (scriptPath)"
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
                    if ($HasWriteProperty -and -not $IsAllProperties -and ($AppliesToUsers -or $AppliesToComputers)) {
                        # msDS-AllowedToDelegateTo (Constrained Delegation)
                        if ($ACE.ObjectType -eq $PropertyGUIDs['msDS-AllowedToDelegateTo']) {
                            $Severity = if ($IsPrivileged) { "Info" } else { "High" }
                            $Findings += [PSCustomObject]@{
                                CheckType     = "Delegation"
                                Right         = "WriteProperty (msDS-AllowedToDelegateTo)"
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
                                Right         = "WriteProperty (msDS-AllowedToActOnBehalfOfOtherIdentity)"
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

                    $HasReadProperty = $ACE.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty
                    $HasGenericAll = $ACE.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                    $HasExtendedRight = $ACE.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight

                    if (($HasReadProperty -or $HasGenericAll -or $HasExtendedRight) -and $AppliesToComputers) {
                        # LAPS permissions on OUs can be configured in several ways:
                        # 1. Specific property read: ObjectType = LAPS-Property-GUID (most common for delegated LAPS read)
                        # 2. All properties read: ObjectType = Empty GUID (GenericAll or full ReadProperty)
                        # 3. Extended Right for Control Access (Windows LAPS specific)
                        #
                        # We need to check all scenarios to catch LAPS read permissions

                        # Use different variable name to avoid collision with $IsAllProperties
                        $lapsIsAllProperties = $IsAllProperties
                        $lapsPropertyFound = $false

                        # Legacy LAPS (ms-Mcs-AdmPwd) - GUID: E5C0983D-B71E-4F1D-B798-9B0F5ECAEEA3
                        $legacyLAPSMatch = ($ACE.ObjectType -and $ACE.ObjectType.Guid -eq $PropertyGUIDs['ms-Mcs-AdmPwd'].Guid)
                        if ($legacyLAPSMatch) {
                            $Severity = if ($IsPrivileged) { "Info" } else { "Medium" }
                            $Findings += [PSCustomObject]@{
                                CheckType     = "LAPS"
                                Right         = "ReadProperty (ms-Mcs-AdmPwd - Legacy LAPS)"
                                Principal     = $TrusteeName
                                SID           = $TrusteeSID
                                Severity      = $Severity
                                InheritedFrom = $InheritedFrom
                            }
                            $lapsPropertyFound = $true
                        }

                        # Windows LAPS - Encrypted Password (most common)
                        # GUID: 0bf205b5-8bcb-4943-8413-52e492d7cf63
                        $encPwdMatch = ($ACE.ObjectType -and $ACE.ObjectType.Guid -eq $PropertyGUIDs['msLAPS-EncryptedPassword'].Guid)
                        if ($encPwdMatch) {
                            $Severity = if ($IsPrivileged) { "Info" } else { "Medium" }
                            $Findings += [PSCustomObject]@{
                                CheckType     = "LAPS"
                                Right         = "ReadProperty (msLAPS-EncryptedPassword - Windows LAPS)"
                                Principal     = $TrusteeName
                                SID           = $TrusteeSID
                                Severity      = $Severity
                                InheritedFrom = $InheritedFrom
                            }
                            $lapsPropertyFound = $true
                        }

                        # Windows LAPS - Encrypted Password History
                        # GUID: 01b40040-aeb0-4bb4-ad1c-6b3e09ceeafc
                        $encHistMatch = ($ACE.ObjectType -and $ACE.ObjectType.Guid -eq $PropertyGUIDs['msLAPS-EncryptedPasswordHistory'].Guid)
                        if ($encHistMatch) {
                            $Severity = if ($IsPrivileged) { "Info" } else { "Medium" }
                            $Findings += [PSCustomObject]@{
                                CheckType     = "LAPS"
                                Right         = "ReadProperty (msLAPS-EncryptedPasswordHistory - Windows LAPS)"
                                Principal     = $TrusteeName
                                SID           = $TrusteeSID
                                Severity      = $Severity
                                InheritedFrom = $InheritedFrom
                            }
                            $lapsPropertyFound = $true
                        }

                        # Windows LAPS - Plain Password (unencrypted mode)
                        # GUID: 5B47D60F-6090-40B2-9F37-2A4DE88F3063
                        $plainPwdMatch = ($ACE.ObjectType -and $ACE.ObjectType.Guid -eq $PropertyGUIDs['msLAPS-Password'].Guid)
                        if ($plainPwdMatch) {
                            $Severity = if ($IsPrivileged) { "Info" } else { "Medium" }
                            $Findings += [PSCustomObject]@{
                                CheckType     = "LAPS"
                                Right         = "ReadProperty (msLAPS-Password - Windows LAPS)"
                                Principal     = $TrusteeName
                                SID           = $TrusteeSID
                                Severity      = $Severity
                                InheritedFrom = $InheritedFrom
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
                                Right         = "ReadProperty (msLAPS-CurrentPasswordVersion - Windows LAPS)"
                                Principal     = $TrusteeName
                                SID           = $TrusteeSID
                                Severity      = $Severity
                                InheritedFrom = $InheritedFrom
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
                                Right         = "ReadProperty (msLAPS-PasswordExpirationTime - Windows LAPS)"
                                Principal     = $TrusteeName
                                SID           = $TrusteeSID
                                Severity      = $Severity
                                InheritedFrom = $InheritedFrom
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
                            $Findings += [PSCustomObject]@{
                                CheckType     = "LAPS"
                                Right         = "ReadProperty (All Properties - includes LAPS)"
                                Principal     = $TrusteeName
                                SID           = $TrusteeSID
                                Severity      = $Severity
                                InheritedFrom = $InheritedFrom
                            }
                        }
                    }
                }

                # Check 9: Object Creation Rights
                # ObjectType specifies WHICH object class can be created (User, Computer, Group, etc.)
                if ($CheckType -contains 'ObjectCreation') {

                    $HasCreateChild = $ACE.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::CreateChild
                    if ($HasCreateChild) {
                        # Determine what can be created based on ObjectType
                        # Empty ObjectType = "All Objects" (but may be limited by other mechanisms)
                        # Specific GUID = specific object class (User, Computer, Group, etc.)
                        $createTarget = if ($IsAllProperties) {
                            "All Objects"
                        } else {
                            # Try to resolve the schema class name
                            $className = Get-SchemaClassName -GUID $objectType
                            if ($className) {
                                # Title case for readability (user -> User, computer -> Computer)
                                (Get-Culture).TextInfo.ToTitleCase($className)
                            } else {
                                # Unknown GUID - show as-is
                                $objectType.ToString()
                            }
                        }

                        # Severity: Creating computers is more critical (can be used for RBCD attacks)
                        # "All Objects" includes Computer, so also High severity
                        $Severity = if ($IsPrivileged) {
                            "Info"
                        } elseif ($objectType -eq $SchemaClassGUIDs['computer'] -or $IsAllProperties) {
                            "High"  # Computer creation enables RBCD attacks
                        } else {
                            "Medium"
                        }

                        $Findings += [PSCustomObject]@{
                            CheckType     = "ObjectCreation"
                            Right         = "CreateChild ($createTarget)"
                            Principal     = $TrusteeName
                            SID           = $TrusteeSID
                            Severity      = $Severity
                            InheritedFrom = $InheritedFrom
                        }
                    }
                }

                # Check 10: GPO Linking Rights
                # Note: GUID::Empty is handled by generic "WriteProperty (All Properties)" above
                # gPLink is an attribute of the OU itself, NOT child objects
                # So InheritedObjectType must be empty (applies to the OU) or organizationalUnit
                if ($CheckType -contains 'GPOLinking') {
                    $AppliesToOU = $IsAllObjectTypes -or ($inheritedObjectType -eq $SchemaClassGUIDs['organizationalUnit'])
                    if ($HasWriteProperty -and -not $IsAllProperties -and $AppliesToOU) {
                        if ($ACE.ObjectType -eq $PropertyGUIDs['gPLink']) {
                            $Severity = if ($IsPrivileged) { "Info" } else { "Medium" }
                            $Findings += [PSCustomObject]@{
                                CheckType     = "GPOLinking"
                                Right         = "WriteProperty (gPLink)"
                                Principal     = $TrusteeName
                                SID           = $TrusteeSID
                                Severity      = $Severity
                                InheritedFrom = $InheritedFrom
                            }
                        }
                    }
                }
            }

            $result = [PSCustomObject]@{
                OU       = $DistinguishedName
                Findings = $Findings
            }

            # Cache full-scan results for cross-module reuse
            if ($isFullScan) {
                $Script:OUPermissionsCache[$cacheKey] = $result
            }

            return $result

        } catch {
            Write-Log "[Get-OUPermissions] Error analyzing OU '$DistinguishedName': $_"
            return $null
        }
    }

    end {
        Write-Log "[Get-OUPermissions] ACL analysis completed"
    }
}

