function Get-ObjectACL {
<#
.SYNOPSIS
    Retrieves and analyzes Access Control Lists (ACLs) from Active Directory objects.

.DESCRIPTION
    Get-ObjectACL is a central function for ACL analysis in adPEAS v2. It provides:

    - Direct ACL retrieval for any AD object (user, computer, group, OU, GPO, etc.)
    - Filtering by trustee, rights, extended rights
    - Dangerous ACE detection (GenericAll, WriteDacl, WriteOwner, etc.)
    - Pipeline support for batch analysis
    - Integration with ConvertTo-FormattedACE for human-readable output

    This function is designed to be used by:
    - Check modules (Get-DangerousACLs, Get-DangerousOUPermissions, etc.)
    - Direct command-line analysis by pentesters/admins
    - Other Core modules via -ShowACE parameter

    Well-Known Dangerous Rights:
    - GenericAll: Full control over object
    - GenericWrite: Modify most attributes
    - WriteDacl: Modify object's ACL
    - WriteOwner: Take ownership of object
    - WriteProperty: Modify specific attributes
    - ExtendedRight: Includes DCSync, ForceChangePassword, etc.

.PARAMETER Identity
    Target object identity. Accepts:
    - sAMAccountName (e.g., "Administrator", "DC01$")
    - DistinguishedName (e.g., "CN=Domain Admins,CN=Users,DC=contoso,DC=com")
    - SID (e.g., "S-1-5-21-...")
    - GUID (e.g., "{12345678-1234-...}")

.PARAMETER DistinguishedName
    Direct DN specification (alternative to -Identity).

.PARAMETER Trustee
    Filter ACEs by trustee name or SID. Supports wildcards.
    Example: -Trustee "CONTOSO\helpdesk*"

.PARAMETER ExcludeTrustee
    Exclude ACEs for specified trustees. Useful for filtering out well-known admins.
    Example: -ExcludeTrustee "NT AUTHORITY\SYSTEM","CONTOSO\Domain Admins"

.PARAMETER Rights
    Filter for specific rights.
    Example: -Rights "GenericAll","WriteDacl","WriteOwner"

.PARAMETER ExtendedRight
    Filter for specific extended rights by name.
    Example: -ExtendedRight "DS-Replication-Get-Changes-All"

.PARAMETER DangerousOnly
    Only return ACEs with dangerous rights:
    - GenericAll, GenericWrite, WriteDacl, WriteOwner
    - WriteProperty, Self, ExtendedRight
    - Delete, DeleteTree, CreateChild, DeleteChild

.PARAMETER WriteOnly
    Only return ACEs with write permissions:
    - GenericAll, GenericWrite, WriteDacl, WriteOwner, WriteProperty

.PARAMETER ExtendedRightsOnly
    Only return ACEs with ExtendedRight flag set.

.PARAMETER ExplicitOnly
    Exclude inherited ACEs, show only explicit permissions.

.PARAMETER AllowOnly
    Only return Allow ACEs (exclude Deny).

.PARAMETER DenyOnly
    Only return Deny ACEs (exclude Allow).

.PARAMETER IncludeObjectInfo
    Include object information (DN, objectClass) in output.

.PARAMETER NoResolveGUIDs
    If set, skips GUID-to-Name resolution for ObjectType and InheritedObjectType.
    By default, GUIDs are resolved to friendly names (e.g., "DS-Replication-Get-Changes").

.PARAMETER NoResolveSIDs
    If set, skips SID-to-Name resolution and displays raw SIDs instead.
    By default, SIDs are resolved to friendly names (e.g., "CONTOSO\Domain Admins").

.PARAMETER Domain
    Target domain (FQDN).

.PARAMETER Server
    Specific Domain Controller to query.

.PARAMETER Credential
    PSCredential object for authentication.

.EXAMPLE
    Get-ObjectACL -Identity "Domain Admins"
    Returns all ACEs for the Domain Admins group.

.EXAMPLE
    Get-ObjectACL -Identity "CN=AdminSDHolder,CN=System,DC=contoso,DC=com" -DangerousOnly
    Returns only dangerous ACEs on the AdminSDHolder object.

.EXAMPLE
    Get-ObjectACL -Identity "krbtgt" -Trustee "CONTOSO\helpdesk"
    Returns ACEs where helpdesk has permissions on krbtgt.

.EXAMPLE
    Get-DomainUser -AdminCount | Get-ObjectACL -DangerousOnly -ExcludeTrustee "NT AUTHORITY\SYSTEM"
    Batch analysis: Get dangerous ACEs on all admin users.

.EXAMPLE
    Get-ObjectACL -Identity $domainDN -ExtendedRight "DS-Replication-Get-Changes-All"
    Find who has DCSync rights on the domain.

.EXAMPLE
    Get-ObjectACL -Identity "OU=Servers,DC=contoso,DC=com" -WriteOnly -ExplicitOnly
    Find explicit write permissions on the Servers OU.

.OUTPUTS
    PSCustomObject with properties:
    - ObjectDN: Distinguished Name of the target object
    - ObjectClass: Object class (user, group, computer, etc.)
    - Owner: ACL owner (resolved name)
    - OwnerSID: ACL owner SID
    - ACEs: Array of filtered ACE objects

    Each ACE object contains:
    - AccessControlType: Allow/Deny
    - Trustee: Resolved trustee name
    - TrusteeSID: Trustee SID
    - Rights: Formatted rights string
    - RightsRaw: Array of individual rights
    - ObjectType: GUID of property/extended right (if applicable)
    - ObjectTypeName: Resolved name (if ResolveGUIDs)
    - InheritedObjectType: GUID for inheritance filter
    - IsInherited: Boolean indicating if ACE is inherited
    - InheritanceFlags: Inheritance flag details
    - PropagationFlags: Propagation flag details

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
    [CmdletBinding(DefaultParameterSetName='Identity')]
    param(
        [Parameter(Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, ParameterSetName='Identity')]
        [Alias('samAccountName', 'Name')]
        [string]$Identity,

        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='DN')]
        [Alias('DN')]
        [string]$DistinguishedName,

        # ACE Filters
        [Parameter(Mandatory=$false)]
        [string[]]$Trustee,

        [Parameter(Mandatory=$false)]
        [string[]]$ExcludeTrustee,

        [Parameter(Mandatory=$false)]
        [ValidateSet('GenericAll', 'GenericRead', 'GenericWrite', 'GenericExecute',
                     'CreateChild', 'DeleteChild', 'ListChildren', 'Self',
                     'ReadProperty', 'WriteProperty', 'DeleteTree', 'ListObject',
                     'ExtendedRight', 'Delete', 'ReadControl', 'WriteDacl', 'WriteOwner', 'Synchronize')]
        [string[]]$Rights,

        [Parameter(Mandatory=$false)]
        [string[]]$ExtendedRight,

        # Convenience Switches
        [Parameter(Mandatory=$false)]
        [switch]$DangerousOnly,

        [Parameter(Mandatory=$false)]
        [switch]$WriteOnly,

        [Parameter(Mandatory=$false)]
        [switch]$ExtendedRightsOnly,

        [Parameter(Mandatory=$false)]
        [switch]$ExplicitOnly,

        [Parameter(Mandatory=$false)]
        [switch]$AllowOnly,

        [Parameter(Mandatory=$false)]
        [switch]$DenyOnly,

        # Output Options
        [Parameter(Mandatory=$false)]
        [switch]$IncludeObjectInfo,

        [Parameter(Mandatory=$false)]
        [switch]$NoResolveGUIDs,

        [Parameter(Mandatory=$false)]
        [switch]$NoResolveSIDs,

        # Connection Parameters
        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential
    )

    begin {
        Write-Log "[Get-ObjectACL] Starting ACL enumeration"
    }

    process {
        try {
            # Build connection parameters
            $connectionParams = @{}
            if ($Domain) { $connectionParams['Domain'] = $Domain }
            if ($Server) { $connectionParams['Server'] = $Server }
            if ($Credential) { $connectionParams['Credential'] = $Credential }

            # Ensure LDAP connection
            if (-not (Ensure-LDAPConnection @connectionParams)) {
                return $null
            }

            # Determine target DN
            $targetDN = $null
            $targetObject = $null

            if ($DistinguishedName) {
                $targetDN = $DistinguishedName
            }
            elseif ($Identity) {
                # Check if Identity is already a DN
                if ($Identity -match '^(CN|OU|DC)=') {
                    $targetDN = $Identity
                }
                else {
                    # Resolve Identity to DN via Get-DomainObject
                    # Use -Raw to get nTSecurityDescriptor as byte[] instead of converted format
                    $targetObject = @(Get-DomainObject -Identity $Identity -Properties 'distinguishedName','objectClass','nTSecurityDescriptor' -Raw @connectionParams)[0]
                    if (-not $targetObject) {
                        Write-Warning "[Get-ObjectACL] Object not found: $Identity"
                        return $null
                    }
                    $targetDN = $targetObject.distinguishedName
                }
            }
            else {
                Write-Warning "[Get-ObjectACL] No Identity or DistinguishedName specified"
                return $null
            }

            Write-Log "[Get-ObjectACL] Target DN: $targetDN"

            # Get object with nTSecurityDescriptor if not already loaded
            if (-not $targetObject -or -not $targetObject.nTSecurityDescriptor) {
                # Use -Raw to get nTSecurityDescriptor as byte[] instead of converted format
                $targetObject = @(Get-DomainObject -Identity $targetDN -Properties 'distinguishedName','objectClass','nTSecurityDescriptor' -Raw @connectionParams)[0]
                if (-not $targetObject) {
                    Write-Warning "[Get-ObjectACL] Failed to retrieve object: $targetDN"
                    return $null
                }
            }

            # Check if nTSecurityDescriptor is available
            if (-not $targetObject.nTSecurityDescriptor) {
                Write-Warning "[Get-ObjectACL] No nTSecurityDescriptor available for: $targetDN (access denied or not present)"
                return $null
            }

            # Parse security descriptor
            $securityDescriptor = $targetObject.nTSecurityDescriptor

            # Handle if already parsed by Get-DomainObject -ShowACE
            if ($securityDescriptor -is [PSCustomObject] -and $securityDescriptor.ACEs) {
                $parsedSD = $securityDescriptor
            }
            elseif ($securityDescriptor -is [System.DirectoryServices.ActiveDirectorySecurity] -or
                    $securityDescriptor -is [byte[]] -or
                    ($securityDescriptor -is [System.Array] -and -not ($securityDescriptor -is [byte[]]))) {
                # Parse via shared helper (handles byte[], ActiveDirectorySecurity, and array-wrapped bytes)
                $sdParsed = ConvertTo-AccessRules -SecurityDescriptorBytes $securityDescriptor
                if (-not $sdParsed) {
                    Write-Warning "[Get-ObjectACL] Failed to parse nTSecurityDescriptor for: $targetDN"
                    return $null
                }

                $OwnerSID = $sdParsed.OwnerSID
                $OwnerName = if (-not $NoResolveSIDs) { ConvertFrom-SID -SID $OwnerSID } else { $OwnerSID }
                $DACL = $sdParsed.AccessRules

                # Parse ACEs with extended information
                $ACEList = @()

                foreach ($ACE in $DACL) {
                    $TrusteeSID = $ACE.IdentityReference.Value
                    $TrusteeName = if (-not $NoResolveSIDs) { ConvertFrom-SID -SID $TrusteeSID } else { $TrusteeSID }

                    # Parse rights
                    $RightsArray = @()
                    $ADRights = $ACE.ActiveDirectoryRights

                    # Use central AllActiveDirectoryRights from adPEAS-GUIDs.ps1
                    foreach ($Right in $Script:AllActiveDirectoryRights) {
                        # IMPORTANT: Check if ALL bits of the right are set, not just ANY overlap
                        # Using ($ADRights -band $Right) -eq $Right instead of just ($ADRights -band $Right)
                        # because the latter returns true if ANY bits match (e.g., ReadProperty 0x10
                        # would falsely match GenericAll 0xF01FF since they share bits)
                        if (($ADRights -band $Right) -eq $Right) {
                            $RightsArray += $Right.ToString()
                        }
                    }

                    # Resolve ObjectType GUID (extended rights, property sets)
                    $ObjectTypeGuid = if ($ACE.ObjectType -and $ACE.ObjectType -ne [System.Guid]::Empty) {
                        $ACE.ObjectType.ToString()
                    } else { $null }

                    $ObjectTypeName = $null
                    if ($ObjectTypeGuid -and (-not $NoResolveGUIDs)) {
                        # Use central GUID resolution from adPEAS-GUIDs.ps1
                        $ObjectTypeName = Get-ExtendedRightName -GUID $ObjectTypeGuid
                    }

                    # Add extended right name to rights array if applicable
                    if ($ObjectTypeName -and ($RightsArray -contains 'ExtendedRight')) {
                        $RightsArray = $RightsArray | Where-Object { $_ -ne 'ExtendedRight' }
                        $RightsArray += $ObjectTypeName
                    }

                    # InheritedObjectType
                    $InheritedObjectTypeGuid = if ($ACE.InheritedObjectType -and $ACE.InheritedObjectType -ne [System.Guid]::Empty) {
                        $ACE.InheritedObjectType.ToString()
                    } else { $null }

                    # Build ACE object with extended info
                    $ACEObj = [PSCustomObject]@{
                        AccessControlType    = $ACE.AccessControlType.ToString()
                        Trustee              = $TrusteeName
                        TrusteeSID           = $TrusteeSID
                        Rights               = ($RightsArray -join ', ')
                        RightsRaw            = $RightsArray
                        ObjectType           = $ObjectTypeGuid
                        ObjectTypeName       = $ObjectTypeName
                        InheritedObjectType  = $InheritedObjectTypeGuid
                        IsInherited          = $ACE.IsInherited
                        InheritanceFlags     = $ACE.InheritanceFlags.ToString()
                        PropagationFlags     = $ACE.PropagationFlags.ToString()
                    }

                    $ACEList += $ACEObj
                }

                $parsedSD = [PSCustomObject]@{
                    Owner    = $OwnerName
                    OwnerSID = $OwnerSID
                    ACEs     = $ACEList
                }
            }
            else {
                Write-Warning "[Get-ObjectACL] Unknown nTSecurityDescriptor format for: $targetDN (Type: $($securityDescriptor.GetType().FullName))"
                return $null
            }

            # Apply filters to ACEs
            $filteredACEs = $parsedSD.ACEs

            # Filter: AllowOnly / DenyOnly
            if ($AllowOnly) {
                $filteredACEs = $filteredACEs | Where-Object { $_.AccessControlType -eq 'Allow' }
            }
            if ($DenyOnly) {
                $filteredACEs = $filteredACEs | Where-Object { $_.AccessControlType -eq 'Deny' }
            }

            # Filter: ExplicitOnly (exclude inherited)
            if ($ExplicitOnly) {
                $filteredACEs = $filteredACEs | Where-Object { $_.IsInherited -eq $false }
            }

            # Filter: Trustee
            if ($Trustee) {
                $filteredACEs = $filteredACEs | Where-Object {
                    $ace = $_
                    $matchFound = $false
                    foreach ($t in $Trustee) {
                        if ($ace.Trustee -like $t -or $ace.TrusteeSID -like $t) {
                            $matchFound = $true
                            break
                        }
                    }
                    $matchFound
                }
            }

            # Filter: ExcludeTrustee
            if ($ExcludeTrustee) {
                $filteredACEs = $filteredACEs | Where-Object {
                    $ace = $_
                    $excluded = $false
                    foreach ($t in $ExcludeTrustee) {
                        if ($ace.Trustee -like $t -or $ace.TrusteeSID -like $t) {
                            $excluded = $true
                            break
                        }
                    }
                    -not $excluded
                }
            }

            # Filter: DangerousOnly
            if ($DangerousOnly) {
                $filteredACEs = $filteredACEs | Where-Object {
                    $ace = $_
                    $hasDangerous = $false
                    foreach ($right in $ace.RightsRaw) {
                        if ($Script:DangerousRights -contains $right) {
                            $hasDangerous = $true
                            break
                        }
                        # Also check for dangerous extended rights
                        if ($right -match 'DS-Replication|Force-Change-Password|All-Extended-Rights') {
                            $hasDangerous = $true
                            break
                        }
                    }
                    $hasDangerous
                }
            }

            # Filter: WriteOnly
            if ($WriteOnly) {
                $filteredACEs = $filteredACEs | Where-Object {
                    $ace = $_
                    $hasWrite = $false
                    foreach ($right in $ace.RightsRaw) {
                        if ($Script:WriteRights -contains $right) {
                            $hasWrite = $true
                            break
                        }
                    }
                    $hasWrite
                }
            }

            # Filter: ExtendedRightsOnly
            if ($ExtendedRightsOnly) {
                $filteredACEs = $filteredACEs | Where-Object {
                    ($_.RightsRaw -contains 'ExtendedRight') -or ($null -ne $_.ObjectTypeName)
                }
            }

            # Filter: Rights
            if ($Rights) {
                $filteredACEs = $filteredACEs | Where-Object {
                    $ace = $_
                    $hasRight = $false
                    foreach ($right in $Rights) {
                        if ($ace.RightsRaw -contains $right) {
                            $hasRight = $true
                            break
                        }
                    }
                    $hasRight
                }
            }

            # Filter: ExtendedRight (by name)
            if ($ExtendedRight) {
                $filteredACEs = $filteredACEs | Where-Object {
                    $ace = $_
                    $hasExtRight = $false
                    foreach ($extRight in $ExtendedRight) {
                        if ($ace.ObjectTypeName -like $extRight -or $ace.RightsRaw -contains $extRight) {
                            $hasExtRight = $true
                            break
                        }
                    }
                    $hasExtRight
                }
            }

            # Build result object
            $result = [PSCustomObject]@{
                ObjectDN    = $targetDN
                ObjectClass = if ($targetObject.objectClass) {
                    if ($targetObject.objectClass -is [array]) { $targetObject.objectClass[-1] }
                    else { $targetObject.objectClass }
                } else { "Unknown" }
                Owner       = $parsedSD.Owner
                OwnerSID    = $parsedSD.OwnerSID
                ACECount    = @($filteredACEs).Count
                ACEs        = @($filteredACEs)
            }

            Write-Log "[Get-ObjectACL] Found $($result.ACECount) ACE(s) after filtering for: $targetDN"

            return $result

        } catch {
            Write-Log "[Get-ObjectACL] Error: $_"
            Write-Error "[Get-ObjectACL] Failed to get ACL for object: $_"
            return $null
        }
    }

    end {
        Write-Log "[Get-ObjectACL] ACL enumeration completed"
    }
}
