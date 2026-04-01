<#
.SYNOPSIS
    Central GUID definitions for Active Directory Extended Rights and Properties.

.DESCRIPTION
    This module provides centralized GUID mappings used across all adPEAS modules for:
    - Extended Rights (DCSync, Password Reset, Certificate Enrollment, etc.)
    - Property GUIDs (LAPS, SPN, UAC, etc.)
    - Schema Class GUIDs

    All modules should use these central definitions instead of maintaining their own copies.
    This ensures consistency and simplifies maintenance.

    Reference: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb

.NOTES
    Author: Alexander Sturz (@_61106960_)
    This module must be loaded BEFORE any module that uses GUID lookups.
#>

# ============================================================================
# EXTENDED RIGHTS GUIDs (GUID -> Friendly Name)
# ============================================================================
# Used for resolving ObjectType GUIDs in ACEs to human-readable names
$Script:ExtendedRightsGUIDs = @{
    # === DCSync / Replication Rights ===
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes'
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes-All'
    '89e95b76-444d-4c62-991a-0facbeda640c' = 'DS-Replication-Get-Changes-In-Filtered-Set'
    '1131f6ab-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Synchronize'
    '1131f6ac-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Manage-Topology'

    # === Password / Credential Related ===
    '00299570-246d-11d0-a768-00aa006e0529' = 'User-Force-Change-Password'
    'ab721a53-1e2f-11d0-9819-00aa0040529b' = 'User-Change-Password'
    '5f202010-79a5-11d0-9020-00c04fc2d4cf' = 'User-Logon'
    '4c164200-20c0-11d0-a768-00aa006e0529' = 'User-Account-Restrictions'  # Also a Property Set (dual-use)

    # === Group Membership ===
    'bf9679c0-0de6-11d0-a285-00aa003049e2' = 'Self-Membership'

    # === Exchange / Mail Related ===
    'ab721a55-1e2f-11d0-9819-00aa0040529b' = 'Send-As'
    'ab721a56-1e2f-11d0-9819-00aa0040529b' = 'Receive-As'

    # === Certificate Services (ADCS) ===
    '0e10c968-78fb-11d2-90d4-00c04f79dc55' = 'Certificate-Enrollment'
    'a05b8cc2-17bc-4802-a710-e7c15ab866a2' = 'Certificate-AutoEnrollment'

    # === SPN / Kerberos Related ===
    'f3a64788-5306-11d1-a9c5-0000f80367c1' = 'Validated-SPN'
    '4d076c5f-8a3d-4f1b-b4e8-16f4e8c75fc1' = 'Validated-MS-DS-Behavior-Version'
    '80863791-dbe9-4eb8-837e-7f0ab55d9ac7' = 'Validated-MS-DS-Additional-DNS-Host-Name'

    # === Domain / Forest Trust ===
    'e48d0154-bcf8-11d1-8702-00c04fb96050' = 'Public-Information'  # Also a Property Set (dual-use)
    'ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501' = 'Unexpire-Password'
    '05c74c5e-4deb-43b4-bd9f-86664c2a7fd5' = 'Enable-Per-User-Reversibly-Encrypted-Password'

    # === DNS Related ===
    '72e39547-7b18-11d1-adef-00c04fd8d5cd' = 'DNS-Host-Name-Attributes'  # Also a Property Set (dual-use)

    # === GPO / Policy Related ===
    'f30e3bbe-9ff0-11d1-b603-0000f80367c1' = 'GP-Link'
    'f30e3bbf-9ff0-11d1-b603-0000f80367c1' = 'GP-Options'

    # === Computer Related ===
    '4828cc14-1437-45bc-9b07-ad6f015e5f28' = 'Allowed-To-Act-On-Behalf-Of-Other-Identity'
    '9923a32a-3607-11d2-b9be-0000f87a36b2' = 'DS-Install-Replica'
    '69ae6200-7f46-11d2-b9ad-00c04f79f805' = 'DS-Check-Stale-Phantoms'
    '2f16c4a5-b98e-432c-952a-cb388ba33f2e' = 'DS-Execute-Intentions-Script'

    # === Tombstone / Object Recovery ===
    '45ec5156-db7e-47bb-b53f-dbeb2d03c40f' = 'Reanimate-Tombstones'

    # === FSMO Role Transfer ===
    'e12b56b6-0a95-11d1-adbb-00c04fd8d5cd' = 'Change-Schema-Master'
    'd58d5f36-0a98-11d1-adbb-00c04fd8d5cd' = 'Change-Rid-Master'
    '014bf69c-7b3b-11d1-85f6-08002be74fab' = 'Change-PDC'
    'bae50096-4752-11d1-9052-00c04fc2d4cf' = 'Change-Infrastructure-Master'
    'fec364e0-0a98-11d1-adbb-00c04fd8d5cd' = 'Change-Domain-Master'

    # === General / Other ===
    'bc0ac240-79a9-11d0-9020-00c04fc2d4cf' = 'Add-GUID'  # Also Property Set 'Membership' (dual-use)
    '9432c620-033c-4db7-8b58-14ef6d0bf477' = 'Refresh-Group-Cache'
    '62dd28a8-7f46-11d2-b9ad-00c04f79f805' = 'Recalculate-Hierarchy'
    '1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd' = 'Allocate-Rids'
    '68b1d179-0d15-4d4f-ab71-46152e79a7bc' = 'Allowed-To-Authenticate'
    'edacfd8f-ffb3-11d1-b41d-00a0c968f939' = 'Apply-Group-Policy'
    'b7b1b3dd-ab09-4242-9e30-9980e5d322f7' = 'Generate-RSoP-Planning'
    'b7b1b3de-ab09-4242-9e30-9980e5d322f7' = 'Generate-RSoP-Logging'
    '280f369c-67c7-438e-ae98-1d46f3c6f541' = 'Migrate-SID-History'
    'ba33815a-4f93-4c76-87f3-57574bff8109' = 'Manage-Optional-Features'
    'e2a36dc9-ae17-47c3-b58b-be34c55ba633' = 'Create-Inbound-Forest-Trust'
    '3e0f7e18-2c7a-4c10-ba82-4d926db99a3e' = 'DS-Clone-Domain-Controller'

    # === All Extended Rights (special) ===
    '00000000-0000-0000-0000-000000000000' = 'All-Extended-Rights'
}

# ============================================================================
# PROPERTY GUIDs (Name -> GUID)
# ============================================================================
# Used for checking specific property access in ACLs
# NOTE: Only STATIC schemaIDGUIDs are listed here. Windows LAPS (msLAPS-*) GUIDs
#       are dynamically generated per Forest and cannot be statically defined.
$Script:PropertyGUIDs = @{
    # Legacy LAPS (Microsoft LAPS / AdmPwd) - STATIC GUIDs
    'ms-Mcs-AdmPwd'                  = [GUID]'e5c0983d-b71e-4f1d-b798-9b0f5ecaeea3'
    'ms-Mcs-AdmPwdExpirationTime'    = [GUID]'e5c0983e-b71e-4f1d-b798-9b0f5ecaeea3'

    # NOTE: Windows LAPS (msLAPS-*) schemaIDGUIDs are dynamically generated per Forest!
    # Use Get-ADObject to query them at runtime if needed:
    #   Get-ADObject -SearchBase (Get-ADRootDSE).SchemaNamingContext `
    #       -Filter {lDAPDisplayName -like 'msLAPS-*'} -Properties schemaIDGUID

    # Common properties (schemaIDGUIDs - actual attribute GUIDs)
    # NOTE: servicePrincipalName schemaIDGUID is the SAME GUID as Validated-SPN (f3a64788-...).
    # This is AD dual-use by design: the ACE type (WriteProperty vs Self) determines the interpretation.
    'servicePrincipalName'           = [GUID]'f3a64788-5306-11d1-a9c5-0000f80367c1'
    'userAccountControl'             = [GUID]'bf967a68-0de6-11d0-a285-00aa003049e2'
    'member'                         = [GUID]'bf9679c0-0de6-11d0-a285-00aa003049e2'
    'scriptPath'                     = [GUID]'bf9679a8-0de6-11d0-a285-00aa003049e2'
    'msDS-AllowedToDelegateTo'       = [GUID]'800d94d7-b7a1-42a1-b14d-7cae1423d07f'
    'msDS-AllowedToActOnBehalfOfOtherIdentity' = [GUID]'3f78c3e5-f79a-46bd-a0b8-9d18116ddc79'
    'gPLink'                         = [GUID]'f30e3bbe-9ff0-11d1-b603-0000f80367c1'
    'dNSHostName'                    = [GUID]'72e39547-7b18-11d1-adef-00c04fd8d5cd'  # DNS hostname attribute

    # gMSA (Group Managed Service Account) password attribute
    'msDS-ManagedPassword'           = [GUID]'e362ed86-b728-0842-b27d-2dea7a9df218'

    # Shadow Credentials (CVE-2022-26923, Key Trust attack)
    # schemaIdGuid per MS-ADA2: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/45916e5b-d66f-444e-b1e5-5b0666ed4d66
    'msDS-KeyCredentialLink'         = [GUID]'5b47d60f-6090-40b2-9f37-2a4de88f3063'
}

# ============================================================================
# PROPERTY SET GUIDs (Name -> GUID)
# ============================================================================
# Property Sets are groups of attributes that can be granted permissions as a unit.
# When an ACE ObjectType matches a Property Set GUID, it grants access to ALL
# attributes in that set. These are different from individual attribute GUIDs!
# Reference: https://learn.microsoft.com/en-us/windows/win32/adschema/property-sets
$Script:PropertySetGUIDs = @{
    # User-Account-Restrictions - Contains: userAccountControl, pwdLastSet, accountExpires, etc.
    # CRITICAL: WriteProperty on this grants control over UAC flags!
    'User-Account-Restrictions'      = [GUID]'4c164200-20c0-11d0-a768-00aa006e0529'

    # DNS-Host-Name-Attributes - Contains: dNSHostName, msDS-AdditionalDnsHostName
    # WriteProperty enables Kerberos relay attacks
    'DNS-Host-Name-Attributes'       = [GUID]'72e39547-7b18-11d1-adef-00c04fd8d5cd'

    # Public-Information - General public attributes
    'Public-Information'             = [GUID]'e48d0154-bcf8-11d1-8702-00c04fb96050'

    # Personal-Information - Personal user attributes
    'Personal-Information'           = [GUID]'77b5b886-944a-11d1-aebd-0000f80367c1'

    # General-Information - General object info
    'General-Information'            = [GUID]'59ba2f42-79a2-11d0-9020-00c04fc2d3cf'

    # Membership - Group membership related
    'Membership'                     = [GUID]'bc0ac240-79a9-11d0-9020-00c04fc2d4cf'
}

# ============================================================================
# VALIDATED WRITE GUIDs (Name -> GUID)
# ============================================================================
# Validated Writes are special "Self" rights that allow controlled self-modification.
# These use the "Self" right type with a specific ObjectType GUID.
# NOTE: Validated-SPN shares the same GUID as servicePrincipalName attribute (AD dual-use by design).
$Script:ValidatedWriteGUIDs = @{
    # Validated-SPN - Allows writing to servicePrincipalName with validation
    # This is what's commonly granted for SPN modification, NOT direct WriteProperty on SPN
    'Validated-SPN'                  = [GUID]'f3a64788-5306-11d1-a9c5-0000f80367c1'

    # Validated-DNS-Host-Name - Allows writing to dNSHostName with validation
    'Validated-DNS-Host-Name'        = [GUID]'72e39547-7b18-11d1-adef-00c04fd8d5cd'

    # Validated-MS-DS-Behavior-Version
    'Validated-MS-DS-Behavior-Version' = [GUID]'4d076c5f-8a3d-4f1b-b4e8-16f4e8c75fc1'

    # Validated-MS-DS-Additional-DNS-Host-Name
    'Validated-MS-DS-Additional-DNS-Host-Name' = [GUID]'80863791-dbe9-4eb8-837e-7f0ab55d9ac7'
}

# ============================================================================
# SCHEMA CLASS GUIDs (Name -> GUID)
# ============================================================================
# Used for checking InheritedObjectType in ACEs to determine which object class the ACE applies to. These are schemaIDGUIDs from the AD Schema.
$Script:SchemaClassGUIDs = @{
    # Core object classes
    'user'                           = [GUID]'bf967aba-0de6-11d0-a285-00aa003049e2'
    'computer'                       = [GUID]'bf967a86-0de6-11d0-a285-00aa003049e2'
    'group'                          = [GUID]'bf967a9c-0de6-11d0-a285-00aa003049e2'
    'organizationalUnit'             = [GUID]'bf967aa5-0de6-11d0-a285-00aa003049e2'
    'domain'                         = [GUID]'19195a5a-6da0-11d0-afd3-00c04fd930c9'
    'domainDNS'                      = [GUID]'19195a5b-6da0-11d0-afd3-00c04fd930c9'

    # Service accounts
    'msDS-GroupManagedServiceAccount' = [GUID]'7b8b558a-93a5-4af7-adca-c017e67f1057'
    'msDS-ManagedServiceAccount'     = [GUID]'ce206244-5827-4a86-ba1c-1c0c386c1b64'

    # Certificate Services
    'pKICertificateTemplate'         = [GUID]'e5209ca2-3bba-11d2-90cc-00c04fd91ab1'
    'pKIEnrollmentService'           = [GUID]'ee4aa692-3bba-11d2-90cc-00c04fd91ab1'
    'certificationAuthority'         = [GUID]'3fdfee50-47f4-11d1-a9c3-0000f80367c1'

    # GPO
    'groupPolicyContainer'           = [GUID]'f30e3bc2-9ff0-11d1-b603-0000f80367c1'

    # Trust
    'trustedDomain'                  = [GUID]'bf967ab8-0de6-11d0-a285-00aa003049e2'

    # Contact (non-security principal)
    'contact'                        = [GUID]'5cb41ed0-0e4c-11d0-a286-00aa003049e2'
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

<#
.SYNOPSIS
    Resolves an Extended Rights GUID to its friendly name.
.DESCRIPTION
    Looks up a GUID in the central ExtendedRightsGUIDs hashtable and returns the human-readable name. Returns $null if the GUID is not found.
.PARAMETER GUID
    The GUID string to resolve (e.g., '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2').
.EXAMPLE
    Get-ExtendedRightName -GUID '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
    Returns: 'DS-Replication-Get-Changes'
.OUTPUTS
    String - The friendly name of the extended right, or $null if not found.
#>
function Get-ExtendedRightName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$GUID
    )

    if ([string]::IsNullOrEmpty($GUID)) {
        return $null
    }

    # Normalize GUID (lowercase, no braces)
    $normalizedGUID = $GUID.ToLower().Trim('{}')

    if ($Script:ExtendedRightsGUIDs.ContainsKey($normalizedGUID)) {
        return $Script:ExtendedRightsGUIDs[$normalizedGUID]
    }

    return $null
}

<#
.SYNOPSIS
    Gets the GUID for a named Extended Right.
.DESCRIPTION
    Looks up an Extended Right name in the central ExtendedRightsGUIDs hashtable and returns the corresponding GUID object. This is the reverse lookup of
    Get-ExtendedRightName.
.PARAMETER Name
    The Extended Right name (e.g., 'User-Force-Change-Password', 'DS-Replication-Get-Changes').
.EXAMPLE
    Get-ExtendedRightGUID -Name 'User-Force-Change-Password'
    Returns: [GUID] object for the password reset extended right
.OUTPUTS
    GUID object or $null if not found.
#>
function Get-ExtendedRightGUID {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name
    )

    # Search through ExtendedRightsGUIDs (which is GUID -> Name) for matching name
    foreach ($entry in $Script:ExtendedRightsGUIDs.GetEnumerator()) {
        if ($entry.Value -eq $Name) {
            return [GUID]$entry.Key
        }
    }

    return $null
}

<#
.SYNOPSIS
    Resolves a Schema Class GUID to its friendly name.
.DESCRIPTION
    Looks up a GUID in the central SchemaClassGUIDs hashtable and returns the human-readable class name.
.PARAMETER GUID
    The GUID to resolve (as string or GUID object).
.EXAMPLE
    Get-SchemaClassName -GUID 'bf967a86-0de6-11d0-a285-00aa003049e2'
    Returns: 'computer'
.OUTPUTS
    String - The class name, or $null if not found.
#>
function Get-SchemaClassName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $GUID
    )

    if (-not $GUID -or $GUID -eq [GUID]::Empty) {
        return 'All Objects'
    }

    # Normalize to GUID string
    $guidString = if ($GUID -is [GUID]) { $GUID.ToString() } else { $GUID.ToString().Trim('{}').ToLower() }

    foreach ($entry in $Script:SchemaClassGUIDs.GetEnumerator()) {
        if ($entry.Value.ToString() -eq $guidString) {
            return $entry.Key
        }
    }

    return $null
}

<#
.SYNOPSIS
    Resolves a Property Set GUID to its friendly name.
.DESCRIPTION
    Looks up a GUID in the central PropertySetGUIDs hashtable and returns the human-readable name.
.PARAMETER GUID
    The GUID to resolve (as string or GUID object).
.EXAMPLE
    Get-PropertySetName -GUID '4c164200-20c0-11d0-a768-00aa006e0529'
    Returns: 'User-Account-Restrictions'
.OUTPUTS
    String - The property set name, or $null if not found.
#>
function Get-PropertySetName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $GUID
    )

    if (-not $GUID -or $GUID -eq [GUID]::Empty) {
        return $null
    }

    # Normalize to GUID string
    $guidString = if ($GUID -is [GUID]) { $GUID.ToString().ToLower() } else { $GUID.ToString().Trim('{}').ToLower() }

    foreach ($entry in $Script:PropertySetGUIDs.GetEnumerator()) {
        if ($entry.Value.ToString().ToLower() -eq $guidString) {
            return $entry.Key
        }
    }

    return $null
}

<#
.SYNOPSIS
    Resolves a Validated Write GUID to its friendly name.
.DESCRIPTION
    Looks up a GUID in the central ValidatedWriteGUIDs hashtable and returns the human-readable name.
.PARAMETER GUID
    The GUID to resolve (as string or GUID object).
.EXAMPLE
    Get-ValidatedWriteName -GUID 'f3a64788-5306-11d1-a9c5-0000f80367c1'
    Returns: 'Validated-SPN'
.OUTPUTS
    String - The validated write name, or $null if not found.
#>
function Get-ValidatedWriteName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $GUID
    )

    if (-not $GUID -or $GUID -eq [GUID]::Empty) {
        return $null
    }

    # Normalize to GUID string
    $guidString = if ($GUID -is [GUID]) { $GUID.ToString().ToLower() } else { $GUID.ToString().Trim('{}').ToLower() }

    foreach ($entry in $Script:ValidatedWriteGUIDs.GetEnumerator()) {
        if ($entry.Value.ToString().ToLower() -eq $guidString) {
            return $entry.Key
        }
    }

    return $null
}

<#
.SYNOPSIS
    Resolves any ObjectType GUID to its type and friendly name.
.DESCRIPTION
    Comprehensive lookup that checks Extended Rights, Property Sets, Validated Writes,
    Properties, and Schema Classes to identify what an ACE ObjectType GUID represents.
.PARAMETER GUID
    The GUID to resolve (as string or GUID object).
.EXAMPLE
    Resolve-ObjectTypeGUID -GUID 'f3a64788-5306-11d1-a9c5-0000f80367c1'
    Returns: @{ Type = 'ValidatedWrite'; Name = 'Validated-SPN' }
.OUTPUTS
    Hashtable with Type and Name, or $null if not found.
#>
function Resolve-ObjectTypeGUID {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $GUID
    )

    if (-not $GUID -or $GUID -eq [GUID]::Empty) {
        return @{ Type = 'All'; Name = 'All Objects/Properties' }
    }

    # Normalize to GUID string
    $guidString = if ($GUID -is [GUID]) { $GUID.ToString().ToLower() } else { $GUID.ToString().Trim('{}').ToLower() }

    # Check Extended Rights first (most common in security ACEs)
    $extRightName = Get-ExtendedRightName -GUID $guidString
    if ($extRightName) {
        return @{ Type = 'ExtendedRight'; Name = $extRightName }
    }

    # Check Property Sets
    $propSetName = Get-PropertySetName -GUID $guidString
    if ($propSetName) {
        return @{ Type = 'PropertySet'; Name = $propSetName }
    }

    # Check Validated Writes
    $validatedWriteName = Get-ValidatedWriteName -GUID $guidString
    if ($validatedWriteName) {
        return @{ Type = 'ValidatedWrite'; Name = $validatedWriteName }
    }

    # Check Schema Classes (for InheritedObjectType)
    $schemaClassName = Get-SchemaClassName -GUID $guidString
    if ($schemaClassName) {
        return @{ Type = 'SchemaClass'; Name = $schemaClassName }
    }

    # Check Properties (attribute schemaIDGUIDs)
    foreach ($entry in $Script:PropertyGUIDs.GetEnumerator()) {
        if ($entry.Value.ToString().ToLower() -eq $guidString) {
            return @{ Type = 'Property'; Name = $entry.Key }
        }
    }

    return $null
}

# ============================================================================
# AD RIGHTS DEFINITIONS (for ACL analysis)
# ============================================================================
# These lists define which ActiveDirectoryRights are considered dangerous or write-related. Used by Get-ObjectACL, Get-DomainGPO, Get-ADCSVulnerabilities.

<#
.SYNOPSIS
    List of dangerous AD rights that can lead to privilege escalation.
.DESCRIPTION
    These rights, when granted to non-privileged principals, can be abused for attacks like DCSync, password changes, object takeover, etc.
#>
$Script:DangerousRights = @(
    'GenericAll',       # Full control - most dangerous
    'GenericWrite',     # Can modify most attributes
    'WriteDacl',        # Can modify ACL - grant self more permissions
    'WriteOwner',       # Can take ownership - then modify ACL
    'WriteProperty',    # Can write specific attributes (depends on ObjectType)
    'Self',             # Validated writes (e.g., add self to group)
    'ExtendedRight',    # Extended rights like DCSync, password reset
    'Delete',           # Can delete the object
    'DeleteTree',       # Can delete object and all children
    'CreateChild',      # Can create child objects (e.g., new computer)
    'DeleteChild'       # Can delete child objects
)

<#
.SYNOPSIS
    List of AD rights that grant write access.
.DESCRIPTION
    Subset of DangerousRights focused specifically on write permissions.
    Used for -WriteOnly filtering in ACL analysis.
#>
$Script:WriteRights = @(
    'GenericAll',       # Includes all permissions including write
    'GenericWrite',     # General write access
    'WriteDacl',        # Write to security descriptor
    'WriteOwner',       # Change owner
    'WriteProperty'     # Write to properties
)

<#
.SYNOPSIS
    List of generic dangerous rights (without extended rights).
.DESCRIPTION
    Core dangerous rights used in ADCS vulnerability checks.
    These are the "generic" dangerous permissions without ExtendedRight.
#>
$Script:GenericDangerousRights = @(
    'GenericAll',
    'GenericWrite',
    'WriteDacl',
    'WriteOwner'
)

# ============================================================================
# ALL ACTIVE DIRECTORY RIGHTS (Enum values for ACE parsing)
# ============================================================================
# Complete list of all ActiveDirectoryRights enum values.
# Used for bitmask parsing of ACE.ActiveDirectoryRights field.
# Each value is an enum that can be used with bitwise AND (-band) operations.

<#
.SYNOPSIS
    Complete array of all ActiveDirectoryRights enum values.
.DESCRIPTION
    This array contains all 18 ActiveDirectoryRights enum values for parsing ACEs in security descriptors.
    Used by Get-ObjectACL, Get-DomainGPO, Get-DomainObject, and ConvertTo-FormattedACE for bitmask operations.

    The ActiveDirectoryRights field in an ACE is a bitmask, so multiple rights
    can be set simultaneously. Use bitwise AND to check: ($ADRights -band $Right) -eq $Right

    Reference: https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights
#>
$Script:AllActiveDirectoryRights = @(
    [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
    [System.DirectoryServices.ActiveDirectoryRights]::GenericRead,
    [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite,
    [System.DirectoryServices.ActiveDirectoryRights]::GenericExecute,
    [System.DirectoryServices.ActiveDirectoryRights]::CreateChild,
    [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild,
    [System.DirectoryServices.ActiveDirectoryRights]::ListChildren,
    [System.DirectoryServices.ActiveDirectoryRights]::Self,
    [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty,
    [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
    [System.DirectoryServices.ActiveDirectoryRights]::DeleteTree,
    [System.DirectoryServices.ActiveDirectoryRights]::ListObject,
    [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
    [System.DirectoryServices.ActiveDirectoryRights]::Delete,
    [System.DirectoryServices.ActiveDirectoryRights]::ReadControl,
    [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl,
    [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner,
    [System.DirectoryServices.ActiveDirectoryRights]::Synchronize
)

# ============================================================================
# Extended Rights Aliases (for SET operations via Set-DomainObject)
# ============================================================================
<#
.SYNOPSIS
    User-friendly aliases for Extended Rights GUIDs.
.DESCRIPTION
    Maps common operation names to their corresponding Extended Rights GUIDs.
    Used by Set-DomainObject for granting/revoking Extended Rights.

    NOTE: These are ACTUAL Extended Rights (controlAccessRight objects in AD schema).
    They use ExtendedRight ACE type in security descriptors.
#>
$Script:ExtendedRightsAliases = @{
    # === DCSync (Critical - grants ALL 3 required rights!) ===
    'DCSync' = @(
        '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',  # DS-Replication-Get-Changes
        '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',  # DS-Replication-Get-Changes-All
        '89e95b76-444d-4c62-991a-0facbeda640c'   # DS-Replication-Get-Changes-In-Filtered-Set
    )

    # === Password Manipulation ===
    'ForceChangePassword' = '00299570-246d-11d0-a768-00aa006e0529'  # User-Force-Change-Password
    'ResetPassword'       = '00299570-246d-11d0-a768-00aa006e0529'  # Alias for ForceChangePassword

    # === Exchange Rights ===
    'SendAs'    = 'ab721a55-1e2f-11d0-9819-00aa0040529b'  # Send-As
    'ReceiveAs' = 'ab721a56-1e2f-11d0-9819-00aa0040529b'  # Receive-As

    # === Certificate Enrollment (ADCS Abuse) ===
    'CertificateEnrollment'     = '0e10c968-78fb-11d2-90d4-00c04f79dc55'  # Certificate-Enrollment
    'CertificateAutoEnrollment' = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'  # Certificate-AutoEnrollment
    'CertEnroll'  = '0e10c968-78fb-11d2-90d4-00c04f79dc55'  # Alias
    'AutoEnroll'  = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'  # Alias

    # === Kerberos Authentication ===
    'AllowedToAuthenticate' = '68b1d179-0d15-4d4f-ab71-46152e79a7bc'  # Allowed-To-Authenticate

    # === SID History Injection (Direct Priv-Esc!) ===
    'MigrateSIDHistory' = '280f369c-67c7-438e-ae98-1d46f3c6f541'  # Migrate-SID-History (CORRECTED!)
    'SIDHistory'        = '280f369c-67c7-438e-ae98-1d46f3c6f541'  # Alias

    # === RBCD (Resource-Based Constrained Delegation) ===
    'RBCD' = '4828cc14-1437-45bc-9b07-ad6f015e5f28'  # Allowed-To-Act-On-Behalf-Of-Other-Identity
    'AllowedToActOnBehalfOfOtherIdentity' = '4828cc14-1437-45bc-9b07-ad6f015e5f28'  # Full name alias

    # === Password Storage (Dangerous!) ===
    'ReversibleEncryption' = '05c74c5e-4deb-43b4-bd9f-86664c2a7fd5'  # Enable-Per-User-Reversibly-Encrypted-Password

    # === Replication ===
    'ReplicateDirectory' = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes
    'InstallReplica'     = '9923a32a-3607-11d2-b9be-0000f87a36b2'  # DS-Install-Replica
    'CloneDC'            = '3e0f7e18-2c7a-4c10-ba82-4d926db99a3e'  # DS-Clone-Domain-Controller

    # === GPO Manipulation ===
    'ApplyGroupPolicy' = 'edacfd8f-ffb3-11d1-b41d-00a0c968f939'  # Apply-Group-Policy
    'GPOLink'          = 'f30e3bbe-9ff0-11d1-b603-0000f80367c1'  # GP-Link (link GPO to OU) (CORRECTED!)
    'CreateGPOLink'    = 'f30e3bbe-9ff0-11d1-b603-0000f80367c1'  # Alias for GP-Link
    'GPOOptions'       = 'f30e3bbf-9ff0-11d1-b603-0000f80367c1'  # GP-Options (enforce/block inheritance)

    # === RSoP ===
    'GenerateRSoPLogging'  = 'b7b1b3de-ab09-4242-9e30-9980e5d322f7'  # Generate-RSoP-Logging
    'GenerateRSoPPlanning' = 'b7b1b3dd-ab09-4242-9e30-9980e5d322f7'  # Generate-RSoP-Planning

    # === Tombstone Reanimation ===
    'ReanimateTombstones' = '45ec5156-db7e-47bb-b53f-dbeb2d03c40f'  # Reanimate-Tombstones

    # === FSMO Role Seizure (Domain Takeover!) ===
    'SeizeRidMaster'    = 'd58d5f36-0a98-11d1-adbb-00c04fd8d5cd'  # Change-Rid-Master
    'SeizePDC'          = '014bf69c-7b3b-11d1-85f6-08002be74fab'  # Change-PDC
    'SeizeInfrastructure' = 'bae50096-4752-11d1-9052-00c04fc2d4cf'  # Change-Infrastructure-Master
    'SeizeSchemaMaster' = 'e12b56b6-0a95-11d1-adbb-00c04fd8d5cd'  # Change-Schema-Master
    'SeizeDomainMaster' = 'fec364e0-0a98-11d1-adbb-00c04fd8d5cd'  # Change-Domain-Master (Naming Master)

    # === All Extended Rights (Dangerous!) ===
    'AllExtendedRights' = '00000000-0000-0000-0000-000000000000'  # Grants ALL extended rights!
}

# ============================================================================
# WriteProperty Aliases (for SET operations via Set-DomainObject)
# ============================================================================
<#
.SYNOPSIS
    User-friendly aliases for WriteProperty GUIDs.
.DESCRIPTION
    Maps common operation names to their corresponding attribute schemaIDGUIDs.
    Used by Set-DomainObject for granting WriteProperty permissions on specific attributes.

    NOTE: These use WriteProperty ACE type, NOT ExtendedRight!
    The GUID is the schemaIDGUID of the attribute being written.
#>
$Script:WritePropertyAliases = @{
    # === Group Membership ===
    # bf9679c0-0de6-11d0-a285-00aa003049e2 = schemaIDGUID of 'member' attribute
    'AddMember'      = 'bf9679c0-0de6-11d0-a285-00aa003049e2'  # member
    'WriteMembers'   = 'bf9679c0-0de6-11d0-a285-00aa003049e2'  # Alias

    # === Kerberos / SPN Manipulation (Kerberoasting Setup) ===
    'WriteSPN'            = 'f3a64788-5306-11d1-a9c5-0000f80367c1'  # servicePrincipalName
    'SetSPN'              = 'f3a64788-5306-11d1-a9c5-0000f80367c1'  # Alias (common pentesting term)

    # === Account Control (Enable Delegation, Disable PreAuth, etc.) ===
    'WriteAccountControl' = 'bf967a68-0de6-11d0-a285-00aa003049e2'  # userAccountControl
    'WriteUAC'            = 'bf967a68-0de6-11d0-a285-00aa003049e2'  # Alias

    # === RBCD (Resource-Based Constrained Delegation) ===
    # Write access to this attribute = RBCD attack
    'WriteRBCD'           = '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79'  # msDS-AllowedToActOnBehalfOfOtherIdentity

    # === Constrained Delegation Target List ===
    # Write access = set delegation targets (e.g., add cifs/dc01)
    'WriteAllowedToDelegateTo' = '800d94d7-b7a1-42a1-b14d-7cae1423d07f'  # msDS-AllowedToDelegateTo

    # === Shadow Credentials (CVE-2022-26923, Key Trust Attack) ===
    # Write access = add malicious key credential for PKINIT
    'WriteKeyCredentialLink'   = '5b47d60f-6090-40b2-9f37-2a4de88f3063'  # msDS-KeyCredentialLink
    'ShadowCredentials'        = '5b47d60f-6090-40b2-9f37-2a4de88f3063'  # Alias (common pentesting term)

    # === GPO Link Manipulation (GPO Hijacking) ===
    # Write access to gPLink on OU = link malicious GPO
    'WriteGPLink'         = 'f30e3bbe-9ff0-11d1-b603-0000f80367c1'  # gPLink

    # === Logon Script Hijacking ===
    # Write access = replace user's logon script
    'WriteScriptPath'     = 'bf9679a8-0de6-11d0-a285-00aa003049e2'  # scriptPath

    # === DNS Host Name (Kerberos Relay, Machine Account Quota Abuse) ===
    # Write access = change DNS hostname for Kerberos relay attacks
    'WriteDNSHostName'    = '72e39547-7b18-11d1-adef-00c04fd8d5cd'  # dNSHostName
}

# ============================================================================
# ReadProperty Aliases (for SET operations via Set-DomainObject)
# ============================================================================
<#
.SYNOPSIS
    User-friendly aliases for ReadProperty GUIDs.
.DESCRIPTION
    Maps common operation names to their corresponding attribute schemaIDGUIDs.
    Used by Set-DomainObject for granting ReadProperty permissions on specific attributes.

    NOTE: These use ReadProperty ACE type, NOT ExtendedRight or WriteProperty!
    The GUID is the schemaIDGUID of the attribute being read.
#>
$Script:ReadPropertyAliases = @{
    # === LAPS Passwords ===
    # ms-Mcs-AdmPwd - Local Administrator Password (LAPS v1)
    # schemaIDGUID: e5c0983d-b71e-4f1d-b798-9b0f5ecaeea3
    'ReadLAPSPassword'    = 'e5c0983d-b71e-4f1d-b798-9b0f5ecaeea3'

    # ms-Mcs-AdmPwdExpirationTime - LAPS Password Expiration Time
    # schemaIDGUID: e5c0983e-b71e-4f1d-b798-9b0f5ecaeea3
    'ReadLAPSExpiration'  = 'e5c0983e-b71e-4f1d-b798-9b0f5ecaeea3'

    # === Windows LAPS (v2) - Windows Server 2019+ ===
    # msLAPS-Password - Encrypted LAPS password (Windows LAPS)
    # schemaIDGUID: 35eb61e8-0ae2-4e1a-b60f-f6aa82d54867
    'ReadWindowsLAPSPassword'       = '35eb61e8-0ae2-4e1a-b60f-f6aa82d54867'

    # msLAPS-EncryptedPassword - Encrypted LAPS password blob
    # schemaIDGUID: cc635e81-fda1-4e92-96d2-cf5d9a958a4f
    'ReadWindowsLAPSEncrypted'      = 'cc635e81-fda1-4e92-96d2-cf5d9a958a4f'

    # msLAPS-EncryptedPasswordHistory - Encrypted password history
    # schemaIDGUID: b0449bea-a05e-47eb-b1ce-a1c72b9c4a89
    'ReadWindowsLAPSHistory'        = 'b0449bea-a05e-47eb-b1ce-a1c72b9c4a89'

    # msLAPS-EncryptedDSRMPassword - DSRM password for DCs
    # schemaIDGUID: 64397849-c0bb-47e5-9eb4-a13cc22ee13c
    'ReadWindowsLAPSDSRM'           = '64397849-c0bb-47e5-9eb4-a13cc22ee13c'

    # msLAPS-EncryptedDSRMPasswordHistory - DSRM password history
    # schemaIDGUID: ddb68b4d-8037-4dbe-8721-fcc3d59b57a7
    'ReadWindowsLAPSDSRMHistory'    = 'ddb68b4d-8037-4dbe-8721-fcc3d59b57a7'

    # === Password Hashes (DCSync alternative - direct read) ===
    # unicodePwd - NT password hash (requires special permissions)
    # schemaIDGUID: bf9679e1-0de6-11d0-a285-00aa003049e2
    'ReadUnicodePwd'      = 'bf9679e1-0de6-11d0-a285-00aa003049e2'
    'ReadNTPassword'      = 'bf9679e1-0de6-11d0-a285-00aa003049e2'  # Alias

    # ntPwdHistory - NT password hash history
    # schemaIDGUID: a8df7489-c5ea-11d1-bbcb-0080c76670c0
    'ReadNTHash'          = 'a8df7489-c5ea-11d1-bbcb-0080c76670c0'
    'ReadNTPwdHistory'    = 'a8df7489-c5ea-11d1-bbcb-0080c76670c0'  # Alias

    # lmPwdHistory - LM password hash history (legacy)
    # schemaIDGUID: bf9679d5-0de6-11d0-a285-00aa003049e2
    'ReadLMHash'          = 'bf9679d5-0de6-11d0-a285-00aa003049e2'
    'ReadLMPwdHistory'    = 'bf9679d5-0de6-11d0-a285-00aa003049e2'  # Alias

    # === Unix/POSIX Passwords ===
    # unixUserPassword - Unix password for Services for Unix
    # schemaIDGUID: 612cb747-c0e8-4f92-9221-fdd5f15b550d
    'ReadUnixPassword'    = '612cb747-c0e8-4f92-9221-fdd5f15b550d'

    # userPassword - LDAP standard password attribute
    # schemaIDGUID: bf9679e0-0de6-11d0-a285-00aa003049e2
    'ReadUserPassword'    = 'bf9679e0-0de6-11d0-a285-00aa003049e2'

    # === Credential Roaming ===
    # msPKI-RoamingTimeStamp - Credential Roaming timestamp
    # schemaIDGUID: 91e647de-d96f-4b70-9557-d63ff4f3ccd8
    'ReadRoamingTimestamp'       = '91e647de-d96f-4b70-9557-d63ff4f3ccd8'

    # msPKI-DPAPIMasterKeys - DPAPI Master Keys (credential roaming)
    # schemaIDGUID: b3f93023-9239-4f7c-b99c-6745d87adbc2
    'ReadDPAPIMasterKeys'        = 'b3f93023-9239-4f7c-b99c-6745d87adbc2'

    # msPKI-AccountCredentials - Account credentials blob
    # schemaIDGUID: b8dfa744-31dc-4ef1-ac7c-84baf7ef9da7
    'ReadAccountCredentials'     = 'b8dfa744-31dc-4ef1-ac7c-84baf7ef9da7'

    # === gMSA Passwords ===
    # msDS-ManagedPassword - Group Managed Service Account password
    # schemaIDGUID: e362ed86-b728-0842-b27d-2dea7a9df218
    'ReadGMSAPassword'    = 'e362ed86-b728-0842-b27d-2dea7a9df218'

    # msDS-GroupMSAMembership - Who can read gMSA password
    # schemaIDGUID: 888eedd6-ce04-df40-b462-b8a50e41ba38
    'ReadGMSAMembership'  = '888eedd6-ce04-df40-b462-b8a50e41ba38'

    # === BitLocker Recovery ===
    # msFVE-RecoveryPassword - BitLocker recovery password
    # schemaIDGUID: 43061ac1-c8ad-4ccc-b785-2bfac20fc60a
    'ReadBitLockerRecoveryPassword' = '43061ac1-c8ad-4ccc-b785-2bfac20fc60a'

    # msFVE-KeyPackage - BitLocker key package
    # schemaIDGUID: 1fd55ea8-88a7-47dc-8129-0daa97186a54
    'ReadBitLockerKeyPackage'       = '1fd55ea8-88a7-47dc-8129-0daa97186a54'
}

# ============================================================================
# Well-Known Relative Identifiers (RIDs)
# ============================================================================
<#
.SYNOPSIS
    Maps well-known RIDs to their friendly names for FOREIGN domain SIDs.
.DESCRIPTION
    Domain-relative RIDs that have standard meanings across all AD domains.
    Used by ConvertFrom-SID ONLY for resolving foreign domain SIDs when:
    - LDAP lookup fails (SID not in current domain)
    - Domain SID part differs from current domain (trusted/migrated domains)
    - SID appears in sIDHistory from old domain

    Output format: "FOREIGN\<RID-Name> (RID:<number>)"
    Example: "FOREIGN\Domain Admins (RID:512)"

    NOTE: For SIDs in the CURRENT domain, LDAP resolution is always used.
    This list is only a fallback for cross-domain/cross-forest scenarios.

    Reference: https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers
#>
$Script:WellKnownRIDs = @{
    # === Built-in User Accounts (RID 500-504) ===
    '500' = 'Administrator'
    '501' = 'Guest'
    '502' = 'krbtgt'
    '503' = 'DefaultAccount'
    '504' = 'WDAGUtilityAccount'

    # === Built-in Global Groups (RID 512-527) ===
    '512' = 'Domain Admins'
    '513' = 'Domain Users'
    '514' = 'Domain Guests'
    '515' = 'Domain Computers'
    '516' = 'Domain Controllers'
    '517' = 'Cert Publishers'
    '518' = 'Schema Admins'
    '519' = 'Enterprise Admins'
    '520' = 'Group Policy Creator Owners'
    '521' = 'Read-only Domain Controllers'
    '522' = 'Cloneable Domain Controllers'
    '523' = 'Allowed RODC Password Replication Group'   # Global scope (same name as RID 571)
    '524' = 'Denied RODC Password Replication Group'    # Global scope (same name as RID 572)
    '525' = 'Protected Users'
    '526' = 'Key Admins'
    '527' = 'Enterprise Key Admins'

    # === Domain Local Groups (RID 553+) ===
    '553' = 'RAS and IAS Servers'
    '571' = 'Allowed RODC Password Replication Group'   # Domain Local scope (same name as RID 523)
    '572' = 'Denied RODC Password Replication Group'    # Domain Local scope (same name as RID 524)
}

# ============================================================================
# Well-Known Security Identities
# ============================================================================
<#
.SYNOPSIS
    Canonical definition of all well-known security identities.
.DESCRIPTION
    This is the SINGLE SOURCE OF TRUTH for well-known SIDs and their names.
    All lookup tables ($Script:SIDToName, $Script:NameToSID) are auto-generated from this data structure.

    Structure:
    - SID: The Security Identifier string
    - Name: Canonical English name (with prefix like NT AUTHORITY\, BUILTIN\)
    - Short: Short form without prefix (optional, for common identities)

    Usage:
    - ConvertFrom-SID uses $Script:SIDToName for SID → Name resolution
    - ConvertTo-SID uses $Script:NameToSID for Name → SID resolution
    - Both tables are auto-generated at module load time

    Reference: https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers
#>
$Script:WellKnownIdentities = @(
    # Special Identities (S-1-0, S-1-1, S-1-2, S-1-3)
    @{ SID = 'S-1-0-0';     Name = 'Null Authority\Nobody' }
    @{ SID = 'S-1-1-0';     Name = 'Everyone' }
    @{ SID = 'S-1-2-0';     Name = 'Local' }
    @{ SID = 'S-1-2-1';     Name = 'Console Logon' }
    @{ SID = 'S-1-3-0';     Name = 'Creator Owner' }
    @{ SID = 'S-1-3-1';     Name = 'Creator Group' }
    @{ SID = 'S-1-3-2';     Name = 'Creator Owner Server' }
    @{ SID = 'S-1-3-3';     Name = 'Creator Group Server' }
    @{ SID = 'S-1-3-4';     Name = 'Owner Rights' }

    # NT AUTHORITY (S-1-5-x)
    # NOTE: Localized names (German NT-AUTORITÄT, French AUTORITE NT, etc.) are automatically resolved via NTAccount.Translate() in ConvertTo-SID.
    @{ SID = 'S-1-5-1';     Name = 'NT AUTHORITY\Dialup' }
    @{ SID = 'S-1-5-2';     Name = 'NT AUTHORITY\Network';        Short = 'Network' }
    @{ SID = 'S-1-5-3';     Name = 'NT AUTHORITY\Batch' }
    @{ SID = 'S-1-5-4';     Name = 'NT AUTHORITY\Interactive';    Short = 'Interactive' }
    @{ SID = 'S-1-5-6';     Name = 'NT AUTHORITY\Service';        Short = 'Service' }
    @{ SID = 'S-1-5-7';     Name = 'NT AUTHORITY\Anonymous';      Short = 'Anonymous' }
    @{ SID = 'S-1-5-8';     Name = 'NT AUTHORITY\Proxy' }
    @{ SID = 'S-1-5-9';     Name = 'NT AUTHORITY\Enterprise Domain Controllers' }
    @{ SID = 'S-1-5-10';    Name = 'NT AUTHORITY\Self';           Short = 'Self' }
    @{ SID = 'S-1-5-11';    Name = 'NT AUTHORITY\Authenticated Users'; Short = 'Authenticated Users' }
    @{ SID = 'S-1-5-12';    Name = 'NT AUTHORITY\Restricted';     Short = 'Restricted' }
    @{ SID = 'S-1-5-13';    Name = 'NT AUTHORITY\Terminal Server User' }
    @{ SID = 'S-1-5-14';    Name = 'NT AUTHORITY\Remote Interactive Logon' }
    @{ SID = 'S-1-5-15';    Name = 'NT AUTHORITY\This Organization' }
    @{ SID = 'S-1-5-17';    Name = 'NT AUTHORITY\IUSR' }
    @{ SID = 'S-1-5-18';    Name = 'NT AUTHORITY\SYSTEM';         Short = 'SYSTEM' }
    @{ SID = 'S-1-5-19';    Name = 'NT AUTHORITY\Local Service' }
    @{ SID = 'S-1-5-20';    Name = 'NT AUTHORITY\Network Service' }

    # BUILTIN Groups (S-1-5-32-xxx)
    # NOTE: Localized names (German VORDEFINIERT, French BUILTIN, etc.) are automatically resolved via NTAccount.Translate() in ConvertTo-SID.
    @{ SID = 'S-1-5-32-544'; Name = 'BUILTIN\Administrators';     Short = 'Administrators' }
    @{ SID = 'S-1-5-32-545'; Name = 'BUILTIN\Users';              Short = 'Users' }
    @{ SID = 'S-1-5-32-546'; Name = 'BUILTIN\Guests';             Short = 'Guests' }
    @{ SID = 'S-1-5-32-547'; Name = 'BUILTIN\Power Users' }
    @{ SID = 'S-1-5-32-548'; Name = 'BUILTIN\Account Operators';  Short = 'Account Operators' }
    @{ SID = 'S-1-5-32-549'; Name = 'BUILTIN\Server Operators';   Short = 'Server Operators' }
    @{ SID = 'S-1-5-32-550'; Name = 'BUILTIN\Print Operators';    Short = 'Print Operators' }
    @{ SID = 'S-1-5-32-551'; Name = 'BUILTIN\Backup Operators';   Short = 'Backup Operators' }
    @{ SID = 'S-1-5-32-552'; Name = 'BUILTIN\Replicators' }
    @{ SID = 'S-1-5-32-554'; Name = 'BUILTIN\Pre-Windows 2000 Compatible Access' }
    @{ SID = 'S-1-5-32-555'; Name = 'BUILTIN\Remote Desktop Users' }
    @{ SID = 'S-1-5-32-556'; Name = 'BUILTIN\Network Configuration Operators' }
    @{ SID = 'S-1-5-32-557'; Name = 'BUILTIN\Incoming Forest Trust Builders' }
    @{ SID = 'S-1-5-32-558'; Name = 'BUILTIN\Performance Monitor Users' }
    @{ SID = 'S-1-5-32-559'; Name = 'BUILTIN\Performance Log Users' }
    @{ SID = 'S-1-5-32-560'; Name = 'BUILTIN\Windows Authorization Access Group' }
    @{ SID = 'S-1-5-32-561'; Name = 'BUILTIN\Terminal Server License Servers' }
    @{ SID = 'S-1-5-32-562'; Name = 'BUILTIN\Distributed COM Users' }
    @{ SID = 'S-1-5-32-568'; Name = 'BUILTIN\IIS_IUSRS' }
    @{ SID = 'S-1-5-32-569'; Name = 'BUILTIN\Cryptographic Operators' }
    @{ SID = 'S-1-5-32-573'; Name = 'BUILTIN\Event Log Readers' }
    @{ SID = 'S-1-5-32-574'; Name = 'BUILTIN\Certificate Service DCOM Access' }
    @{ SID = 'S-1-5-32-575'; Name = 'BUILTIN\RDS Remote Access Servers' }
    @{ SID = 'S-1-5-32-576'; Name = 'BUILTIN\RDS Endpoint Servers' }
    @{ SID = 'S-1-5-32-577'; Name = 'BUILTIN\RDS Management Servers' }
    @{ SID = 'S-1-5-32-578'; Name = 'BUILTIN\Hyper-V Administrators' }
    @{ SID = 'S-1-5-32-579'; Name = 'BUILTIN\Access Control Assistance Operators' }
    @{ SID = 'S-1-5-32-580'; Name = 'BUILTIN\Remote Management Users' }
    @{ SID = 'S-1-5-32-581'; Name = 'BUILTIN\System Managed Accounts Group' }
    @{ SID = 'S-1-5-32-582'; Name = 'BUILTIN\Storage Replica Administrators' }
    @{ SID = 'S-1-5-32-583'; Name = 'BUILTIN\Device Owners' }
)

# ============================================================================
# Auto-generated Lookup Tables (built from WellKnownIdentities)
# ============================================================================

# SID → Name lookup (for ConvertFrom-SID)
$Script:SIDToName = @{}

# Name → SID lookup (for ConvertTo-SID)
# Includes: canonical names and short forms
$Script:NameToSID = @{}

# Build lookup tables from single source of truth
foreach ($identity in $Script:WellKnownIdentities) {
    $sid = $identity.SID
    $name = $identity.Name

    # SID → Name (always the canonical name)
    $Script:SIDToName[$sid] = $name

    # Name → SID (canonical name)
    $Script:NameToSID[$name] = $sid

    # Short form → SID (if defined)
    if ($identity.Short) {
        $Script:NameToSID[$identity.Short] = $sid
    }
}
