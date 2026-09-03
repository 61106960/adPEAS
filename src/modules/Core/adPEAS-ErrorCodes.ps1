<#
.SYNOPSIS
    Central Win32 and HRESULT error code definitions and conversion functions.

.DESCRIPTION
    adPEAS-ErrorCodes provides language-independent error code handling for all
    adPEAS modules that interact with Windows APIs (SMB, WMI, RPC, LDAP, etc.).

    Features:
    - Win32 error code mappings
    - HRESULT to Win32 conversion
    - WMI/WBEM-specific error codes
    - LDAP error codes
    - Structured error information extraction from exceptions

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

# =============================================================================
# Win32 Error Codes (from winerror.h)
# =============================================================================
$Script:Win32ErrorCodes = @{
    # Success
    0     = @{ Name = 'ERROR_SUCCESS';                    Message = 'Success';                        Category = 'Success' }

    # Access/Authentication errors
    5     = @{ Name = 'ERROR_ACCESS_DENIED';              Message = 'Access denied';                  Category = 'AccessDenied' }
    1326  = @{ Name = 'ERROR_LOGON_FAILURE';              Message = 'Invalid credentials';            Category = 'AccessDenied' }
    1327  = @{ Name = 'ERROR_ACCOUNT_RESTRICTION';        Message = 'Account restriction';            Category = 'AccessDenied' }
    1328  = @{ Name = 'ERROR_INVALID_LOGON_HOURS';        Message = 'Invalid logon hours';            Category = 'AccessDenied' }
    1329  = @{ Name = 'ERROR_INVALID_WORKSTATION';        Message = 'Invalid workstation';            Category = 'AccessDenied' }
    1330  = @{ Name = 'ERROR_PASSWORD_EXPIRED';           Message = 'Password expired';               Category = 'AccessDenied' }
    1331  = @{ Name = 'ERROR_ACCOUNT_DISABLED';           Message = 'Account disabled';               Category = 'AccessDenied' }
    1219  = @{ Name = 'ERROR_SESSION_CREDENTIAL_CONFLICT'; Message = 'Session credential conflict';   Category = 'AccessDenied' }
    1385  = @{ Name = 'ERROR_LOGON_TYPE_NOT_GRANTED';     Message = 'Logon type not granted';         Category = 'AccessDenied' }

    # Network errors
    53    = @{ Name = 'ERROR_BAD_NETPATH';                Message = 'Network path not found';         Category = 'Network' }
    64    = @{ Name = 'ERROR_NETNAME_DELETED';            Message = 'Network name deleted';           Category = 'Network' }
    67    = @{ Name = 'ERROR_BAD_NET_NAME';               Message = 'Network name not found';         Category = 'Network' }
    1203  = @{ Name = 'ERROR_NO_NET_OR_BAD_PATH';         Message = 'No network or bad path';         Category = 'Network' }
    1222  = @{ Name = 'ERROR_NO_NETWORK';                 Message = 'No network available';           Category = 'Network' }
    1231  = @{ Name = 'ERROR_NETWORK_UNREACHABLE';        Message = 'Network unreachable';            Category = 'Network' }
    1232  = @{ Name = 'ERROR_HOST_UNREACHABLE';           Message = 'Host unreachable';               Category = 'Network' }
    1234  = @{ Name = 'ERROR_PORT_UNREACHABLE';           Message = 'Port unreachable';               Category = 'Network' }

    # RPC errors
    1722  = @{ Name = 'RPC_S_SERVER_UNAVAILABLE';         Message = 'RPC server unavailable';         Category = 'RPC' }
    1723  = @{ Name = 'RPC_S_SERVER_TOO_BUSY';            Message = 'RPC server too busy';            Category = 'RPC' }
    1727  = @{ Name = 'RPC_S_CALL_FAILED_DNE';            Message = 'RPC call failed';                Category = 'RPC' }

    # Domain/DC errors
    1311  = @{ Name = 'ERROR_NO_LOGON_SERVERS';           Message = 'No logon servers available';     Category = 'Domain' }
    1355  = @{ Name = 'ERROR_NO_SUCH_DOMAIN';             Message = 'Domain not found';               Category = 'Domain' }

    # Timeout
    121   = @{ Name = 'ERROR_SEM_TIMEOUT';                Message = 'Semaphore timeout';              Category = 'Timeout' }
    258   = @{ Name = 'WAIT_TIMEOUT';                     Message = 'Operation timed out';            Category = 'Timeout' }
    1460  = @{ Name = 'ERROR_TIMEOUT';                    Message = 'Operation timed out';            Category = 'Timeout' }

    # Resource errors
    1450  = @{ Name = 'ERROR_NO_SYSTEM_RESOURCES';        Message = 'Insufficient system resources';  Category = 'Resource' }
    1451  = @{ Name = 'ERROR_NONPAGED_SYSTEM_RESOURCES';  Message = 'Insufficient nonpaged resources'; Category = 'Resource' }
}

# =============================================================================
# HRESULT Error Codes (COM/WMI/LDAP specific)
# =============================================================================
$Script:HResultCodes = @{
    # Standard HRESULT
    0x80070005 = @{ Name = 'E_ACCESSDENIED';              Message = 'Access denied';                  Category = 'AccessDenied' }
    0x80070035 = @{ Name = 'ERROR_BAD_NETPATH';           Message = 'Network path not found';         Category = 'Network' }
    0x800706BA = @{ Name = 'RPC_S_SERVER_UNAVAILABLE';    Message = 'RPC server unavailable';         Category = 'RPC' }
    0x800706BE = @{ Name = 'RPC_S_CALL_FAILED';           Message = 'RPC call failed';                Category = 'RPC' }

    # WMI/WBEM specific (0x8004xxxx)
    0x80041001 = @{ Name = 'WBEM_E_FAILED';               Message = 'WMI general failure';            Category = 'WMI' }
    0x80041002 = @{ Name = 'WBEM_E_NOT_FOUND';            Message = 'WMI object not found';           Category = 'WMI' }
    0x80041003 = @{ Name = 'WBEM_E_ACCESS_DENIED';        Message = 'WMI access denied';              Category = 'AccessDenied' }
    0x80041004 = @{ Name = 'WBEM_E_PROVIDER_FAILURE';     Message = 'WMI provider failure';           Category = 'WMI' }
    0x80041008 = @{ Name = 'WBEM_E_INVALID_PARAMETER';    Message = 'WMI invalid parameter';          Category = 'WMI' }
    0x80041010 = @{ Name = 'WBEM_E_INVALID_CLASS';        Message = 'WMI invalid class';              Category = 'WMI' }
    0x80041011 = @{ Name = 'WBEM_E_PROVIDER_NOT_FOUND';   Message = 'WMI provider not found';         Category = 'WMI' }
    0x80041013 = @{ Name = 'WBEM_E_PROVIDER_NOT_CAPABLE'; Message = 'WMI provider not capable';       Category = 'WMI' }
    0x8004100E = @{ Name = 'WBEM_E_INVALID_NAMESPACE';    Message = 'WMI invalid namespace';          Category = 'WMI' }
    0x80041017 = @{ Name = 'WBEM_E_INVALID_QUERY';        Message = 'WMI invalid query';              Category = 'WMI' }

    # LDAP/DirectoryServices specific (0x8007xxxx with LDAP codes in low bits)
    # HRESULT format for LDAP: 0x80072000 + LDAP_ERROR_CODE
    0x80072020 = @{ Name = 'LDAP_OPERATIONS_ERROR';       Message = 'LDAP operations error';          Category = 'LDAP'; LDAPCode = 1 }
    0x80072021 = @{ Name = 'LDAP_PROTOCOL_ERROR';         Message = 'LDAP protocol error';            Category = 'LDAP'; LDAPCode = 2 }
    0x80072022 = @{ Name = 'LDAP_TIMELIMIT_EXCEEDED';     Message = 'LDAP time limit exceeded';       Category = 'Timeout'; LDAPCode = 3 }
    0x80072023 = @{ Name = 'LDAP_SIZELIMIT_EXCEEDED';     Message = 'LDAP size limit exceeded';       Category = 'LDAP'; LDAPCode = 4 }
    0x80072027 = @{ Name = 'LDAP_AUTH_METHOD_NOT_SUPPORTED'; Message = 'LDAP auth method not supported'; Category = 'AccessDenied'; LDAPCode = 7 }
    0x80072028 = @{ Name = 'LDAP_STRONG_AUTH_REQUIRED';   Message = 'LDAP strong auth required';      Category = 'AccessDenied'; LDAPCode = 8 }
    0x80072030 = @{ Name = 'LDAP_NO_SUCH_OBJECT';         Message = 'LDAP object not found';          Category = 'LDAPNotFound'; LDAPCode = 32 }
    0x80072031 = @{ Name = 'LDAP_INVALID_CREDENTIALS';    Message = 'LDAP invalid credentials';       Category = 'AccessDenied'; LDAPCode = 49 }
    0x80072032 = @{ Name = 'LDAP_INSUFFICIENT_RIGHTS';    Message = 'LDAP insufficient access rights'; Category = 'AccessDenied'; LDAPCode = 50 }
    0x80072033 = @{ Name = 'LDAP_BUSY';                   Message = 'LDAP server busy';               Category = 'Resource'; LDAPCode = 51 }
    0x80072034 = @{ Name = 'LDAP_UNAVAILABLE';            Message = 'LDAP server unavailable';        Category = 'Network'; LDAPCode = 52 }
    0x80072035 = @{ Name = 'LDAP_UNWILLING_TO_PERFORM';   Message = 'LDAP server unwilling to perform'; Category = 'LDAP'; LDAPCode = 53 }
    0x80072051 = @{ Name = 'LDAP_SERVER_DOWN';            Message = 'LDAP server down';               Category = 'Network'; LDAPCode = 81 }

    # PFX/Certificate crypto errors (0x8007xxxx, 0x8009xxxx)
    0x80070056 = @{ Name = 'ERROR_INVALID_PASSWORD';        Message = 'Incorrect certificate password';                             Category = 'AccessDenied' }
    0x80092009 = @{ Name = 'CRYPT_E_NO_MATCH';              Message = 'Invalid certificate format (not a valid PFX/P12 file)';      Category = 'LDAP' }
    0x8009310B = @{ Name = 'CRYPT_E_ASN1_BADTAG';           Message = 'Invalid certificate format (not a valid PFX/P12 file)';      Category = 'LDAP' }
    0x80092002 = @{ Name = 'CRYPT_E_BAD_ENCODE';            Message = 'Invalid certificate encoding - ensure the file is PFX/P12 format'; Category = 'LDAP' }
    0x80090016 = @{ Name = 'NTE_BAD_KEYSET';                Message = 'Keyset does not exist - PFX private key could not be imported'; Category = 'LDAP' }
}

# =============================================================================
# LDAP Error Codes (RFC 4511)
# =============================================================================
$Script:LDAPErrorCodes = @{
    0   = @{ Name = 'LDAP_SUCCESS';                       Message = 'Success';                        Category = 'Success' }
    1   = @{ Name = 'LDAP_OPERATIONS_ERROR';              Message = 'Operations error';               Category = 'AccessDenied' }
    2   = @{ Name = 'LDAP_PROTOCOL_ERROR';                Message = 'Protocol error';                 Category = 'LDAP' }
    3   = @{ Name = 'LDAP_TIMELIMIT_EXCEEDED';            Message = 'Time limit exceeded';            Category = 'Timeout' }
    4   = @{ Name = 'LDAP_SIZELIMIT_EXCEEDED';            Message = 'Size limit exceeded';            Category = 'LDAP' }
    7   = @{ Name = 'LDAP_AUTH_METHOD_NOT_SUPPORTED';     Message = 'Auth method not supported';      Category = 'AccessDenied' }
    8   = @{ Name = 'LDAP_STRONG_AUTH_REQUIRED';          Message = 'Strong auth required';           Category = 'AccessDenied' }
    # Category 'LDAPNotFound', not 'LDAP': this is the same LDAP_NO_SUCH_OBJECT the
    # HResult table's 0x80072030 entry already carries as 'LDAPNotFound' (IsError=$false,
    # IsNotFound=$true) - a plain-integer lookup of the identical error must classify it
    # the same way. Nothing currently reaches this table entry with code 32 in a way that
    # depended on the old, inconsistent classification (Test-LDAPErrorNotFound decides
    # the search-empty-result case independently via a direct HResult check, and
    # Connect-LDAP.ps1's category switch maps both 'LDAP' and the 'default' case to the
    # same "GenericError" outcome either way) - fixed for a caller that relies on
    # ConvertFrom-LDAPError/Get-ExceptionErrorInfo's IsNotFound in the future, since nothing
    # about "not found" changes depending on which of the two tables answered the lookup.
    32  = @{ Name = 'LDAP_NO_SUCH_OBJECT';                Message = 'Object not found';               Category = 'LDAPNotFound' }
    49  = @{ Name = 'LDAP_INVALID_CREDENTIALS';           Message = 'Invalid credentials';            Category = 'AccessDenied' }
    50  = @{ Name = 'LDAP_INSUFFICIENT_RIGHTS';           Message = 'Insufficient access rights';     Category = 'AccessDenied' }
    51  = @{ Name = 'LDAP_BUSY';                          Message = 'Server busy';                    Category = 'Resource' }
    52  = @{ Name = 'LDAP_UNAVAILABLE';                   Message = 'Server unavailable';             Category = 'Network' }
    53  = @{ Name = 'LDAP_UNWILLING_TO_PERFORM';          Message = 'Server unwilling to perform';    Category = 'LDAP' }
    80  = @{ Name = 'LDAP_OTHER';                        Message = 'Other/unspecified error';        Category = 'LDAP' }
    81  = @{ Name = 'LDAP_SERVER_DOWN';                   Message = 'Server down';                    Category = 'Network' }

    # Client-side LDAP errors (82-91)
    82  = @{ Name = 'LDAP_LOCAL_ERROR';                   Message = 'Local GSSAPI/Negotiate error (ticket not usable or SPN mismatch)'; Category = 'LDAP' }
    83  = @{ Name = 'LDAP_ENCODING_ERROR';                Message = 'BER encoding error';             Category = 'LDAP' }
    84  = @{ Name = 'LDAP_DECODING_ERROR';                Message = 'BER decoding error';             Category = 'LDAP' }
    85  = @{ Name = 'LDAP_TIMEOUT';                       Message = 'LDAP operation timed out';       Category = 'Timeout' }
    86  = @{ Name = 'LDAP_AUTH_UNKNOWN';                  Message = 'Unknown authentication method';  Category = 'AccessDenied' }
    87  = @{ Name = 'LDAP_FILTER_ERROR';                  Message = 'Invalid LDAP filter';            Category = 'LDAP' }
    89  = @{ Name = 'LDAP_PARAM_ERROR';                   Message = 'Invalid parameter';              Category = 'LDAP' }
    90  = @{ Name = 'LDAP_NO_MEMORY';                     Message = 'Out of memory';                  Category = 'Resource' }
    91  = @{ Name = 'LDAP_CONNECT_ERROR';                 Message = 'Cannot connect to LDAP server';  Category = 'Network' }
}

# =============================================================================
# AD Extended (sub) Error Codes
# =============================================================================
# When a directory WRITE operation (Add/Modify/Delete) is rejected, AD DS embeds
# an 8-hex-digit Win32/directory sub-error at the START of the server-side
# ErrorMessage, e.g.:
#   "0000216D: SvcErr: DSID-031A125C, problem 5003 (WILL_NOT_PERFORM), data 0"
# The LDAP ResultCode alone (e.g. 53 UnwillingToPerform) is not actionable - this
# sub-error is what tells a tester the real reason (quota, access rights, etc.).
$Script:ADExtendedErrorCodes = @{
    0x00000005 = @{ Name = 'ERROR_ACCESS_DENIED';                    Hint = 'Access denied. Your account lacks the required rights on the target object or OU.' }
    0x0000052D = @{ Name = 'ERROR_PASSWORD_RESTRICTION';             Hint = 'The password does not meet the domain password policy (length, complexity, or history).' }
    0x00002071 = @{ Name = 'ERROR_DS_ATTRIBUTE_OR_VALUE_EXISTS';     Hint = 'The attribute or value already exists on the object.' }
    0x00002075 = @{ Name = 'ERROR_DS_NO_PARENT_OBJECT';              Hint = 'The target container/OU does not exist. Check the -OrganizationalUnit distinguishedName.' }
    0x00002094 = @{ Name = 'ERROR_DS_OBJ_STRING_NAME_EXISTS';        Hint = 'An object with this name already exists. Choose a different name or delete the existing object first.' }
    # Generic on purpose: 0x2098 is returned for EVERY rejected write - object creation,
    # attribute modification and DACL changes alike. The operation-specific advice lives in
    # $Script:LDAPWriteOperationHints, which Resolve-LDAPWriteError appends as its own line.
    0x00002098 = @{ Name = 'ERROR_DS_INSUFF_ACCESS_RIGHTS';          Hint = 'Insufficient access rights. The Domain Controller rejected the write - the bind account lacks the permission this operation needs on the target object.' }
    0x0000216D = @{ Name = 'ERROR_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED'; Hint = 'The MachineAccountQuota (ms-DS-MachineAccountQuota) is exhausted or set to 0. A common AD hardening step is to set the quota to 0 so non-admins cannot join computers. Use an account delegated "Create Computer Objects" on the target OU, or raise the quota.' }
}

# =============================================================================
# LDAP ResultCode hints for WRITE operations (fallback when no AD sub-error is present)
# =============================================================================
$Script:LDAPWriteResultHints = @{
    8  = 'The server requires stronger authentication (LDAP signing/channel binding or LDAPS). Reconnect with -UseLDAPS or a sealed Kerberos bind.'
    19 = 'Constraint violation - a value violates a policy (e.g. the password does not meet the domain password policy, or an attribute constraint).'
    32 = 'The target container/OU does not exist. Check the target distinguishedName.'
    50 = 'Insufficient access rights - your account is not delegated to perform this write on the target object/OU.'
    53 = 'The Domain Controller is unwilling to perform the operation. See the server sub-error above for the specific reason (frequently MachineAccountQuota or a hardening policy).'
    68 = 'The object already exists.'
}

# Operation-specific guidance for rejected writes (LDAP result 50 / sub-error 0x2098).
# Evaluated in order against the caller's -Operation string; first match wins. This is kept
# separate from the ResultCode and sub-error hints above because the DC returns the very same
# code for every denied write - only the caller knows which attribute or object class it was
# actually after, so only the caller's operation string can name the permission that is missing.
$Script:LDAPWriteOperationHints = @(
    @{
        Pattern = 'shadow credential'
        Hint    = 'Writing msDS-KeyCredentialLink needs GenericAll, GenericWrite, or an explicit WriteProperty ACE on msDS-KeyCredentialLink (5b47d60f-6090-40b2-9f37-2a4de88f3063) - or membership in Key Admins / Enterprise Key Admins. Note an account cannot write this attribute on its own USER object: self-write is a default on COMPUTER objects only. Windows Hello for Business registers user keys through AD FS or Azure AD Connect, not through the user, so being the target account grants nothing here. Verify with: Get-ObjectACL -Identity <target> -WriteOnly'
    }
    @{
        Pattern = 'rbcd'
        Hint    = 'Writing msDS-AllowedToActOnBehalfOfOtherIdentity needs GenericAll, GenericWrite, or an explicit WriteProperty ACE on that attribute of the target computer object. Verify with: Get-ObjectACL -Identity <target> -WriteOnly'
    }
    @{
        Pattern = 'create computer'
        Hint    = 'Creating a computer object needs Create Child (Computer Objects) on the target OU, plus a non-zero ms-DS-MachineAccountQuota when relying on the default user quota. Both are commonly removed during AD hardening.'
    }
    @{
        Pattern = 'create (user|group|GPO)'
        Hint    = 'Creating this object needs Create Child permission for the object class on the target container or OU.'
    }
    @{
        Pattern = 'modify ACL'
        Hint    = 'Writing the DACL needs WriteDacl on the target object, or ownership of it - an owner can always rewrite the DACL. Verify with: Get-ObjectACL -Identity <target> -DangerousOnly'
    }
    @{
        Pattern = '^modify '
        Hint    = 'Modifying this object needs GenericAll, GenericWrite, or a WriteProperty ACE covering the attribute being written. Verify with: Get-ObjectACL -Identity <target> -WriteOnly'
    }
)

# =============================================================================
# Category Definitions
# =============================================================================
$Script:ErrorCategories = @{
    'Success'      = @{ IsError = $false; IsRetryable = $false; IsAccessDenied = $false; IsNotFound = $false }
    'AccessDenied' = @{ IsError = $true;  IsRetryable = $false; IsAccessDenied = $true;  IsNotFound = $false }
    'Network'      = @{ IsError = $true;  IsRetryable = $true;  IsAccessDenied = $false; IsNotFound = $false }
    'RPC'          = @{ IsError = $true;  IsRetryable = $true;  IsAccessDenied = $false; IsNotFound = $false }
    'Domain'       = @{ IsError = $true;  IsRetryable = $true;  IsAccessDenied = $false; IsNotFound = $false }
    'Timeout'      = @{ IsError = $true;  IsRetryable = $true;  IsAccessDenied = $false; IsNotFound = $false }
    'Resource'     = @{ IsError = $true;  IsRetryable = $true;  IsAccessDenied = $false; IsNotFound = $false }
    'WMI'          = @{ IsError = $true;  IsRetryable = $false; IsAccessDenied = $false; IsNotFound = $false }
    'LDAP'         = @{ IsError = $true;  IsRetryable = $false; IsAccessDenied = $false; IsNotFound = $false }
    'LDAPNotFound' = @{ IsError = $false; IsRetryable = $false; IsAccessDenied = $false; IsNotFound = $true }  # Expected case - not an error
    'SSLCertificate' = @{ IsError = $true; IsRetryable = $false; IsAccessDenied = $false; IsNotFound = $false }
    'SSLProtocol'  = @{ IsError = $true;  IsRetryable = $false; IsAccessDenied = $false; IsNotFound = $false }
    'SSLConnection' = @{ IsError = $true; IsRetryable = $false; IsAccessDenied = $false; IsNotFound = $false }
    'Unknown'      = @{ IsError = $true;  IsRetryable = $false; IsAccessDenied = $false; IsNotFound = $false }
}


# =============================================================================
# ConvertFrom-Win32Error
# =============================================================================
function ConvertFrom-Win32Error {
    <#
    .SYNOPSIS
        Converts a Win32 error code to structured error information.

    .PARAMETER ErrorCode
        The Win32 error code (0-65535).

    .EXAMPLE
        ConvertFrom-Win32Error -ErrorCode 5
        # Returns structured info for ERROR_ACCESS_DENIED
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [int]$ErrorCode
    )

    $errorInfo = $Script:Win32ErrorCodes[$ErrorCode]

    if ($errorInfo) {
        $categoryInfo = $Script:ErrorCategories[$errorInfo.Category]
        # Fallback if category is not defined
        if (-not $categoryInfo) {
            $categoryInfo = $Script:ErrorCategories['Unknown']
        }
        return [PSCustomObject]@{
            ErrorCode     = $ErrorCode
            Name          = $errorInfo.Name
            Message       = $errorInfo.Message
            Category      = $errorInfo.Category
            IsError       = $categoryInfo.IsError
            IsRetryable   = $categoryInfo.IsRetryable
            IsAccessDenied = $categoryInfo.IsAccessDenied
            IsNotFound    = $categoryInfo.IsNotFound
        }
    }

    # Unknown error code
    return [PSCustomObject]@{
        ErrorCode     = $ErrorCode
        Name          = "UNKNOWN_ERROR_$ErrorCode"
        Message       = "Unknown error ($ErrorCode)"
        Category      = 'Unknown'
        IsError       = $true
        IsRetryable   = $false
        IsAccessDenied = $false
        IsNotFound    = $false
    }
}


# =============================================================================
# ConvertFrom-HResult
# =============================================================================
function ConvertFrom-HResult {
    <#
    .SYNOPSIS
        Converts an HRESULT to structured error information.

    .DESCRIPTION
        HRESULT format: 0xSRRRCCCC
        - S: Severity (1 bit) - 0=success, 1=error
        - R: Reserved (4 bits)
        - R: Reserved (11 bits)
        - C: Code (16 bits) - can contain Win32 error code

    .PARAMETER HResult
        The HRESULT value.

    .EXAMPLE
        ConvertFrom-HResult -HResult 0x80070005
        # Returns structured info for E_ACCESSDENIED
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [int]$HResult
    )

    # Check if it's a known HRESULT
    $errorInfo = $Script:HResultCodes[$HResult]

    if ($errorInfo) {
        $categoryInfo = $Script:ErrorCategories[$errorInfo.Category]
        # Fallback if category is not defined
        if (-not $categoryInfo) {
            $categoryInfo = $Script:ErrorCategories['Unknown']
        }
        return [PSCustomObject]@{
            HResult       = $HResult
            HResultHex    = '0x{0:X8}' -f $HResult
            Win32Code     = $HResult -band 0xFFFF
            Name          = $errorInfo.Name
            Message       = $errorInfo.Message
            Category      = $errorInfo.Category
            IsError       = $categoryInfo.IsError
            IsRetryable   = $categoryInfo.IsRetryable
            IsAccessDenied = $categoryInfo.IsAccessDenied
            IsNotFound    = $categoryInfo.IsNotFound
        }
    }

    # Extract Win32 error code from HRESULT (low 16 bits)
    $win32Code = $HResult -band 0xFFFF
    $win32Info = ConvertFrom-Win32Error -ErrorCode $win32Code

    if ($win32Info.Name -notmatch '^UNKNOWN_ERROR') {
        # Known Win32 code embedded in HRESULT
        return [PSCustomObject]@{
            HResult       = $HResult
            HResultHex    = '0x{0:X8}' -f $HResult
            Win32Code     = $win32Code
            Name          = $win32Info.Name
            Message       = $win32Info.Message
            Category      = $win32Info.Category
            IsError       = $win32Info.IsError
            IsRetryable   = $win32Info.IsRetryable
            IsAccessDenied = $win32Info.IsAccessDenied
            IsNotFound    = $win32Info.IsNotFound
        }
    }

    # Unknown HRESULT
    return [PSCustomObject]@{
        HResult       = $HResult
        HResultHex    = '0x{0:X8}' -f $HResult
        Win32Code     = $win32Code
        Name          = "UNKNOWN_HRESULT"
        Message       = "Unknown error (0x{0:X8})" -f $HResult
        Category      = 'Unknown'
        IsError       = $true
        IsRetryable   = $false
        IsAccessDenied = $false
        IsNotFound    = $false
    }
}


# =============================================================================
# ConvertFrom-LDAPError
# =============================================================================
function ConvertFrom-LDAPError {
    <#
    .SYNOPSIS
        Converts an LDAP error code to structured error information.

    .PARAMETER ErrorCode
        The LDAP error code.

    .EXAMPLE
        ConvertFrom-LDAPError -ErrorCode 49
        # Returns structured info for LDAP_INVALID_CREDENTIALS
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [int]$ErrorCode
    )

    $errorInfo = $Script:LDAPErrorCodes[$ErrorCode]

    if ($errorInfo) {
        $categoryInfo = $Script:ErrorCategories[$errorInfo.Category]
        # Fallback if category is not defined
        if (-not $categoryInfo) {
            $categoryInfo = $Script:ErrorCategories['Unknown']
        }
        return [PSCustomObject]@{
            ErrorCode     = $ErrorCode
            Name          = $errorInfo.Name
            Message       = $errorInfo.Message
            Category      = $errorInfo.Category
            IsError       = $categoryInfo.IsError
            IsRetryable   = $categoryInfo.IsRetryable
            IsAccessDenied = $categoryInfo.IsAccessDenied
            IsNotFound    = $categoryInfo.IsNotFound
        }
    }

    # Unknown LDAP error
    return [PSCustomObject]@{
        ErrorCode     = $ErrorCode
        Name          = "UNKNOWN_LDAP_ERROR_$ErrorCode"
        Message       = "Unknown LDAP error ($ErrorCode)"
        Category      = 'Unknown'
        IsError       = $true
        IsRetryable   = $false
        IsAccessDenied = $false
        IsNotFound    = $false
    }
}


# =============================================================================
# Get-ExceptionErrorInfo
# =============================================================================
function Get-ExceptionErrorInfo {
    <#
    .SYNOPSIS
        Extracts structured error information from an exception.

    .DESCRIPTION
        Analyzes an exception and returns structured error information including:
        - Error code/HRESULT
        - Human-readable message
        - Category (AccessDenied, Network, RPC, etc.)
        - Whether the error is retryable
        - Whether it's an access denied error

    .PARAMETER Exception
        The exception to analyze.

    .PARAMETER Context
        Optional context string for the error message (e.g., "SMB", "WMI", "LDAP").

    .PARAMETER IncludeOriginalMessage
        Include the original exception message in unknown errors.

    .EXAMPLE
        try {
            Get-Item "\\server\share" -ErrorAction Stop
        } catch {
            $errorInfo = Get-ExceptionErrorInfo -Exception $_.Exception -Context "SMB"
            if ($errorInfo.IsAccessDenied) {
                Write-Host "Access denied"
            } elseif ($errorInfo.IsRetryable) {
                Write-Host "Network error, will retry"
            }
        }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [System.Exception]$Exception,

        [Parameter(Mandatory=$false)]
        [string]$Context = "Operation",

        [Parameter(Mandatory=$false)]
        [switch]$IncludeOriginalMessage
    )

    $result = [PSCustomObject]@{
        HResult        = $null
        Win32Code      = $null
        Name           = $null
        Message        = $null
        Category       = 'Unknown'
        IsError        = $true
        IsRetryable    = $false
        IsAccessDenied = $false
        IsNotFound     = $false
        Context        = $Context
        OriginalMessage = $Exception.Message
    }

    # Get HRESULT from exception
    $hresult = $Exception.HResult

    # Note: HResult 0 is valid (SUCCESS), so check for $null explicitly
    if ($null -ne $hresult -and $hresult -ne 0) {
        $result.HResult = $hresult
        $result.Win32Code = $hresult -band 0xFFFF

        # Try HRESULT lookup
        $errorInfo = ConvertFrom-HResult -HResult $hresult

        if ($errorInfo.Name -notmatch '^UNKNOWN') {
            $result.Name = $errorInfo.Name
            $result.Message = $errorInfo.Message
            $result.Category = $errorInfo.Category
            $result.IsError = $errorInfo.IsError
            $result.IsRetryable = $errorInfo.IsRetryable
            $result.IsAccessDenied = $errorInfo.IsAccessDenied
            $result.IsNotFound = $errorInfo.IsNotFound
            return $result
        }
    }

    # Check for specific exception types
    if ($Exception -is [System.UnauthorizedAccessException]) {
        $result.Name = 'UnauthorizedAccessException'
        $result.Message = 'Access denied'
        $result.Category = 'AccessDenied'
        $result.IsAccessDenied = $true
        return $result
    }

    if ($Exception -is [System.Net.Sockets.SocketException]) {
        $socketCode = $Exception.SocketErrorCode
        $result.Win32Code = [int]$socketCode
        $result.Name = "SocketException_$socketCode"
        $result.Message = "Network error: $($Exception.Message)"
        $result.Category = 'Network'
        $result.IsRetryable = $true
        return $result
    }

    if ($Exception -is [System.TimeoutException]) {
        $result.Name = 'TimeoutException'
        $result.Message = 'Operation timed out'
        $result.Category = 'Timeout'
        $result.IsRetryable = $true
        return $result
    }

    # Check for SSL/TLS AuthenticationException (from SslStream.AuthenticateAsClient)
    if ($Exception -is [System.Security.Authentication.AuthenticationException]) {
        # Get the deepest error message for classification
        $sslMsg = if ($Exception.InnerException) { $Exception.InnerException.Message } else { $Exception.Message }
        $result.OriginalMessage = $sslMsg

        # Classify by error message patterns (HResults are not differentiated enough for SSL)
        if ($sslMsg -match 'certificate|trust|validation|verify|chain|revoked|expired') {
            $result.Name = 'SSLCertificateError'
            $result.Message = "SSL certificate validation failed: $sslMsg"
            $result.Category = 'SSLCertificate'
        }
        elseif ($sslMsg -match 'closed|reset|aborted|refused|terminated') {
            $result.Name = 'SSLConnectionClosed'
            $result.Message = "Server closed SSL connection - may not support LDAPS or TLS version mismatch"
            $result.Category = 'SSLConnection'
        }
        elseif ($sslMsg -match 'protocol|version|handshake|TLS|SSL') {
            $result.Name = 'SSLProtocolError'
            $result.Message = "TLS/SSL protocol error - server may require specific TLS version"
            $result.Category = 'SSLProtocol'
        }
        elseif ($sslMsg -match 'timeout|timed out') {
            $result.Name = 'SSLTimeout'
            $result.Message = 'SSL handshake timed out'
            $result.Category = 'Timeout'
            $result.IsRetryable = $true
        }
        else {
            $result.Name = 'SSLError'
            $result.Message = "SSL/TLS handshake failed: $sslMsg"
            $result.Category = 'SSLConnection'
        }
        return $result
    }

    # Check for System.DirectoryServices.Protocols.LdapException (adPEAS primary LDAP client)
    if ($Exception.GetType().FullName -eq 'System.DirectoryServices.Protocols.LdapException') {
        $ldapErrorCode = $Exception.ErrorCode
        $ldapInfo = ConvertFrom-LDAPError -ErrorCode $ldapErrorCode
        $result.Win32Code = $ldapErrorCode
        $result.Name = $ldapInfo.Name
        $result.Message = $ldapInfo.Message
        $result.Category = $ldapInfo.Category
        $result.IsError = $ldapInfo.IsError
        $result.IsRetryable = $ldapInfo.IsRetryable
        $result.IsAccessDenied = $ldapInfo.IsAccessDenied
        $result.IsNotFound = $ldapInfo.IsNotFound
        return $result
    }

    # Fallback: Unknown error
    if ($IncludeOriginalMessage -or -not $hresult) {
        $result.Message = "$Context error: $($Exception.Message)"
    } else {
        $result.Message = "$Context error (0x{0:X8})" -f $hresult
    }

    return $result
}


# =============================================================================
# Test-ErrorRetryable
# =============================================================================
function Test-ErrorRetryable {
    <#
    .SYNOPSIS
        Quick check if an exception represents a retryable error.

    .PARAMETER Exception
        The exception to check.

    .EXAMPLE
        catch {
            if (Test-ErrorRetryable -Exception $_.Exception) {
                Start-Sleep -Seconds 2
                # Retry operation
            }
        }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [System.Exception]$Exception
    )

    $errorInfo = Get-ExceptionErrorInfo -Exception $Exception
    return $errorInfo.IsRetryable
}


# =============================================================================
# Test-ErrorAccessDenied
# =============================================================================
function Test-ErrorAccessDenied {
    <#
    .SYNOPSIS
        Quick check if an exception represents an access denied error.

    .PARAMETER Exception
        The exception to check.

    .EXAMPLE
        catch {
            if (Test-ErrorAccessDenied -Exception $_.Exception) {
                Write-Warning "Insufficient permissions"
            }
        }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [System.Exception]$Exception
    )

    $errorInfo = Get-ExceptionErrorInfo -Exception $Exception
    return $errorInfo.IsAccessDenied
}


# =============================================================================
# Test-LDAPErrorNotFound
# =============================================================================
function Test-LDAPErrorNotFound {
    <#
    .SYNOPSIS
        Quick check if an exception represents LDAP_NO_SUCH_OBJECT error.

    .DESCRIPTION
        Checks if the exception is an LDAP "object not found" error (0x80072030).
        This is an expected case in LDAP searches when the SearchBase doesn't exist,
        and should typically be handled by returning an empty result rather than throwing.

        Checks multiple sources for the error code:
        - Exception.HResult
        - Exception.InnerException.HResult
        - DirectoryServicesCOMException.ErrorCode

    .PARAMETER Exception
        The exception to check.

    .EXAMPLE
        catch {
            if (Test-LDAPErrorNotFound -Exception $_.Exception) {
                # SearchBase doesn't exist - return empty result
                return @()
            }
            # Real error - rethrow
            throw
        }

    .NOTES
        LDAP_NO_SUCH_OBJECT (error code 32) is returned as HRESULT 0x80072030
        where 0x8007 is the FACILITY_WIN32 prefix and 0x2030 is 32 in decimal
        with an offset (0x2000 base for LDAP errors).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [System.Exception]$Exception
    )

    # LDAP_NO_SUCH_OBJECT = 0x80072030
    $LDAP_NO_SUCH_OBJECT = [int]0x80072030

    # Method 1: Check HResult directly (most common)
    if ($Exception.HResult -eq $LDAP_NO_SUCH_OBJECT) {
        return $true
    }

    # Method 2: Check InnerException HResult
    if ($Exception.InnerException -and $Exception.InnerException.HResult -eq $LDAP_NO_SUCH_OBJECT) {
        return $true
    }

    # Method 3: Check DirectoryServicesCOMException.ErrorCode
    if ($Exception -is [System.DirectoryServices.DirectoryServicesCOMException] -and
        $Exception.ErrorCode -eq $LDAP_NO_SUCH_OBJECT) {
        return $true
    }

    # Method 4: Check low 16 bits for LDAP code (0x2030 = 8240 decimal)
    # This catches cases where the full HRESULT might differ slightly
    if (($Exception.HResult -band 0xFFFF) -eq 0x2030) {
        return $true
    }

    return $false
}


# =============================================================================
# Resolve-LDAPWriteError
# =============================================================================
function Resolve-LDAPWriteError {
    <#
    .SYNOPSIS
        Decodes an exception from an LDAP write operation into a tester-actionable message.

    .DESCRIPTION
        Directory write operations (AddRequest/ModifyRequest/DeleteRequest) via
        $Script:LdapConnection.SendRequest() throw a DirectoryOperationException on
        failure. PowerShell wraps that in a MethodInvocationException, so the raw
        error a user sees is the generic ".NET" message (e.g. "The server cannot
        handle directory requests.") with no LDAP ResultCode and no AD sub-error.

        This function unwraps the inner exception chain, extracts the LDAP ResultCode
        and the server-side ErrorMessage, decodes the AD extended sub-error (the
        8-hex-digit prefix, e.g. 0000216D = MachineAccountQuota exceeded), and returns
        a structured object plus a formatted, actionable hint. It also degrades
        gracefully when the failure was re-thrown as a plain string message.

    .PARAMETER Exception
        The exception to decode (typically $_.Exception from a catch block).

    .PARAMETER Operation
        Short description of the attempted operation, used in the formatted output
        (e.g. "create computer 'BadPC$'"). On an access-rights rejection it also
        selects the "Required rights" line from $Script:LDAPWriteOperationHints,
        so keep the wording aligned with the patterns defined there.

    .EXAMPLE
        catch {
            $info = Resolve-LDAPWriteError -Exception $_.Exception -Operation "create computer '$Name'"
            Write-Error "Failed to $($info.Operation).`n  $($info.Formatted)"
        }

    .NOTES
        Author: Alexander Sturz (@_61106960_)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [System.Exception]$Exception,

        [Parameter(Mandatory=$false)]
        [string]$Operation = 'LDAP write operation'
    )

    # Walk the InnerException chain to find the underlying directory exception.
    # PowerShell wraps .NET method exceptions in a MethodInvocationException, so the
    # DirectoryOperationException/LdapException is usually one or more levels down.
    $dirEx = $null
    $ldapEx = $null
    $messageChain = New-Object System.Collections.Generic.List[string]
    $cursor = $Exception
    $depth = 0
    while ($cursor -and $depth -lt 10) {
        if ($cursor.Message) { $messageChain.Add($cursor.Message) }
        $typeName = $cursor.GetType().FullName
        if (-not $dirEx -and $typeName -eq 'System.DirectoryServices.Protocols.DirectoryOperationException') {
            $dirEx = $cursor
        }
        if (-not $ldapEx -and $typeName -eq 'System.DirectoryServices.Protocols.LdapException') {
            $ldapEx = $cursor
        }
        $cursor = $cursor.InnerException
        $depth++
    }

    $resultCode = $null
    $resultName = $null
    $serverMessage = $null

    if ($dirEx -and $dirEx.Response) {
        $resultCode = [int]$dirEx.Response.ResultCode
        $resultName = [string]$dirEx.Response.ResultCode
        $serverMessage = $dirEx.Response.ErrorMessage
    }
    elseif ($ldapEx) {
        $resultCode = [int]$ldapEx.ErrorCode
        $resultName = (ConvertFrom-LDAPError -ErrorCode $resultCode).Name
        $serverMessage = $ldapEx.ServerErrorMessage
    }

    # Text to scan for the AD extended sub-error: prefer the server ErrorMessage,
    # otherwise the concatenated exception-chain messages (covers re-thrown strings).
    $scanText = $serverMessage
    if (-not $scanText) { $scanText = ($messageChain -join ' ') }

    # If no ResultCode was found via exception type, try to recover it from the
    # message text (e.g. a re-thrown "... failed: UnwillingToPerform - ..." string).
    if ($null -eq $resultCode -and $scanText) {
        $resultNameMap = @{
            'UnwillingToPerform'       = 53
            'InsufficientAccessRights' = 50
            'ConstraintViolation'      = 19
            'EntryAlreadyExists'       = 68
            'NoSuchObject'             = 32
            'StrongAuthRequired'       = 8
        }
        foreach ($rn in $resultNameMap.Keys) {
            if ($scanText -match $rn) {
                $resultCode = $resultNameMap[$rn]
                $resultName = $rn
                break
            }
        }
    }

    # Parse the AD extended sub-error (8-hex-digit code). Anchored form is the
    # canonical AD layout; the loose 0000xxxx form catches it embedded in free text.
    $extCode = $null
    $extHex = $null
    $extName = $null
    $extHint = $null
    if ($scanText) {
        if ($scanText -match '(^|[^0-9A-Fa-f])([0-9A-Fa-f]{8})\s*:') {
            $extHex = $matches[2].ToUpper()
        }
        elseif ($scanText -match '\b(0000[0-9A-Fa-f]{4})\b') {
            $extHex = $matches[1].ToUpper()
        }
        if ($extHex) {
            $extCode = [Convert]::ToInt32($extHex, 16)
            $extInfo = $Script:ADExtendedErrorCodes[$extCode]
            if ($extInfo) {
                $extName = $extInfo.Name
                $extHint = $extInfo.Hint
            }
        }
    }

    # Choose the most specific hint available: sub-error first, then ResultCode.
    $hint = $extHint
    if (-not $hint -and $null -ne $resultCode -and $Script:LDAPWriteResultHints.ContainsKey($resultCode)) {
        $hint = $Script:LDAPWriteResultHints[$resultCode]
    }

    # For an access-rights rejection the codes above can only say "denied" - which permission is
    # missing depends entirely on what was being written. Derive that from the operation string
    # so the message points at the right ACE instead of a generic delegation remark.
    $operationHint = $null
    if ($Operation -and ($resultCode -eq 50 -or $extCode -eq 0x00002098)) {
        foreach ($rule in $Script:LDAPWriteOperationHints) {
            if ($Operation -match $rule.Pattern) {
                $operationHint = $rule.Hint
                break
            }
        }
    }

    # Build a formatted, tester-friendly multi-line message.
    $lines = New-Object System.Collections.Generic.List[string]
    if ($null -ne $resultCode) {
        $lines.Add(("LDAP result: {0} ({1})" -f $resultCode, $resultName))
    }
    if ($extHex) {
        if ($extName) {
            $lines.Add(("Server sub-error: {0} ({1})" -f $extHex, $extName))
        } else {
            $lines.Add(("Server sub-error: {0}" -f $extHex))
        }
    }
    if ($hint) {
        $lines.Add(("Likely cause: {0}" -f $hint))
    }
    if ($operationHint) {
        $lines.Add(("Required rights: {0}" -f $operationHint))
    }
    if ($lines.Count -eq 0) {
        # Nothing structured could be extracted - surface the raw message so the
        # tester is never left with less information than before.
        $lines.Add($Exception.Message)
    }

    return [PSCustomObject]@{
        Operation     = $Operation
        ResultCode    = $resultCode
        ResultName    = $resultName
        ExtendedCode  = $extCode
        ExtendedHex   = $extHex
        ExtendedName  = $extName
        Hint          = $hint
        OperationHint = $operationHint
        ServerMessage = $serverMessage
        Formatted     = ($lines -join ([Environment]::NewLine + '  '))
    }
}

