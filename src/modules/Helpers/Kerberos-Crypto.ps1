<#
.SYNOPSIS
    Shared Kerberos cryptographic functions for adPEAS.

.DESCRIPTION
    This module contains all cryptographic primitives required for Kerberos authentication:
    - HMAC-MD5, HMAC-SHA1 for checksums
    - MD4 for NT-Hash calculation
    - RC4-HMAC encryption/decryption (etype 23)
    - AES-CTS encryption/decryption (etype 17, 18)
    - n-fold key derivation (RFC 3961)
    - PBKDF2-based AES key derivation from password

    These functions are used by:
    - Invoke-KerberosAuth.ps1
    - Request-ServiceTicket.ps1
    - Invoke-PKINITAuth-Native.ps1
    - Invoke-Kerberoast.ps1

.NOTES
    Author: Alexander Sturz (@_61106960_)

    References:
    - RFC 1320 (MD4)
    - RFC 3961 (Kerberos Encryption Framework)
    - RFC 3962 (AES Encryption for Kerberos 5)
    - RFC 4757 (RC4-HMAC for Kerberos)
#>

# Block and key sizes (RFC 3962, RFC 4757)
$Script:AES_BLOCK_SIZE = 16          # AES block size in bytes
$Script:AES128_KEY_SIZE = 16         # AES-128 key size in bytes
$Script:AES256_KEY_SIZE = 32         # AES-256 key size in bytes
$Script:RC4_CONFOUNDER_SIZE = 8      # RC4-HMAC confounder size (RFC 4757)
$Script:AES_CONFOUNDER_SIZE = 16     # AES-CTS confounder size (RFC 3962)
$Script:HMAC_MD5_SIZE = 16           # HMAC-MD5 output size
$Script:HMAC_SHA1_SIZE = 20          # HMAC-SHA1 output size
$Script:AES_CHECKSUM_SIZE = 12       # AES-CTS checksum size (truncated HMAC-SHA1)
$Script:MD4_HASH_SIZE = 16           # MD4 hash output size
$Script:NT_HASH_SIZE = 16            # NT hash size (same as MD4)

# Minimum ciphertext sizes
$Script:RC4_MIN_CIPHERTEXT = 24      # 16 (checksum) + 8 (confounder)
$Script:AES_MIN_CIPHERTEXT = 28      # 16 (confounder) + 12 (checksum)

# Key derivation constants (RFC 3961)
$Script:KE_CONSTANT_SUFFIX = 0xAA    # Encryption key derivation
$Script:KI_CONSTANT_SUFFIX = 0x55    # Integrity key derivation
$Script:KC_CONSTANT_SUFFIX = 0x99    # Checksum key derivation (for standalone checksums like PAC signatures)

# PBKDF2 iterations for AES key derivation (RFC 3962)
$Script:PBKDF2_ITERATIONS = 4096

# Kerberos Encryption Types - centralized map for all modules
# Used by: Invoke-Kerberoast, Invoke-ASREPRoast
$Script:KERBEROS_ENCRYPTION_TYPES = @{
    1  = @{ Name = "DES-CBC-CRC"; Severity = "Critical"; Description = "Obsolete and insecure"; HashcatMode = $null }
    2  = @{ Name = "DES-CBC-MD5"; Severity = "Critical"; Description = "Obsolete and insecure"; HashcatMode = $null }
    3  = @{ Name = "DES-CBC-MD4"; Severity = "Critical"; Description = "Obsolete and insecure"; HashcatMode = $null }
    17 = @{ Name = "AES128-CTS-HMAC-SHA1-96"; Severity = "Medium"; Description = "Moderate security"; HashcatMode = 19700 }
    18 = @{ Name = "AES256-CTS-HMAC-SHA1-96"; Severity = "Low"; Description = "Strong encryption"; HashcatMode = 19700 }
    23 = @{ Name = "RC4-HMAC"; Severity = "Critical"; Description = "Weak - very fast to crack"; HashcatMode = 13100 }
}

# Minimum ticket size for hash extraction
$Script:MIN_TICKET_SIZE = 32          # Minimum bytes for valid Kerberos ticket

# ============================================
# KDC Error Code Constants - Named constants for common error codes
# Used by: Connect-adPEAS, Show-ConnectionError, Invoke-KerberosAuth
# ============================================
$Script:KDC_ERR_C_PRINCIPAL_UNKNOWN = 6    # Client not found in Kerberos database
$Script:KDC_ERR_POLICY = 12                # KDC policy rejects request
$Script:KDC_ERR_ETYPE_NOSUPP = 14          # KDC has no support for encryption type
$Script:KDC_ERR_CLIENT_REVOKED = 18        # Client credentials have been revoked (disabled/locked)
$Script:KDC_ERR_KEY_EXPIRED = 23           # Password has expired
$Script:KDC_ERR_PREAUTH_FAILED = 24        # Pre-authentication failed (wrong password/key)
$Script:KDC_ERR_WRONG_REALM = 68           # Wrong realm (domain name doesn't match KDC's realm)

# Array of fatal KDC errors that should stop execution (no fallback to SimpleBind/NTLM)
# These indicate credential or configuration problems where fallback would also fail
# Used by: Connect-adPEAS for error classification
$Script:KDC_FATAL_ERROR_CODES = @(
    $Script:KDC_ERR_PREAUTH_FAILED,         # 24 - Wrong password/hash
    $Script:KDC_ERR_C_PRINCIPAL_UNKNOWN,    # 6  - User not found
    $Script:KDC_ERR_CLIENT_REVOKED,         # 18 - Account disabled/locked
    $Script:KDC_ERR_KEY_EXPIRED,            # 23 - Password expired
    $Script:KDC_ERR_WRONG_REALM             # 68 - Wrong realm (domain name mismatch)
    # Note: KDC_ERR_ETYPE_NOSUPP (14) is NOT fatal - credentials may be valid,
    #       just the Kerberos etype is not supported. NTLM/SimpleBind can still work.
)

# Kerberos Error Codes (RFC 4120) - centralized map for all modules
# Used by: Invoke-KerberosAuth, Request-ServiceTicket, Invoke-PKINITAuth-Native, Invoke-ASREPRoast
$Script:KERBEROS_ERROR_CODES = @{
    0  = @{ Name = "KDC_ERR_NONE"; Description = "No error" }
    1  = @{ Name = "KDC_ERR_NAME_EXP"; Description = "Client's entry in database has expired" }
    2  = @{ Name = "KDC_ERR_SERVICE_EXP"; Description = "Server's entry in database has expired" }
    3  = @{ Name = "KDC_ERR_BAD_PVNO"; Description = "Requested protocol version not supported" }
    4  = @{ Name = "KDC_ERR_C_OLD_MAST_KVNO"; Description = "Client's key encrypted in old master key" }
    5  = @{ Name = "KDC_ERR_S_OLD_MAST_KVNO"; Description = "Server's key encrypted in old master key" }
    6  = @{ Name = "KDC_ERR_C_PRINCIPAL_UNKNOWN"; Description = "Client not found in Kerberos database" }
    7  = @{ Name = "KDC_ERR_S_PRINCIPAL_UNKNOWN"; Description = "Server not found in Kerberos database" }
    8  = @{ Name = "KDC_ERR_PRINCIPAL_NOT_UNIQUE"; Description = "Multiple principal entries in database" }
    9  = @{ Name = "KDC_ERR_NULL_KEY"; Description = "The client or server has a null key" }
    10 = @{ Name = "KDC_ERR_CANNOT_POSTDATE"; Description = "Ticket not eligible for postdating" }
    11 = @{ Name = "KDC_ERR_NEVER_VALID"; Description = "Requested start time is later than end time" }
    12 = @{ Name = "KDC_ERR_POLICY"; Description = "KDC policy rejects request (account disabled/locked)" }
    13 = @{ Name = "KDC_ERR_BADOPTION"; Description = "KDC cannot accommodate requested option" }
    14 = @{ Name = "KDC_ERR_ETYPE_NOSUPP"; Description = "KDC has no support for encryption type" }
    15 = @{ Name = "KDC_ERR_SUMTYPE_NOSUPP"; Description = "KDC has no support for checksum type" }
    16 = @{ Name = "KDC_ERR_PADATA_TYPE_NOSUPP"; Description = "KDC has no support for padata type" }
    17 = @{ Name = "KDC_ERR_TRTYPE_NOSUPP"; Description = "KDC has no support for transited type" }
    18 = @{ Name = "KDC_ERR_CLIENT_REVOKED"; Description = "Client credentials have been revoked" }
    19 = @{ Name = "KDC_ERR_SERVICE_REVOKED"; Description = "Server credentials have been revoked" }
    20 = @{ Name = "KDC_ERR_TGT_REVOKED"; Description = "TGT has been revoked" }
    21 = @{ Name = "KDC_ERR_CLIENT_NOTYET"; Description = "Client not yet valid (try again later)" }
    22 = @{ Name = "KDC_ERR_SERVICE_NOTYET"; Description = "Server not yet valid (try again later)" }
    23 = @{ Name = "KDC_ERR_KEY_EXPIRED"; Description = "Password has expired (change password)" }
    24 = @{ Name = "KDC_ERR_PREAUTH_FAILED"; Description = "Pre-authentication failed (wrong password/key)" }
    25 = @{ Name = "KDC_ERR_PREAUTH_REQUIRED"; Description = "Additional pre-authentication required" }
    26 = @{ Name = "KDC_ERR_SERVER_NOMATCH"; Description = "Requested server and ticket don't match" }
    27 = @{ Name = "KDC_ERR_MUST_USE_USER2USER"; Description = "Server principal valid for user2user only" }
    28 = @{ Name = "KDC_ERR_PATH_NOT_ACCEPTED"; Description = "KDC Policy rejects transited path" }
    29 = @{ Name = "KDC_ERR_SVC_UNAVAILABLE"; Description = "KDC Service unavailable" }
    31 = @{ Name = "KRB_AP_ERR_BAD_INTEGRITY"; Description = "Integrity check on decrypted field failed" }
    32 = @{ Name = "KRB_AP_ERR_TKT_EXPIRED"; Description = "Ticket expired" }
    33 = @{ Name = "KRB_AP_ERR_TKT_NYV"; Description = "Ticket not yet valid" }
    34 = @{ Name = "KRB_AP_ERR_REPEAT"; Description = "Request is a replay" }
    35 = @{ Name = "KRB_AP_ERR_NOT_US"; Description = "The ticket isn't for us" }
    36 = @{ Name = "KRB_AP_ERR_BADMATCH"; Description = "Ticket and authenticator don't match" }
    37 = @{ Name = "KRB_AP_ERR_SKEW"; Description = "Clock skew too great (sync time with DC)" }
    38 = @{ Name = "KRB_AP_ERR_BADADDR"; Description = "Incorrect net address" }
    39 = @{ Name = "KRB_AP_ERR_BADVERSION"; Description = "Protocol version mismatch" }
    40 = @{ Name = "KRB_AP_ERR_MSG_TYPE"; Description = "Invalid msg type" }
    41 = @{ Name = "KRB_AP_ERR_MODIFIED"; Description = "Message stream modified" }
    42 = @{ Name = "KRB_AP_ERR_BADORDER"; Description = "Message out of order" }
    44 = @{ Name = "KRB_AP_ERR_BADKEYVER"; Description = "Specified version of key is not available" }
    45 = @{ Name = "KRB_AP_ERR_NOKEY"; Description = "Service key not available" }
    46 = @{ Name = "KRB_AP_ERR_MUT_FAIL"; Description = "Mutual authentication failed" }
    47 = @{ Name = "KRB_AP_ERR_BADDIRECTION"; Description = "Incorrect message direction" }
    48 = @{ Name = "KRB_AP_ERR_METHOD"; Description = "Alternative authentication method required" }
    49 = @{ Name = "KRB_AP_ERR_BADSEQ"; Description = "Incorrect sequence number in message" }
    50 = @{ Name = "KRB_AP_ERR_INAPP_CKSUM"; Description = "Inappropriate type of checksum in message" }
    51 = @{ Name = "KRB_AP_PATH_NOT_ACCEPTED"; Description = "Desired path is unreachable" }
    52 = @{ Name = "KRB_ERR_RESPONSE_TOO_BIG"; Description = "Too much data (response too big for UDP, retry with TCP)" }
    60 = @{ Name = "KRB_ERR_GENERIC"; Description = "Generic error" }
    61 = @{ Name = "KRB_ERR_FIELD_TOOLONG"; Description = "Field is too long for implementation" }
    62 = @{ Name = "KDC_ERR_CLIENT_NOT_TRUSTED"; Description = "Client not trusted (PKINIT)" }
    63 = @{ Name = "KDC_ERR_KDC_NOT_TRUSTED"; Description = "KDC not trusted (PKINIT)" }
    64 = @{ Name = "KDC_ERR_INVALID_SIG"; Description = "Invalid signature (PKINIT)" }
    65 = @{ Name = "KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED"; Description = "DH key parameters not accepted (PKINIT)" }
    66 = @{ Name = "KDC_ERR_CERTIFICATE_MISMATCH"; Description = "Certificate doesn't match principal (PKINIT)" }
    67 = @{ Name = "KRB_AP_ERR_NO_TGT"; Description = "No TGT available" }
    68 = @{ Name = "KDC_ERR_WRONG_REALM"; Description = "Wrong realm" }
    69 = @{ Name = "KRB_AP_ERR_USER_TO_USER_REQUIRED"; Description = "User-to-user authentication required" }
    70 = @{ Name = "KDC_ERR_CANT_VERIFY_CERTIFICATE"; Description = "Cannot verify certificate (PKINIT)" }
    71 = @{ Name = "KDC_ERR_INVALID_CERTIFICATE"; Description = "Invalid certificate (PKINIT)" }
    72 = @{ Name = "KDC_ERR_REVOKED_CERTIFICATE"; Description = "Certificate revoked (PKINIT)" }
    73 = @{ Name = "KDC_ERR_REVOCATION_STATUS_UNKNOWN"; Description = "Revocation status unknown (PKINIT)" }
    74 = @{ Name = "KDC_ERR_REVOCATION_STATUS_UNAVAILABLE"; Description = "Revocation status unavailable (PKINIT)" }
    75 = @{ Name = "KDC_ERR_CLIENT_NAME_MISMATCH"; Description = "Client name mismatch in certificate (PKINIT)" }
    76 = @{ Name = "KDC_ERR_KDC_NAME_MISMATCH"; Description = "KDC name mismatch in certificate (PKINIT)" }
    77 = @{ Name = "KDC_ERR_INCONSISTENT_KEY_PURPOSE"; Description = "Certificate cannot be used for PKINIT client authentication" }
    78 = @{ Name = "KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED"; Description = "Digest algorithm in certificate not accepted" }
    79 = @{ Name = "KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED"; Description = "paChecksum2 required (Windows Server 2022+)" }
    80 = @{ Name = "KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED"; Description = "Digest algorithm in signed data not accepted" }
    81 = @{ Name = "KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED"; Description = "Public key encryption not supported" }
}

function Get-KerberosErrorMessage {
    <#
    .SYNOPSIS
        Returns a human-readable error message for a Kerberos error code.
    .PARAMETER ErrorCode
        The Kerberos error code (integer).
    .PARAMETER DescriptionOnly
        Return only the description without the error name.
        By default, returns "ERROR_NAME - Description".
    .OUTPUTS
        [string] Error message.
    .EXAMPLE
        Get-KerberosErrorMessage -ErrorCode 24
        Returns: "KDC_ERR_PREAUTH_FAILED - Pre-authentication failed (wrong password/key)"
    .EXAMPLE
        Get-KerberosErrorMessage -ErrorCode 24 -DescriptionOnly
        Returns: "Pre-authentication failed (wrong password/key)"
    #>
    param(
        [Parameter(Mandatory = $true)]
        [int]$ErrorCode,

        [Parameter(Mandatory = $false)]
        [switch]$DescriptionOnly
    )

    if ($Script:KERBEROS_ERROR_CODES.ContainsKey($ErrorCode)) {
        $errorInfo = $Script:KERBEROS_ERROR_CODES[$ErrorCode]
        if ($DescriptionOnly) {
            return $errorInfo.Description
        }
        return "$($errorInfo.Name) - $($errorInfo.Description)"
    }

    return "Unknown Kerberos error code: $ErrorCode"
}

function Compare-ByteArrayConstantTime {
    <#
    .SYNOPSIS
        Constant-time byte array comparison to prevent timing attacks.
    .DESCRIPTION
        Compares two byte arrays in constant time regardless of where differences occur.
        This prevents timing attacks where an attacker measures response time to determine
        how many bytes match.
    .PARAMETER Array1
        First byte array.
    .PARAMETER Array2
        Second byte array.
    .OUTPUTS
        [bool] $true if arrays are equal, $false otherwise.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Array1,

        [Parameter(Mandatory = $true)]
        [byte[]]$Array2
    )

    # Length check - still constant time since we compare all bytes regardless
    if ($Array1.Length -ne $Array2.Length) {
        return $false
    }

    # XOR all bytes and accumulate differences
    # This ensures we always iterate through ALL bytes regardless of differences
    $diff = 0
    for ($i = 0; $i -lt $Array1.Length; $i++) {
        $diff = $diff -bor ($Array1[$i] -bxor $Array2[$i])
    }

    return ($diff -eq 0)
}

function Get-KeyUsageConstant {
    <#
    .SYNOPSIS
        Creates the key usage constant for AES key derivation.
    .DESCRIPTION
        Builds the 5-byte constant used in RFC 3961 key derivation:
        [KeyUsage as 4 big-endian bytes] + [Suffix byte (0xAA for Ke, 0x55 for Ki)]
    .PARAMETER KeyUsage
        The Kerberos key usage number.
    .PARAMETER Suffix
        The derivation suffix: 0xAA for encryption key (Ke), 0x55 for integrity key (Ki).
    .OUTPUTS
        [byte[]] 5-byte key derivation constant.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [int]$KeyUsage,

        [Parameter(Mandatory = $true)]
        [byte]$Suffix
    )

    return @(
        [byte](($KeyUsage -shr 24) -band 0xFF),
        [byte](($KeyUsage -shr 16) -band 0xFF),
        [byte](($KeyUsage -shr 8) -band 0xFF),
        [byte]($KeyUsage -band 0xFF),
        $Suffix
    )
}

function Get-HMACMD5 {
    <#
    .SYNOPSIS
        Computes HMAC-MD5 hash.
    .PARAMETER Key
        The secret key for HMAC.
    .PARAMETER Data
        The data to hash.
    .OUTPUTS
        [byte[]] 16-byte HMAC-MD5 hash.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Key,

        [Parameter(Mandatory = $true)]
        [byte[]]$Data
    )

    $hmac = New-Object System.Security.Cryptography.HMACMD5
    try {
        $hmac.Key = $Key
        return $hmac.ComputeHash($Data)
    }
    finally {
        $hmac.Dispose()
    }
}

function Get-HMACSHA1 {
    <#
    .SYNOPSIS
        Computes HMAC-SHA1 hash.
    .PARAMETER Key
        The secret key for HMAC.
    .PARAMETER Data
        The data to hash.
    .OUTPUTS
        [byte[]] 20-byte HMAC-SHA1 hash.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Key,

        [Parameter(Mandatory = $true)]
        [byte[]]$Data
    )

    $hmac = New-Object System.Security.Cryptography.HMACSHA1
    try {
        $hmac.Key = $Key
        return $hmac.ComputeHash($Data)
    }
    finally {
        $hmac.Dispose()
    }
}

function Get-MD4Hash {
    <#
    .SYNOPSIS
        Computes MD4 hash (RFC 1320).
    .DESCRIPTION
        Pure PowerShell MD4 implementation for NT-Hash calculation.
        Uses [long] arithmetic with masking to avoid signed integer overflow issues.
    .PARAMETER Data
        The data to hash.
    .OUTPUTS
        [byte[]] 16-byte MD4 hash.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Data
    )

    # Helper: Left rotate with proper masking
    function LeftRotate([long]$x, [int]$n) {
        $x = $x -band 0xFFFFFFFFL
        return (($x -shl $n) -bor ($x -shr (32 - $n))) -band 0xFFFFFFFFL
    }

    # Helper: Safe addition with overflow protection
    function SafeAdd {
        param([long[]]$Values)
        $result = 0L
        foreach ($v in $Values) {
            $result = ($result + ($v -band 0xFFFFFFFFL)) -band 0xFFFFFFFFL
        }
        return $result
    }

    function ToUInt32([long]$x) {
        return [uint32]($x -band 0xFFFFFFFFL)
    }

    # Initialize state
    [long]$A = 0x67452301L
    [long]$B = 0xefcdab89L
    [long]$C = 0x98badcfeL
    [long]$D = 0x10325476L

    # Pre-processing: adding padding bits
    $msgLen = $Data.Length
    $padLen = 64 - (($msgLen + 9) % 64)
    if ($padLen -eq 64) { $padLen = 0 }

    $paddedMsg = New-Object byte[] ($msgLen + 1 + $padLen + 8)
    [Array]::Copy($Data, $paddedMsg, $msgLen)
    $paddedMsg[$msgLen] = 0x80

    # Append length in bits as 64-bit little-endian
    $bitLen = [uint64]$msgLen * 8
    $lenBytes = [System.BitConverter]::GetBytes($bitLen)
    [Array]::Copy($lenBytes, 0, $paddedMsg, $paddedMsg.Length - 8, 8)

    # Process each 64-byte block
    for ($i = 0; $i -lt $paddedMsg.Length; $i += 64) {
        $X = New-Object long[] 16
        for ($j = 0; $j -lt 16; $j++) {
            $X[$j] = [long][System.BitConverter]::ToUInt32($paddedMsg, $i + $j * 4)
        }

        $AA = $A; $BB = $B; $CC = $C; $DD = $D

        # F(X,Y,Z) = (X AND Y) OR (NOT X AND Z)
        # Round 1
        $A = LeftRotate (SafeAdd @($A, (($B -band $C) -bor ((-bnot $B) -band $D)), $X[0])) 3
        $D = LeftRotate (SafeAdd @($D, (($A -band $B) -bor ((-bnot $A) -band $C)), $X[1])) 7
        $C = LeftRotate (SafeAdd @($C, (($D -band $A) -bor ((-bnot $D) -band $B)), $X[2])) 11
        $B = LeftRotate (SafeAdd @($B, (($C -band $D) -bor ((-bnot $C) -band $A)), $X[3])) 19
        $A = LeftRotate (SafeAdd @($A, (($B -band $C) -bor ((-bnot $B) -band $D)), $X[4])) 3
        $D = LeftRotate (SafeAdd @($D, (($A -band $B) -bor ((-bnot $A) -band $C)), $X[5])) 7
        $C = LeftRotate (SafeAdd @($C, (($D -band $A) -bor ((-bnot $D) -band $B)), $X[6])) 11
        $B = LeftRotate (SafeAdd @($B, (($C -band $D) -bor ((-bnot $C) -band $A)), $X[7])) 19
        $A = LeftRotate (SafeAdd @($A, (($B -band $C) -bor ((-bnot $B) -band $D)), $X[8])) 3
        $D = LeftRotate (SafeAdd @($D, (($A -band $B) -bor ((-bnot $A) -band $C)), $X[9])) 7
        $C = LeftRotate (SafeAdd @($C, (($D -band $A) -bor ((-bnot $D) -band $B)), $X[10])) 11
        $B = LeftRotate (SafeAdd @($B, (($C -band $D) -bor ((-bnot $C) -band $A)), $X[11])) 19
        $A = LeftRotate (SafeAdd @($A, (($B -band $C) -bor ((-bnot $B) -band $D)), $X[12])) 3
        $D = LeftRotate (SafeAdd @($D, (($A -band $B) -bor ((-bnot $A) -band $C)), $X[13])) 7
        $C = LeftRotate (SafeAdd @($C, (($D -band $A) -bor ((-bnot $D) -band $B)), $X[14])) 11
        $B = LeftRotate (SafeAdd @($B, (($C -band $D) -bor ((-bnot $C) -band $A)), $X[15])) 19

        # G(X,Y,Z) = (X AND Y) OR (X AND Z) OR (Y AND Z)
        # Round 2
        $A = LeftRotate (SafeAdd @($A, (($B -band $C) -bor ($B -band $D) -bor ($C -band $D)), $X[0], 0x5A827999L)) 3
        $D = LeftRotate (SafeAdd @($D, (($A -band $B) -bor ($A -band $C) -bor ($B -band $C)), $X[4], 0x5A827999L)) 5
        $C = LeftRotate (SafeAdd @($C, (($D -band $A) -bor ($D -band $B) -bor ($A -band $B)), $X[8], 0x5A827999L)) 9
        $B = LeftRotate (SafeAdd @($B, (($C -band $D) -bor ($C -band $A) -bor ($D -band $A)), $X[12], 0x5A827999L)) 13
        $A = LeftRotate (SafeAdd @($A, (($B -band $C) -bor ($B -band $D) -bor ($C -band $D)), $X[1], 0x5A827999L)) 3
        $D = LeftRotate (SafeAdd @($D, (($A -band $B) -bor ($A -band $C) -bor ($B -band $C)), $X[5], 0x5A827999L)) 5
        $C = LeftRotate (SafeAdd @($C, (($D -band $A) -bor ($D -band $B) -bor ($A -band $B)), $X[9], 0x5A827999L)) 9
        $B = LeftRotate (SafeAdd @($B, (($C -band $D) -bor ($C -band $A) -bor ($D -band $A)), $X[13], 0x5A827999L)) 13
        $A = LeftRotate (SafeAdd @($A, (($B -band $C) -bor ($B -band $D) -bor ($C -band $D)), $X[2], 0x5A827999L)) 3
        $D = LeftRotate (SafeAdd @($D, (($A -band $B) -bor ($A -band $C) -bor ($B -band $C)), $X[6], 0x5A827999L)) 5
        $C = LeftRotate (SafeAdd @($C, (($D -band $A) -bor ($D -band $B) -bor ($A -band $B)), $X[10], 0x5A827999L)) 9
        $B = LeftRotate (SafeAdd @($B, (($C -band $D) -bor ($C -band $A) -bor ($D -band $A)), $X[14], 0x5A827999L)) 13
        $A = LeftRotate (SafeAdd @($A, (($B -band $C) -bor ($B -band $D) -bor ($C -band $D)), $X[3], 0x5A827999L)) 3
        $D = LeftRotate (SafeAdd @($D, (($A -band $B) -bor ($A -band $C) -bor ($B -band $C)), $X[7], 0x5A827999L)) 5
        $C = LeftRotate (SafeAdd @($C, (($D -band $A) -bor ($D -band $B) -bor ($A -band $B)), $X[11], 0x5A827999L)) 9
        $B = LeftRotate (SafeAdd @($B, (($C -band $D) -bor ($C -band $A) -bor ($D -band $A)), $X[15], 0x5A827999L)) 13

        # H(X,Y,Z) = X XOR Y XOR Z
        # Round 3
        $A = LeftRotate (SafeAdd @($A, ($B -bxor $C -bxor $D), $X[0], 0x6ED9EBA1L)) 3
        $D = LeftRotate (SafeAdd @($D, ($A -bxor $B -bxor $C), $X[8], 0x6ED9EBA1L)) 9
        $C = LeftRotate (SafeAdd @($C, ($D -bxor $A -bxor $B), $X[4], 0x6ED9EBA1L)) 11
        $B = LeftRotate (SafeAdd @($B, ($C -bxor $D -bxor $A), $X[12], 0x6ED9EBA1L)) 15
        $A = LeftRotate (SafeAdd @($A, ($B -bxor $C -bxor $D), $X[2], 0x6ED9EBA1L)) 3
        $D = LeftRotate (SafeAdd @($D, ($A -bxor $B -bxor $C), $X[10], 0x6ED9EBA1L)) 9
        $C = LeftRotate (SafeAdd @($C, ($D -bxor $A -bxor $B), $X[6], 0x6ED9EBA1L)) 11
        $B = LeftRotate (SafeAdd @($B, ($C -bxor $D -bxor $A), $X[14], 0x6ED9EBA1L)) 15
        $A = LeftRotate (SafeAdd @($A, ($B -bxor $C -bxor $D), $X[1], 0x6ED9EBA1L)) 3
        $D = LeftRotate (SafeAdd @($D, ($A -bxor $B -bxor $C), $X[9], 0x6ED9EBA1L)) 9
        $C = LeftRotate (SafeAdd @($C, ($D -bxor $A -bxor $B), $X[5], 0x6ED9EBA1L)) 11
        $B = LeftRotate (SafeAdd @($B, ($C -bxor $D -bxor $A), $X[13], 0x6ED9EBA1L)) 15
        $A = LeftRotate (SafeAdd @($A, ($B -bxor $C -bxor $D), $X[3], 0x6ED9EBA1L)) 3
        $D = LeftRotate (SafeAdd @($D, ($A -bxor $B -bxor $C), $X[11], 0x6ED9EBA1L)) 9
        $C = LeftRotate (SafeAdd @($C, ($D -bxor $A -bxor $B), $X[7], 0x6ED9EBA1L)) 11
        $B = LeftRotate (SafeAdd @($B, ($C -bxor $D -bxor $A), $X[15], 0x6ED9EBA1L)) 15

        $A = SafeAdd @($A, $AA)
        $B = SafeAdd @($B, $BB)
        $C = SafeAdd @($C, $CC)
        $D = SafeAdd @($D, $DD)
    }

    $result = New-Object byte[] 16
    [Array]::Copy([System.BitConverter]::GetBytes((ToUInt32 $A)), 0, $result, 0, 4)
    [Array]::Copy([System.BitConverter]::GetBytes((ToUInt32 $B)), 0, $result, 4, 4)
    [Array]::Copy([System.BitConverter]::GetBytes((ToUInt32 $C)), 0, $result, 8, 4)
    [Array]::Copy([System.BitConverter]::GetBytes((ToUInt32 $D)), 0, $result, 12, 4)

    return $result
}

function Get-NTHashFromPassword {
    <#
    .SYNOPSIS
        Computes NT-Hash from plaintext password.
    .DESCRIPTION
        NT-Hash = MD4(UTF-16LE(password))
    .PARAMETER PlainPassword
        The plaintext password.
    .OUTPUTS
        [byte[]] 16-byte NT hash.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$PlainPassword
    )

    $utf16leBytes = [System.Text.Encoding]::Unicode.GetBytes($PlainPassword)
    return Get-MD4Hash -Data $utf16leBytes
}

function Invoke-RC4 {
    <#
    .SYNOPSIS
        RC4 stream cipher implementation.
    .PARAMETER Key
        The encryption key.
    .PARAMETER Data
        The data to encrypt/decrypt.
    .OUTPUTS
        [byte[]] Encrypted/decrypted data.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Key,

        [Parameter(Mandatory = $true)]
        [byte[]]$Data
    )

    # Key-scheduling algorithm (KSA)
    $S = [byte[]](0..255)
    $j = 0

    for ($i = 0; $i -lt 256; $i++) {
        $j = ($j + $S[$i] + $Key[$i % $Key.Length]) % 256
        $temp = $S[$i]
        $S[$i] = $S[$j]
        $S[$j] = $temp
    }

    # Pseudo-random generation algorithm (PRGA)
    $i = 0
    $j = 0
    $result = New-Object byte[] $Data.Length

    for ($k = 0; $k -lt $Data.Length; $k++) {
        $i = ($i + 1) % 256
        $j = ($j + $S[$i]) % 256
        $temp = $S[$i]
        $S[$i] = $S[$j]
        $S[$j] = $temp
        $result[$k] = $Data[$k] -bxor $S[($S[$i] + $S[$j]) % 256]
    }

    return $result
}

function Encrypt-RC4HMAC {
    <#
    .SYNOPSIS
        Encrypts data using RC4-HMAC (etype 23).
    .DESCRIPTION
        Implements RFC 4757 RC4-HMAC encryption for Kerberos.
    .PARAMETER Key
        The RC4 key (NT-Hash).
    .PARAMETER Data
        The plaintext data.
    .PARAMETER KeyUsage
        The Kerberos key usage number.
    .OUTPUTS
        [byte[]] Encrypted data with checksum (16 bytes checksum + encrypted data).
    #>
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Key,

        [Parameter(Mandatory = $true)]
        [byte[]]$Data,

        [Parameter(Mandatory = $true)]
        [int]$KeyUsage
    )

    # Generate random confounder (RFC 4757: 8 bytes for RC4-HMAC)
    $confounder = New-Object byte[] $Script:RC4_CONFOUNDER_SIZE
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($confounder)
    }
    finally {
        $rng.Dispose()
    }

    # K1 = HMAC-MD5(Key, usage)
    $usageBytes = [System.BitConverter]::GetBytes([int32]$KeyUsage)
    $K1 = Get-HMACMD5 -Key $Key -Data $usageBytes

    # Plaintext = confounder || data
    $plaintext = $confounder + $Data

    # Checksum = HMAC-MD5(K1, plaintext)
    $checksum = Get-HMACMD5 -Key $K1 -Data $plaintext

    # K2 = HMAC-MD5(K1, checksum)
    $K2 = Get-HMACMD5 -Key $K1 -Data $checksum

    # Encrypted = RC4(K2, plaintext)
    $encrypted = Invoke-RC4 -Key $K2 -Data $plaintext

    return $checksum + $encrypted
}

function Decrypt-RC4HMAC {
    <#
    .SYNOPSIS
        Decrypts data using RC4-HMAC (etype 23).
    .DESCRIPTION
        Implements RFC 4757 RC4-HMAC decryption for Kerberos.
    .PARAMETER Key
        The RC4 key (NT-Hash).
    .PARAMETER CipherText
        The encrypted data with checksum.
    .PARAMETER KeyUsage
        The Kerberos key usage number.
    .OUTPUTS
        [byte[]] Decrypted plaintext (without confounder).
    #>
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Key,

        [Parameter(Mandatory = $true)]
        [byte[]]$CipherText,

        [Parameter(Mandatory = $true)]
        [int]$KeyUsage
    )

    if ($CipherText.Length -lt $Script:RC4_MIN_CIPHERTEXT) {
        throw "RC4-HMAC ciphertext too short (minimum $Script:RC4_MIN_CIPHERTEXT bytes: $Script:HMAC_MD5_SIZE checksum + $Script:RC4_CONFOUNDER_SIZE confounder)"
    }

    $checksum = $CipherText[0..($Script:HMAC_MD5_SIZE - 1)]
    $encrypted = $CipherText[$Script:HMAC_MD5_SIZE..($CipherText.Length - 1)]

    # K1 = HMAC-MD5(Key, usage)
    $usageBytes = [System.BitConverter]::GetBytes([int32]$KeyUsage)
    $K1 = Get-HMACMD5 -Key $Key -Data $usageBytes

    # K2 = HMAC-MD5(K1, checksum)
    $K2 = Get-HMACMD5 -Key $K1 -Data $checksum

    # Decrypted = RC4(K2, encrypted)
    $decrypted = Invoke-RC4 -Key $K2 -Data $encrypted

    # Verify checksum using constant-time comparison (prevents timing attacks)
    $expectedChecksum = Get-HMACMD5 -Key $K1 -Data $decrypted
    if (-not (Compare-ByteArrayConstantTime -Array1 $checksum -Array2 $expectedChecksum)) {
        # Debug: Show checksum comparison for diagnostics
        $receivedHex = ($checksum | ForEach-Object { $_.ToString('X2') }) -join ''
        $expectedHex = ($expectedChecksum | ForEach-Object { $_.ToString('X2') }) -join ''
        Write-Debug "[Decrypt-RC4HMAC] Checksum mismatch - Received: $receivedHex, Expected: $expectedHex"
        throw "RC4-HMAC checksum verification failed"
    }

    # Return plaintext without confounder
    return $decrypted[$Script:RC4_CONFOUNDER_SIZE..($decrypted.Length - 1)]
}

function Invoke-NFold {
    <#
    .SYNOPSIS
        n-fold implementation per RFC 3961.
    .DESCRIPTION
        Direct port from MIT Kerberos (krb5/src/lib/crypto/krb/nfold.c).
        Used for AES key derivation.
    .PARAMETER InputData
        The input bytes.
    .PARAMETER OutputBits
        The desired output size in bits.
    .OUTPUTS
        [byte[]] n-folded output.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$InputData,

        [Parameter(Mandatory = $true)]
        [int]$OutputBits
    )

    # Use [long] to prevent integer overflow with large inputs
    [long]$inbits = $InputData.Length
    [long]$outbits = $OutputBits / 8

    # Calculate GCD using Euclidean algorithm
    [long]$a = $outbits
    [long]$b = $inbits
    while ($b -ne 0) {
        $c = $b
        $b = $a % $b
        $a = $c
    }

    # Calculate LCM (use [long] to prevent overflow)
    [long]$lcm = ([long]$outbits * [long]$inbits) / $a

    # Initialize output
    $out = New-Object byte[] $outbits
    $byte = 0

    # Main loop
    for ($i = $lcm - 1; $i -ge 0; $i--) {
        $inbits_bits = $inbits * 8
        $msbit = ((($inbits_bits - 1) +
                   (($inbits_bits + 13) * [int][Math]::Floor($i / $inbits)) +
                   (($inbits - ($i % $inbits)) * 8)) % $inbits_bits)

        $msbit_byte = [int][Math]::Floor($msbit / 8)
        $msbit_bit = $msbit -band 7

        $idx1 = (($inbits - 1 - $msbit_byte) % $inbits + $inbits) % $inbits
        $idx2 = (($inbits - $msbit_byte) % $inbits + $inbits) % $inbits

        $combined = ([int]$InputData[$idx1] -shl 8) -bor [int]$InputData[$idx2]
        $shifted = ($combined -shr ($msbit_bit + 1)) -band 0xFF

        $byte = $byte + $shifted

        $outIdx = $i % $outbits
        $byte = $byte + [int]$out[$outIdx]
        $out[$outIdx] = [byte]($byte -band 0xFF)
        $byte = $byte -shr 8
    }

    # Final carry propagation
    if ($byte -gt 0) {
        for ($i = $outbits - 1; $i -ge 0; $i--) {
            $byte = $byte + [int]$out[$i]
            $out[$i] = [byte]($byte -band 0xFF)
            $byte = $byte -shr 8
        }
    }

    return $out
}

function Get-AESDerivedKey {
    <#
    .SYNOPSIS
        Derives AES key using DK function (RFC 3961).
    .PARAMETER BaseKey
        The base key.
    .PARAMETER Constant
        The constant for key derivation.
    .PARAMETER KeyLength
        The desired key length (16 or 32).
    .OUTPUTS
        [byte[]] Derived key.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$BaseKey,

        [Parameter(Mandatory = $true)]
        [byte[]]$Constant,

        [Parameter(Mandatory = $true)]
        [int]$KeyLength
    )

    # Validate key lengths (RFC 3962)
    if ($BaseKey.Length -notin @($Script:AES128_KEY_SIZE, $Script:AES256_KEY_SIZE)) {
        throw "BaseKey must be $Script:AES128_KEY_SIZE (AES-128) or $Script:AES256_KEY_SIZE (AES-256) bytes, got $($BaseKey.Length)"
    }
    if ($KeyLength -notin @($Script:AES128_KEY_SIZE, $Script:AES256_KEY_SIZE)) {
        throw "KeyLength must be $Script:AES128_KEY_SIZE (AES-128) or $Script:AES256_KEY_SIZE (AES-256), got $KeyLength"
    }

    $aes = [System.Security.Cryptography.Aes]::Create()
    try {
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::None
        $aes.Key = $BaseKey
        $aes.IV = New-Object byte[] $Script:AES_BLOCK_SIZE

        $encryptor = $aes.CreateEncryptor()
        try {
            $blockSize = $Script:AES_BLOCK_SIZE
            $nfoldedConstant = Invoke-NFold -InputData $Constant -OutputBits ($blockSize * 8)

            $derivedKey = @()
            $currentBlock = $nfoldedConstant

            while ($derivedKey.Length -lt $KeyLength) {
                $currentBlock = $encryptor.TransformFinalBlock($currentBlock, 0, $currentBlock.Length)
                $derivedKey += $currentBlock
            }

            return $derivedKey[0..($KeyLength - 1)]
        }
        finally {
            $encryptor.Dispose()
        }
    }
    finally {
        $aes.Dispose()
    }
}

function Get-AESKeyFromPassword {
    <#
    .SYNOPSIS
        Derives AES key from password per RFC 3962.
    .DESCRIPTION
        Key = DK(PBKDF2(password, salt, 4096, keyLength), "kerberos")
        Salt = uppercase(realm) + username
    .PARAMETER PlainPassword
        The plaintext password.
    .PARAMETER Salt
        The salt (uppercase realm + username).
    .PARAMETER KeyLength
        The key length (16 for AES128, 32 for AES256).
    .OUTPUTS
        [byte[]] Derived AES key.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$PlainPassword,

        [Parameter(Mandatory = $true)]
        [string]$Salt,

        [Parameter(Mandatory = $true)]
        [int]$KeyLength
    )

    $passwordBytes = [System.Text.Encoding]::UTF8.GetBytes($PlainPassword)
    $saltBytes = [System.Text.Encoding]::UTF8.GetBytes($Salt)

    $pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
        $passwordBytes,
        $saltBytes,
        4096,
        [System.Security.Cryptography.HashAlgorithmName]::SHA1
    )
    try {
        $tempKey = $pbkdf2.GetBytes($KeyLength)
    }
    finally {
        $pbkdf2.Dispose()
    }

    # Apply DK function: DK(tempKey, "kerberos")
    $constant = [System.Text.Encoding]::ASCII.GetBytes("kerberos")
    $finalKey = Get-AESDerivedKey -BaseKey $tempKey -Constant $constant -KeyLength $KeyLength

    return $finalKey
}

function Get-Hash {
    <#
    .SYNOPSIS
        Derives common password hashes and Kerberos keys from a plaintext password.
    .DESCRIPTION
        Computes multiple hash formats from a password, returned as hex strings for easy copy/paste.

        Always computed:
        - RC4 (NT-Hash): MD4(UTF-16LE(password)) — no salt, domain-independent
        - MD5, SHA1, SHA256, SHA512: Standard cryptographic hashes

        Computed when -UserName is provided:
        - DCC (mscache v1): MD4(NT-Hash || UTF-16LE(lowercase(username)))
        - DCC2 (mscachev2): PBKDF2-HMAC-SHA1(DCC, lowercase(username), 10240, 16)

        Computed when -Domain and -UserName are provided:
        - AES128/AES256: PBKDF2-SHA1 + DK("kerberos") per RFC 3962
    .PARAMETER Password
        The plaintext password.
    .PARAMETER Domain
        The domain FQDN (e.g., "contoso.com"). Will be uppercased for the AES salt.
        Required for AES key derivation.
    .PARAMETER UserName
        The sAMAccountName (e.g., "admin"). Case-sensitive for the AES salt.
        Required for AES and DCC/DCC2 key derivation.
    .OUTPUTS
        [PSCustomObject] with hash values as hex strings. Properties depend on provided parameters.
    .EXAMPLE
        Get-Hash -Password "P@ssw0rd"
    .EXAMPLE
        Get-Hash -Password "P@ssw0rd" -Domain "contoso.com" -UserName "admin"
    .EXAMPLE
        # Use output with Connect-adPEAS
        $h = Get-Hash -Password "P@ssw0rd" -Domain "contoso.com" -UserName "admin"
        Connect-adPEAS -Domain "contoso.com" -Username "admin" -NTHash $h.RC4
        Connect-adPEAS -Domain "contoso.com" -Username "admin" -AES256Key $h.AES256
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Password,

        [Parameter(Mandatory = $false)]
        [string]$Domain,

        [Parameter(Mandatory = $false)]
        [string]$UserName
    )

    $passwordBytes = [System.Text.Encoding]::UTF8.GetBytes($Password)

    # --- Always computed (no salt required) ---

    # RC4 key (NT-Hash): MD4(UTF-16LE(password))
    $ntHashBytes = Get-NTHashFromPassword -PlainPassword $Password
    $rc4Hex = ($ntHashBytes | ForEach-Object { $_.ToString("X2") }) -join ''

    # MD5
    $md5 = [System.Security.Cryptography.MD5]::Create()
    try { $md5Hex = ($md5.ComputeHash($passwordBytes) | ForEach-Object { $_.ToString("X2") }) -join '' }
    finally { $md5.Dispose() }

    # SHA1
    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    try { $sha1Hex = ($sha1.ComputeHash($passwordBytes) | ForEach-Object { $_.ToString("X2") }) -join '' }
    finally { $sha1.Dispose() }

    # SHA256
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try { $sha256Hex = ($sha256.ComputeHash($passwordBytes) | ForEach-Object { $_.ToString("X2") }) -join '' }
    finally { $sha256.Dispose() }

    # SHA512
    $sha512 = [System.Security.Cryptography.SHA512]::Create()
    try { $sha512Hex = ($sha512.ComputeHash($passwordBytes) | ForEach-Object { $_.ToString("X2") }) -join '' }
    finally { $sha512.Dispose() }

    # --- Requires UserName (salt) ---

    $dccHex  = $null
    $dcc2Hex = $null

    if ($UserName) {
        # DCC (Domain Cached Credentials v1): MD4(NT-Hash || UTF-16LE(lowercase(username)))
        # Also known as "mscache" — stored locally when DC is unreachable
        $userLower = [System.Text.Encoding]::Unicode.GetBytes($UserName.ToLower())
        $dccInput = New-Object byte[] ($ntHashBytes.Length + $userLower.Length)
        [Array]::Copy($ntHashBytes, 0, $dccInput, 0, $ntHashBytes.Length)
        [Array]::Copy($userLower, 0, $dccInput, $ntHashBytes.Length, $userLower.Length)
        $dccBytes = Get-MD4Hash -Data $dccInput
        $dccHex = ($dccBytes | ForEach-Object { $_.ToString("X2") }) -join ''

        # DCC2 (Domain Cached Credentials v2): PBKDF2-HMAC-SHA1(DCC, lowercase(username), 10240, 16)
        # Also known as "mscachev2" — used since Vista/2008
        # Manual PBKDF2 because Rfc2898DeriveBytes requires minimum 8-byte salt
        $dcc2Salt = [System.Text.Encoding]::UTF8.GetBytes($UserName.ToLower())
        $dcc2Iterations = 10240
        $dcc2Len = 16

        # PBKDF2-HMAC-SHA1 (RFC 2898 Section 5.2) — single block (dkLen <= 20)
        $saltBlock = New-Object byte[] ($dcc2Salt.Length + 4)
        [Array]::Copy($dcc2Salt, 0, $saltBlock, 0, $dcc2Salt.Length)
        $saltBlock[$saltBlock.Length - 1] = 1  # Block index 1 (big-endian)

        $uBlock = Get-HMACSHA1 -Key $dccBytes -Data $saltBlock
        $xorAccum = $uBlock.Clone()

        for ($iter = 1; $iter -lt $dcc2Iterations; $iter++) {
            $uBlock = Get-HMACSHA1 -Key $dccBytes -Data $uBlock
            for ($j = 0; $j -lt $xorAccum.Length; $j++) {
                $xorAccum[$j] = $xorAccum[$j] -bxor $uBlock[$j]
            }
        }

        $dcc2Bytes = $xorAccum[0..($dcc2Len - 1)]
        $dcc2Hex = ($dcc2Bytes | ForEach-Object { $_.ToString("X2") }) -join ''
    }

    # --- Requires Domain + UserName (Kerberos salt) ---

    $aes128Hex = $null
    $aes256Hex = $null

    if ($Domain -and $UserName) {
        $salt = $Domain.ToUpper() + $UserName

        $aes128Bytes = Get-AESKeyFromPassword -PlainPassword $Password -Salt $salt -KeyLength $Script:AES128_KEY_SIZE
        $aes128Hex = ($aes128Bytes | ForEach-Object { $_.ToString("X2") }) -join ''

        $aes256Bytes = Get-AESKeyFromPassword -PlainPassword $Password -Salt $salt -KeyLength $Script:AES256_KEY_SIZE
        $aes256Hex = ($aes256Bytes | ForEach-Object { $_.ToString("X2") }) -join ''
    }

    # Build result object
    $resultObj = [ordered]@{
        UserName = if ($UserName) { $UserName } else { $null }
        Domain   = if ($Domain) { $Domain.ToUpper() } else { $null }
        Password = $Password
        RC4      = $rc4Hex
        AES128   = $aes128Hex
        AES256   = $aes256Hex
        DCC      = $dccHex
        DCC2     = $dcc2Hex
        MD5      = $md5Hex
        SHA1     = $sha1Hex
        SHA256   = $sha256Hex
        SHA512   = $sha512Hex
    }

    return [PSCustomObject]$resultObj
}

function Invoke-AESCBC-CTS {
    <#
    .SYNOPSIS
        AES-CBC-CTS encryption/decryption per RFC 3962.
    .DESCRIPTION
        Implements Ciphertext Stealing (CTS) mode for AES.
        Used by Kerberos AES128 (etype 17) and AES256 (etype 18).
    .PARAMETER Key
        The AES key.
    .PARAMETER Data
        The data to encrypt/decrypt.
    .PARAMETER Encrypt
        $true for encryption, $false for decryption.
    .OUTPUTS
        [byte[]] Encrypted or decrypted data.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Key,

        [Parameter(Mandatory = $true)]
        [byte[]]$Data,

        [Parameter(Mandatory = $true)]
        [bool]$Encrypt
    )

    $blockSize = $Script:AES_BLOCK_SIZE

    # Pad to multiple of block size with zeros
    $padLen = ($blockSize - ($Data.Length % $blockSize)) % $blockSize
    $padded = $Data + (New-Object byte[] $padLen)

    $aes = [System.Security.Cryptography.Aes]::Create()
    try {
        $aes.Key = $Key
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::None
        $aes.IV = New-Object byte[] $blockSize

        if ($Encrypt) {
            $encryptor = $aes.CreateEncryptor()
            try {
                $ctext = $encryptor.TransformFinalBlock($padded, 0, $padded.Length)
            }
            finally {
                $encryptor.Dispose()
            }

            if ($Data.Length -gt $blockSize) {
                # Swap the last two ciphertext blocks and truncate
                $lastLen = $Data.Length % $blockSize
                if ($lastLen -eq 0) { $lastLen = $blockSize }

                $beforeLastTwo = $ctext.Length - 32
                $resultLen = $beforeLastTwo + $blockSize + $lastLen
                $result = New-Object byte[] $resultLen

                if ($beforeLastTwo -gt 0) {
                    [Array]::Copy($ctext, 0, $result, 0, $beforeLastTwo)
                }

                # Swap: put last block in second-to-last position
                [Array]::Copy($ctext, $ctext.Length - $blockSize, $result, $beforeLastTwo, $blockSize)

                # Put second-to-last block (truncated) in last position
                [Array]::Copy($ctext, $ctext.Length - 2 * $blockSize, $result, $beforeLastTwo + $blockSize, $lastLen)

                return $result
            }
            else {
                # Single block - return truncated to original length
                return $ctext[0..($Data.Length - 1)]
            }
        }
        else {
            # DECRYPTION
            if ($Data.Length -le $blockSize) {
                $decryptor = $aes.CreateDecryptor()
                try {
                    $ptext = $decryptor.TransformFinalBlock($padded, 0, $padded.Length)
                }
                finally {
                    $decryptor.Dispose()
                }
                return $ptext[0..($Data.Length - 1)]
            }

            # Multiple blocks with CTS
            $lastLen = $Data.Length % $blockSize
            if ($lastLen -eq 0) { $lastLen = $blockSize }

            $Cn = $Data[($Data.Length - $blockSize - $lastLen)..($Data.Length - $lastLen - 1)]
            $CnMinus1Partial = $Data[($Data.Length - $lastLen)..($Data.Length - 1)]

            # Decrypt Cn with ECB
            $aes.Mode = [System.Security.Cryptography.CipherMode]::ECB
            $decryptorEcb = $aes.CreateDecryptor()
            try {
                $intermediate = $decryptorEcb.TransformFinalBlock($Cn, 0, $blockSize)
            }
            finally {
                $decryptorEcb.Dispose()
            }

            # Pad Cn-1 with stolen bytes
            $CnMinus1Full = New-Object byte[] $blockSize
            [Array]::Copy($CnMinus1Partial, 0, $CnMinus1Full, 0, $lastLen)
            for ($i = $lastLen; $i -lt $blockSize; $i++) {
                $CnMinus1Full[$i] = $intermediate[$i]
            }

            # XOR to get Pn
            $Pn = New-Object byte[] $lastLen
            for ($i = 0; $i -lt $lastLen; $i++) {
                $Pn[$i] = $intermediate[$i] -bxor $CnMinus1Partial[$i]
            }

            # IV for Cn-1
            if ($Data.Length -gt 2 * $blockSize) {
                $ivForCnMinus1 = $Data[($Data.Length - $blockSize - $lastLen - $blockSize)..($Data.Length - $blockSize - $lastLen - 1)]
            }
            else {
                $ivForCnMinus1 = New-Object byte[] $blockSize
            }

            # Decrypt Cn-1
            $decryptorEcb2 = $aes.CreateDecryptor()
            try {
                $PnMinus1Intermediate = $decryptorEcb2.TransformFinalBlock($CnMinus1Full, 0, $blockSize)
            }
            finally {
                $decryptorEcb2.Dispose()
            }

            $PnMinus1 = New-Object byte[] $blockSize
            for ($i = 0; $i -lt $blockSize; $i++) {
                $PnMinus1[$i] = $PnMinus1Intermediate[$i] -bxor $ivForCnMinus1[$i]
            }

            # Decrypt remaining blocks with CBC
            $result = New-Object byte[] $Data.Length

            if ($Data.Length -gt 2 * $blockSize) {
                $beforeLastTwoLen = $Data.Length - $blockSize - $lastLen
                $beforeLastTwo = $Data[0..($beforeLastTwoLen - 1)]

                $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
                $aes.IV = New-Object byte[] $blockSize
                $decryptorCbc = $aes.CreateDecryptor()
                try {
                    $plainBefore = $decryptorCbc.TransformFinalBlock($beforeLastTwo, 0, $beforeLastTwo.Length)
                }
                finally {
                    $decryptorCbc.Dispose()
                }

                [Array]::Copy($plainBefore, 0, $result, 0, $beforeLastTwoLen)
            }

            $pnMinus1Offset = $Data.Length - $blockSize - $lastLen
            [Array]::Copy($PnMinus1, 0, $result, $pnMinus1Offset, $blockSize)
            [Array]::Copy($Pn, 0, $result, $pnMinus1Offset + $blockSize, $lastLen)

            return $result
        }
    }
    finally {
        $aes.Dispose()
    }
}

function Encrypt-AESCTS {
    <#
    .SYNOPSIS
        Encrypts data using AES-CTS with HMAC-SHA1 checksum.
    .DESCRIPTION
        Implements RFC 3962 AES encryption for Kerberos (etype 17/18).
    .PARAMETER Key
        The AES key.
    .PARAMETER Data
        The plaintext data.
    .PARAMETER KeyUsage
        The Kerberos key usage number.
    .OUTPUTS
        [byte[]] Encrypted data with checksum.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Key,

        [Parameter(Mandatory = $true)]
        [byte[]]$Data,

        [Parameter(Mandatory = $true)]
        [int]$KeyUsage
    )

    $keyLength = $Key.Length

    # Ke = DK(base-key, usage | 0xAA) - Encryption key
    $keConstant = Get-KeyUsageConstant -KeyUsage $KeyUsage -Suffix $Script:KE_CONSTANT_SUFFIX
    $Ke = Get-AESDerivedKey -BaseKey $Key -Constant $keConstant -KeyLength $keyLength

    # Ki = DK(base-key, usage | 0x55) - Integrity key
    $kiConstant = Get-KeyUsageConstant -KeyUsage $KeyUsage -Suffix $Script:KI_CONSTANT_SUFFIX
    $Ki = Get-AESDerivedKey -BaseKey $Key -Constant $kiConstant -KeyLength $keyLength

    # Generate random confounder (RFC 3962: 16 bytes for AES-CTS)
    $confounder = New-Object byte[] $Script:AES_CONFOUNDER_SIZE
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($confounder)
    }
    finally {
        $rng.Dispose()
    }

    $plaintext = $confounder + $Data

    # AES-CTS handles non-block-aligned data natively (no pre-padding needed)
    # Invoke-AESCBC-CTS pads internally for CBC but uses CTS block swap for correct output size
    $encrypted = Invoke-AESCBC-CTS -Key $Ke -Data $plaintext -Encrypt $true

    # Checksum = first 12 bytes of HMAC-SHA1 over unpadded confounder + plaintext
    $hmac = Get-HMACSHA1 -Key $Ki -Data $plaintext
    $checksum = $hmac[0..($Script:AES_CHECKSUM_SIZE - 1)]

    return $encrypted + $checksum
}

function Decrypt-AESCTS {
    <#
    .SYNOPSIS
        Decrypts data using AES-CTS with HMAC-SHA1 checksum verification.
    .DESCRIPTION
        Implements RFC 3962 AES decryption for Kerberos (etype 17/18).
    .PARAMETER Key
        The AES key.
    .PARAMETER CipherText
        The encrypted data with checksum.
    .PARAMETER KeyUsage
        The Kerberos key usage number.
    .OUTPUTS
        [byte[]] Decrypted plaintext (without confounder).
    #>
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Key,

        [Parameter(Mandatory = $true)]
        [byte[]]$CipherText,

        [Parameter(Mandatory = $true)]
        [int]$KeyUsage
    )

    $keyLength = $Key.Length
    $checksumLength = $Script:AES_CHECKSUM_SIZE

    if ($CipherText.Length -lt $Script:AES_MIN_CIPHERTEXT) {
        throw "AES-CTS ciphertext too short (minimum $Script:AES_MIN_CIPHERTEXT bytes: $Script:AES_CONFOUNDER_SIZE confounder + $Script:AES_CHECKSUM_SIZE checksum)"
    }

    $encrypted = $CipherText[0..($CipherText.Length - $checksumLength - 1)]
    $checksum = $CipherText[($CipherText.Length - $checksumLength)..($CipherText.Length - 1)]

    # Ke = DK(base-key, usage | 0xAA) - Encryption key
    $keConstant = Get-KeyUsageConstant -KeyUsage $KeyUsage -Suffix $Script:KE_CONSTANT_SUFFIX
    $Ke = Get-AESDerivedKey -BaseKey $Key -Constant $keConstant -KeyLength $keyLength

    # Ki = DK(base-key, usage | 0x55) - Integrity key
    $kiConstant = Get-KeyUsageConstant -KeyUsage $KeyUsage -Suffix $Script:KI_CONSTANT_SUFFIX
    $Ki = Get-AESDerivedKey -BaseKey $Key -Constant $kiConstant -KeyLength $keyLength

    $decrypted = Invoke-AESCBC-CTS -Key $Ke -Data $encrypted -Encrypt $false

    # Verify checksum using constant-time comparison (prevents timing attacks)
    $expectedHmac = Get-HMACSHA1 -Key $Ki -Data $decrypted
    $expectedChecksum = [byte[]]$expectedHmac[0..($Script:AES_CHECKSUM_SIZE - 1)]

    if (-not (Compare-ByteArrayConstantTime -Array1 $checksum -Array2 $expectedChecksum)) {
        throw "AES-CTS checksum verification failed"
    }

    # Return plaintext without confounder
    return $decrypted[$Script:AES_CONFOUNDER_SIZE..($decrypted.Length - 1)]
}

<#
.SYNOPSIS
    Creates a standardized Kerberos operation result object.
.DESCRIPTION
    Factory function to ensure consistent return objects across all Kerberos functions.
    This pattern allows callers to check $result.Success before accessing other properties.

    Standard Result Schema:
    - Success      : [bool]   - Whether the operation succeeded
    - Message      : [string] - Human-readable status message
    - Error        : [string] - Error details if Success is $false (null otherwise)
    - Data         : [object] - Operation-specific data (tickets, keys, etc.)

.PARAMETER Success
    Whether the operation succeeded.
.PARAMETER Message
    Human-readable status message.
.PARAMETER Error
    Error details (only for failures).
.PARAMETER Data
    Additional data as hashtable (merged into result).
.OUTPUTS
    [PSCustomObject] Standardized result object.
.EXAMPLE
    # Success case
    return New-KerberosResult -Success $true -Message "TGT obtained" -Data @{
        Ticket = $ticketBytes
        SessionKey = $sessionKey
    }

    # Failure case
    return New-KerberosResult -Success $false -Error "KRB-ERROR 24: Pre-authentication failed"
#>
function New-KerberosResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Success,

        [Parameter(Mandatory = $false)]
        [string]$Message = "",

        [Parameter(Mandatory = $false)]
        [string]$Error = $null,

        [Parameter(Mandatory = $false)]
        [hashtable]$Data = @{}
    )

    $result = [PSCustomObject]@{
        Success = $Success
        Message = $Message
        Error   = $Error
    }

    # Merge additional data properties into result
    foreach ($key in $Data.Keys) {
        $result | Add-Member -NotePropertyName $key -NotePropertyValue $Data[$key] -Force
    }

    return $result
}

<#
.SYNOPSIS
    Extracts a crackable hash from a Kerberos ticket for Hashcat/John the Ripper.

.DESCRIPTION
    Central function to extract hashes from Kerberos tickets (TGS for Kerberoasting,
    AS-REP for AS-REP Roasting). Parses the ASN.1 structure to find the encrypted part and formats it for offline cracking tools.

    Supported hash formats:
    - TGS (Kerberoast): $krb5tgs$etype$*user$realm$spn*$checksum$encrypted
    - AS-REP: $krb5asrep$etype$user@realm:checksum$encrypted

    Used by: Invoke-Kerberoast, Invoke-ASREPRoast

.PARAMETER TicketBytes
    The raw ASN.1 encoded Kerberos ticket bytes.

.PARAMETER EncryptionType
    The encryption type (etype) used for the ticket:
    - 17: AES128-CTS-HMAC-SHA1-96
    - 18: AES256-CTS-HMAC-SHA1-96
    - 23: RC4-HMAC

.PARAMETER UserName
    The username associated with the ticket.

.PARAMETER Realm
    The Kerberos realm (domain) in uppercase.

.PARAMETER SPN
    The Service Principal Name (for TGS tickets).

.PARAMETER TicketType
    The type of ticket: "TGS" (Kerberoast) or "ASREP" (AS-REP Roast).
    Default: "TGS"

.OUTPUTS
    String - The formatted hash string for Hashcat/John, or $null on failure.

.EXAMPLE
    $hash = Get-KerberosTicketHash -TicketBytes $tgsBytes -EncryptionType 23 -UserName "admin" -Realm "CONTOSO.COM" -SPN "MSSQLSvc/sql.contoso.com"

.EXAMPLE
    $hash = Get-KerberosTicketHash -TicketBytes $asrepBytes -EncryptionType 23 -UserName "vulnuser" -Realm "CONTOSO.COM" -TicketType "ASREP"

.NOTES
    Hash formats:
    - RC4 (etype 23): checksum is first 16 bytes of cipher
    - AES (etype 17/18): checksum is last 12 bytes of cipher
#>
function Get-KerberosTicketHash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$TicketBytes,

        [Parameter(Mandatory = $true)]
        [int]$EncryptionType,

        [Parameter(Mandatory = $true)]
        [string]$UserName,

        [Parameter(Mandatory = $true)]
        [string]$Realm,

        [Parameter(Mandatory = $false)]
        [string]$SPN = "",

        [Parameter(Mandatory = $false)]
        [ValidateSet("TGS", "ASREP")]
        [string]$TicketType = "TGS"
    )

    try {
        # Early validation - ticket must be at least MIN_TICKET_SIZE bytes
        if ($TicketBytes.Length -lt $Script:MIN_TICKET_SIZE) {
            Write-Log "[Get-KerberosTicketHash] Ticket too short: $($TicketBytes.Length) bytes (minimum $Script:MIN_TICKET_SIZE)"
            return $null
        }

        # Parse ASN.1 encoded ticket to find encrypted part
        # Looking for context tag [3] (enc-part) containing EncryptedData
        #
        # Ticket/AS-REP structure contains:
        # enc-part [3] EncryptedData {
        #     etype  [0] Int32
        #     kvno   [1] UInt32 OPTIONAL
        #     cipher [2] OCTET STRING
        # }

        $pos = 0
        $encryptedPart = $null

        # Scan for enc-part tag (0xA3 = context-specific tag 3)
        while ($pos -lt $TicketBytes.Length - 20) {
            if ($TicketBytes[$pos] -eq 0xA3) {
                # Found enc-part tag
                $pos++

                # Parse length (BER encoding)
                $length = $TicketBytes[$pos]
                if ($length -gt 0x80) {
                    $numLengthBytes = $length -band 0x7F
                    $pos += $numLengthBytes + 1
                } else {
                    $pos++
                }

                # Now at EncryptedData SEQUENCE (0x30)
                if ($TicketBytes[$pos] -eq 0x30) {
                    $pos++
                    $seqLength = $TicketBytes[$pos]
                    if ($seqLength -gt 0x80) {
                        $numLengthBytes = $seqLength -band 0x7F
                        $pos += $numLengthBytes + 1
                    } else {
                        $pos++
                    }

                    # Skip to cipher field (tag 0xA2)
                    while ($pos -lt $TicketBytes.Length -and $TicketBytes[$pos] -ne 0xA2) {
                        $pos++
                    }

                    # Found cipher field
                    if ($pos -lt $TicketBytes.Length -and $TicketBytes[$pos] -eq 0xA2) {
                        $pos++

                        # Parse cipher context length
                        $cipherContextLength = $TicketBytes[$pos]
                        if ($cipherContextLength -gt 0x80) {
                            $numLengthBytes = $cipherContextLength -band 0x7F
                            $pos++
                            $cipherContextLength = 0
                            for ($i = 0; $i -lt $numLengthBytes; $i++) {
                                $cipherContextLength = ($cipherContextLength -shl 8) -bor $TicketBytes[$pos]
                                $pos++
                            }
                        } else {
                            $pos++
                        }

                        # Now at OCTET STRING (0x04)
                        if ($TicketBytes[$pos] -eq 0x04) {
                            $pos++
                            $octetLength = $TicketBytes[$pos]
                            if ($octetLength -gt 0x80) {
                                $numLengthBytes = $octetLength -band 0x7F
                                $pos++
                                $octetLength = 0
                                for ($i = 0; $i -lt $numLengthBytes; $i++) {
                                    $octetLength = ($octetLength -shl 8) -bor $TicketBytes[$pos]
                                    $pos++
                                }
                            } else {
                                $pos++
                            }

                            # Extract cipher bytes
                            if ($pos + $octetLength -le $TicketBytes.Length) {
                                $encryptedPart = $TicketBytes[$pos..($pos + $octetLength - 1)]
                            }
                        }
                    }
                }
                break
            }
            $pos++
        }

        # Validate extracted data
        $minLength = if ($EncryptionType -eq 23) { $Script:RC4_MIN_CIPHERTEXT } else { $Script:AES_MIN_CIPHERTEXT }
        if (-not $encryptedPart -or $encryptedPart.Length -lt $minLength) {
            Write-Log "[Get-KerberosTicketHash] Failed to extract cipher from ticket (got $($encryptedPart.Length) bytes, need $minLength)"
            return $null
        }

        # Format hash based on encryption type
        # RC4 (etype 23): checksum is first 16 bytes
        # AES (etype 17/18): checksum is last 12 bytes
        $hash = $null

        if ($EncryptionType -eq 23) {
            # RC4-HMAC: checksum at beginning
            $checksum = $encryptedPart[0..($Script:HMAC_MD5_SIZE - 1)]
            $encrypted = $encryptedPart[$Script:HMAC_MD5_SIZE..($encryptedPart.Length - 1)]

            $checksumHex = ($checksum | ForEach-Object { $_.ToString("x2") }) -join ''
            $encryptedHex = ($encrypted | ForEach-Object { $_.ToString("x2") }) -join ''

            if ($TicketType -eq "TGS") {
                $hash = "`$krb5tgs`$23`$*$UserName`$$Realm`$$SPN*`$$checksumHex`$$encryptedHex"
            } else {
                $hash = "`$krb5asrep`$23`$$UserName@$Realm`:$checksumHex`$$encryptedHex"
            }
        } else {
            # AES: checksum at end (last 12 bytes)
            $encrypted = $encryptedPart[0..($encryptedPart.Length - $Script:AES_CHECKSUM_SIZE - 1)]
            $checksum = $encryptedPart[($encryptedPart.Length - $Script:AES_CHECKSUM_SIZE)..($encryptedPart.Length - 1)]

            $checksumHex = ($checksum | ForEach-Object { $_.ToString("x2") }) -join ''
            $encryptedHex = ($encrypted | ForEach-Object { $_.ToString("x2") }) -join ''

            if ($TicketType -eq "TGS") {
                $hash = "`$krb5tgs`$$EncryptionType`$*$UserName`$$Realm`$$SPN*`$$checksumHex`$$encryptedHex"
            } else {
                $hash = "`$krb5asrep`$$EncryptionType`$$UserName@$Realm`:$checksumHex`$$encryptedHex"
            }
        }

        Write-Log "[Get-KerberosTicketHash] Extracted $TicketType hash (etype $EncryptionType, cipher $($encryptedPart.Length) bytes)"
        return $hash
    }
    catch {
        Write-Log "[Get-KerberosTicketHash] Error extracting hash: $_"
        return $null
    }
}

<#
.SYNOPSIS
    Sends a Kerberos request to a KDC and receives the response.

.DESCRIPTION
    Establishes a TCP connection to a Kerberos KDC (port 88) and sends a
    Kerberos message (AS-REQ or TGS-REQ). The message is prefixed with a
    4-byte big-endian length field as per RFC 4120.

    Used by:
    - Invoke-KerberosAuth.ps1 (AS-REQ/AS-REP)
    - Request-ServiceTicket.ps1 (TGS-REQ/TGS-REP)

.PARAMETER Server
    The KDC server hostname or IP address.

.PARAMETER Request
    The Kerberos request message as byte array.

.PARAMETER Port
    The port to connect to. Default is 88 (standard Kerberos).

.PARAMETER TimeoutMs
    Connection and read/write timeout in milliseconds. Default is 30000 (30 seconds).

.OUTPUTS
    [byte[]] The KDC response message.

.EXAMPLE
    $response = Send-KerberosRequest -Server "dc01.contoso.com" -Request $asReqBytes

.NOTES
    References:
    - RFC 4120 Section 7.2.1: TCP transport for Kerberos
#>
function Send-KerberosRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $true)]
        [byte[]]$Request,

        [Parameter(Mandatory = $false)]
        [int]$Port = 88,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutMs = 30000
    )

    $tcpClient = $null
    $stream = $null

    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.Connect($Server, $Port)
        $stream = $tcpClient.GetStream()
        $stream.ReadTimeout = $TimeoutMs
        $stream.WriteTimeout = $TimeoutMs

        # Send length prefix (4 bytes, big-endian) followed by request
        $lengthBytes = [System.BitConverter]::GetBytes([uint32]$Request.Length)
        [Array]::Reverse($lengthBytes)
        $stream.Write($lengthBytes, 0, 4)
        $stream.Write($Request, 0, $Request.Length)
        $stream.Flush()

        # Read response length (4 bytes, big-endian)
        # Must handle partial reads - Read() may return fewer bytes than requested
        $responseLengthBytes = New-Object byte[] 4
        $totalLengthRead = 0
        while ($totalLengthRead -lt 4) {
            $lengthBytesRead = $stream.Read($responseLengthBytes, $totalLengthRead, 4 - $totalLengthRead)
            if ($lengthBytesRead -eq 0) {
                throw "Connection closed while reading response length (got $totalLengthRead of 4 bytes)"
            }
            $totalLengthRead += $lengthBytesRead
        }
        [Array]::Reverse($responseLengthBytes)
        $responseLength = [System.BitConverter]::ToUInt32($responseLengthBytes, 0)

        # Read response data
        $responseBytes = New-Object byte[] $responseLength
        $bytesRead = 0
        while ($bytesRead -lt $responseLength) {
            $chunkRead = $stream.Read($responseBytes, $bytesRead, $responseLength - $bytesRead)
            if ($chunkRead -eq 0) {
                throw "Connection closed while reading response data (got $bytesRead of $responseLength bytes)"
            }
            $bytesRead += $chunkRead
        }

        return $responseBytes
    }
    finally {
        if ($stream) { $stream.Close() }
        if ($tcpClient) { $tcpClient.Close() }
    }
}

#region Windows Native Kerberos Crypto (cryptdll.dll)

# P/Invoke definitions for Windows Kerberos crypto API
# This uses the same CDLocateCSystem approach as Rubeus/Mimikatz
# to leverage the Windows-native AES-CTS and RC4-HMAC implementations.
$Script:KerbCryptoTypeAdded = $false
$Script:KerbCryptoHasChecksum = $false

function Initialize-KerbCryptoInterop {
    <#
    .SYNOPSIS
        Initializes P/Invoke types for Windows Kerberos crypto API.
    .DESCRIPTION
        Adds the C# interop types for calling CDLocateCSystem and CDLocateCheckSum from cryptdll.dll.
        This is the same API used by Rubeus and Mimikatz for Kerberos encryption/checksums.
    #>
    if ($Script:KerbCryptoTypeAdded) {
        # Check if checksum types also exist (they may not if loaded from older version)
        if (-not $Script:KerbCryptoHasChecksum) {
            try {
                $null = [adPEAS.KERB_CHECKSUM_ALGORITHM]
                $Script:KerbCryptoHasChecksum = $true
            }
            catch {
                # Checksum types not available in this session
                # A fresh PowerShell session is required after module update
                $Script:KerbCryptoHasChecksum = $false
            }
        }
        return $true
    }

    try {
        # Check if type already exists (from previous import)
        $null = [adPEAS.KerbCrypto]
        $Script:KerbCryptoTypeAdded = $true
        # Also check for checksum types
        try {
            $null = [adPEAS.KERB_CHECKSUM_ALGORITHM]
            $Script:KerbCryptoHasChecksum = $true
        }
        catch {
            $Script:KerbCryptoHasChecksum = $false
        }
        return $true
    }
    catch {
        # Type not loaded yet, add it
    }

    try {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace adPEAS
{
    public enum KERB_ETYPE : int
    {
        aes128_cts_hmac_sha1 = 17,
        aes256_cts_hmac_sha1 = 18,
        rc4_hmac = 23
    }

    // Kerberos checksum types (MS-PAC, RFC 3961)
    // Note: HMAC_MD5 uses negative value per MS-KILE
    public enum KERB_CHECKSUM_ALGORITHM : int
    {
        HMAC_SHA1_96_AES128 = 15,  // AES128 checksum (12 bytes output)
        HMAC_SHA1_96_AES256 = 16,  // AES256 checksum (12 bytes output)
        HMAC_MD5 = -138            // RC4-HMAC checksum (16 bytes output)
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_ECRYPT
    {
        int Type0;
        public int BlockSize;
        int Type1;
        public int KeySize;
        public int Size;
        int unk2;
        int unk3;
        public IntPtr AlgName;
        public IntPtr Initialize;
        public IntPtr Encrypt;
        public IntPtr Decrypt;
        public IntPtr Finish;
        public IntPtr HashPassword;
        IntPtr RandomKey;
        IntPtr Control;
        IntPtr unk0_null;
        IntPtr unk1_null;
        IntPtr unk2_null;
    }

    // Structure for checksum functions (KERB_CHECKSUM)
    // Layout from Windows SDK / Rubeus implementation
    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_CHECKSUM
    {
        public int Type;
        public int Size;               // Checksum output size
        public int Flag;
        public IntPtr Initialize;      // void Initialize(void* pContext)
        public IntPtr Sum;             // void Sum(void* pContext, int cbData, byte* pbData)
        public IntPtr Finalize;        // void Finalize(void* pContext, byte* pbChecksum)
        public IntPtr Finish;          // void Finish(void* pContext)
        public IntPtr InitializeEx;    // int InitializeEx(byte* key, int keyLen, int keyUsage, out void* pContext)
        public IntPtr InitializeEx2;   // Extended init (not used)
    }

    public class KerbCrypto
    {
        [DllImport("cryptdll.dll", CharSet = CharSet.Auto, SetLastError = false)]
        public static extern int CDLocateCSystem(KERB_ETYPE type, out IntPtr pCSystem);

        [DllImport("cryptdll.dll", CharSet = CharSet.Auto, SetLastError = false)]
        public static extern int CDLocateCheckSum(KERB_CHECKSUM_ALGORITHM type, out IntPtr pCheckSum);

        // Delegate types for function pointers in KERB_ECRYPT (encryption)
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int InitializeDelegate(byte[] Key, int KeySize, int KeyUsage, out IntPtr pContext);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int EncryptDelegate(IntPtr pContext, byte[] data, int dataSize, byte[] output, ref int outputSize);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int DecryptDelegate(IntPtr pContext, byte[] data, int dataSize, byte[] output, ref int outputSize);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int FinishDelegate(ref IntPtr pContext);

        // Delegate types for function pointers in KERB_CHECKSUM (checksums)
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int ChecksumInitializeExDelegate(byte[] Key, int KeySize, int KeyUsage, out IntPtr pContext);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int ChecksumSumDelegate(IntPtr pContext, int dataSize, byte[] data);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int ChecksumFinalizeDelegate(IntPtr pContext, byte[] checksum);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int ChecksumFinishDelegate(ref IntPtr pContext);

        /// <summary>
        /// Encrypts data using the Windows Kerberos crypto provider.
        /// </summary>
        public static byte[] KerberosEncrypt(KERB_ETYPE eType, int keyUsage, byte[] key, byte[] data)
        {
            IntPtr pCSystemPtr;
            int status = CDLocateCSystem(eType, out pCSystemPtr);
            if (status != 0)
                throw new Exception("CDLocateCSystem failed with status: 0x" + status.ToString("X8"));

            KERB_ECRYPT pCSystem = (KERB_ECRYPT)Marshal.PtrToStructure(pCSystemPtr, typeof(KERB_ECRYPT));

            InitializeDelegate pInit = (InitializeDelegate)Marshal.GetDelegateForFunctionPointer(
                pCSystem.Initialize, typeof(InitializeDelegate));
            EncryptDelegate pEncrypt = (EncryptDelegate)Marshal.GetDelegateForFunctionPointer(
                pCSystem.Encrypt, typeof(EncryptDelegate));
            FinishDelegate pFinish = (FinishDelegate)Marshal.GetDelegateForFunctionPointer(
                pCSystem.Finish, typeof(FinishDelegate));

            IntPtr pContext;
            status = pInit(key, key.Length, keyUsage, out pContext);
            if (status != 0)
                throw new Exception("Kerberos crypto Initialize failed with status: 0x" + status.ToString("X8"));

            try
            {
                int outputSize = data.Length;
                if (data.Length % pCSystem.BlockSize != 0)
                    outputSize += pCSystem.BlockSize - (data.Length % pCSystem.BlockSize);
                outputSize += pCSystem.Size;

                byte[] output = new byte[outputSize];
                status = pEncrypt(pContext, data, data.Length, output, ref outputSize);
                if (status != 0)
                    throw new Exception("Kerberos crypto Encrypt failed with status: 0x" + status.ToString("X8"));

                // Trim to actual output size
                if (outputSize != output.Length)
                {
                    byte[] trimmed = new byte[outputSize];
                    Array.Copy(output, trimmed, outputSize);
                    return trimmed;
                }
                return output;
            }
            finally
            {
                pFinish(ref pContext);
            }
        }

        /// <summary>
        /// Decrypts data using the Windows Kerberos crypto provider.
        /// </summary>
        public static byte[] KerberosDecrypt(KERB_ETYPE eType, int keyUsage, byte[] key, byte[] data)
        {
            IntPtr pCSystemPtr;
            int status = CDLocateCSystem(eType, out pCSystemPtr);
            if (status != 0)
                throw new Exception("CDLocateCSystem failed with status: 0x" + status.ToString("X8"));

            KERB_ECRYPT pCSystem = (KERB_ECRYPT)Marshal.PtrToStructure(pCSystemPtr, typeof(KERB_ECRYPT));

            InitializeDelegate pInit = (InitializeDelegate)Marshal.GetDelegateForFunctionPointer(
                pCSystem.Initialize, typeof(InitializeDelegate));
            DecryptDelegate pDecrypt = (DecryptDelegate)Marshal.GetDelegateForFunctionPointer(
                pCSystem.Decrypt, typeof(DecryptDelegate));
            FinishDelegate pFinish = (FinishDelegate)Marshal.GetDelegateForFunctionPointer(
                pCSystem.Finish, typeof(FinishDelegate));

            IntPtr pContext;
            status = pInit(key, key.Length, keyUsage, out pContext);
            if (status != 0)
                throw new Exception("Kerberos crypto Initialize failed with status: 0x" + status.ToString("X8"));

            try
            {
                int outputSize = data.Length;
                if (data.Length % pCSystem.BlockSize != 0)
                    outputSize += pCSystem.BlockSize - (data.Length % pCSystem.BlockSize);
                outputSize += pCSystem.Size;

                byte[] output = new byte[outputSize];
                status = pDecrypt(pContext, data, data.Length, output, ref outputSize);
                if (status != 0)
                    throw new Exception("Kerberos crypto Decrypt failed with status: 0x" + status.ToString("X8"));

                // Trim to actual output size
                if (outputSize != output.Length)
                {
                    byte[] trimmed = new byte[outputSize];
                    Array.Copy(output, trimmed, outputSize);
                    return trimmed;
                }
                return output;
            }
            finally
            {
                pFinish(ref pContext);
            }
        }

        /// <summary>
        /// Computes a Kerberos checksum using the Windows crypto provider (cryptdll.dll).
        /// This is the same approach used by Rubeus for PAC signatures.
        /// </summary>
        /// <param name="checksumType">The checksum algorithm (15=AES128, 16=AES256, -138=HMAC_MD5)</param>
        /// <param name="keyUsage">The Kerberos key usage number (17 for PAC checksums)</param>
        /// <param name="key">The key bytes</param>
        /// <param name="data">The data to checksum</param>
        /// <returns>The checksum bytes (12 bytes for AES, 16 bytes for RC4)</returns>
        public static byte[] KerberosChecksum(KERB_CHECKSUM_ALGORITHM checksumType, int keyUsage, byte[] key, byte[] data)
        {
            IntPtr pCheckSumPtr;
            int status = CDLocateCheckSum(checksumType, out pCheckSumPtr);
            if (status != 0)
                throw new Exception("CDLocateCheckSum failed with status: 0x" + status.ToString("X8"));

            KERB_CHECKSUM pCheckSum = (KERB_CHECKSUM)Marshal.PtrToStructure(pCheckSumPtr, typeof(KERB_CHECKSUM));

            ChecksumInitializeExDelegate pInitEx = (ChecksumInitializeExDelegate)Marshal.GetDelegateForFunctionPointer(
                pCheckSum.InitializeEx, typeof(ChecksumInitializeExDelegate));
            ChecksumSumDelegate pSum = (ChecksumSumDelegate)Marshal.GetDelegateForFunctionPointer(
                pCheckSum.Sum, typeof(ChecksumSumDelegate));
            ChecksumFinalizeDelegate pFinalize = (ChecksumFinalizeDelegate)Marshal.GetDelegateForFunctionPointer(
                pCheckSum.Finalize, typeof(ChecksumFinalizeDelegate));
            ChecksumFinishDelegate pFinish = (ChecksumFinishDelegate)Marshal.GetDelegateForFunctionPointer(
                pCheckSum.Finish, typeof(ChecksumFinishDelegate));

            IntPtr pContext;
            status = pInitEx(key, key.Length, keyUsage, out pContext);
            if (status != 0)
                throw new Exception("Checksum InitializeEx failed with status: 0x" + status.ToString("X8"));

            try
            {
                status = pSum(pContext, data.Length, data);
                if (status != 0)
                    throw new Exception("Checksum Sum failed with status: 0x" + status.ToString("X8"));

                byte[] checksum = new byte[pCheckSum.Size];
                status = pFinalize(pContext, checksum);
                if (status != 0)
                    throw new Exception("Checksum Finalize failed with status: 0x" + status.ToString("X8"));

                return checksum;
            }
            finally
            {
                pFinish(ref pContext);
            }
        }
    }
}
'@ -ErrorAction Stop

        $Script:KerbCryptoTypeAdded = $true
        $Script:KerbCryptoHasChecksum = $true  # Fresh compile includes checksum types
        return $true
    }
    catch {
        Write-Verbose "[Initialize-KerbCryptoInterop] Failed to add P/Invoke types: $_"
        return $false
    }
}

function Protect-KerberosNative {
    <#
    .SYNOPSIS
        Encrypts data using Windows native Kerberos crypto (cryptdll.dll).
    .DESCRIPTION
        Uses the same CDLocateCSystem API as Rubeus/Mimikatz for guaranteed
        compatibility with the KDC's encryption implementation.
        Falls back to the pure PowerShell implementation if P/Invoke fails.
    .PARAMETER Key
        The encryption key bytes.
    .PARAMETER Data
        The plaintext data to encrypt.
    .PARAMETER KeyUsage
        The Kerberos key usage number (e.g., 2 for ticket encryption).
    .PARAMETER EncryptionType
        The Kerberos encryption type (17=AES128, 18=AES256, 23=RC4).
    .OUTPUTS
        [byte[]] Encrypted data (confounder + ciphertext + checksum).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Key,

        [Parameter(Mandatory=$true)]
        [byte[]]$Data,

        [Parameter(Mandatory=$true)]
        [int]$KeyUsage,

        [Parameter(Mandatory=$true)]
        [int]$EncryptionType
    )

    # Try native Windows crypto first
    if (Initialize-KerbCryptoInterop) {
        try {
            $eType = [adPEAS.KERB_ETYPE]$EncryptionType
            $result = [adPEAS.KerbCrypto]::KerberosEncrypt($eType, $KeyUsage, $Key, $Data)
            Write-Verbose "[Protect-KerberosNative] Native encryption successful: input=$($Data.Length) output=$($result.Length)"
            return $result
        }
        catch {
            Write-Verbose "[Protect-KerberosNative] Native encryption failed, falling back to PowerShell: $_"
        }
    }

    # Fallback to pure PowerShell implementation
    Write-Verbose "[Protect-KerberosNative] Using PowerShell fallback for etype $EncryptionType"
    switch ($EncryptionType) {
        23 { return Encrypt-RC4HMAC -Key $Key -Data $Data -KeyUsage $KeyUsage }
        17 { return Encrypt-AESCTS -Key $Key -Data $Data -KeyUsage $KeyUsage }
        18 { return Encrypt-AESCTS -Key $Key -Data $Data -KeyUsage $KeyUsage }
        default { throw "Unsupported encryption type: $EncryptionType" }
    }
}

function Unprotect-KerberosNative {
    <#
    .SYNOPSIS
        Decrypts data using Windows native Kerberos crypto (cryptdll.dll).
    .DESCRIPTION
        Uses the same CDLocateCSystem API as Rubeus/Mimikatz for guaranteed
        compatibility with the KDC's decryption implementation.
        Falls back to the pure PowerShell implementation if P/Invoke fails.
    .PARAMETER Key
        The decryption key bytes.
    .PARAMETER CipherText
        The encrypted data (confounder + ciphertext + checksum).
    .PARAMETER KeyUsage
        The Kerberos key usage number (e.g., 2 for ticket encryption).
    .PARAMETER EncryptionType
        The Kerberos encryption type (17=AES128, 18=AES256, 23=RC4).
    .OUTPUTS
        [byte[]] Decrypted plaintext.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Key,

        [Parameter(Mandatory=$true)]
        [byte[]]$CipherText,

        [Parameter(Mandatory=$true)]
        [int]$KeyUsage,

        [Parameter(Mandatory=$true)]
        [int]$EncryptionType
    )

    # Try native Windows crypto first
    if (Initialize-KerbCryptoInterop) {
        try {
            $eType = [adPEAS.KERB_ETYPE]$EncryptionType
            $result = [adPEAS.KerbCrypto]::KerberosDecrypt($eType, $KeyUsage, $Key, $CipherText)
            Write-Verbose "[Unprotect-KerberosNative] Native decryption successful: input=$($CipherText.Length) output=$($result.Length)"
            return $result
        }
        catch {
            Write-Verbose "[Unprotect-KerberosNative] Native decryption failed, falling back to PowerShell: $_"
        }
    }

    # Fallback to pure PowerShell implementation
    Write-Verbose "[Unprotect-KerberosNative] Using PowerShell fallback for etype $EncryptionType"
    switch ($EncryptionType) {
        23 { return Decrypt-RC4HMAC -Key $Key -CipherText $CipherText -KeyUsage $KeyUsage }
        17 { return Decrypt-AESCTS -Key $Key -CipherText $CipherText -KeyUsage $KeyUsage }
        18 { return Decrypt-AESCTS -Key $Key -CipherText $CipherText -KeyUsage $KeyUsage }
        default { throw "Unsupported encryption type: $EncryptionType" }
    }
}

function Get-KerberosChecksumNative {
    <#
    .SYNOPSIS
        Computes a Kerberos checksum using Windows native crypto (cryptdll.dll).
    .DESCRIPTION
        Uses the same CDLocateCheckSum API as Rubeus for guaranteed compatibility
        with the KDC's checksum implementation. This is critical for PAC signatures
        where our pure PowerShell implementation produces different results.

        Falls back to the pure PowerShell implementation if P/Invoke fails.
    .PARAMETER Key
        The key bytes (krbtgt key for PAC signatures).
    .PARAMETER Data
        The data to compute the checksum over.
    .PARAMETER KeyUsage
        The Kerberos key usage number (17 for PAC checksums).
    .PARAMETER EncryptionType
        The Kerberos encryption type (17=AES128, 18=AES256, 23=RC4).
    .OUTPUTS
        [byte[]] The checksum bytes (12 bytes for AES, 16 bytes for RC4).
    .EXAMPLE
        $checksum = Get-KerberosChecksumNative -Key $krbtgtKey -Data $pacData -KeyUsage 17 -EncryptionType 18
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Key,

        [Parameter(Mandatory=$true)]
        [byte[]]$Data,

        [Parameter(Mandatory=$true)]
        [int]$KeyUsage,

        [Parameter(Mandatory=$true)]
        [int]$EncryptionType
    )

    # Map encryption type to checksum type
    # AES256 (etype 18) → HMAC_SHA1_96_AES256 (checksum type 16)
    # AES128 (etype 17) → HMAC_SHA1_96_AES128 (checksum type 15)
    # RC4 (etype 23) → HMAC_MD5 (checksum type -138)
    $checksumType = switch ($EncryptionType) {
        18 { 16 }    # AES256 → HMAC_SHA1_96_AES256
        17 { 15 }    # AES128 → HMAC_SHA1_96_AES128
        23 { -138 }  # RC4 → HMAC_MD5
        default { throw "Unsupported encryption type for checksum: $EncryptionType" }
    }

    # Try native Windows crypto first (requires checksum types to be loaded)
    Write-Verbose "[Get-KerberosChecksumNative] Called with: etype=$EncryptionType, checksumType=$checksumType, keyUsage=$KeyUsage, keyLen=$($Key.Length), dataLen=$($Data.Length)"
    if ((Initialize-KerbCryptoInterop) -and $Script:KerbCryptoHasChecksum) {
        try {
            $cksumType = [adPEAS.KERB_CHECKSUM_ALGORITHM]$checksumType
            $result = [adPEAS.KerbCrypto]::KerberosChecksum($cksumType, $KeyUsage, $Key, $Data)
            Write-Verbose "[Get-KerberosChecksumNative] Native checksum successful: data=$($Data.Length) checksum=$($result.Length) bytes"
            Write-Verbose "[Get-KerberosChecksumNative] Checksum: $(($result | ForEach-Object { '{0:X2}' -f $_ }) -join '')"
            return $result
        }
        catch {
            Write-Verbose "[Get-KerberosChecksumNative] Native checksum failed, falling back to PowerShell: $_"
        }
    }
    elseif (-not $Script:KerbCryptoHasChecksum) {
        Write-Verbose "[Get-KerberosChecksumNative] Native checksum types not available (requires fresh PowerShell session after module update)"
    }

    # Fallback to pure PowerShell implementation
    Write-Verbose "[Get-KerberosChecksumNative] Using PowerShell fallback for etype $EncryptionType"
    switch ($EncryptionType) {
        23 {
            # RC4-HMAC: HMAC-MD5 with key derived from base key
            # K = HMAC-MD5(key, little-endian keyUsage)
            $usageBytes = [BitConverter]::GetBytes([int32]$KeyUsage)
            $derivedKey = Get-HMACMD5 -Key $Key -Data $usageBytes
            return Get-HMACMD5 -Key $derivedKey -Data $Data
        }
        { $_ -in @(17, 18) } {
            # AES: HMAC-SHA1 with Kc (checksum key) derived from base key, truncated to 12 bytes
            $kcConstant = Get-KeyUsageConstant -KeyUsage $KeyUsage -Suffix $Script:KC_CONSTANT_SUFFIX
            $checksumKey = Get-AESDerivedKey -BaseKey $Key -Constant $kcConstant -KeyLength $Key.Length
            $fullHmac = Get-HMACSHA1 -Key $checksumKey -Data $Data
            return $fullHmac[0..11]  # Truncate to 12 bytes
        }
        default { throw "Unsupported encryption type: $EncryptionType" }
    }
}

#endregion