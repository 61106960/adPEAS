<#
.SYNOPSIS
    Displays a standardized connection error message.

.DESCRIPTION
    Central helper function for displaying consistent, short error messages for all connection and authentication failures in adPEAS.

    Error types:
    - AuthenticationFailed: Invalid credentials (username/password/hash/certificate)
    - NetworkError: Cannot reach domain controller
    - CertificateError: SSL/TLS certificate validation failed (use -IgnoreSSLErrors)
    - SSLHandshakeError: SSL/TLS handshake failed (server doesn't support LDAPS or TLS version mismatch)
    - PFXLoadError: Failed to load PFX/P12 certificate file
    - PermissionError: Access denied
    - DomainError: Domain not found or unreachable
    - KerberosError: Kerberos-specific failures (with sub-types via ErrorCode)
    - NTLMDisabledError: NTLM disabled and Kerberos not available
    - TicketImportError: Pass-the-Ticket import failed
    - GenericError: Unclassified connection error

    Error code resolution:
    Callers should pass structured error codes via -ErrorCode and -ErrorCodeType instead of free-text -Details.
    Show-ConnectionError resolves error codes to English text using the central lookup tables:
    - Kerberos: $Script:KERBEROS_ERROR_CODES (Kerberos-Crypto.ps1)
    - LDAP: ConvertFrom-LDAPError (adPEAS-ErrorCodes.ps1)
    - Win32: ConvertFrom-Win32Error (adPEAS-ErrorCodes.ps1)
    - HRESULT: ConvertFrom-HResult (adPEAS-ErrorCodes.ps1)

.PARAMETER ErrorType
    The type of error to display.

.PARAMETER Details
    Optional fallback details when no error code is available.

.PARAMETER ErrorCode
    Numeric error code (LDAP, Win32, Kerberos KDC, or HRESULT).

.PARAMETER ErrorCodeType
    Type of the error code: "Kerberos", "LDAP", "Win32", or "HRESULT".

.PARAMETER NoThrow
    If specified, does not throw an exception after displaying the error.

.EXAMPLE
    Show-ConnectionError -ErrorType "AuthenticationFailed" -ErrorCode 1326 -ErrorCodeType "Win32"

.EXAMPLE
    Show-ConnectionError -ErrorType "KerberosError" -ErrorCode 14 -ErrorCodeType "Kerberos"

.EXAMPLE
    Show-ConnectionError -ErrorType "PFXLoadError" -ErrorCode 0x80070056 -ErrorCodeType "HRESULT"

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

function Show-ConnectionError {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet(
            "AuthenticationFailed",
            "NetworkError",
            "CertificateError",
            "SSLHandshakeError",
            "PFXLoadError",
            "PermissionError",
            "DomainError",
            "KerberosError",
            "NTLMDisabledError",
            "TicketImportError",
            "GenericError"
        )]
        [string]$ErrorType,

        [Parameter(Mandatory=$false)]
        [string]$Details,

        [Parameter(Mandatory=$false)]
        [object]$ErrorCode,

        [Parameter(Mandatory=$false)]
        [ValidateSet("Kerberos", "LDAP", "Win32", "HRESULT")]
        [string]$ErrorCodeType,

        [Parameter(Mandatory=$false)]
        [switch]$NoThrow
    )

    process {
        if ($Details) {
            $Details = $Details.Trim()
        }

        $ThrowMessage = "Connection failed"

        # Phase 1: Resolve error code to user-friendly details
        # For common error codes, provide specific helpful text (like Kerberos switch does)
        # For uncommon codes, fall back to central lookup tables
        # Kerberos codes are resolved in the KerberosError case below (has extended handling)
        $resolvedDetails = $null
        if ($null -ne $ErrorCode -and $ErrorCodeType -and $ErrorCodeType -ne "Kerberos") {
            switch ($ErrorCodeType) {
                "LDAP" {
                    # Specific messages for common LDAP auth/connection errors
                    switch ([int]$ErrorCode) {
                        1  { $resolvedDetails = "Reason: LDAP server denied the request - credentials were not accepted or bind resulted in anonymous access." }  # LDAP_OPERATIONS_ERROR
                        8  { $resolvedDetails = "Reason: LDAP signing or channel binding is enforced by domain policy." }  # LDAP_STRONG_AUTH_REQUIRED
                        49 { $resolvedDetails = "Reason: Wrong username or password." }  # LDAP_INVALID_CREDENTIALS
                        50 { $resolvedDetails = "Reason: The account does not have sufficient privileges for this operation." }  # LDAP_INSUFFICIENT_RIGHTS
                        81 { $resolvedDetails = "Reason: Cannot connect to the LDAP server - verify hostname and port." }  # LDAP_SERVER_DOWN
                        82 { $resolvedDetails = "Reason: Authentication negotiation failed - Kerberos SPN mismatch, invalid ticket, or NTLM negotiation error." }  # LDAP_LOCAL_ERROR
                        91 { $resolvedDetails = "Reason: Cannot establish TCP connection to LDAP server." }  # LDAP_CONNECT_ERROR
                        default {
                            $lookupInfo = ConvertFrom-LDAPError -ErrorCode $ErrorCode
                            if ($lookupInfo -and $lookupInfo.Message) { $resolvedDetails = "Reason: $($lookupInfo.Message)" }
                        }
                    }
                }
                "Win32" {
                    # Specific messages for common Win32 auth errors (NTLM LogonUser)
                    switch ([int]$ErrorCode) {
                        1326 { $resolvedDetails = "Reason: Wrong username or password." }  # ERROR_LOGON_FAILURE
                        1327 { $resolvedDetails = "Reason: Account has restrictions that prevent logon." }  # ERROR_ACCOUNT_RESTRICTION
                        1328 { $resolvedDetails = "Reason: Account is not allowed to log on at this time." }  # ERROR_INVALID_LOGON_HOURS
                        1329 { $resolvedDetails = "Reason: Account is not allowed to log on from this workstation." }  # ERROR_INVALID_WORKSTATION
                        1330 { $resolvedDetails = "Reason: Password has expired - change password required." }  # ERROR_PASSWORD_EXPIRED
                        1331 { $resolvedDetails = "Reason: Account is disabled." }  # ERROR_ACCOUNT_DISABLED
                        1385 { $resolvedDetails = "Reason: Logon type (network) is not granted for this account." }  # ERROR_LOGON_TYPE_NOT_GRANTED
                        5    { $resolvedDetails = "Reason: Access denied - insufficient privileges." }  # ERROR_ACCESS_DENIED
                        53   { $resolvedDetails = "Reason: Network path not found - verify server hostname." }  # ERROR_BAD_NETPATH
                        1355 { $resolvedDetails = "Reason: Domain not found - verify domain name." }  # ERROR_NO_SUCH_DOMAIN
                        default {
                            $lookupInfo = ConvertFrom-Win32Error -ErrorCode $ErrorCode
                            if ($lookupInfo -and $lookupInfo.Message) { $resolvedDetails = "Reason: $($lookupInfo.Message)" }
                        }
                    }
                }
                "HRESULT" {
                    $lookupInfo = ConvertFrom-HResult -HResult $ErrorCode
                    if ($lookupInfo -and $lookupInfo.Message -and $lookupInfo.Message -notmatch '^Unknown') { $resolvedDetails = "Reason: $($lookupInfo.Message)" }
                }
            }
        }

        # Use resolved text from lookup, fall back to Details if no code or lookup failed.
        # Exception: if an explicit $Details string was provided alongside an ErrorCode,
        # the caller wants to override the generic lookup message with context-specific text.
        $effectiveDetails = if ($Details) { $Details } elseif ($resolvedDetails) { $resolvedDetails } else { $null }

        switch ($ErrorType) {
            "AuthenticationFailed" {
                $detailsArray = @()
                if ($effectiveDetails) {
                    $detailsArray += $effectiveDetails
                }

                # Check if this might be an expired Kerberos ticket (Windows Auth without explicit credentials)
                $IsWindowsAuth = $Script:AuthInfo.ParameterSet -eq 'WindowsAuth'
                $IsNTLMImpersonation = $Script:AuthInfo.NTLMImpersonation -eq $true

                $hints = @()
                if ($IsWindowsAuth -and -not $IsNTLMImpersonation) {
                    $hints += "If using Windows Authentication, your Kerberos ticket may have expired."
                }

                Show-Message -Type Error -Title "Authentication failed: Invalid credentials" -Details $detailsArray -Hints $hints
                $ThrowMessage = "Authentication failed"
            }

            "NetworkError" {
                $detailsArray = @()
                if ($effectiveDetails) {
                    $detailsArray += $effectiveDetails
                }
                Show-Message -Type Error -Title "Connection failed: Server unreachable" -Details $detailsArray
                $ThrowMessage = "Network error: Server unreachable"
            }

            "CertificateError" {
                $detailsArray = @()
                if ($effectiveDetails) {
                    $detailsArray += $effectiveDetails
                } else {
                    $detailsArray += "Use LDAP instead (remove -UseLDAPS) or fix certificate validation"
                }
                $hints = @(
                    "Try: -IgnoreSSLErrors to bypass certificate validation",
                    "Or: Remove -UseLDAPS to use unencrypted LDAP"
                )
                Show-Message -Type Error -Title "LDAPS failed: Certificate validation error" -Details $detailsArray -Hints $hints
                $ThrowMessage = "LDAPS certificate error"
            }

            "SSLHandshakeError" {
                $detailsArray = @()
                if ($effectiveDetails) {
                    $detailsArray += $effectiveDetails
                }
                $hints = @(
                    "Server may not support LDAPS on port 636",
                    "Server may require specific TLS version (1.2+)",
                    "Try: Remove -UseLDAPS to use unencrypted LDAP"
                )
                Show-Message -Type Error -Title "LDAPS failed: SSL/TLS handshake error" -Details $detailsArray -Hints $hints
                $ThrowMessage = "LDAPS SSL handshake failed"
            }

            "PFXLoadError" {
                $detailsArray = @()
                if ($effectiveDetails) {
                    $detailsArray += $effectiveDetails
                }
                $hints = @(
                    "Verify: Certificate password is correct",
                    "Verify: File is a valid PFX/P12 certificate and certificate contains a private key"
                )
                Show-Message -Type Error -Title "Certificate load failed" -Details $detailsArray -Hints $hints
                $ThrowMessage = "Certificate load failed"
            }

            "PermissionError" {
                $detailsArray = @()
                if ($effectiveDetails) {
                    $detailsArray += $effectiveDetails
                }
                Show-Message -Type Error -Title "Access denied: Insufficient privileges" -Details $detailsArray
                $ThrowMessage = "Permission denied"
            }

            "DomainError" {
                $detailsArray = @()
                if ($effectiveDetails) {
                    $detailsArray += $effectiveDetails
                }
                Show-Message -Type Error -Title "Domain not found or unreachable" -Details $detailsArray
                $ThrowMessage = "Domain error"
            }

            "KerberosError" {
                $detailsArray = @()

                # Kerberos error codes have extended handling with detailed messages and hints
                if ($null -ne $ErrorCode -and $ErrorCodeType -eq "Kerberos") {
                    switch ($ErrorCode) {
                        # === Authentication Errors (AS-REQ) ===
                        6 {  # KDC_ERR_C_PRINCIPAL_UNKNOWN
                            $detailsArray += "Reason: User not found in the domain."
                        }
                        12 {  # KDC_ERR_POLICY
                            $detailsArray += "Reason: KDC policy rejects the request (check account restrictions)."
                        }
                        14 {  # KDC_ERR_ETYPE_NOSUPP
                            $detailsArray += "Reason: RC4 encryption disabled - use -AES256Key instead of -NTHash"
                        }
                        18 {  # KDC_ERR_CLIENT_REVOKED
                            $detailsArray += "Reason: Account is disabled or locked out."
                        }
                        23 {  # KDC_ERR_KEY_EXPIRED
                            $detailsArray += "Reason: Password has expired - change password required."
                        }
                        24 {  # KDC_ERR_PREAUTH_FAILED
                            $detailsArray += "Reason: Wrong password, hash, or key."
                        }
                        25 {  # KDC_ERR_PREAUTH_REQUIRED
                            $detailsArray += "Reason: Pre-authentication required (internal error)."
                        }

                        # === Service Ticket Errors (TGS-REQ) ===
                        7 {  # KDC_ERR_S_PRINCIPAL_UNKNOWN
                            $detailsArray += "Reason: Service principal (SPN) not found in the domain."
                        }
                        26 {  # KDC_ERR_SERVER_NOMATCH
                            $detailsArray += "Reason: Requested server and ticket don't match."
                        }
                        29 {  # KDC_ERR_SVC_UNAVAILABLE
                            $detailsArray += "Reason: KDC service unavailable - check if DC is reachable."
                        }

                        # === Time/Clock Errors ===
                        37 {  # KRB_AP_ERR_SKEW
                            $detailsArray += "Reason: Clock skew too great - sync system time with DC (max 5 min difference)."
                        }

                        # === Ticket Errors ===
                        31 {  # KRB_AP_ERR_BAD_INTEGRITY
                            $detailsArray += "Reason: Integrity check failed - wrong key or corrupted ticket."
                        }
                        32 {  # KRB_AP_ERR_TKT_EXPIRED
                            $detailsArray += "Reason: Ticket has expired - request a new ticket."
                        }
                        33 {  # KRB_AP_ERR_TKT_NYV
                            $detailsArray += "Reason: Ticket not yet valid - check system time."
                        }
                        41 {  # KRB_AP_ERR_MODIFIED
                            $detailsArray += "Reason: Message stream modified - ticket checksum validation failed."
                            $detailsArray += "This usually means the wrong key was used for encryption/signing."
                        }

                        # === PKINIT (Certificate) Errors ===
                        62 {  # KDC_ERR_CLIENT_NOT_TRUSTED
                            $detailsArray += "Reason: Client certificate not trusted by KDC."
                            $detailsArray += "This typically means the Domain Controller lacks PKINIT support."
                            $detailsArray += ""
                            $detailsArray += "PKINIT Prerequisites (Shadow Credentials / Certificate Auth):"
                            $detailsArray += "  1. AD CS must be installed in the domain, OR"
                            $detailsArray += "  2. DC must have a certificate from another PKI"
                            $detailsArray += "  3. DC certificate must have 'Kerberos Authentication' EKU"
                            $detailsArray += ""
                            $detailsArray += "Alternative: Use Schannel/LDAPS authentication instead:"
                            $detailsArray += "  - PassTheCert tool (LDAP/S with certificate)"
                            $detailsArray += "  - Or use RBCD attack if you have write access to the target"
                        }
                        63 {  # KDC_ERR_KDC_NOT_TRUSTED
                            $detailsArray += "Reason: KDC certificate not trusted by client."
                        }
                        64 {  # KDC_ERR_INVALID_SIG
                            $detailsArray += "Reason: Invalid signature in PKINIT request."
                        }
                        66 {  # KDC_ERR_CERTIFICATE_MISMATCH
                            $detailsArray += "Reason: Certificate doesn't match the principal name."
                        }
                        70 {  # KDC_ERR_CANT_VERIFY_CERTIFICATE
                            $detailsArray += "Reason: Cannot verify certificate - check CA trust chain."
                        }
                        71 {  # KDC_ERR_INVALID_CERTIFICATE
                            $detailsArray += "Reason: Invalid certificate - not valid for Kerberos authentication."
                        }
                        72 {  # KDC_ERR_REVOKED_CERTIFICATE
                            $detailsArray += "Reason: Certificate has been revoked."
                        }
                        77 {  # KDC_ERR_INCONSISTENT_KEY_PURPOSE
                            $detailsArray += "Reason: Certificate cannot be used for PKINIT client authentication."
                            $detailsArray += "The certificate's Extended Key Usage (EKU) must include:"
                            $detailsArray += "  - Smart Card Logon (1.3.6.1.4.1.311.20.2.2), or"
                            $detailsArray += "  - Client Authentication (1.3.6.1.5.5.7.3.2)"
                        }
                        79 {  # KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED
                            $detailsArray += "Reason: Windows Server 2022+ requires paChecksum2 with SHA-256."
                            $detailsArray += "This error indicates the PKINIT request is missing the SHA-256 checksum."
                            $detailsArray += ""
                            $detailsArray += "Note: This should not occur with the current adPEAS version."
                            $detailsArray += "If you see this error, please report it as a bug."
                        }

                        default {
                            # Fallback: central error code map
                            if ($Script:KERBEROS_ERROR_CODES -and $Script:KERBEROS_ERROR_CODES.ContainsKey([int]$ErrorCode)) {
                                $errorInfo = $Script:KERBEROS_ERROR_CODES[[int]$ErrorCode]
                                $detailsArray += "Reason: $($errorInfo.Name): $($errorInfo.Description)"
                            }
                            elseif ($Details) {
                                $detailsArray += $Details
                            }
                            else {
                                $detailsArray += "Reason: KDC error code: $ErrorCode"
                            }
                        }
                    }
                }
                elseif ($effectiveDetails) {
                    # No Kerberos error code provided - use effective details as fallback
                    $detailsArray += $effectiveDetails
                }

                Show-Message -Type Error -Title "Authentication failed: Invalid credentials" -Details $detailsArray
                $ThrowMessage = "Authentication failed"
            }

            "NTLMDisabledError" {
                $detailsArray = @("Windows SSPI negotiation failed - NTLM unavailable and Kerberos not possible")
                if ($effectiveDetails) {
                    $detailsArray += "Technical: $effectiveDetails"
                }
                $hints = @(
                    "Use explicit credentials with Kerberos or SimpleBind:",
                    "  Connect-adPEAS -Domain 'domain.com' -Username 'user' -Password 'pass'",
                    "  Connect-adPEAS -Domain 'domain.com' -Username 'user' -Password 'pass' -ForceSimpleBind"
                )
                Show-Message -Type Error -Title "Authentication failed: NTLM is disabled" -Details $detailsArray -Hints $hints
                $ThrowMessage = "NTLM disabled - use explicit credentials or Kerberos"
            }

            "TicketImportError" {
                $detailsArray = @()

                # Determine if this is a file format error or PTT error
                if ($effectiveDetails -match "Invalid kirbi file|Invalid ccache file") {
                    $detailsArray += $effectiveDetails
                    Show-Message -Type Error -Title "Invalid ticket file format" -Details $detailsArray
                }
                else {
                    if ($effectiveDetails) {
                        if ($effectiveDetails -match "non-domain-joined|Remote Credential Guard") {
                            $detailsArray += "PTT requires domain-joined machine or elevated privileges"
                        } else {
                            $detailsArray += $effectiveDetails
                        }
                    }
                    Show-Message -Type Error -Title "Ticket import failed (Pass-the-Ticket)" -Details $detailsArray
                }
                $ThrowMessage = "Ticket import failed"
            }

            "GenericError" {
                $detailsArray = @()
                if ($effectiveDetails) {
                    $detailsArray += $effectiveDetails
                }
                Show-Message -Type Error -Title "Connection failed" -Details $detailsArray
                $ThrowMessage = "Connection failed"
            }
        }

        if (-not $NoThrow) {
            throw $ThrowMessage
        }
    }
}
