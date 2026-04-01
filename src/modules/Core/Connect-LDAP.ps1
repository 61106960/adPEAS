<#
.SYNOPSIS
    Establishes an LDAP/LDAPS connection to an Active Directory environment.

.DESCRIPTION
    Initializes an LDAP connection to the target domain using System.DirectoryServices.Protocols

    Supports:
    - LDAP (Port 389) and LDAPS (Port 636) with SSL/TLS
    - Global Catalog connections (Ports 3268/3269) via -AsGlobalCatalog
    - Alternative credentials (SimpleBind) or Windows Authentication (Negotiate)
    - Schannel (TLS client certificate) via -ClientCertificate (Pass-the-Cert)
    - Automatic domain and DC discovery
    - Anonymous access detection
    - Custom DNS server support (via $Script:LDAPContext['DnsServer'])

    In normal mode, stores the connection in $Script:LdapConnection and $Script:LDAPContext.
    In GC mode (-AsGlobalCatalog), returns the raw LdapConnection without modifying global state.

.PARAMETER Domain
    The target domain (FQDN).
    Optional - Default: Automatic detection via GetCurrentDomain()

.PARAMETER Server
    Specific Domain Controller (FQDN or IP).
    Optional - Default: Automatic via Domain

.PARAMETER Credential
    PSCredential object for alternative authentication.
    Optional - Default: Current user context (Negotiate/Kerberos)

.PARAMETER UseLDAPS
    Forces LDAPS (no fallback to LDAP).

.PARAMETER IgnoreSSLErrors
    Ignores SSL certificate errors for LDAPS connections (self-signed certs, expired certs,
    hostname mismatches, untrusted CAs, etc.).
    Default: $true (for maximum compatibility in pentesting environments)
    Can be explicitly disabled with -IgnoreSSLErrors:$false

.PARAMETER TimeoutSeconds
    Timeout in seconds for LDAP operations.
    Default: 30 seconds
    Valid range: 5-600 seconds. Increase for high-latency connections (SOCKS tunnels, VPN).

.PARAMETER AsGlobalCatalog
    Connects to the Global Catalog (port 3268 or 3269 with -UseLDAPS).
    Requires -Domain and -Server to be specified.
    Returns the raw LdapConnection object without storing it globally.

.EXAMPLE
    Connect-LDAP
    Connects to current domain (automatic detection)

.EXAMPLE
    Connect-LDAP -Domain "contoso.com" -UseLDAPS
    Connects to contoso.com via LDAPS

.EXAMPLE
    Connect-LDAP -Domain "contoso.com" -Credential (Get-Credential)
    Connects with alternative credentials

.EXAMPLE
    Connect-LDAP -Domain "contoso.com" -Server "dc01.contoso.com" -AsGlobalCatalog
    Returns a GC LdapConnection on port 3268

.OUTPUTS
    Hashtable with connection context (normal mode) or LdapConnection object (GC mode)

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

function Connect-LDAP {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [switch]$UseLDAPS,

        [Parameter(Mandatory=$false)]
        [bool]$IgnoreSSLErrors = $true,

        [Parameter(Mandatory=$false)]
        [ValidateRange(5, 600)]
        [int]$TimeoutSeconds = 30,

        [Parameter(Mandatory=$false)]
        [switch]$AsGlobalCatalog,

        [Parameter(Mandatory=$false)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$ClientCertificate,

        # Forces explicit NTLM authentication via Sicily (AuthType::Ntlm) instead of Negotiate.
        # SSPI sends a pure NTLM NEGOTIATE_MESSAGE without offering Kerberos first.
        # Works against real AD DCs on domain-joined and non-domain-joined systems.
        # Requires -Credential to be set.
        [Parameter(Mandatory=$false)]
        [switch]$ForceNTLM,

        # Suppress user-visible error messages (Show-ConnectionError) while still tracking error codes.
        # Used by Connect-adPEAS when it knows it will auto-retry (e.g., LDAPS upgrade after SimpleBind failure).
        [Parameter(Mandatory=$false)]
        [switch]$SuppressErrorDisplay
    )

    begin {
        Write-Log "[Connect-LDAP] Starting LDAP connection..."

        # Reset connection state at the beginning
        $Script:ConnectionState = $null
        $Script:LastLDAPErrorCode = $null

        # SSL Certificate Validation Callback (only relevant for LDAPS)
        if ($IgnoreSSLErrors) {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
            # Disable CRL (Certificate Revocation List) checking to prevent ~15s timeout
            # during LDAPS Bind() when CRL Distribution Points are unreachable (lab/isolated environments)
            # SChannel performs CRL checks BEFORE VerifyServerCertificate callback is invoked
            [System.Net.ServicePointManager]::CheckCertificateRevocationList = $false
        }

        # Helper: Classify LDAP/connection errors and show appropriate error message
        # Used by Phase 5, Phase 6, and final catch block to avoid code duplication
        function Resolve-LDAPConnectionError {
            param(
                [Parameter(Mandatory)] $ErrorRecord,
                [string]$Context = "Connection",
                [switch]$BindSucceeded  # Set when Bind() succeeded but a subsequent SendRequest() failed
            )
            # Extract error message and code from exception chain
            # PowerShell wraps .NET exceptions: MethodInvocationException → LdapException or DirectoryOperationException
            # - LdapException: has ErrorCode property (e.g., 49 = invalid credentials)
            # - DirectoryOperationException: thrown for LDAP result codes like StrongAuthRequired (8),
            #   but does NOT expose the numeric error code - must be identified by exception type
            $ex = $ErrorRecord.Exception
            $innerEx = $ex.InnerException

            # Walk the full exception chain to find known LDAP exception types
            $ldapEx = $null
            $dirOpEx = $null
            $walker = $ex
            while ($walker) {
                $typeName = $walker.GetType().FullName
                if ($typeName -eq 'System.DirectoryServices.Protocols.LdapException') {
                    $ldapEx = $walker
                    break
                }
                if ($typeName -eq 'System.DirectoryServices.Protocols.DirectoryOperationException') {
                    $dirOpEx = $walker
                }
                $walker = $walker.InnerException
            }

            $msg = if ($ldapEx) { $ldapEx.Message } elseif ($dirOpEx) { $dirOpEx.Message } elseif ($innerEx) { $innerEx.Message } else { $ex.Message }

            $errorInfo = $null
            $ldapErrorCode = $null

            if ($ldapEx) {
                # LdapException has ErrorCode property
                $ldapErrorCode = $ldapEx.ErrorCode
                $errorInfo = ConvertFrom-LDAPError -ErrorCode $ldapErrorCode
                Write-Log "[Connect-LDAP] $Context failed: $msg (LDAP error $ldapErrorCode`: $($errorInfo.Name))"
            } elseif ($dirOpEx) {
                # DirectoryOperationException: extract ResultCode from Response if available,
                # otherwise fall back to code 8 (StrongAuthRequired) for Bind failures where Response is null
                if ($dirOpEx.Response -and $dirOpEx.Response.ResultCode) {
                    $ldapErrorCode = [int]$dirOpEx.Response.ResultCode
                } else {
                    $ldapErrorCode = 8
                }
                $errorInfo = ConvertFrom-LDAPError -ErrorCode $ldapErrorCode
                Write-Log "[Connect-LDAP] $Context failed: $msg (LDAP error $ldapErrorCode`: $($errorInfo.Name))"
            } elseif ($innerEx -and $innerEx.PSObject.Properties['ErrorCode']) {
                # Generic exception with ErrorCode (e.g., HResult-based)
                $code = $innerEx.ErrorCode
                $errorInfo = ConvertFrom-HResult -HResult $code
                Write-Log "[Connect-LDAP] $Context failed: $msg (Error 0x$($code.ToString('X8')): $($errorInfo.Name))"
                if ($errorInfo.LDAPCode) { $ldapErrorCode = $errorInfo.LDAPCode }
            } else {
                Write-Log "[Connect-LDAP] $Context failed: $msg"
            }

            # Store LDAP error code and details for upstream callers (e.g., Connect-adPEAS LDAPS auto-upgrade)
            $Script:LastLDAPErrorCode = $ldapErrorCode
            $Script:LastLDAPErrorDetails = $msg

            $errorType = switch ($errorInfo.Category) {
                'AccessDenied' { if ($errorInfo.Name -match 'LOGON|CREDENTIALS|OPERATIONS_ERROR') { "AuthenticationFailed" } else { "PermissionError" } }
                'Network'      { "NetworkError" }
                'Domain'       { "DomainError" }
                'Timeout'      { "NetworkError" }
                'LDAP'         { "GenericError" }
                default        { "GenericError" }
            }

            # Override: LDAP 81 (SERVER_DOWN) after a successful Bind() is NOT a network error —
            # the server IS reachable and authentication succeeded. The failure is in the LDAP
            # protocol layer (post-bind request processing). Use GenericError to avoid the
            # misleading "Server unreachable" title from NetworkError.
            if ($ldapErrorCode -eq 81 -and $BindSucceeded) {
                $errorType = "GenericError"
            }

            $Script:ConnectionState = $errorType
            if (-not $SuppressErrorDisplay) {
                if ($null -ne $ldapErrorCode) {
                    # For LDAP 81 after a successful Bind(), provide more specific details:
                    # the TCP connection and authentication handshake worked, but the server
                    # stopped responding to LDAP protocol messages (e.g., incomplete LDAP server implementation)
                    $extraDetails = $null
                    if ($ldapErrorCode -eq 81 -and $BindSucceeded) {
                        $extraDetails = "Bind() succeeded but the server did not respond to the search request. The LDAP server may not fully support authenticated queries."
                    }
                    # For LDAP 82 after a successful Bind(), distinguish the NTLM/GSSAPI negotiation failure
                    # from a Kerberos SPN mismatch (which is the typical non-bind context for error 82)
                    elseif ($ldapErrorCode -eq 82 -and $BindSucceeded) {
                        $extraDetails = "GSSAPI/NTLM negotiation failed during Bind() - the server may not support this authentication mechanism."
                    }
                    if ($extraDetails) {
                        Show-ConnectionError -ErrorType $errorType -ErrorCode $ldapErrorCode -ErrorCodeType "LDAP" -Details $extraDetails -NoThrow
                    } else {
                        Show-ConnectionError -ErrorType $errorType -ErrorCode $ldapErrorCode -ErrorCodeType "LDAP" -NoThrow
                    }
                } else {
                    Show-ConnectionError -ErrorType $errorType -Details $msg -NoThrow
                }
            }
        }
    }

    process {
        try {
            # ===== Phase 1: Domain Discovery =====
            if ($AsGlobalCatalog) {
                # GC mode: Domain and Server must be pre-populated from existing session
                if ([string]::IsNullOrEmpty($Domain) -or [string]::IsNullOrEmpty($Server)) {
                    Write-Log "[Connect-LDAP] AsGlobalCatalog requires -Domain and -Server parameters"
                    return $null
                }
                $DomainDN = "DC=" + ($Domain -replace "\.", ",DC=")
                Write-Log "[Connect-LDAP] GC mode: Server=$Server, Domain=$Domain"
            } else {
                if ([string]::IsNullOrEmpty($Domain)) {
                    Write-Log "[Connect-LDAP] No domain specified, attempting automatic discovery..."
                    try {
                        $CurrentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
                        $Domain = $CurrentDomain.Name
                        Write-Log "[Connect-LDAP] Automatically detected domain: $Domain"
                    } catch {
                        $Script:ConnectionState = "DomainError"
                        Show-ConnectionError -ErrorType "DomainError" -Details "Domain parameter required or system must be domain-joined" -NoThrow
                        return $null
                    }
                }

                # Determine Domain Controller if not specified
                if ([string]::IsNullOrEmpty($Server)) {
                    Write-Log "[Connect-LDAP] No server specified, using domain name: $Domain"
                    $Server = $Domain
                }

                # Create Distinguished Name for Domain
                $DomainDN = "DC=" + ($Domain -replace "\.", ",DC=")
                Write-Log "[Connect-LDAP] Domain DN: $DomainDN"
            }

            # ===== Phase 2: DNS Resolution =====
            Write-Log "[Connect-LDAP] Testing DNS resolution for: $Server"
            $ResolvedIPs = $null
            $ResolvedIPString = $null

            # Check if custom DNS server is configured (from Connect-adPEAS -DnsServer parameter)
            $CustomDnsServer = $null
            if ($Script:LDAPContext -and $Script:LDAPContext['DnsServer']) {
                $CustomDnsServer = $Script:LDAPContext['DnsServer']
                Write-Log "[Connect-LDAP] Using custom DNS server: $CustomDnsServer"
            }

            try {
                if ($CustomDnsServer) {
                    # Use custom DNS resolution via Resolve-adPEASName
                    $ResolvedIPString = Resolve-adPEASName -Name $Server -DnsServer $CustomDnsServer
                    if ($ResolvedIPString) {
                        Write-Log "[Connect-LDAP] DNS resolution via custom DNS successful: $ResolvedIPString"
                    } else {
                        throw "Custom DNS resolution failed for $Server"
                    }
                } else {
                    # Use system DNS
                    $ResolvedIPs = [System.Net.Dns]::GetHostAddresses($Server)
                    if (-not $ResolvedIPs -or $ResolvedIPs.Count -eq 0) {
                        throw "DNS resolution returned no addresses"
                    }
                    $ResolvedIPString = $ResolvedIPs[0].IPAddressToString
                    Write-Log "[Connect-LDAP] DNS resolution successful: $ResolvedIPString"
                }
            } catch {
                $Script:ConnectionState = "DomainError"
                $Detail = if ($Server -eq $Domain) {
                    "Domain '$Domain' could not be resolved"
                } else {
                    "Server '$Server' could not be resolved"
                }
                Show-ConnectionError -ErrorType "DomainError" -Details $Detail -NoThrow
                return $null
            }

            # ===== Phase 3: Port Reachability =====
            # Use resolved IP for connection test when custom DNS is active
            $ConnectTarget = if ($CustomDnsServer -and $ResolvedIPString) { $ResolvedIPString } else { $Server }
            Write-Log "[Connect-LDAP] Testing port reachability to: $ConnectTarget"
            $ServerReachable = $false
            $TestPort = if ($AsGlobalCatalog) {
                if ($UseLDAPS) { 3269 } else { 3268 }
            } else {
                if ($UseLDAPS) { 636 } else { 389 }
            }

            try {
                $TcpClient = New-Object System.Net.Sockets.TcpClient
                $ConnectTask = $TcpClient.BeginConnect($ConnectTarget, $TestPort, $null, $null)
                $WaitHandle = $ConnectTask.AsyncWaitHandle

                if ($WaitHandle.WaitOne(2000, $false)) {
                    $TcpClient.EndConnect($ConnectTask)
                    $ServerReachable = $true
                    Write-Log "[Connect-LDAP] Server is reachable on port $TestPort"
                }
                $TcpClient.Close()
            } catch {
                Write-Log "[Connect-LDAP] Port test failed: $_"
            }

            if (-not $ServerReachable) {
                $Script:ConnectionState = "NetworkError"
                $PortDesc = "$TestPort ($(if ($AsGlobalCatalog) { 'GC' } else { if ($UseLDAPS) { 'LDAPS' } else { 'LDAP' } }))"
                Show-ConnectionError -ErrorType "NetworkError" -Details "Port $PortDesc unreachable on $Server" -NoThrow
                return $null
            }

            # ===== Phase 3b: SSL/TLS Handshake Test (LDAPS only) =====
            if ($UseLDAPS) {
                $SSLPort = $TestPort  # Already set to 3269 for GC, 636 for normal LDAPS
                Write-Log "[Connect-LDAP] Testing SSL/TLS handshake on port $SSLPort..."
                $SSLTestPassed = $false
                $sslErrorInfo = $null

                try {
                    $TcpClientSSL = New-Object System.Net.Sockets.TcpClient
                    $TcpClientSSL.Connect($ConnectTarget, $SSLPort)

                    $SslStream = New-Object System.Net.Security.SslStream(
                        $TcpClientSSL.GetStream(),
                        $false,
                        { param($sslSender, $cert, $chain, $errors)
                            return $IgnoreSSLErrors -or ($errors -eq [System.Net.Security.SslPolicyErrors]::None)
                        }
                    )

                    # Authenticate as client
                    $SslStream.AuthenticateAsClient($Server)
                    $SSLTestPassed = $true

                    Write-Log "[Connect-LDAP] SSL/TLS handshake successful"
                    Write-Log "[Connect-LDAP] SSL Protocol: $($SslStream.SslProtocol)"
                    Write-Log "[Connect-LDAP] Cipher: $($SslStream.CipherAlgorithm)"
                    if ($SslStream.RemoteCertificate) {
                        Write-Log "[Connect-LDAP] Certificate Subject: $($SslStream.RemoteCertificate.Subject)"
                        Write-Log "[Connect-LDAP] Certificate Issuer: $($SslStream.RemoteCertificate.Issuer)"

                        # Pre-cache the certificate chain with CRL check disabled (X509RevocationMode.NoCheck)
                        # This prevents a ~15s timeout during LdapConnection.Bind() when SChannel tries to
                        # download the CRL from an unreachable CDP (common in labs/isolated environments).
                        # The Windows CryptoAPI caches the chain result, so the subsequent Bind() gets a cache hit.
                        if ($IgnoreSSLErrors) {
                            try {
                                $cert2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($SslStream.RemoteCertificate)
                                $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
                                $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
                                $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain
                                $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllFlags
                                [void]$chain.Build($cert2)
                                $chain.Reset()
                                Write-Log "[Connect-LDAP] Certificate chain pre-cached (CRL check disabled)"
                            } catch {
                                Write-Log "[Connect-LDAP] Certificate chain pre-cache failed (non-critical): $_"
                            }
                        }
                    }

                    $SslStream.Close()
                    $TcpClientSSL.Close()
                }
                catch {
                    $sslErrorInfo = Get-ExceptionErrorInfo -Exception $_.Exception -Context "SSL handshake"
                    Write-Log "[Connect-LDAP] SSL/TLS handshake FAILED: $($sslErrorInfo.Message)"

                    if ($sslErrorInfo.Category -eq 'SSLCertificate' -and -not $IgnoreSSLErrors) {
                        Write-Log "[Connect-LDAP] Consider using -IgnoreSSLErrors parameter"
                    }
                }

                if (-not $SSLTestPassed) {
                    $errorType = if ($sslErrorInfo.Category -eq 'SSLCertificate') { "CertificateError" } else { "SSLHandshakeError" }
                    $Script:ConnectionState = $errorType
                    Show-ConnectionError -ErrorType $errorType -Details $sslErrorInfo.Message -NoThrow
                    return $null
                }
            }

            # ===== Phase 4: Anonymous Access Check (A-NullSession) =====
            # Test if anonymous LDAP bind is possible and can read AD data
            # This check is silent - failures are expected and NOT displayed to user
            # UNIFIED: Use System.DirectoryServices.Protocols.LdapConnection with Anonymous AuthType
            # NOTE: Skip for LDAPS - anonymous access over SSL is extremely rare and the SSL handshake timeout cannot be reliably controlled, causing delays of 10+ seconds
            # NOTE: Skip for GC mode - anonymous check is not relevant for auxiliary GC connections
            $Script:AnonymousAccessEnabled = $false
            $Script:AnonymousAccessDetails = $null

            if ($AsGlobalCatalog) {
                Write-Log "[Connect-LDAP] Skipping anonymous access check for GC mode"
            }
            elseif ($UseLDAPS) {
                Write-Log "[Connect-LDAP] Skipping anonymous access check for LDAPS (rarely enabled over SSL)"
            }

            $AnonLdapConn = $null
            if (-not $UseLDAPS -and -not $AsGlobalCatalog) {
            try {
                # Use resolved IP when custom DNS is active
                $AnonTarget = if ($CustomDnsServer -and $ResolvedIPString) { $ResolvedIPString } else { $Server }

                # Create temporary LdapConnection for anonymous bind test (always port 389 - LDAPS/GC are skipped above)
                $AnonIdentifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($AnonTarget, 389)
                $AnonLdapConn = New-Object System.DirectoryServices.Protocols.LdapConnection($AnonIdentifier)
                $AnonLdapConn.SessionOptions.ProtocolVersion = 3
                # Short timeouts for anonymous test - Bind() uses SendTimeout, SendRequest uses Timeout
                $AnonLdapConn.Timeout = [TimeSpan]::FromSeconds(2)
                $AnonLdapConn.SessionOptions.SendTimeout = [TimeSpan]::FromSeconds(2)

                # Set Anonymous authentication
                $AnonLdapConn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Anonymous

                # Attempt anonymous bind
                $AnonLdapConn.Bind()
                Write-Log "[Connect-LDAP] Anonymous bind successful - testing read access..."

                # Try to read the domain object
                $AnonSearchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest(
                    $DomainDN,
                    "(objectClass=domainDNS)",
                    [System.DirectoryServices.Protocols.SearchScope]::Base,
                    @("distinguishedName", "name", "objectSid")
                )

                $AnonSearchResponse = $AnonLdapConn.SendRequest($AnonSearchRequest)

                if ($AnonSearchResponse -and $AnonSearchResponse.Entries.Count -gt 0) {
                    $AnonEntry = $AnonSearchResponse.Entries[0]

                    if ($AnonEntry.DistinguishedName) {
                        # Anonymous access is possible
                        $Script:AnonymousAccessEnabled = $true

                        # Determine what we can read
                        $ReadableAttrs = @()
                        foreach ($attr in $AnonEntry.Attributes.AttributeNames) {
                            $ReadableAttrs += $attr
                        }

                        # Try to enumerate users
                        $CanEnumUsers = $false
                        $UserCount = 0
                        try {
                            $UserSearchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest(
                                $DomainDN,
                                "(objectClass=user)",
                                [System.DirectoryServices.Protocols.SearchScope]::Subtree,
                                @("sAMAccountName")
                            )
                            $UserSearchRequest.SizeLimit = 5  # Just test if we can read any

                            $UserSearchResponse = $AnonLdapConn.SendRequest($UserSearchRequest)
                            $UserCount = $UserSearchResponse.Entries.Count
                            if ($UserCount -gt 0) {
                                $CanEnumUsers = $true
                            }
                        } catch {
                            Write-Log "[Connect-LDAP] Anonymous user enumeration test failed (expected)"
                        }

                        $Script:AnonymousAccessDetails = @{
                            CanReadDomainRoot = $true
                            ReadableAttributes = $ReadableAttrs
                            CanEnumerateUsers = $CanEnumUsers
                            UsersSampled = $UserCount
                        }

                        Write-Log "[Connect-LDAP] WARNING: Anonymous LDAP access is enabled!"
                        Write-Log "[Connect-LDAP] Readable attributes: $($ReadableAttrs -join ', ')"
                        if ($CanEnumUsers) {
                            Write-Log "[Connect-LDAP] WARNING: Anonymous user enumeration is possible!"
                        }
                    }
                }

            } catch {
                # Anonymous access not possible (expected/secure configuration)
                Write-Log "[Connect-LDAP] Anonymous access test: denied (secure - this is expected)"
                $Script:AnonymousAccessEnabled = $false
            } finally {
                # Always dispose the temporary anonymous connection
                if ($AnonLdapConn) {
                    try { $AnonLdapConn.Dispose() } catch { }
                }
            }
            }  # End of: if (-not $UseLDAPS -and -not $AsGlobalCatalog)

            # ===== Phase 5: LDAP Connection =====
            # UNIFIED APPROACH: Always use System.DirectoryServices.Protocols.LdapConnection for ALL operations
            # This includes queries (SearchRequest) AND modifications (ModifyRequest)
            $ConnectionEstablished = $false
            $LdapProtocolConn = $null
            $LDAPPort = if ($AsGlobalCatalog) {
                if ($UseLDAPS) { 3269 } else { 3268 }
            } else {
                if ($UseLDAPS) { 636 } else { 389 }
            }
            $LDAPTarget = $Server
            Write-Log "[Connect-LDAP] Using hostname for LDAP connection: $LDAPTarget"

            $ProtocolDisplay = if ($AsGlobalCatalog) { "GC" } elseif ($UseLDAPS) { "LDAPS" } else { "LDAP" }
            Write-Log "[Connect-LDAP] Attempting $ProtocolDisplay connection to ${LDAPTarget}:${LDAPPort}..."

            try {
                # ===== UNIFIED: Always use System.DirectoryServices.Protocols.LdapConnection =====
                # This works reliably for both LDAP (389) and LDAPS (636)
                Write-Log "[Connect-LDAP] Using System.DirectoryServices.Protocols.LdapConnection for $ProtocolDisplay..."

                # Load the assembly
                Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction Stop

                # Create LdapConnection with server:port
                $LdapIdentifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($LDAPTarget, $LDAPPort)
                $LdapProtocolConn = New-Object System.DirectoryServices.Protocols.LdapConnection($LdapIdentifier)

                if ($ClientCertificate) {
                    # ===== Schannel (Pass-the-Cert): Minimal configuration =====
                    # CRITICAL: For Schannel to work, the LdapConnection must be configured with
                    # MINIMAL SessionOptions. Extra options like ProtocolVersion, ReferralChasing,
                    # and Timeouts interfere with the implicit TLS authentication.
                    # This matches exactly what Invoke-PassTheCert (Viper-One) does:
                    # Only ClientCertificates.Add() + SecureSocketLayer + VerifyServerCertificate
                    $LdapProtocolConn.ClientCertificates.Add($ClientCertificate) | Out-Null
                    $LdapProtocolConn.SessionOptions.SecureSocketLayer = $true
                    $LdapProtocolConn.SessionOptions.VerifyServerCertificate = { param($conn, $cert) return $true }
                    Write-Log "[Connect-LDAP] Schannel: Minimal config (ClientCert + SSL + VerifyServerCert)"
                } else {
                    # ===== Standard configuration for non-Schannel connections =====
                    # Configure protocol version
                    $LdapProtocolConn.SessionOptions.ProtocolVersion = 3

                    # Configure timeouts for faster connection/response
                    $LdapProtocolConn.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
                    $SendTimeoutSeconds = [Math]::Max(5, [Math]::Floor($TimeoutSeconds / 2))
                    $LdapProtocolConn.SessionOptions.SendTimeout = [TimeSpan]::FromSeconds($SendTimeoutSeconds)
                    Write-Log "[Connect-LDAP] Configured timeouts: Operation=${TimeoutSeconds}s, Send=${SendTimeoutSeconds}s"

                    # Disable referral chasing
                    $LdapProtocolConn.SessionOptions.ReferralChasing = [System.DirectoryServices.Protocols.ReferralChasingOptions]::None
                    Write-Log "[Connect-LDAP] Referral chasing disabled (domain-local queries only)"

                    # Configure SSL for LDAPS
                    if ($UseLDAPS) {
                        $LdapProtocolConn.SessionOptions.SecureSocketLayer = $true
                        if ($IgnoreSSLErrors) {
                            $LdapProtocolConn.SessionOptions.VerifyServerCertificate = { param($conn, $cert) return $true }
                            Write-Log "[Connect-LDAP] SSL certificate validation disabled (IgnoreSSLErrors)"
                        }
                    }
                }

                # Set authentication and bind
                if ($ClientCertificate) {
                    # Schannel: No AuthType, no Bind() - exactly like Viper-One and AlmondOffSec
                    # The first SendRequest() will trigger AutoBind with TLS client certificate identity
                    Write-Log "[Connect-LDAP] Schannel: No explicit AuthType or Bind() - TLS handshake provides identity"
                }
                elseif ($Credential -and $ForceNTLM) {
                    # Explicit NTLM via Sicily: AuthType::Ntlm + NetworkCredential.
                    # Sicily is Microsoft's proprietary NTLM-over-LDAP mechanism. Unlike Negotiate,
                    # SSPI sends a pure NTLM NEGOTIATE_MESSAGE without offering Kerberos first.
                    # Works correctly against real AD DCs (domain-joined and non-domain-joined).
                    $NtlmNetCred = $Credential.GetNetworkCredential()
                    $NtlmUser   = $NtlmNetCred.UserName
                    $NtlmDomain = $NtlmNetCred.Domain
                    $NtlmPass   = $NtlmNetCred.Password

                    Write-Log "[Connect-LDAP] Configuring explicit NTLM authentication (Sicily): $NtlmDomain\$NtlmUser"
                    $LdapProtocolConn.AuthType  = [System.DirectoryServices.Protocols.AuthType]::Ntlm
                    $LdapProtocolConn.Credential = New-Object System.Net.NetworkCredential($NtlmUser, $NtlmPass, $NtlmDomain)
                }
                elseif ($Credential) {
                    $NetworkCred = $Credential.GetNetworkCredential()
                    $UserName = $NetworkCred.UserName  # Username part only (without domain prefix)
                    $Password = $NetworkCred.Password
                    $CredDomain = $NetworkCred.Domain  # Domain part (if user specified DOMAIN\user)

                    # SimpleBind requires domain-qualified username
                    # AD accepts: NETBIOS\user or user@domain.fqdn (UPN format)
                    # AD does NOT accept: domain.fqdn\user

                    # Determine correct format based on what user provided:
                    # 1. If NetworkCredential.Domain is set → user specified DOMAIN\username → reconstruct it
                    # 2. If username contains '@' → user specified UPN → keep it as-is
                    # 3. Otherwise → bare username → auto-qualify with UPN format

                    if (-not [string]::IsNullOrEmpty($CredDomain)) {
                        # User specified DOMAIN\username format - reconstruct it
                        $UserName = "$CredDomain\$UserName"
                        Write-Log "[Connect-LDAP] Username from credential (NETBIOS format): $UserName"
                    }
                    elseif ($UserName -match '@') {
                        # User specified UPN format (user@domain.com) - keep as-is
                        Write-Log "[Connect-LDAP] Username from credential (UPN format): $UserName"
                    }
                    else {
                        # Bare username without domain/UPN - auto-qualify with UPN format
                        if ($Domain) {
                            $UserName = "$UserName@$Domain"
                            Write-Log "[Connect-LDAP] Username qualified for SimpleBind (UPN): $UserName"
                        } else {
                            Write-Log "[Connect-LDAP] WARNING: Username '$UserName' is not domain-qualified and no domain available"
                        }
                    }

                    Write-Log "[Connect-LDAP] Configuring SimpleBind with credentials: $UserName"

                    # Use Basic auth for SimpleBind
                    $LdapProtocolConn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Basic
                    $LdapProtocolConn.Credential = New-Object System.Net.NetworkCredential($UserName, $Password)
                } else {
                    Write-Log "[Connect-LDAP] Configuring Negotiate (Kerberos/NTLM) authentication"
                    $LdapProtocolConn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
                }

                # Bind to server (skip for Schannel - AutoBind handles it on first SendRequest)
                $LdapBindSucceeded = $false
                if ($ClientCertificate) {
                    Write-Log "[Connect-LDAP] Schannel: Skipping Bind() - first SendRequest() will trigger AutoBind"
                    $LdapBindSucceeded = $true  # AutoBind - treat as succeeded for error context
                } else {
                    Write-Log "[Connect-LDAP] Binding to $ProtocolDisplay server..."
                    $bindStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                    $LdapProtocolConn.Bind()
                    $bindStopwatch.Stop()
                    Write-Log "[Connect-LDAP] $ProtocolDisplay bind successful! ($($bindStopwatch.ElapsedMilliseconds)ms)"
                    $LdapBindSucceeded = $true
                }

                if ($AsGlobalCatalog) {
                    # ===== GC Mode: Verify isGlobalCatalogReady and return =====
                    # For GC connections, skip RootDSE/DomainSID/UserVerification and return
                    # the raw LdapConnection WITHOUT writing to global state.
                    $ConnectionEstablished = $true

                    try {
                        $gcRootDSE = New-Object System.DirectoryServices.Protocols.SearchRequest(
                            "", "(objectClass=*)",
                            [System.DirectoryServices.Protocols.SearchScope]::Base,
                            @("isGlobalCatalogReady")
                        )
                        $gcRootDSEResponse = $LdapProtocolConn.SendRequest($gcRootDSE)
                        $isGC = $false
                        if ($gcRootDSEResponse -and $gcRootDSEResponse.Entries.Count -gt 0) {
                            $gcReadyAttr = $gcRootDSEResponse.Entries[0].Attributes["isglobalcatalogready"]
                            if ($gcReadyAttr -and $gcReadyAttr.Count -gt 0) {
                                $isGC = ([string]$gcReadyAttr[0]) -eq "TRUE"
                            }
                        }
                        if (-not $isGC) {
                            Write-Log "[Connect-LDAP] GC mode: ${LDAPTarget}:${LDAPPort} is NOT a Global Catalog (isGlobalCatalogReady != TRUE)"
                            try { $LdapProtocolConn.Dispose() } catch { }
                            return $null
                        }
                    } catch {
                        Write-Log "[Connect-LDAP] GC mode: Could not verify GC status on ${LDAPTarget}:${LDAPPort}: $($_.Exception.Message)"
                        try { $LdapProtocolConn.Dispose() } catch { }
                        return $null
                    }

                    Write-Log "[Connect-LDAP] GC mode: Connection to ${LDAPTarget}:${LDAPPort} established and verified as Global Catalog"
                    return $LdapProtocolConn
                }

                # ===== Normal Mode: Test search and store globally =====
                # Test by searching for domain root
                Write-Log "[Connect-LDAP] Testing $ProtocolDisplay connection with search query..."
                Write-Log "[Connect-LDAP] Connection state: AuthType=$($LdapProtocolConn.AuthType), AutoBind=$($LdapProtocolConn.AutoBind)"
                if ($ClientCertificate) {
                    Write-Log "[Connect-LDAP] Client certificates count: $($LdapProtocolConn.ClientCertificates.Count)"
                }
                $SearchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest(
                    $DomainDN,
                    "(objectClass=domainDNS)",
                    [System.DirectoryServices.Protocols.SearchScope]::Base,
                    @("distinguishedName", "name")
                )

                $SearchResponse = $LdapProtocolConn.SendRequest($SearchRequest)

                if ($SearchResponse -and $SearchResponse.Entries.Count -gt 0) {
                    $TestDN = $SearchResponse.Entries[0].DistinguishedName
                    Write-Log "[Connect-LDAP] $ProtocolDisplay search successful! DN: $TestDN"
                    $ConnectionEstablished = $true

                    # Store the LdapConnection for ALL operations (queries AND modifications)
                    $Script:LdapConnection = $LdapProtocolConn
                    Write-Log "[Connect-LDAP] LdapConnection stored for all LDAP operations"

                } else {
                    throw "$ProtocolDisplay search returned no results"
                }

            } catch {
                # Enhanced error logging for Schannel debugging
                if ($ClientCertificate) {
                    Write-Log "[Connect-LDAP] Schannel connection error details:"
                    Write-Log "[Connect-LDAP]   Exception Type: $($_.Exception.GetType().FullName)"
                    Write-Log "[Connect-LDAP]   Message: $($_.Exception.Message)"
                    if ($_.Exception.InnerException) {
                        Write-Log "[Connect-LDAP]   Inner Exception: $($_.Exception.InnerException.Message)"
                        Write-Log "[Connect-LDAP]   Inner Type: $($_.Exception.InnerException.GetType().FullName)"
                    }
                    # DirectoryOperationException has ResultCode and ErrorMessage
                    if ($_.Exception -is [System.DirectoryServices.Protocols.DirectoryOperationException]) {
                        $dirEx = $_.Exception
                        Write-Log "[Connect-LDAP]   ResultCode: $($dirEx.Response.ResultCode)"
                        Write-Log "[Connect-LDAP]   ErrorMessage: $($dirEx.Response.ErrorMessage)"
                    }
                }

                Resolve-LDAPConnectionError -ErrorRecord $_ -Context "LDAP connection" -BindSucceeded:$LdapBindSucceeded

                # Dispose the connection on failure to avoid resource leak
                if ($LdapProtocolConn) {
                    try { $LdapProtocolConn.Dispose() } catch { }
                }
            }

            # Stop if connection failed
            if (-not $ConnectionEstablished) {
                return $null
            }

            # ===== Phase 6: RootDSE Retrieval =====
            # UNIFIED: Always use LdapConnection (works for both LDAP and LDAPS)
            Write-Log "[Connect-LDAP] Retrieving RootDSE via LdapConnection..."
            $RootDSEData = @{}

            try {
                # Request RootDSE attributes
                # IMPORTANT: For System.DirectoryServices.Protocols, we need to add attributes via the Attributes property, not the constructor.
                # The constructor's string[] parameter doesn't work reliably for all LDAP servers.
                $RootDSERequest = New-Object System.DirectoryServices.Protocols.SearchRequest
                $RootDSERequest.DistinguishedName = ""  # Empty DN = RootDSE
                $RootDSERequest.Filter = "(objectClass=*)"
                $RootDSERequest.Scope = [System.DirectoryServices.Protocols.SearchScope]::Base

                # Add attributes to request (this is the correct way for S.DS.P)
                $attributesToExtract = @(
                    "defaultNamingContext",
                    "configurationNamingContext",
                    "schemaNamingContext",
                    "rootDomainNamingContext",
                    "dnsHostName",
                    "domainFunctionality",
                    "forestFunctionality"
                )
                foreach ($attr in $attributesToExtract) {
                    [void]$RootDSERequest.Attributes.Add($attr)
                }

                Write-Log "[Connect-LDAP] Sending RootDSE request for attributes: $($attributesToExtract -join ', ')"

                $RootDSEResponse = $Script:LdapConnection.SendRequest($RootDSERequest)

                if ($RootDSEResponse -and $RootDSEResponse.Entries.Count -gt 0) {
                    $RootDSEEntry = $RootDSEResponse.Entries[0]

                    # Debug: Log what we got back
                    Write-Log "[Connect-LDAP] RootDSE entry returned, Attributes.Count = $($RootDSEEntry.Attributes.Count)"

                    # Extract attributes from the response
                    # Use direct access by attribute name (case-insensitive in LDAP)
                    foreach ($attrName in $attributesToExtract) {
                        if ($RootDSEEntry.Attributes.Contains($attrName)) {
                            $dirAttr = $RootDSEEntry.Attributes[$attrName]
                            if ($dirAttr -and $dirAttr.Count -gt 0) {
                                # GetValues returns the actual values as the specified type
                                $value = $dirAttr.GetValues([string])[0]
                                $RootDSEData[$attrName] = $value
                                Write-Log "[Connect-LDAP] RootDSE attribute $attrName = $value"
                            }
                        } else {
                            Write-Log "[Connect-LDAP] RootDSE attribute $attrName not found in server response"
                        }
                    }

                    Write-Log "[Connect-LDAP] RootDSE retrieved successfully with $($RootDSEData.Count) attributes"
                } else {
                    throw "RootDSE query returned no results"
                }

            } catch {
                Resolve-LDAPConnectionError -ErrorRecord $_ -Context "RootDSE retrieval"
                return $null
            }

            # Get actual DC name from RootDSE
            $ActualDCName = if ($RootDSEData["dnsHostName"]) {
                $RootDSEData["dnsHostName"]
            } else {
                $Server
            }

            # ===== Phase 7: Build Domain Info =====
            $DomainInfo = @{
                Domain = $Domain
                Server = $ActualDCName
                DomainDN = $DomainDN
                Protocol = if ($UseLDAPS) { "LDAPS" } else { "LDAP" }
                Port = if ($UseLDAPS) { 636 } else { 389 }

                # RootDSE Properties (from RootDSEData hashtable)
                DefaultNamingContext = $RootDSEData["defaultNamingContext"]
                ConfigurationNamingContext = $RootDSEData["configurationNamingContext"]
                ConfigurationDN = $RootDSEData["configurationNamingContext"]
                SchemaNamingContext = $RootDSEData["schemaNamingContext"]
                RootDomainNamingContext = $RootDSEData["rootDomainNamingContext"]
                DnsHostName = $RootDSEData["dnsHostName"]
                DomainFunctionality = $RootDSEData["domainFunctionality"]
                ForestFunctionality = $RootDSEData["forestFunctionality"]

                # Connection Details
                LdapConnection = $Script:LdapConnection  # Primary connection for all operations
                Credential = $Credential
                Timestamp = Get-Date
                Connected = $true
                UseLDAPS = $UseLDAPS

                # Track explicit parameters
                ExplicitServer = $PSBoundParameters.ContainsKey('Server')
                ExplicitDomain = $PSBoundParameters.ContainsKey('Domain')
                ExplicitCredential = $PSBoundParameters.ContainsKey('Credential')

                # Schannel (Pass-the-Cert)
                ClientCertificate = $ClientCertificate  # X509Certificate2 object for session reuse
            }

            # ===== Phase 7b: Get Domain SID =====
            # UNIFIED: Always use LdapConnection (works for both LDAP and LDAPS)
            Write-Log "[Connect-LDAP] Retrieving Domain SID via LdapConnection..."
            $DomainSID = $null
            try {
                $SIDRequest = New-Object System.DirectoryServices.Protocols.SearchRequest(
                    $DomainDN,
                    "(objectClass=domainDNS)",
                    [System.DirectoryServices.Protocols.SearchScope]::Base,
                    @("objectSid")
                )
                $SIDResponse = $Script:LdapConnection.SendRequest($SIDRequest)

                if ($SIDResponse -and $SIDResponse.Entries.Count -gt 0 -and $SIDResponse.Entries[0].Attributes["objectsid"]) {
                    $SIDBytes = $SIDResponse.Entries[0].Attributes["objectsid"][0]
                    $DomainSID = (New-Object System.Security.Principal.SecurityIdentifier($SIDBytes, 0)).Value
                    Write-Log "[Connect-LDAP] Domain SID: $DomainSID"
                }
            } catch {
                Write-Log "[Connect-LDAP] Could not retrieve Domain SID: $_"
            }

            $DomainInfo['DomainSID'] = $DomainSID

            # ===== Phase 7c: Store Anonymous Access Results =====
            # Note: Display of anonymous access findings is handled by Get-DomainInformation
            $DomainInfo['AnonymousAccessEnabled'] = $Script:AnonymousAccessEnabled
            $DomainInfo['AnonymousAccessDetails'] = $Script:AnonymousAccessDetails

            # ===== Phase 8: User Context Verification via LDAP =====
            Write-Log "[Connect-LDAP] Verifying authenticated user context via LDAP..."

            $AuthenticatedUser = $null
            $AuthenticatedUserDN = $null
            $AuthenticatedUserSAM = $null

            try {
                if ($Credential) {
                    # Explicit credentials - use the provided username
                    $AuthenticatedUser = $Credential.UserName
                    Write-Log "[Connect-LDAP] Using explicit credential: $AuthenticatedUser"

                    # Extract sAMAccountName from credential for LDAP lookup
                    $CredentialSAM = $Credential.UserName
                    if ($CredentialSAM -match '\\') {
                        $CredentialSAM = $CredentialSAM.Split('\')[1]
                    } elseif ($CredentialSAM -match '@') {
                        $CredentialSAM = $CredentialSAM.Split('@')[0]
                    }

                    # Query LDAP to get full user DN and verify the user exists
                    # UNIFIED: Always use LdapConnection (works for both LDAP and LDAPS)
                    try {
                        $UserRequest = New-Object System.DirectoryServices.Protocols.SearchRequest(
                            $DomainDN,
                            "(sAMAccountName=$CredentialSAM)",
                            [System.DirectoryServices.Protocols.SearchScope]::Subtree,
                            @("distinguishedName", "sAMAccountName", "userPrincipalName")
                        )
                        $UserResponse = $Script:LdapConnection.SendRequest($UserRequest)

                        if ($UserResponse -and $UserResponse.Entries.Count -gt 0) {
                            $UserEntry = $UserResponse.Entries[0]
                            $AuthenticatedUserDN = $UserEntry.DistinguishedName
                            if ($UserEntry.Attributes["samaccountname"]) {
                                $AuthenticatedUserSAM = $UserEntry.Attributes["samaccountname"][0]
                            }
                            Write-Log "[Connect-LDAP] Verified user: $AuthenticatedUserDN"
                        }
                    } catch {
                        Write-Log "[Connect-LDAP] Could not verify user via LDAP: $_"
                    }
                } else {
                    # Windows Authentication (SSPI) - use LDAP "Who Am I?" Extended Operation
                    # This is the authoritative way to determine the authenticated identity
                    # UNIFIED: Always use existing LdapConnection (works for both LDAP and LDAPS)
                    Write-Log "[Connect-LDAP] Using LDAP Who Am I? Extended Operation..."

                    try {
                        # Send Who Am I? Extended Operation (OID 1.3.6.1.4.1.4203.1.11.3)
                        $WhoAmIRequest = New-Object System.DirectoryServices.Protocols.ExtendedRequest("1.3.6.1.4.1.4203.1.11.3")
                        $WhoAmIResponse = $Script:LdapConnection.SendRequest($WhoAmIRequest)

                        if ($WhoAmIResponse -and $WhoAmIResponse.ResponseValue) {
                            # Response format: "u:DOMAIN\username" or "dn:CN=User,OU=Users,DC=domain,DC=com"
                            $WhoAmIResult = [System.Text.Encoding]::UTF8.GetString($WhoAmIResponse.ResponseValue)
                            Write-Log "[Connect-LDAP] LDAP Who Am I? response: $WhoAmIResult"

                            if ($WhoAmIResult -match '^u:(.+)$') {
                                # Format: u:DOMAIN\username
                                $AuthenticatedUser = $Matches[1]
                            } elseif ($WhoAmIResult -match '^dn:(.+)$') {
                                # Format: dn:CN=User,OU=Users,DC=domain,DC=com
                                $AuthenticatedUserDN = $Matches[1]
                                # Extract CN from DN for display
                                if ($AuthenticatedUserDN -match '^CN=([^,]+)') {
                                    $AuthenticatedUser = $Matches[1]
                                } else {
                                    $AuthenticatedUser = $AuthenticatedUserDN
                                }
                            } else {
                                $AuthenticatedUser = $WhoAmIResult
                            }

                            Write-Log "[Connect-LDAP] Authenticated user from LDAP: $AuthenticatedUser"
                        }

                    } catch {
                        Write-Log "[Connect-LDAP] LDAP Who Am I? failed: $_ - falling back to LSA ticket cache"

                        # Fallback: Query Kerberos ticket cache via native LSA API
                        $DomainNetBIOS = $Domain.Split('.')[0].ToUpper()
                        try {
                            $TGTStatus = Test-KerberosTGTExists -Detailed -Force
                            if ($TGTStatus.Valid -and $TGTStatus.ClientName) {
                                $AuthenticatedUser = "$DomainNetBIOS\$($TGTStatus.ClientName)"
                                Write-Log "[Connect-LDAP] Found user via LSA ticket cache: $AuthenticatedUser"
                            } else {
                                $AuthenticatedUser = "$DomainNetBIOS\[Kerberos Authenticated]"
                                Write-Log "[Connect-LDAP] Kerberos authenticated but no valid TGT in cache"
                            }
                        } catch {
                            Write-Log "[Connect-LDAP] LSA ticket cache query failed: $_"
                            $AuthenticatedUser = "$DomainNetBIOS\[Kerberos Authenticated]"
                        }
                    }
                }

                # If we still don't have a user, mark as unknown
                if ([string]::IsNullOrEmpty($AuthenticatedUser)) {
                    $AuthenticatedUser = "[LDAP Identity Unknown]"
                }

                Write-Log "[Connect-LDAP] Final Authenticated User: $AuthenticatedUser"
                $DomainInfo['AuthenticatedUser'] = $AuthenticatedUser
                $DomainInfo['AuthenticatedUserDN'] = $AuthenticatedUserDN
                $DomainInfo['AuthenticatedUserSAM'] = $AuthenticatedUserSAM

                # Detect if Kerberos was used for authentication
                if ($AuthenticatedUser -notmatch '^\[' -and -not $Credential) {
                    $DomainInfo['DetectedKerberos'] = $true
                    Write-Log "[Connect-LDAP] Kerberos authentication detected (Who Am I? returned domain user)"
                } else {
                    $DomainInfo['DetectedKerberos'] = $false
                }

            } catch {
                Write-Log "[Connect-LDAP] User verification failed (non-critical): $_"
                $DomainInfo['AuthenticatedUser'] = "[Error determining identity]"
            }

            # ===== Phase 9: Store Connection Globally =====
            # Note: $Script:LdapConnection is already set in Phase 5

            # Preserve existing LDAPContext values (like DnsServer, DnsCache) that were set by Connect-adPEAS before calling Connect-LDAP
            if ($Script:LDAPContext) {
                # Merge: DomainInfo overwrites existing keys, but preserve keys not in DomainInfo
                foreach ($key in $DomainInfo.Keys) {
                    $Script:LDAPContext[$key] = $DomainInfo[$key]
                }
            }
            else {
                $Script:LDAPContext = $DomainInfo
            }

            $Script:LDAPCredential = $Credential
            $Script:ConnectionState = "Success"

            # Set AuthMethod if not already set by Connect-adPEAS
            # This handles direct calls to Connect-LDAP (via Ensure-LDAPConnection)
            if (-not $Script:LDAPContext['AuthMethod']) {
                if ($ClientCertificate) {
                    $Script:LDAPContext['AuthMethod'] = 'Schannel'
                }
                elseif ($Credential) {
                    $Script:LDAPContext['AuthMethod'] = 'SimpleBind'
                } else {
                    $Script:LDAPContext['AuthMethod'] = 'WindowsAuth'
                }
                Write-Log "[Connect-LDAP] Set AuthMethod: $($Script:LDAPContext['AuthMethod'])"
            }

            Write-Log "[Connect-LDAP] Connection established successfully"
            Write-Log "[Connect-LDAP] Domain: $Domain, Server: $ActualDCName, Protocol: $ProtocolDisplay"

            return $DomainInfo

        } catch {
            # Final catch for any unhandled errors - only show if not already handled
            if (-not $Script:ConnectionState) {
                Resolve-LDAPConnectionError -ErrorRecord $_ -Context "Unhandled error"
            }
            return $null
        }
    }

    end {
        if ($Script:LdapConnection) {
            Write-Log "[Connect-LDAP] LDAP connection setup completed"
        }
    }
}
