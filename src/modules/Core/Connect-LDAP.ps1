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

        # [switch], not [bool]: see the identical fix and rationale in Connect-adPEAS - a
        # [bool] parameter still requires an explicit argument for the bare flag even with
        # a $true default. -IgnoreSSLErrors:$false keeps working; the bare flag now also
        # does.
        [Parameter(Mandatory=$false)]
        [switch]$IgnoreSSLErrors = $true,

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
        # Used by Connect-adPEAS when it knows it will auto-retry (e.g., LDAPS upgrade after SimpleBind failure),
        # and by Get-GCConnection, whose connection is auxiliary and whose failure is tolerated.
        #
        # It is honoured at every Show-ConnectionError in this function. It used to be checked
        # at one of five, so a caller that asked for silence still got "Connection failed" from
        # the DNS, port and SSL phases - the port one being the single most likely to fire.
        [Parameter(Mandatory=$false)]
        [switch]$SuppressErrorDisplay
    )

    begin {
        Write-Log "[Connect-LDAP] Starting LDAP connection..."

        # Reset connection state at the beginning.
        #
        # Not in GC mode. This function's own contract says a Global Catalog connection
        # "returns the raw LdapConnection without modifying global state", and both of these
        # belong to the main session. An auxiliary GC probe wiped the main connection's
        # recorded state on entry and then overwrote it with its own outcome - Success or
        # NetworkError - long after Connect-adPEAS had finished.
        #
        # The consequence was the quiet kind: the unhandled-error catch at the end of this
        # function skips reporting when $Script:ConnectionState is already set, so a stale
        # NetworkError left behind by a blocked port 3268 silenced the report of a later,
        # genuine connection failure.
        if (-not $AsGlobalCatalog) {
            $Script:ConnectionState = $null
            $Script:LastLDAPErrorCode = $null
        }

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
            # PowerShell wraps .NET exceptions: MethodInvocationException -> LdapException or DirectoryOperationException
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

            # Override: LDAP 81 (SERVER_DOWN) after a successful Bind() is NOT a network error -
            # the server IS reachable and authentication succeeded. The failure is in the LDAP
            # protocol layer (post-bind request processing). Use GenericError to avoid the
            # misleading "Server unreachable" title from NetworkError.
            if ($ldapErrorCode -eq 81 -and $BindSucceeded) {
                $errorType = "GenericError"
            }

            if (-not $AsGlobalCatalog) { $Script:ConnectionState = $errorType }
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
                        if (-not $AsGlobalCatalog) { $Script:ConnectionState = "DomainError" }
                        if (-not $SuppressErrorDisplay) {
                            Show-ConnectionError -ErrorType "DomainError" -Details "Domain parameter required or system must be domain-joined" -NoThrow
                        }
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
                if (-not $AsGlobalCatalog) { $Script:ConnectionState = "DomainError" }
                $Detail = if ($Server -eq $Domain) {
                    "Domain '$Domain' could not be resolved"
                } else {
                    "Server '$Server' could not be resolved"
                }
                if (-not $SuppressErrorDisplay) {
                    Show-ConnectionError -ErrorType "DomainError" -Details $Detail -NoThrow
                }
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
                if (-not $AsGlobalCatalog) { $Script:ConnectionState = "NetworkError" }
                $PortDesc = "$TestPort ($(if ($AsGlobalCatalog) { 'GC' } else { if ($UseLDAPS) { 'LDAPS' } else { 'LDAP' } }))"
                if (-not $SuppressErrorDisplay) {
                    Show-ConnectionError -ErrorType "NetworkError" -Details "Port $PortDesc unreachable on $Server" -NoThrow
                }
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
                    if (-not $AsGlobalCatalog) { $Script:ConnectionState = $errorType }

                    # The negotiation failed; ask each version on its own to find out whether it
                    # was the version or the cipher suites. "An existing connection was forcibly
                    # closed by the remote host" is the same sentence for both, and the two call
                    # for different work.
                    #
                    # Only for a handshake failure, and only when the error is going to be shown.
                    # A certificate the client does not trust is a different answer with its own
                    # error type, and probing would add three connections to say nothing new.
                    # Suppressed output means an auxiliary connection whose caller degrades
                    # quietly - the GC - and there nobody reads the diagnosis either.
                    $probeSummary = $null
                    if ($errorType -eq 'SSLHandshakeError' -and -not $SuppressErrorDisplay) {
                        $probe = Test-LDAPSProtocolSupport -Server $Server -ConnectTarget $ConnectTarget -Port $SSLPort
                        if ($probe) { $probeSummary = $probe.Summary }
                    }

                    if (-not $SuppressErrorDisplay) {
                        Show-ConnectionError -ErrorType $errorType -Details $sslErrorInfo.Message -NoThrow

                        # After the hint block rather than folded into Details: the probe result
                        # is a hint, and joining it onto the exception message would make one
                        # unreadable line out of two statements.
                        if ($probeSummary) { Show-Line $probeSummary -Class Hint }
                    }
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

            # Whether the question was asked at all, which is a third state the boolean
            # above cannot hold. It is set to $false before the two skips below, and
            # Get-DomainInformation then printed no row at all - so a reader of a report
            # from an -UseLDAPS scan saw the same thing they see for a domain that
            # refuses anonymous binds, which is nothing. That is the scan mode a
            # security-conscious customer picks.
            $Script:AnonymousAccessTested = $false
            # Why the question was not answered, in a word or two: Get-DomainInformation
            # prints it in brackets after "Not tested", and the log has the rest.
            $Script:AnonymousAccessSkipReason = $null

            if ($AsGlobalCatalog) {
                Write-Log "[Connect-LDAP] Skipping anonymous access check for GC mode"
                $Script:AnonymousAccessSkipReason = 'global catalog'
            }
            elseif ($UseLDAPS) {
                Write-Log "[Connect-LDAP] Skipping anonymous access check for LDAPS (rarely enabled over SSL)"
                $Script:AnonymousAccessSkipReason = 'LDAPS'
            }
            else {
                # From here the answer is measured rather than assumed - Test-AnonymousLDAPBind
                # hands it back as untested when no server answered.
                # Use resolved IP when custom DNS is active
                $AnonTarget = if ($CustomDnsServer -and $ResolvedIPString) { $ResolvedIPString } else { $Server }
                $anonResult = Test-AnonymousLDAPBind -Target $AnonTarget -DomainDN $DomainDN
                $Script:AnonymousAccessTested = $anonResult.Tested
                $Script:AnonymousAccessEnabled = $anonResult.Enabled
                $Script:AnonymousAccessDetails = $anonResult.Details
                $Script:AnonymousAccessSkipReason = $anonResult.SkipReason
            }

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
                    # 1. If NetworkCredential.Domain is set -> user specified DOMAIN\username -> reconstruct it
                    # 2. If username contains '@' -> user specified UPN -> keep it as-is
                    # 3. Otherwise -> bare username -> auto-qualify with UPN format

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

            # ===== Phase 7b2: Resolve the TRUE NetBIOS domain name =====
            # The NetBIOS name is NOT the first DNS label. A domain "example.com"
            # can have the NetBIOS name "CORP". The only authoritative source is the crossRef
            # object in the Partitions container (nETBIOSName keyed by nCName=<DomainDN>).
            # Deriving it from Domain.Split('.')[0] is wrong for any domain that was renamed or
            # provisioned with a NetBIOS name that differs from its DNS label. Resolve it once
            # here so every consumer (Resolve-CrossDomainIdentity, Get-DomainInformation, etc.)
            # can read LDAPContext.DomainNetBIOS instead of guessing.
            $DomainNetBIOS = $null
            try {
                $ConfigNC = $RootDSEData["configurationNamingContext"]
                if ($ConfigNC) {
                    $PartitionsDN = "CN=Partitions,$ConfigNC"
                    $CrossRefRequest = New-Object System.DirectoryServices.Protocols.SearchRequest(
                        $PartitionsDN,
                        "(&(objectClass=crossRef)(nCName=$DomainDN))",
                        [System.DirectoryServices.Protocols.SearchScope]::OneLevel,
                        @("nETBIOSName")
                    )
                    $CrossRefResponse = $Script:LdapConnection.SendRequest($CrossRefRequest)
                    if ($CrossRefResponse -and $CrossRefResponse.Entries.Count -gt 0 -and $CrossRefResponse.Entries[0].Attributes["netbiosname"]) {
                        $DomainNetBIOS = [string]$CrossRefResponse.Entries[0].Attributes["netbiosname"][0]
                        Write-Log "[Connect-LDAP] Domain NetBIOS name (from crossRef): $DomainNetBIOS"
                    }
                }
            } catch {
                Write-Log "[Connect-LDAP] Could not resolve NetBIOS name from crossRef: $_"
            }
            if (-not $DomainNetBIOS) {
                # Fallback only: first DNS label, upper-cased. Logged so the guess is traceable.
                $DomainNetBIOS = ($Domain -split '\.')[0].ToUpper()
                Write-Log "[Connect-LDAP] NetBIOS name not resolved via crossRef - falling back to DNS label guess: $DomainNetBIOS" -Level Warning
            }
            $DomainInfo['DomainNetBIOS'] = $DomainNetBIOS

            # ===== Phase 7c: Store Anonymous Access Results =====
            # Note: Display of anonymous access findings is handled by Get-DomainInformation
            $DomainInfo['AnonymousAccessEnabled'] = $Script:AnonymousAccessEnabled
            $DomainInfo['AnonymousAccessTested'] = $Script:AnonymousAccessTested
            $DomainInfo['AnonymousAccessDetails'] = $Script:AnonymousAccessDetails
            $DomainInfo['AnonymousAccessSkipReason'] = $Script:AnonymousAccessSkipReason

            # ===== Phase 8: User Context Verification via LDAP =====
            Write-Log "[Connect-LDAP] Verifying authenticated user context via LDAP..."

            $AuthenticatedUser = $null
            $AuthenticatedUserDN = $null
            $AuthenticatedUserSAM = $null
            $AuthenticatedUserSID = $null
            $AuthenticatedUserUPN = $null

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
                        # objectSid and userPrincipalName as well: Get-adPEASSession prints
                        # both, reading AuthenticatedUserSID and AuthenticatedUserUPN off the
                        # context.
                        $BoundAccount = Read-LDAPBoundAccount -Connection $Script:LdapConnection -DomainDN $DomainDN -SAMAccountName $CredentialSAM
                        if ($BoundAccount) {
                            $AuthenticatedUserDN = $BoundAccount.DistinguishedName
                            $AuthenticatedUserSAM = $BoundAccount.SAMAccountName
                            $AuthenticatedUserUPN = $BoundAccount.UPN
                            $AuthenticatedUserSID = $BoundAccount.SID
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

                        # Fallback: Query Kerberos ticket cache via native LSA API.
                        # Reuse the NetBIOS name resolved via crossRef in Phase 7b2; only guess from
                        # the DNS label if that lookup failed (it is guaranteed set, but guard anyway).
                        if (-not $DomainNetBIOS) { $DomainNetBIOS = $Domain.Split('.')[0].ToUpper() }
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

                    # The account behind the name. "Who Am I?" answers "u:DOMAIN\name" on
                    # Active Directory, and nothing below it ever looked that up - so a
                    # session opened with Windows authentication, and every Kerberos login
                    # that binds the same way, knew its account by name only. DN, SID,
                    # sAMAccountName and UPN stayed empty: Get-LAPSCredentialAccess could not
                    # tell whether the scanning account is privileged and called an
                    # administrator's expected LAPS read a finding, and the session summary
                    # showed no SID. Only names of this domain are looked up here - a name
                    # of another domain would match a different account of the same name.
                    try {
                        $BoundAccount = $null
                        if ($AuthenticatedUserDN) {
                            $BoundAccount = Read-LDAPBoundAccount -Connection $Script:LdapConnection -DistinguishedName $AuthenticatedUserDN
                        } else {
                            $BoundAccountName = Get-BoundAccountName -AuthenticatedUser $AuthenticatedUser -DomainNetBIOS $DomainNetBIOS
                            if ($BoundAccountName) {
                                $BoundAccount = Read-LDAPBoundAccount -Connection $Script:LdapConnection -DomainDN $DomainDN -SAMAccountName $BoundAccountName
                            } else {
                                Write-Log "[Connect-LDAP] '$AuthenticatedUser' is not an account name of $DomainNetBIOS - not looked up"
                            }
                        }
                        if ($BoundAccount) {
                            $AuthenticatedUserDN = $BoundAccount.DistinguishedName
                            $AuthenticatedUserSAM = $BoundAccount.SAMAccountName
                            $AuthenticatedUserUPN = $BoundAccount.UPN
                            $AuthenticatedUserSID = $BoundAccount.SID
                            Write-Log "[Connect-LDAP] Bound account: $AuthenticatedUserDN ($AuthenticatedUserSID)"
                        }
                    } catch {
                        Write-Log "[Connect-LDAP] Could not read the bound account $AuthenticatedUser : $_"
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
                $DomainInfo['AuthenticatedUserSID'] = $AuthenticatedUserSID
                $DomainInfo['AuthenticatedUserUPN'] = $AuthenticatedUserUPN

                # Who the operating system thinks we are, against who the directory
                # answered - see Test-SessionIdentityMismatch for when the difference means
                # something. Get-adPEASSession shows the two where it does.
                $LocalIdentity = $null
                if ($env:USERDOMAIN -and $env:USERNAME) {
                    $LocalIdentity = "$($env:USERDOMAIN)\$($env:USERNAME)"
                }
                $DomainInfo['LocalIdentity'] = $LocalIdentity
                $DomainInfo['IdentityMismatch'] = Test-SessionIdentityMismatch -AuthenticatedUser $AuthenticatedUser `
                    -LocalIdentity $LocalIdentity -Credential $Credential

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
            if (-not $AsGlobalCatalog) { $Script:ConnectionState = "Success" }

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


<#
.SYNOPSIS
    Tries an anonymous bind against a domain controller and a read of the domain object.
.DESCRIPTION
    The A-NullSession test of Connect-LDAP, on a temporary connection of its own. Failures
    are expected and silent; Get-AnonymousBindOutcome decides whether one was the server
    refusing or no answer at all.
.PARAMETER Target
    The domain controller to bind to, by name or address.
.PARAMETER DomainDN
    The domain naming context, read with a base search.
.PARAMETER Port
    The LDAP port. Connect-LDAP skips the test for LDAPS and the global catalog, so 389.
.OUTPUTS
    PSCustomObject with Tested, Enabled, Details and SkipReason - the four values Connect-LDAP
    keeps as $Script:AnonymousAccess*.
#>
function Test-AnonymousLDAPBind {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target,

        [Parameter(Mandatory = $true)]
        [string]$DomainDN,

        [int]$Port = 389
    )

    $result = [PSCustomObject]@{
        Tested     = $true
        Enabled    = $false
        Details    = $null
        SkipReason = $null
    }

    $AnonLdapConn = $null
    try {
        # The test is the first code of a session to touch these types, and Windows
        # PowerShell 5.1 does not load the assembly on its own. It used to be loaded only in
        # Phase 5 of Connect-LDAP, so in a fresh session New-Object threw here, the catch
        # read that as a refused bind, and Get-DomainInformation printed the green
        # "Refused - an anonymous bind was tried" for a test that never ran.
        Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction Stop

        $AnonIdentifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($Target, $Port)
        $AnonLdapConn = New-Object System.DirectoryServices.Protocols.LdapConnection($AnonIdentifier)
        $AnonLdapConn.SessionOptions.ProtocolVersion = 3
        # Short timeouts for anonymous test - Bind() uses SendTimeout, SendRequest uses Timeout
        $AnonLdapConn.Timeout = [TimeSpan]::FromSeconds(2)
        $AnonLdapConn.SessionOptions.SendTimeout = [TimeSpan]::FromSeconds(2)

        # Set Anonymous authentication
        $AnonLdapConn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Anonymous

        # Attempt anonymous bind
        $AnonLdapConn.Bind()
        Write-Log "[Test-AnonymousLDAPBind] Anonymous bind successful - testing read access..."

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
                $result.Enabled = $true

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
                    Write-Log "[Test-AnonymousLDAPBind] Anonymous user enumeration test failed (expected)"
                }

                $result.Details = @{
                    CanReadDomainRoot = $true
                    ReadableAttributes = $ReadableAttrs
                    CanEnumerateUsers = $CanEnumUsers
                    UsersSampled = $UserCount
                }

                Write-Log "[Test-AnonymousLDAPBind] WARNING: Anonymous LDAP access is enabled!"
                Write-Log "[Test-AnonymousLDAPBind] Readable attributes: $($ReadableAttrs -join ', ')"
                if ($CanEnumUsers) {
                    Write-Log "[Test-AnonymousLDAPBind] WARNING: Anonymous user enumeration is possible!"
                }
            }
        }

    } catch {
        # Every failure used to land here as "denied", including the ones where no server
        # ever answered - Get-AnonymousBindOutcome tells the two apart.
        $result.Enabled = $false
        $anonOutcome = Get-AnonymousBindOutcome -Exception $_.Exception
        if ($anonOutcome.Refused) {
            Write-Log "[Test-AnonymousLDAPBind] Anonymous access test: denied (secure - this is expected)"
        } else {
            Write-Log "[Test-AnonymousLDAPBind] Anonymous access test did not run - $($anonOutcome.Detail)"
            $result.Tested = $false
            $result.SkipReason = $anonOutcome.Reason
        }
    } finally {
        # Always dispose the temporary anonymous connection
        if ($AnonLdapConn) {
            try { $AnonLdapConn.Dispose() } catch { }
        }
    }

    return $result
}

<#
.SYNOPSIS
    Reads the exception the anonymous bind test caught as a refusal, or as a test that got no answer.
.DESCRIPTION
    A refusal is the server's answer: an LDAP result code on the bind or on the search.
    Measured against Windows Server 2025, the anonymous bind succeeds and the read of the
    domain object fails with a DirectoryOperationException (OperationsError). An LdapException
    whose code is a server result code (below 81, e.g. 49) is a refused bind.

    Codes 81 to 97 are the Windows LDAP client's own (winldap.h, LDAP_SERVER_DOWN to
    LDAP_REFERRAL_LIMIT_EXCEEDED): a server out of reach fails the bind with 81, a timeout
    with 85, a connect error with 91. No server answered, so nothing was refused. Neither was
    it when the exception is not an LDAP one at all - the types failing to load throws before
    anything is sent. Reading those as "refused" printed a green verdict for a test that never
    ran.

    PowerShell wraps the .NET exception of a method call in a MethodInvocationException, so
    the InnerException chain is walked.
.PARAMETER Exception
    The exception the anonymous bind test caught.
.OUTPUTS
    PSCustomObject with Refused (bool), Reason (the words Get-DomainInformation prints in
    brackets after "Not tested") and Detail (the error, for the log); both $null when Refused.
#>
function Get-AnonymousBindOutcome {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Exception]$Exception
    )

    $current = $Exception
    while ($null -ne $current) {
        $typeName = $current.GetType().FullName
        if ($typeName -eq 'System.DirectoryServices.Protocols.DirectoryOperationException') {
            return [PSCustomObject]@{ Refused = $true; Reason = $null; Detail = $null }
        }
        if ($typeName -eq 'System.DirectoryServices.Protocols.LdapException') {
            $code = [int]$current.ErrorCode
            if ($code -ge 81 -and $code -le 97) {
                return [PSCustomObject]@{
                    Refused = $false
                    Reason  = 'no answer from the server'
                    Detail  = "the anonymous bind got no answer from the server (LDAP client error $code`: $($current.Message))"
                }
            }
            return [PSCustomObject]@{ Refused = $true; Reason = $null; Detail = $null }
        }
        $current = $current.InnerException
    }

    [PSCustomObject]@{
        Refused = $false
        Reason  = 'test failed'
        Detail  = "the anonymous bind test failed before the server answered: $($Exception.Message)"
    }
}

<#
.SYNOPSIS
    Reads the account an LDAP session is bound as out of the directory.
.DESCRIPTION
    Connect-LDAP knows the bound account by a name: the user name of the credential, or what
    the LDAP "Who Am I?" operation (RFC 4532) answers - on Active Directory "u:DOMAIN\name",
    or a DN after a certificate bind. This reads the account's distinguished name,
    sAMAccountName, SID and userPrincipalName, which the session context carries for the
    checks that judge the scanning account itself.

    The values are read with GetValues: the indexer of a search result attribute hands back
    a string whenever the bytes happen to decode as UTF-8, which a binary objectSid can.
.PARAMETER Connection
    The bound System.DirectoryServices.Protocols.LdapConnection.
.PARAMETER DomainDN
    The DN of the connected domain, the search base of a lookup by name.
.PARAMETER SAMAccountName
    The account's sAMAccountName. Escaped here for the filter.
.PARAMETER DistinguishedName
    The account's DN, read with a Base search.
.OUTPUTS
    PSCustomObject with DistinguishedName, SAMAccountName, SID and UPN, or $null when no
    account was found.
#>
function Read-LDAPBoundAccount {
    [CmdletBinding(DefaultParameterSetName = 'ByName')]
    param(
        [Parameter(Mandatory = $true)]
        $Connection,

        [Parameter(Mandatory = $true, ParameterSetName = 'ByName')]
        [string]$DomainDN,

        [Parameter(Mandatory = $true, ParameterSetName = 'ByName')]
        [string]$SAMAccountName,

        [Parameter(Mandatory = $true, ParameterSetName = 'ByDN')]
        [string]$DistinguishedName
    )

    $attributes = [string[]]@('distinguishedName', 'sAMAccountName', 'userPrincipalName', 'objectSid')
    if ($PSCmdlet.ParameterSetName -eq 'ByDN') {
        $request = New-Object System.DirectoryServices.Protocols.SearchRequest(
            $DistinguishedName, '(objectClass=*)', [System.DirectoryServices.Protocols.SearchScope]::Base, $attributes)
    } else {
        $escapedName = Escape-LDAPFilterValue -Value $SAMAccountName
        $request = New-Object System.DirectoryServices.Protocols.SearchRequest(
            $DomainDN, "(sAMAccountName=$escapedName)", [System.DirectoryServices.Protocols.SearchScope]::Subtree, $attributes)
    }

    $response = $Connection.SendRequest($request)
    if (-not $response -or @($response.Entries).Count -eq 0) { return $null }

    $entry = @($response.Entries)[0]
    $account = [PSCustomObject]@{
        DistinguishedName = [string]$entry.DistinguishedName
        SAMAccountName    = $null
        SID               = $null
        UPN               = $null
    }

    $samAttribute = $entry.Attributes.get_Item('samaccountname')
    if ($samAttribute) { $account.SAMAccountName = [string]@($samAttribute.GetValues([string]))[0] }
    $upnAttribute = $entry.Attributes.get_Item('userprincipalname')
    if ($upnAttribute) { $account.UPN = [string]@($upnAttribute.GetValues([string]))[0] }
    $sidAttribute = $entry.Attributes.get_Item('objectsid')
    if ($sidAttribute) {
        try {
            $sidBytes = [byte[]]@($sidAttribute.GetValues([byte[]]))[0]
            $account.SID = (New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)).Value
        } catch {
            Write-Log "[Connect-LDAP] Could not decode the objectSid of $($account.DistinguishedName) : $_"
        }
    }

    return $account
}

<#
.SYNOPSIS
    Says which account of the connected domain a "DOMAIN\name" identity names, if any.
.DESCRIPTION
    The sAMAccountName to look the bound account up by. Nothing for a name of another
    domain - looked up here it would match a different account of the same name - and
    nothing for the placeholders Connect-LDAP writes when it knows no name at all, such as
    "CONTOSO\[Kerberos Authenticated]".
.PARAMETER AuthenticatedUser
    The identity as Connect-LDAP holds it, e.g. "CONTOSO\jdoe".
.PARAMETER DomainNetBIOS
    The NetBIOS name of the connected domain.
.OUTPUTS
    String - the sAMAccountName, or $null.
#>
function Get-BoundAccountName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$AuthenticatedUser,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$DomainNetBIOS
    )

    if ($AuthenticatedUser -notmatch '^([^\\]+)\\(.+)$') { return $null }
    $domainPart = $Matches[1]
    $namePart = $Matches[2]

    if ($namePart.StartsWith('[')) { return $null }
    if (-not [string]::Equals($domainPart, $DomainNetBIOS, [System.StringComparison]::OrdinalIgnoreCase)) { return $null }
    return $namePart
}

<#
.SYNOPSIS
    Says whether a session is bound as another account than the Windows logon, where that
    means something.
.DESCRIPTION
    With Windows authentication the bind uses the network credentials of the logon session.
    They belong to another account after a pass-the-ticket outside adPEAS or under
    runas /netonly - which is when an operator wants to be told.

    Wherever the account was chosen for adPEAS, the two differ by design. A credential is one
    way to choose it, and Connect-adPEAS has more: a password, a key, a certificate or a
    ticket file all end in a bind without a credential, as the account named, whose ticket
    Connect-adPEAS imported into this logon session. Asked only "was a credential passed?",
    the comparison flagged every such login - "Identity Mismatch Detected" straight after
    Connect-adPEAS -Username. $Script:AuthInfo carries the parameter set Connect-adPEAS was
    called with; without it, Connect-LDAP was called on its own, as Ensure-LDAPConnection
    does, with the logon session's credentials.

    A placeholder such as "CONTOSO\[Kerberos Authenticated]" names no account and is compared
    with nothing.
.PARAMETER AuthenticatedUser
    The identity the directory answered, e.g. "CONTOSO\jdoe".
.PARAMETER LocalIdentity
    The Windows logon, "USERDOMAIN\USERNAME".
.PARAMETER Credential
    The credential the bind used, if any.
.OUTPUTS
    Boolean
#>
function Test-SessionIdentityMismatch {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$AuthenticatedUser,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$LocalIdentity,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential
    )

    if ($Credential) { return $false }
    if ($Script:AuthInfo -and $Script:AuthInfo.ParameterSet -and [string]$Script:AuthInfo.ParameterSet -ne 'WindowsAuth') { return $false }
    if (-not $LocalIdentity -or -not $AuthenticatedUser) { return $false }
    if ($AuthenticatedUser.Contains('[')) { return $false }
    return ($LocalIdentity -ne $AuthenticatedUser)
}
