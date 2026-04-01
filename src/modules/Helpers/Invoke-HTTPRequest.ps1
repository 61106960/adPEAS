<#
.SYNOPSIS
    Generic HTTP/HTTPS request helper for adPEAS with specialized detection modes.

.DESCRIPTION
    Provides HTTP/HTTPS request functionality for adPEAS with maximum compatibility:
    - Supports all TLS versions (1.0, 1.1, 1.2, 1.3)
    - Ignores SSL certificate errors by default
    - Works with self-signed and expired certificates
    - Specialized modes for version detection (Exchange, ADCS, etc.)

    This is a generic helper that can be extended for various HTTP-based checks.

    IMPORTANT - Thread Safety Note:
    This module uses [System.Net.ServicePointManager] which is a GLOBAL static class.
    Changes to SecurityProtocol and ServerCertificateValidationCallback affect ALL
    HTTP connections in the entire PowerShell process, not just this function.
    The module saves and restores original settings, but parallel calls from multiple
    threads could cause race conditions. For single-threaded use (typical adPEAS usage),
    this is not an issue. For parallel scanning scenarios, consider external synchronization.

.PARAMETER Uri
    The target URI or hostname for the HTTP request.
    If no protocol is specified, https:// is automatically prepended.
    For specialized modes (-ScanExchange, -ScanADCS), the hostname
    is automatically extracted from the URI.

.PARAMETER Method
    HTTP method (GET, HEAD, POST). Default: GET. Only used in standard mode.

.PARAMETER Headers
    Optional hashtable of additional HTTP headers. Only used in standard mode.

.PARAMETER Body
    Optional request body for POST requests. Only used in standard mode.

.PARAMETER ContentType
    Content-Type header for POST requests. Default: application/x-www-form-urlencoded.
    Only used in standard mode.

.PARAMETER TimeoutSeconds
    Request timeout in seconds. Default: 5 (balanced for reliability and speed).
    Valid range: 1-300 seconds.

.PARAMETER UserAgent
    User-Agent header. Default: Mozilla/5.0 (Windows NT 10.0; Win64; x64).

.PARAMETER IgnoreSSLErrors
    Ignore SSL certificate errors. Default: $true.

.PARAMETER ScanExchange
    Special mode: Detect Exchange Server build number from the specified URI/hostname.
    Returns RAW build number only - version interpretation is done by the calling module.
    Detection methods (in order):
    1. /ecp/exporttool endpoint (anonymous XML response)
    2. X-OWA-Version header from /owa/
    3. X-OWA-Version header from /autodiscover/autodiscover.xml (401 response)
    4. X-OWA-Version header via HTTP (non-SSL fallback)

.PARAMETER ScanADCS
    Special mode: Detect ADCS Web Enrollment availability and configuration.
    Tests for /certsrv/ endpoint via HTTP and HTTPS.
    Returns authentication methods from WWW-Authenticate header.

.PARAMETER CAName
    Optional CA common name for ADCS mode. Required for testing CES (Certificate Enrollment Service)
    endpoints. The CES URL pattern is: https://<hostname>/<CAName>_CES_<AuthType>/service.svc
    If not provided, CES endpoint testing will be skipped.
    Only used with -ScanADCS.

.PARAMETER TestEPA
    When used with -ScanExchange or -ScanADCS: Test Extended Protection for Authentication (EPA).
    Performs an NTLM handshake without Channel Binding Token to detect if EPA is enabled.
    EPA protects against NTLM relay attacks over HTTPS.
    Only applicable when HTTPS + NTLM is available.

.EXAMPLE
    Invoke-HTTPRequest -Uri "https://mail.contoso.com/owa/"
    Performs a simple GET request to the specified URL.

.EXAMPLE
    Invoke-HTTPRequest -Uri "mail.contoso.com"
    Performs a GET request (https:// is automatically added).

.EXAMPLE
    Invoke-HTTPRequest -ScanExchange -Uri "mail.contoso.com"
    Returns raw Exchange build number (e.g., "15.2.2562.35").

.EXAMPLE
    Invoke-HTTPRequest -ScanADCS -Uri "ca.contoso.com"
    Tests ADCS Web Enrollment availability via HTTP and HTTPS.

.EXAMPLE
    Invoke-HTTPRequest -ScanADCS -Uri "ca.contoso.com" -TestEPA
    Tests ADCS Web Enrollment and checks if Extended Protection for Authentication is enabled.

.EXAMPLE
    Invoke-HTTPRequest -ScanADCS -Uri "ca.contoso.com" -CAName "Contoso-CA" -TestEPA
    Tests ADCS endpoints including CES (Certificate Enrollment Service) using the CA name.

.EXAMPLE
    Invoke-HTTPRequest -Uri "https://pki.contoso.com/certsrv/" -Method HEAD
    Performs a HEAD request to check ADCS web enrollment.

.OUTPUTS
    [PSCustomObject] with properties depending on mode:
    - Standard mode: Success, StatusCode, Headers, Content, Error
    - ScanExchange: Success, Hostname, BuildNumber, Method, Endpoints, NTLMInfo, Error
    - ScanADCS: Success, Hostname, HttpAvailable, HttpsAvailable, Endpoints, NTLMInfo, Error

    When -TestEPA is used, NTLMInfo contains NTLM Type2 challenge data:
    - NbComputerName: NetBIOS computer name
    - NbDomainName: NetBIOS domain name
    - DnsComputerName: DNS FQDN of the server
    - DnsDomainName: DNS domain name
    - DnsTreeName: DNS forest name
    - ServerTimestamp: Server time (DateTime)
    - NTLMChallenge: NTLM challenge in hex format
    - SourceEndpoint: Which endpoint provided this information

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

function Invoke-HTTPRequest {
    [CmdletBinding(DefaultParameterSetName = 'Standard')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Standard', Position = 0)]
        [Parameter(Mandatory = $true, ParameterSetName = 'Exchange', Position = 0)]
        [Parameter(Mandatory = $true, ParameterSetName = 'ADCS', Position = 0)]
        [string]$Uri,

        [Parameter(Mandatory = $false, ParameterSetName = 'Standard')]
        [ValidateSet('GET', 'HEAD', 'POST')]
        [string]$Method = 'GET',

        [Parameter(Mandatory = $false, ParameterSetName = 'Standard')]
        [hashtable]$Headers,

        [Parameter(Mandatory = $false, ParameterSetName = 'Standard')]
        [string]$Body,

        [Parameter(Mandatory = $false, ParameterSetName = 'Standard')]
        [string]$ContentType = 'application/x-www-form-urlencoded',

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 300)]
        [int]$TimeoutSeconds = 3,

        [Parameter(Mandatory = $false)]
        [string]$UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',

        [Parameter(Mandatory = $false)]
        [bool]$IgnoreSSLErrors = $true,

        # ===== Specialized Detection Modes =====

        [Parameter(Mandatory = $true, ParameterSetName = 'Exchange')]
        [switch]$ScanExchange,

        [Parameter(Mandatory = $true, ParameterSetName = 'ADCS')]
        [switch]$ScanADCS,

        [Parameter(Mandatory = $false, ParameterSetName = 'ADCS')]
        [string]$CAName,

        [Parameter(Mandatory = $false, ParameterSetName = 'ADCS')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Exchange')]
        [switch]$TestEPA
    )

    process {
        # Save original settings to restore later (local variables for thread safety)
        $originalSecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol
        $originalCertCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback

        try {
            # Configure TLS settings at the start of process (ensures cleanup in finally)
            Set-TLSConfiguration -IgnoreSSLErrors $IgnoreSSLErrors

            # ===== Exchange Version Detection Mode =====
            if ($PSCmdlet.ParameterSetName -eq 'Exchange') {
                return Invoke-ExchangeScanInternal -Hostname $Uri -TimeoutSeconds $TimeoutSeconds -UserAgent $UserAgent -TestEPA:$TestEPA
            }

            # ===== ADCS Web Enrollment Detection Mode =====
            if ($PSCmdlet.ParameterSetName -eq 'ADCS') {
                return Invoke-ADCSScanInternal -Hostname $Uri -TimeoutSeconds $TimeoutSeconds -UserAgent $UserAgent -CAName $CAName -TestEPA:$TestEPA
            }

            # ===== Standard HTTP Request Mode =====
            return Invoke-StandardHTTPRequest -Uri $Uri -Method $Method -Headers $Headers -Body $Body -ContentType $ContentType -TimeoutSeconds $TimeoutSeconds -UserAgent $UserAgent
        }
        finally {
            # Always restore original security settings (even on exception)
            Restore-TLSConfiguration -OriginalProtocol $originalSecurityProtocol -OriginalCallback $originalCertCallback
        }
    }
}

#region ===== TLS CONFIGURATION HELPERS =====

<#
.SYNOPSIS
    Configures TLS settings for maximum compatibility.
#>
function Set-TLSConfiguration {
    [CmdletBinding()]
    param(
        [bool]$IgnoreSSLErrors
    )

    try {
        # Start with TLS 1.2 (most compatible)
        $protocols = [System.Net.SecurityProtocolType]::Tls12

        # Try to add TLS 1.1 (still needed for some legacy servers)
        try {
            $protocols = $protocols -bor [System.Net.SecurityProtocolType]::Tls11
        }
        catch {
            Write-Log "[Set-TLSConfiguration] TLS 1.1 not available"
        }

        # Try to add TLS 1.0 (legacy, but may be needed)
        try {
            $protocols = $protocols -bor [System.Net.SecurityProtocolType]::Tls
        }
        catch {
            Write-Log "[Set-TLSConfiguration] TLS 1.0 not available"
        }

        # Try to add TLS 1.3 if available (.NET 4.8+)
        try {
            $tls13 = [System.Net.SecurityProtocolType]::Tls13
            $protocols = $protocols -bor $tls13
            Write-Log "[Set-TLSConfiguration] TLS 1.3 enabled"
        }
        catch {
            Write-Log "[Set-TLSConfiguration] TLS 1.3 not available on this system"
        }

        # Note: SSL3 is intentionally NOT added - it's deprecated and disabled in modern .NET

        [System.Net.ServicePointManager]::SecurityProtocol = $protocols
    }
    catch {
        Write-Log "[Set-TLSConfiguration] Error configuring TLS: $_"
    }

    # Ignore SSL certificate errors if requested
    if ($IgnoreSSLErrors) {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        Write-Log "[Set-TLSConfiguration] SSL certificate validation disabled"
    }
}

<#
.SYNOPSIS
    Restores original TLS settings.
#>
function Restore-TLSConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Net.SecurityProtocolType]$OriginalProtocol,

        [Parameter(Mandatory = $false)]
        [System.Net.Security.RemoteCertificateValidationCallback]$OriginalCallback
    )

    try {
        [System.Net.ServicePointManager]::SecurityProtocol = $OriginalProtocol
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $OriginalCallback
        Write-Log "[Restore-TLSConfiguration] TLS settings restored"
    }
    catch {
        Write-Log "[Restore-TLSConfiguration] Error restoring TLS settings: $_"
    }
}

#endregion

#region ===== REDIRECT VALIDATION PATTERNS =====

# Exchange-specific redirect path patterns
# These indicate the redirect is to an Exchange endpoint, not a generic load balancer page
$Script:ExchangeRedirectPatterns = @(
    '/owa/',
    '/ecp/',
    '/ews/',
    '/autodiscover/',
    '/mapi/',
    '/rpc/',
    '/powershell/',
    '/Microsoft-Server-ActiveSync/'
)

# ADCS-specific redirect path patterns (matched case-insensitively via .ToLower())
# These indicate the redirect is to an ADCS endpoint, not a generic load balancer page
$Script:ADCSRedirectPatterns = @(
    '/certsrv/',              # Certificate Services web enrollment
    '/adpolicyprovider_cep',  # Certificate Enrollment Policy (CEP)
    '/_ces_',                 # Certificate Enrollment Service (CES) - pattern includes underscore prefix
    '/mscep/'                 # Network Device Enrollment Service (NDES)
)

#endregion

#region ===== STANDARD HTTP REQUEST =====

<#
.SYNOPSIS
    Performs a standard HTTP request with proper resource cleanup.
#>
function Invoke-StandardHTTPRequest {
    [CmdletBinding()]
    param(
        [string]$Uri,
        [string]$Method,
        [hashtable]$Headers,
        [string]$Body,
        [string]$ContentType,
        [int]$TimeoutSeconds,
        [string]$UserAgent
    )

    $result = [PSCustomObject]@{
        Success    = $false
        StatusCode = $null
        Headers    = @{}
        Content    = $null
        Error      = $null
    }

    # Normalize URI - add https:// if no protocol specified
    $targetUri = $Uri
    if ($targetUri -and -not ($targetUri -match '^https?://')) {
        $targetUri = "https://$targetUri"
        Write-Log "[Invoke-HTTPRequest] Added https:// prefix: $targetUri"
    }

    # Validate URI
    if ([string]::IsNullOrWhiteSpace($targetUri)) {
        $result.Error = "Invalid or empty URI"
        return $result
    }

    $request = $null
    $response = $null
    $responseStream = $null
    $reader = $null
    $requestStream = $null

    try {
        Write-Log "[Invoke-HTTPRequest] $Method $targetUri"

        # Create WebRequest for maximum compatibility
        $request = [System.Net.HttpWebRequest]::Create($targetUri)
        $request.Method = $Method
        $request.Timeout = $TimeoutSeconds * 1000
        $request.ReadWriteTimeout = $TimeoutSeconds * 1000  # Also set stream timeout
        $request.UserAgent = $UserAgent
        $request.AllowAutoRedirect = $true
        $request.MaximumAutomaticRedirections = 5

        # Add custom headers
        if ($Headers) {
            foreach ($key in $Headers.Keys) {
                try {
                    $request.Headers.Add($key, $Headers[$key])
                }
                catch {
                    Write-Log "[Invoke-HTTPRequest] Could not add header ${key}: $_"
                }
            }
        }

        # Add body for POST requests
        if ($Method -eq 'POST' -and $Body) {
            $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($Body)
            $request.ContentLength = $bodyBytes.Length
            $request.ContentType = $ContentType

            try {
                $requestStream = $request.GetRequestStream()
                $requestStream.Write($bodyBytes, 0, $bodyBytes.Length)
            }
            finally {
                if ($requestStream) {
                    try { $requestStream.Close() } catch { }
                    try { $requestStream.Dispose() } catch { }
                }
            }
        }

        # Execute request
        $response = $request.GetResponse()

        $result.StatusCode = [int]$response.StatusCode
        $result.Success = $true

        # Capture headers
        foreach ($header in $response.Headers.AllKeys) {
            $result.Headers[$header] = $response.Headers[$header]
        }

        # Read content (unless HEAD request)
        if ($Method -ne 'HEAD') {
            try {
                $responseStream = $response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($responseStream)
                $result.Content = $reader.ReadToEnd()
            }
            finally {
                if ($reader) { try { $reader.Dispose() } catch { } }
                if ($responseStream) { try { $responseStream.Dispose() } catch { } }
            }
        }

        Write-Log "[Invoke-HTTPRequest] Success: HTTP $($result.StatusCode)"
    }
    catch [System.Net.WebException] {
        $webEx = $_.Exception
        try {
            if ($webEx.Response) {
                $result.StatusCode = [int]$webEx.Response.StatusCode
                $result.Error = "HTTP $($result.StatusCode): $($webEx.Message)"

                # Still capture headers from error response
                foreach ($header in $webEx.Response.Headers.AllKeys) {
                    $result.Headers[$header] = $webEx.Response.Headers[$header]
                }
            }
            else {
                $result.Error = $webEx.Message
            }
        }
        finally {
            # Dispose WebException response to prevent connection pool exhaustion
            if ($webEx.Response) {
                try { $webEx.Response.Close() } catch { }
                try { $webEx.Response.Dispose() } catch { }
            }
        }
        Write-Log "[Invoke-HTTPRequest] WebException: $($result.Error)"
    }
    catch {
        $result.Error = $_.Exception.Message
        Write-Log "[Invoke-HTTPRequest] Error: $($result.Error)"
    }
    finally {
        # Cleanup all resources
        if ($response) {
            try { $response.Close() } catch { }
            try { $response.Dispose() } catch { }
        }
    }

    return $result
}

#endregion

#region ===== EXCHANGE BUILD NUMBER DETECTION =====

<#
.SYNOPSIS
    Internal function to detect Exchange Server build number and configuration.
.DESCRIPTION
    Uses multiple methods to detect Exchange build number and analyzes endpoint configuration:
    1. Primary: /ecp/exporttool endpoint (anonymous, returns XML with version)
    2. Fallback: X-OWA-Version HTTP header from /owa/
    3. Fallback: X-OWA-Version HTTP header from /autodiscover/autodiscover.xml (401 response)
    4. Fallback: X-OWA-Version via HTTP (non-SSL)

    Additionally detects:
    - Available endpoints (OWA, ECP, EWS, Autodiscover, MAPI, RPC, PowerShell, ActiveSync)
    - Authentication methods (NTLM, Negotiate, Basic, Forms)
    - HTTP vs HTTPS availability
    - Extended Protection for Authentication (EPA) status per endpoint (with -TestEPA)

    Returns RAW build number only. Version interpretation (CU, SE, etc.)
    is done by the calling module (Get-ExchangeInfrastructure).
.PARAMETER Hostname
    Target Exchange server hostname.
.PARAMETER TimeoutSeconds
    Request timeout.
.PARAMETER UserAgent
    User-Agent header.
.PARAMETER TestEPA
    Test Extended Protection for Authentication (EPA) for each endpoint with NTLM over HTTPS.
.RETURNS
    PSCustomObject with Success, Hostname, BuildNumber, Method, AuthMethods, Endpoints (with EPA), and Error properties.
#>
function Invoke-ExchangeScanInternal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Hostname,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds = 5,

        [Parameter(Mandatory = $false)]
        [string]$UserAgent,

        [Parameter(Mandatory = $false)]
        [switch]$TestEPA
    )

    # Normalize hostname - extract FQDN only (remove protocol, path, port if present)
    # Input can be: "mail.contoso.com", "https://mail.contoso.com", "https://mail.contoso.com/owa/", "mail.contoso.com:443"
    $targetHost = $Hostname -replace '^https?://', ''  # Remove protocol
    $targetHost = $targetHost -replace '/.*$', ''       # Remove path and everything after first /
    $targetHost = $targetHost -replace ':\d+$', ''      # Remove port number
    $targetHost = $targetHost.Trim()

    $result = [PSCustomObject]@{
        Success          = $false
        Hostname         = $targetHost  # Return normalized hostname (FQDN only)
        BuildNumber      = $null
        Method           = $null
        # Endpoint availability with per-endpoint auth methods and EPA status
        # EPA is tested per endpoint because IIS allows different EPA settings per virtual directory
        Endpoints        = [PSCustomObject]@{
            OWA          = [PSCustomObject]@{ Available = $false; AuthMethods = ''; EPAEnabled = $null; EPAConfidence = $null }
            ECP          = [PSCustomObject]@{ Available = $false; AuthMethods = ''; EPAEnabled = $null; EPAConfidence = $null }
            EWS          = [PSCustomObject]@{ Available = $false; AuthMethods = ''; EPAEnabled = $null; EPAConfidence = $null }
            Autodiscover = [PSCustomObject]@{ Available = $false; AuthMethods = ''; EPAEnabled = $null; EPAConfidence = $null }
            MAPI         = [PSCustomObject]@{ Available = $false; AuthMethods = ''; EPAEnabled = $null; EPAConfidence = $null }
            RPC          = [PSCustomObject]@{ Available = $false; AuthMethods = ''; EPAEnabled = $null; EPAConfidence = $null }
            PowerShell   = [PSCustomObject]@{ Available = $false; AuthMethods = ''; EPAEnabled = $null; EPAConfidence = $null }
            ActiveSync   = [PSCustomObject]@{ Available = $false; AuthMethods = ''; EPAEnabled = $null; EPAConfidence = $null }
        }
        # Protocol availability
        HttpAvailable    = $false
        HttpsAvailable   = $false
        ServerHeader     = $null
        # Legacy EPA properties (for backward compatibility) - reflects first endpoint with NTLM
        EPAEnabled       = $null         # $true = EPA active (secure), $false = EPA not active (vulnerable), $null = not tested
        EPAConfidence    = $null         # "High", "Medium", "Low", "Unknown"
        EPADiagnostic    = $null         # Diagnostic info for EPA test
        # NTLM information from Type2 challenge (populated when -TestEPA is used)
        NTLMInfo         = $null         # PSCustomObject with NTLM details from first successful EPA test
        Error            = $null
    }

    # Validate hostname
    if ([string]::IsNullOrWhiteSpace($targetHost)) {
        $result.Error = "Invalid or empty hostname"
        return $result
    }

    Write-Log "[ScanExchange] Detecting Exchange configuration for: $targetHost"

    # ===== Method 1: /ecp/exporttool (Primary - Anonymous access for version) =====
    $exportToolUrl = "https://$targetHost/ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application"

    Write-Log "[ScanExchange] Method 1: Trying $exportToolUrl"

    $response = $null
    $responseStream = $null
    $reader = $null

    try {
        $request = [System.Net.HttpWebRequest]::Create($exportToolUrl)
        $request.Method = 'GET'
        $request.Timeout = $TimeoutSeconds * 1000
        $request.ReadWriteTimeout = $TimeoutSeconds * 1000
        $request.UserAgent = $UserAgent
        $request.AllowAutoRedirect = $true

        $response = $request.GetResponse()

        if ($response.StatusCode -eq 'OK') {
            $result.HttpsAvailable = $true
            # Note: Don't set ECP.Available here yet - we need to verify the response is actual Exchange XML

            # Capture server header
            if ($response.Headers['Server']) {
                $result.ServerHeader = $response.Headers['Server']
            }

            try {
                $responseStream = $response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($responseStream)
                $content = $reader.ReadToEnd()

                # Parse XML response
                try {
                    # Remove BOM if present (Unicode BOM is U+FEFF)
                    $cleanContent = $content.Trim()
                    if ($cleanContent.Length -gt 0 -and $cleanContent[0] -eq [char]0xFEFF) {
                        $cleanContent = $cleanContent.Substring(1)
                    }

                    # Check if response is HTML instead of XML (common with reverse proxies/load balancers)
                    if ($cleanContent -match '^\s*<(!DOCTYPE\s+html|html)') {
                        Write-Log "[ScanExchange] Method 1: Response is HTML (proxy/load balancer page), not Exchange XML"
                        # Do NOT set ECP.Available - this is not an Exchange response
                    }
                    else {
                        # Try direct XML parse
                        $xml = [xml]$cleanContent

                        # Extract version from assemblyIdentity
                        $buildNumber = $xml.assembly.assemblyIdentity.version

                        if ($buildNumber) {
                            $result.Success = $true
                            $result.BuildNumber = $buildNumber
                            $result.Method = "/ecp/exporttool"
                            # Only mark ECP as available when we successfully got Exchange version from exporttool
                            $result.Endpoints.ECP.Available = $true

                            Write-Log "[ScanExchange] Method 1 SUCCESS: $buildNumber"
                            # Don't return yet - continue to collect endpoint info
                        }
                    }
                }
                catch {
                    # Provide concise error message without dumping entire content
                    $errorMsg = $_.Exception.Message
                    # Truncate if error message contains the content (common with XML parse errors)
                    if ($errorMsg.Length -gt 200) {
                        $errorMsg = $errorMsg.Substring(0, 150) + "... (truncated)"
                    }
                    Write-Log "[ScanExchange] Method 1: XML parse failed - $errorMsg"
                }
            }
            finally {
                if ($reader) { try { $reader.Dispose() } catch { } }
                if ($responseStream) { try { $responseStream.Dispose() } catch { } }
            }
        }
    }
    catch [System.Net.WebException] {
        $statusCode = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { "N/A" }
        Write-Log "[ScanExchange] Method 1 failed (HTTP $statusCode): $($_.Exception.Message)"
        # Dispose WebException response
        if ($_.Exception.Response) {
            try { $_.Exception.Response.Close() } catch { }
        }
    }
    catch {
        Write-Log "[ScanExchange] Method 1 failed: $_"
    }
    finally {
        if ($response) {
            try { $response.Close() } catch { }
            try { $response.Dispose() } catch { }
        }
    }

    # ===== Test OWA endpoint (also used for version detection) =====
    $owaUrl = "https://$targetHost/owa/"
    Write-Log "[ScanExchange] Testing OWA endpoint: $owaUrl"

    $owaResult = Test-ExchangeEndpoint -Url $owaUrl -EndpointName "OWA" -TimeoutSeconds $TimeoutSeconds -UserAgent $UserAgent
    if ($owaResult.IsExchangeEndpoint) {
        $result.HttpsAvailable = $true
        $result.Endpoints.OWA.Available = $true
        $result.Endpoints.OWA.AuthMethods = $owaResult.AuthMethods -join ', '

        if (-not $result.ServerHeader -and $owaResult.ServerHeader) {
            $result.ServerHeader = $owaResult.ServerHeader
        }

        # Try to get version from X-OWA-Version header
        if (-not $result.Success -and $owaResult.OWAVersion) {
            $result.Success = $true
            $result.BuildNumber = $owaResult.OWAVersion
            $result.Method = "X-OWA-Version (/owa)"
            Write-Log "[ScanExchange] OWA version detected: $($owaResult.OWAVersion)"
        }

        Write-Log "[ScanExchange] OWA available (HTTP $($owaResult.StatusCode)), Auth: $($owaResult.AuthMethods -join ', ')"
    }
    elseif ($owaResult.Reachable) {
        Write-Log "[ScanExchange] OWA endpoint responded but is not Exchange (likely load balancer redirect)"
    }

    # ===== Test Autodiscover endpoint =====
    $autodiscoverUrl = "https://$targetHost/autodiscover/autodiscover.xml"
    Write-Log "[ScanExchange] Testing Autodiscover endpoint: $autodiscoverUrl"

    $autodiscoverResult = Test-ExchangeEndpoint -Url $autodiscoverUrl -EndpointName "Autodiscover" -TimeoutSeconds $TimeoutSeconds -UserAgent $UserAgent
    if ($autodiscoverResult.IsExchangeEndpoint) {
        $result.HttpsAvailable = $true
        $result.Endpoints.Autodiscover.Available = $true
        $result.Endpoints.Autodiscover.AuthMethods = $autodiscoverResult.AuthMethods -join ', '

        # Try to get version from X-OWA-Version header
        if (-not $result.Success -and $autodiscoverResult.OWAVersion) {
            $result.Success = $true
            $result.BuildNumber = $autodiscoverResult.OWAVersion
            $result.Method = "X-OWA-Version (/autodiscover)"
            Write-Log "[ScanExchange] Autodiscover version detected: $($autodiscoverResult.OWAVersion)"
        }

        Write-Log "[ScanExchange] Autodiscover available (HTTP $($autodiscoverResult.StatusCode)), Auth: $($autodiscoverResult.AuthMethods -join ', ')"
    }
    elseif ($autodiscoverResult.Reachable) {
        Write-Log "[ScanExchange] Autodiscover endpoint responded but is not Exchange (likely load balancer redirect)"
    }

    # ===== Test EWS endpoint =====
    $ewsUrl = "https://$targetHost/ews/exchange.asmx"
    Write-Log "[ScanExchange] Testing EWS endpoint: $ewsUrl"

    $ewsResult = Test-ExchangeEndpoint -Url $ewsUrl -EndpointName "EWS" -TimeoutSeconds $TimeoutSeconds -UserAgent $UserAgent
    if ($ewsResult.IsExchangeEndpoint) {
        $result.Endpoints.EWS.Available = $true
        $result.Endpoints.EWS.AuthMethods = $ewsResult.AuthMethods -join ', '

        # Try to get version from X-OWA-Version header (EWS also returns this header)
        if (-not $result.Success -and $ewsResult.OWAVersion) {
            $result.Success = $true
            $result.BuildNumber = $ewsResult.OWAVersion
            $result.Method = "X-OWA-Version (/ews)"
            Write-Log "[ScanExchange] EWS version detected: $($ewsResult.OWAVersion)"
        }

        Write-Log "[ScanExchange] EWS available (HTTP $($ewsResult.StatusCode)), Auth: $($ewsResult.AuthMethods -join ', ')"
    }
    elseif ($ewsResult.Reachable) {
        Write-Log "[ScanExchange] EWS endpoint responded but is not Exchange (likely load balancer redirect)"
    }

    # ===== Test ECP endpoint (always test for auth methods, even if detected via exporttool) =====
    $ecpUrl = "https://$targetHost/ecp/"
    Write-Log "[ScanExchange] Testing ECP endpoint: $ecpUrl"

    $ecpResult = Test-ExchangeEndpoint -Url $ecpUrl -EndpointName "ECP" -TimeoutSeconds $TimeoutSeconds -UserAgent $UserAgent
    if ($ecpResult.IsExchangeEndpoint) {
        $result.Endpoints.ECP.Available = $true
        $result.Endpoints.ECP.AuthMethods = $ecpResult.AuthMethods -join ', '
        Write-Log "[ScanExchange] ECP available (HTTP $($ecpResult.StatusCode)), Auth: $($ecpResult.AuthMethods -join ', ')"
    }
    elseif ($ecpResult.Reachable) {
        # Load balancer redirect detected - ECP is NOT actually available
        # Reset ECP.Available in case it was set by exporttool (which might have been HTML from the load balancer)
        if ($result.Endpoints.ECP.Available -and -not $result.BuildNumber) {
            # ECP was marked available but we have no version - likely false positive from load balancer HTML
            $result.Endpoints.ECP.Available = $false
        }
        Write-Log "[ScanExchange] ECP endpoint responded but is not Exchange (likely load balancer redirect)"
    }
    elseif ($result.Endpoints.ECP.Available) {
        # ECP was detected via exporttool (we have BuildNumber) but direct test failed - keep it marked as available
        Write-Log "[ScanExchange] ECP detected via exporttool (no auth method info available)"
    }

    # ===== Test MAPI endpoint =====
    $mapiUrl = "https://$targetHost/mapi/"
    Write-Log "[ScanExchange] Testing MAPI endpoint: $mapiUrl"

    $mapiResult = Test-ExchangeEndpoint -Url $mapiUrl -EndpointName "MAPI" -TimeoutSeconds $TimeoutSeconds -UserAgent $UserAgent
    if ($mapiResult.IsExchangeEndpoint) {
        $result.Endpoints.MAPI.Available = $true
        $result.Endpoints.MAPI.AuthMethods = $mapiResult.AuthMethods -join ', '
        Write-Log "[ScanExchange] MAPI available (HTTP $($mapiResult.StatusCode)), Auth: $($mapiResult.AuthMethods -join ', ')"
    }
    elseif ($mapiResult.Reachable) {
        Write-Log "[ScanExchange] MAPI endpoint responded but is not Exchange (likely load balancer redirect)"
    }

    # ===== Test RPC endpoint =====
    $rpcUrl = "https://$targetHost/rpc/"
    Write-Log "[ScanExchange] Testing RPC endpoint: $rpcUrl"

    $rpcResult = Test-ExchangeEndpoint -Url $rpcUrl -EndpointName "RPC" -TimeoutSeconds $TimeoutSeconds -UserAgent $UserAgent
    if ($rpcResult.IsExchangeEndpoint) {
        $result.Endpoints.RPC.Available = $true
        $result.Endpoints.RPC.AuthMethods = $rpcResult.AuthMethods -join ', '
        Write-Log "[ScanExchange] RPC available (HTTP $($rpcResult.StatusCode)), Auth: $($rpcResult.AuthMethods -join ', ')"
    }
    elseif ($rpcResult.Reachable) {
        Write-Log "[ScanExchange] RPC endpoint responded but is not Exchange (likely load balancer redirect)"
    }

    # ===== Test PowerShell endpoint =====
    $psUrl = "https://$targetHost/powershell/"
    Write-Log "[ScanExchange] Testing PowerShell endpoint: $psUrl"

    $psResult = Test-ExchangeEndpoint -Url $psUrl -EndpointName "PowerShell" -TimeoutSeconds $TimeoutSeconds -UserAgent $UserAgent
    if ($psResult.IsExchangeEndpoint) {
        $result.Endpoints.PowerShell.Available = $true
        $result.Endpoints.PowerShell.AuthMethods = $psResult.AuthMethods -join ', '
        Write-Log "[ScanExchange] PowerShell available (HTTP $($psResult.StatusCode)), Auth: $($psResult.AuthMethods -join ', ')"
    }
    elseif ($psResult.Reachable) {
        Write-Log "[ScanExchange] PowerShell endpoint responded but is not Exchange (likely load balancer redirect)"
    }

    # ===== Test ActiveSync endpoint =====
    $asUrl = "https://$targetHost/Microsoft-Server-ActiveSync/"
    Write-Log "[ScanExchange] Testing ActiveSync endpoint: $asUrl"

    $asResult = Test-ExchangeEndpoint -Url $asUrl -EndpointName "ActiveSync" -TimeoutSeconds $TimeoutSeconds -UserAgent $UserAgent
    if ($asResult.IsExchangeEndpoint) {
        $result.Endpoints.ActiveSync.Available = $true
        $result.Endpoints.ActiveSync.AuthMethods = $asResult.AuthMethods -join ', '
        Write-Log "[ScanExchange] ActiveSync available (HTTP $($asResult.StatusCode)), Auth: $($asResult.AuthMethods -join ', ')"
    }
    elseif ($asResult.Reachable) {
        Write-Log "[ScanExchange] ActiveSync endpoint responded but is not Exchange (likely load balancer redirect)"
    }

    # ===== Test HTTP (non-SSL) OWA as last resort for version =====
    if (-not $result.Success) {
        Write-Log "[ScanExchange] Testing HTTP (non-SSL) for version"

        $httpOwaUrl = "http://$targetHost/owa/"
        $httpResult = Test-ExchangeEndpoint -Url $httpOwaUrl -EndpointName "OWA" -TimeoutSeconds $TimeoutSeconds -UserAgent $UserAgent

        if ($httpResult.IsExchangeEndpoint) {
            $result.HttpAvailable = $true
            # If OWA wasn't available via HTTPS, update it for HTTP
            if (-not $result.Endpoints.OWA.Available) {
                $result.Endpoints.OWA.Available = $true
                $result.Endpoints.OWA.AuthMethods = $httpResult.AuthMethods -join ', '
            }

            if ($httpResult.OWAVersion) {
                $result.Success = $true
                $result.BuildNumber = $httpResult.OWAVersion
                $result.Method = "X-OWA-Version (HTTP)"
                Write-Log "[ScanExchange] HTTP version detected: $($httpResult.OWAVersion)"
            }
        }
    }

    # Set success if any endpoint was found (even without version)
    if (-not $result.Success) {
        $anyEndpoint = $result.Endpoints.OWA.Available -or $result.Endpoints.ECP.Available -or $result.Endpoints.EWS.Available -or
                       $result.Endpoints.Autodiscover.Available -or $result.Endpoints.MAPI.Available -or $result.Endpoints.RPC.Available -or
                       $result.Endpoints.PowerShell.Available -or $result.Endpoints.ActiveSync.Available

        if ($anyEndpoint) {
            $result.Success = $true
            $result.Error = "Exchange endpoints found but could not determine version"
            Write-Log "[ScanExchange] Endpoints found but version detection failed"
        }
        else {
            $result.Error = "No Exchange endpoints found (server may be offline, blocking requests, or not Exchange)"
            Write-Log "[ScanExchange] No endpoints found for $targetHost"
        }
    }

    # Log summary of available endpoints with their auth methods
    $availableEndpoints = @()
    foreach ($ep in @('OWA', 'ECP', 'EWS', 'Autodiscover', 'MAPI', 'RPC', 'PowerShell', 'ActiveSync')) {
        if ($result.Endpoints.$ep.Available) {
            $authStr = if ($result.Endpoints.$ep.AuthMethods) { " ($($result.Endpoints.$ep.AuthMethods))" } else { "" }
            $availableEndpoints += "$ep$authStr"
        }
    }
    if ($availableEndpoints.Count -gt 0) {
        Write-Log "[ScanExchange] Detection complete - Available endpoints: $($availableEndpoints -join ', ')"
    } else {
        Write-Log "[ScanExchange] Detection complete - No Exchange endpoints found"
    }

    # ===== Extended Protection for Authentication (EPA) Test =====
    # Test EPA for EACH endpoint separately because IIS allows different EPA settings per virtual directory
    # Only test if:
    # 1. -TestEPA switch is specified
    # 2. HTTPS is available (EPA only applies to TLS connections)
    # 3. NTLM is in the authentication methods (EPA binds NTLM to TLS channel)
    if ($TestEPA -and $result.Success) {
        Write-Log "[ScanExchange] Testing Extended Protection for Authentication (EPA) per endpoint..."

        # Use longer timeout for EPA test (NTLM handshake needs more time)
        $epaTimeout = [Math]::Max($TimeoutSeconds, 10)

        # Track if we've set the legacy EPA properties (first endpoint with NTLM)
        $legacyEPASet = $false

        # Endpoint URL mapping for EPA testing
        $endpointUrls = @{
            'OWA'          = "https://$targetHost/owa/"
            'ECP'          = "https://$targetHost/ecp/"
            'EWS'          = "https://$targetHost/ews/exchange.asmx"
            'Autodiscover' = "https://$targetHost/autodiscover/autodiscover.xml"
            'MAPI'         = "https://$targetHost/mapi/"
            'RPC'          = "https://$targetHost/rpc/"
            'PowerShell'   = "https://$targetHost/powershell/"
            'ActiveSync'   = "https://$targetHost/Microsoft-Server-ActiveSync/"
        }

        # Test EPA for each available endpoint with NTLM over HTTPS
        foreach ($ep in @('OWA', 'ECP', 'EWS', 'Autodiscover', 'MAPI', 'RPC', 'PowerShell', 'ActiveSync')) {
            if ($result.Endpoints.$ep.Available -and $result.Endpoints.$ep.AuthMethods -match 'NTLM') {
                $epaTestUrl = $endpointUrls[$ep]

                Write-Log "[ScanExchange] Testing EPA for $ep at $epaTestUrl"
                $epaResult = Test-ExtendedProtection -Url $epaTestUrl -TimeoutSeconds $epaTimeout -UserAgent $UserAgent

                # Store EPA result in the endpoint object
                $result.Endpoints.$ep.EPAEnabled = $epaResult.EPAEnabled
                $result.Endpoints.$ep.EPAConfidence = $epaResult.Confidence

                if ($epaResult.Success) {
                    if ($epaResult.EPAEnabled -eq $true) {
                        Write-Log "[ScanExchange] $ep EPA ENABLED ($($epaResult.Confidence) confidence)"
                    }
                    elseif ($epaResult.EPAEnabled -eq $false) {
                        Write-Log "[ScanExchange] $ep EPA DISABLED ($($epaResult.Confidence) confidence) - NTLM relay possible!"
                    }
                    else {
                        Write-Log "[ScanExchange] $ep EPA status: $($epaResult.DiagnosticInfo)"
                    }
                }
                else {
                    Write-Log "[ScanExchange] $ep EPA test failed: $($epaResult.ErrorMessage)"
                }

                # Set legacy properties from first endpoint with NTLM (backward compatibility)
                if (-not $legacyEPASet) {
                    $result.EPAEnabled = $epaResult.EPAEnabled
                    $result.EPAConfidence = $epaResult.Confidence
                    $result.EPADiagnostic = $epaResult.DiagnosticInfo

                    # Capture NTLM information from first successful EPA test
                    if ($epaResult.Type2Received) {
                        $result.NTLMInfo = [PSCustomObject]@{
                            NbComputerName  = $epaResult.NbComputerName      # NetBIOS computer name
                            NbDomainName    = $epaResult.NbDomainName        # NetBIOS domain name
                            DnsComputerName = $epaResult.DnsComputerName     # DNS computer name (FQDN)
                            DnsDomainName   = $epaResult.DnsDomainName       # DNS domain name
                            DnsTreeName     = $epaResult.DnsTreeName         # DNS forest name
                            ServerTimestamp = $epaResult.ServerTimestamp     # Server time (DateTime)
                            NTLMChallenge   = $epaResult.NTLMChallenge       # NTLM challenge (hex)
                            SourceEndpoint  = $ep                            # Which endpoint provided this info
                        }
                        Write-Log "[ScanExchange] NTLM Info captured from $ep - Server: $($epaResult.DnsComputerName), Domain: $($epaResult.DnsDomainName)"
                    }

                    $legacyEPASet = $true
                }
            }
        }

        # If no NTLM endpoints found over HTTPS
        if (-not $legacyEPASet) {
            if (-not $result.HttpsAvailable) {
                $result.EPAEnabled = $false
                $result.EPAConfidence = "High"
                $result.EPADiagnostic = "HTTP only - no TLS channel for EPA to bind to"
                Write-Log "[ScanExchange] EPA not applicable - HTTP only (no TLS)"
            }
            else {
                $result.EPADiagnostic = "NTLM not offered over HTTPS - EPA test not applicable"
                Write-Log "[ScanExchange] EPA test skipped - no NTLM over HTTPS"
            }
        }
    }

    return $result
}

<#
.SYNOPSIS
    Tests a single Exchange endpoint for availability, authentication methods, and version.
.DESCRIPTION
    Tests whether an HTTP endpoint is a real Exchange endpoint or just a load balancer redirect.

    Key validation logic for redirects (HTTP 301/302):
    - Load balancers often redirect ALL requests to a login page (generic redirect)
    - Real Exchange redirects go to Exchange-specific paths (e.g., /owa/auth/logon.aspx)
    - We validate the Location header to distinguish between these cases

    Exchange-specific redirect patterns:
    - /owa/auth/logon.aspx (OWA login)
    - /owa/auth/errorFE.aspx (OWA error)
    - /ecp/auth/logon.aspx (ECP login)
    - /autodiscover/* (Autodiscover redirects)
    - /ews/* (EWS redirects)
    - /mapi/* (MAPI redirects)
    - /rpc/* (RPC redirects)
    - /powershell/* (PowerShell redirects)
    - /Microsoft-Server-ActiveSync/* (ActiveSync redirects)
#>
function Test-ExchangeEndpoint {
    [CmdletBinding()]
    param(
        [string]$Url,
        [string]$EndpointName,
        [int]$TimeoutSeconds,
        [string]$UserAgent
    )

    $endpointResult = [PSCustomObject]@{
        Reachable          = $false      # Server responded (any HTTP response)
        IsExchangeEndpoint = $false      # Confirmed to be Exchange (not a load balancer redirect)
        StatusCode         = $null
        AuthMethods        = @()
        ServerHeader       = $null
        OWAVersion         = $null
        RedirectLocation   = $null       # For debugging redirect issues
    }

    # Validate URL before creating WebRequest
    if ([string]::IsNullOrWhiteSpace($Url)) {
        Write-Log "[Test-ExchangeEndpoint] ${EndpointName}: Empty URL provided"
        return $endpointResult
    }

    $response = $null

    # Use Script-scope redirect patterns defined at module level
    $exchangeRedirectPatterns = $Script:ExchangeRedirectPatterns

    try {
        $request = [System.Net.HttpWebRequest]::Create($Url)
        $request.Method = 'GET'
        $request.Timeout = $TimeoutSeconds * 1000
        $request.ReadWriteTimeout = $TimeoutSeconds * 1000
        $request.UserAgent = $UserAgent
        $request.AllowAutoRedirect = $false  # Don't follow redirects to capture auth headers

        $response = $request.GetResponse()
        $statusCode = [int]$response.StatusCode
        $endpointResult.Reachable = $true
        $endpointResult.StatusCode = $statusCode
        $endpointResult.ServerHeader = $response.Headers['Server']
        $endpointResult.OWAVersion = $response.Headers['X-OWA-Version']

        # Check if this is a redirect (301/302) - even though we disabled auto-redirect,
        # some servers return 302 as a "success" response
        if ($statusCode -in @(301, 302)) {
            $location = $response.Headers['Location']
            $endpointResult.RedirectLocation = $location

            Write-Log "[Test-ExchangeEndpoint] ${EndpointName}: Got redirect (HTTP $statusCode), checking location: $location"

            # Validate if redirect goes to an Exchange-specific path
            $isExchangeRedirect = $false
            if ($location) {
                foreach ($pattern in $exchangeRedirectPatterns) {
                    if ($location.ToLower().Contains($pattern.ToLower())) {
                        $isExchangeRedirect = $true
                        Write-Log "[Test-ExchangeEndpoint] ${EndpointName}: Redirect to Exchange path (matched $pattern)"
                        break
                    }
                }
                if (-not $isExchangeRedirect) {
                    Write-Log "[Test-ExchangeEndpoint] ${EndpointName}: Redirect to non-Exchange path: $location"
                }
            }

            $endpointResult.IsExchangeEndpoint = $isExchangeRedirect

            # For Exchange redirects, follow to get auth methods
            if ($isExchangeRedirect -and $location) {
                try {
                    $redirectUrl = $location
                    if ($location -match '^/') {
                        $uri = [System.Uri]$Url
                        $redirectUrl = "$($uri.Scheme)://$($uri.Host)$location"
                    }

                    $redirectRequest = [System.Net.HttpWebRequest]::Create($redirectUrl)
                    $redirectRequest.Method = 'GET'
                    $redirectRequest.Timeout = $TimeoutSeconds * 1000
                    $redirectRequest.ReadWriteTimeout = $TimeoutSeconds * 1000
                    $redirectRequest.UserAgent = $UserAgent
                    $redirectRequest.AllowAutoRedirect = $false

                    try {
                        $redirectResponse = $redirectRequest.GetResponse()
                        # 200 OK from redirect target - could be Forms auth (login page) or Windows Integrated Auth (Kerberos)
                        if ($redirectResponse) {
                            $redirectStatusCode = [int]$redirectResponse.StatusCode
                            if ($redirectStatusCode -eq 200) {
                                # Check for WWW-Authenticate header first (may indicate Windows Integrated Auth succeeded)
                                $redirectAuth = $redirectResponse.Headers['WWW-Authenticate']
                                if ($redirectAuth) {
                                    $endpointResult.AuthMethods = Parse-WWWAuthenticateHeader -HeaderValue $redirectAuth
                                    Write-Log "[Test-ExchangeEndpoint] ${EndpointName}: Redirect target returns 200 OK with auth header: $($endpointResult.AuthMethods -join ', ')"
                                }
                                else {
                                    # No WWW-Authenticate header with 200 OK typically indicates Forms-based authentication
                                    $endpointResult.AuthMethods = @('Forms')
                                    Write-Log "[Test-ExchangeEndpoint] ${EndpointName}: Redirect target returns 200 OK (Forms-based auth)"
                                }

                                # Extract X-OWA-Version from redirect target response
                                $redirectOWAVersion = $redirectResponse.Headers['X-OWA-Version']
                                if ($redirectOWAVersion -and -not $endpointResult.OWAVersion) {
                                    $endpointResult.OWAVersion = $redirectOWAVersion
                                    Write-Log "[Test-ExchangeEndpoint] ${EndpointName}: OWA version from redirect: $redirectOWAVersion"
                                }
                            }
                            try { $redirectResponse.Close() } catch { }
                            try { $redirectResponse.Dispose() } catch { }
                        }
                    }
                    catch [System.Net.WebException] {
                        $redirectEx = $_.Exception
                        if ($redirectEx.Response) {
                            $redirectAuth = $redirectEx.Response.Headers['WWW-Authenticate']
                            if ($redirectAuth) {
                                $endpointResult.AuthMethods = Parse-WWWAuthenticateHeader -HeaderValue $redirectAuth
                                Write-Log "[Test-ExchangeEndpoint] ${EndpointName}: Got auth methods from redirect target: $($endpointResult.AuthMethods -join ', ')"
                            }

                            # Extract X-OWA-Version from redirect error response (401, 403, etc.)
                            $redirectOWAVersion = $redirectEx.Response.Headers['X-OWA-Version']
                            if ($redirectOWAVersion -and -not $endpointResult.OWAVersion) {
                                $endpointResult.OWAVersion = $redirectOWAVersion
                                Write-Log "[Test-ExchangeEndpoint] ${EndpointName}: OWA version from redirect error response: $redirectOWAVersion"
                            }

                            try { $redirectEx.Response.Close() } catch { }
                            try { $redirectEx.Response.Dispose() } catch { }
                        }
                    }
                }
                catch {
                    Write-Log "[Test-ExchangeEndpoint] ${EndpointName}: Could not follow redirect: $_"
                }
            }
        }
        else {
            # Success (200 OK) - this IS an Exchange endpoint
            $endpointResult.IsExchangeEndpoint = $true

            # Check for WWW-Authenticate header even on 200 OK
            # (Windows Integrated Auth may auto-authenticate and still include the header)
            $wwwAuth = $response.Headers['WWW-Authenticate']
            if ($wwwAuth) {
                $endpointResult.AuthMethods = Parse-WWWAuthenticateHeader -HeaderValue $wwwAuth
                Write-Log "[Test-ExchangeEndpoint] ${EndpointName}: 200 OK with WWW-Authenticate: $($endpointResult.AuthMethods -join ', ')"
            }
        }
    }
    catch [System.Net.WebException] {
        $webEx = $_.Exception
        try {
            if ($webEx.Response) {
                $statusCode = [int]$webEx.Response.StatusCode
                $endpointResult.StatusCode = $statusCode

                # 401 Unauthorized = endpoint exists, requires auth (this IS Exchange)
                # 403 Forbidden = endpoint exists, access denied (this IS Exchange)
                # 440 = Login Timeout (Exchange specific - this IS Exchange)
                if ($statusCode -in @(401, 403, 440)) {
                    $endpointResult.Reachable = $true
                    $endpointResult.IsExchangeEndpoint = $true

                    # Extract WWW-Authenticate header
                    $wwwAuth = $webEx.Response.Headers['WWW-Authenticate']
                    if ($wwwAuth) {
                        $endpointResult.AuthMethods = Parse-WWWAuthenticateHeader -HeaderValue $wwwAuth
                    }

                    # Capture server and version headers
                    $endpointResult.ServerHeader = $webEx.Response.Headers['Server']
                    $endpointResult.OWAVersion = $webEx.Response.Headers['X-OWA-Version']
                }
                # 404 Not Found - Server is reachable but endpoint doesn't exist
                elseif ($statusCode -eq 404) {
                    $endpointResult.Reachable = $true
                    $endpointResult.IsExchangeEndpoint = $false
                    $endpointResult.ServerHeader = $webEx.Response.Headers['Server']
                    Write-Log "[Test-ExchangeEndpoint] ${EndpointName}: HTTP 404 - endpoint not found (server reachable)"
                }
                # 500/502/503 - Server errors indicate the endpoint exists but has issues
                # Still mark as reachable (server responded) but NOT as Exchange endpoint
                elseif ($statusCode -in @(500, 502, 503)) {
                    $endpointResult.Reachable = $true
                    $endpointResult.IsExchangeEndpoint = $false
                    $endpointResult.ServerHeader = $webEx.Response.Headers['Server']
                    Write-Log "[Test-ExchangeEndpoint] ${EndpointName}: Server error (HTTP $statusCode) - endpoint may exist but has issues"
                }
                # 301/302 Redirect - need to validate WHERE it redirects to
                elseif ($statusCode -in @(301, 302)) {
                    $endpointResult.Reachable = $true

                    # Get the redirect location
                    $location = $webEx.Response.Headers['Location']
                    $endpointResult.RedirectLocation = $location
                    $endpointResult.ServerHeader = $webEx.Response.Headers['Server']
                    $endpointResult.OWAVersion = $webEx.Response.Headers['X-OWA-Version']

                    # Validate if redirect goes to an Exchange-specific path
                    $isExchangeRedirect = $false
                    if ($location) {
                        Write-Log "[Test-ExchangeEndpoint] ${EndpointName}: Checking redirect location: $location"
                        foreach ($pattern in $exchangeRedirectPatterns) {
                            # Use simple string contains check instead of regex
                            if ($location.ToLower().Contains($pattern.ToLower())) {
                                $isExchangeRedirect = $true
                                Write-Log "[Test-ExchangeEndpoint] ${EndpointName}: Redirect to Exchange path (matched $pattern)"
                                break
                            }
                        }

                        if (-not $isExchangeRedirect) {
                            Write-Log "[Test-ExchangeEndpoint] ${EndpointName}: Redirect to non-Exchange path (load balancer?): $location"
                        }
                    }
                    else {
                        Write-Log "[Test-ExchangeEndpoint] ${EndpointName}: Redirect without Location header"
                    }

                    $endpointResult.IsExchangeEndpoint = $isExchangeRedirect

                    # For real Exchange redirects, try to get auth methods from the redirect target
                    # Note: 302 redirects typically don't have WWW-Authenticate headers themselves
                    if ($isExchangeRedirect -and $location) {
                        # First try to get from this response (unlikely but possible)
                        $wwwAuth = $webEx.Response.Headers['WWW-Authenticate']
                        if ($wwwAuth) {
                            $endpointResult.AuthMethods = Parse-WWWAuthenticateHeader -HeaderValue $wwwAuth
                        }
                        else {
                            # Follow the redirect to get auth methods from the target
                            try {
                                # Build absolute URL if location is relative
                                $redirectUrl = $location
                                if ($location -match '^/') {
                                    # Relative path - construct absolute URL
                                    $uri = [System.Uri]$Url
                                    $redirectUrl = "$($uri.Scheme)://$($uri.Host)$location"
                                }

                                $redirectRequest = [System.Net.HttpWebRequest]::Create($redirectUrl)
                                $redirectRequest.Method = 'GET'
                                $redirectRequest.Timeout = $TimeoutSeconds * 1000
                                $redirectRequest.ReadWriteTimeout = $TimeoutSeconds * 1000
                                $redirectRequest.UserAgent = $UserAgent
                                $redirectRequest.AllowAutoRedirect = $false

                                try {
                                    $redirectResponse = $redirectRequest.GetResponse()
                                    # 200 OK - no auth required (unlikely)
                                    if ($redirectResponse) {
                                        try { $redirectResponse.Close() } catch { }
                                        try { $redirectResponse.Dispose() } catch { }
                                    }
                                }
                                catch [System.Net.WebException] {
                                    $redirectEx = $_.Exception
                                    if ($redirectEx.Response) {
                                        $redirectAuth = $redirectEx.Response.Headers['WWW-Authenticate']
                                        if ($redirectAuth) {
                                            $endpointResult.AuthMethods = Parse-WWWAuthenticateHeader -HeaderValue $redirectAuth
                                            Write-Log "[Test-ExchangeEndpoint] ${EndpointName}: Got auth methods from redirect target: $($endpointResult.AuthMethods -join ', ')"
                                        }
                                        try { $redirectEx.Response.Close() } catch { }
                                        try { $redirectEx.Response.Dispose() } catch { }
                                    }
                                }
                            }
                            catch {
                                Write-Log "[Test-ExchangeEndpoint] ${EndpointName}: Could not follow redirect to get auth methods: $_"
                            }
                        }
                    }
                }
            }
        }
        finally {
            # Dispose WebException response
            if ($webEx.Response) {
                try { $webEx.Response.Close() } catch { }
                try { $webEx.Response.Dispose() } catch { }
            }
        }
    }
    catch {
        # Connection failed, timeout, etc. - endpoint not reachable
        Write-Log "[Test-ExchangeEndpoint] ${EndpointName}: Connection failed - $($_.Exception.Message)"
    }
    finally {
        if ($response) {
            try { $response.Close() } catch { }
            try { $response.Dispose() } catch { }
        }
    }

    return $endpointResult
}

#endregion

#region ===== ADCS WEB ENROLLMENT DETECTION =====

<#
.SYNOPSIS
    Internal function to detect ADCS Web Enrollment configuration.
.DESCRIPTION
    Tests for ADCS Certificate Services web enrollment endpoints:
    - /certsrv/ (main web enrollment interface)
    - Tests both HTTP and HTTPS availability
    - Extracts authentication methods from WWW-Authenticate header
    - Detects server type from response headers
.PARAMETER Hostname
    Target ADCS server hostname.
.PARAMETER TimeoutSeconds
    Request timeout.
.PARAMETER UserAgent
    User-Agent header.
.PARAMETER CAName
    Optional CA common name for CES endpoint testing.
    If provided, the CES URL will be constructed as: https://<hostname>/<CAName>_CES_Kerberos/service.svc
.RETURNS
    PSCustomObject with availability and configuration details.
#>
function Invoke-ADCSScanInternal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Hostname,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds = 5,

        [Parameter(Mandatory = $false)]
        [string]$UserAgent,

        [Parameter(Mandatory = $false)]
        [string]$CAName,

        [Parameter(Mandatory = $false)]
        [switch]$TestEPA
    )

    # Normalize hostname - extract FQDN only (remove protocol, path, port if present)
    # Input can be: "ca.contoso.com", "https://ca.contoso.com", "https://ca.contoso.com/certsrv/", "ca.contoso.com:443"
    $targetHost = $Hostname -replace '^https?://', ''  # Remove protocol
    $targetHost = $targetHost -replace '/.*$', ''       # Remove path and everything after first /
    $targetHost = $targetHost -replace ':\d+$', ''      # Remove port number
    $targetHost = $targetHost.Trim()

    $result = [PSCustomObject]@{
        Success          = $false
        Hostname         = $targetHost  # Return normalized hostname (FQDN only)
        HttpAvailable    = $false
        HttpsAvailable   = $false
        HttpStatusCode   = $null
        HttpsStatusCode  = $null
        ServerHeader     = $null
        # Per-endpoint availability, auth methods, and EPA status
        # EPA is tested per endpoint because IIS allows different EPA settings per virtual directory
        Endpoints        = [PSCustomObject]@{
            CertSrv      = [PSCustomObject]@{ Available = $false; AuthMethods = ''; EPAEnabled = $null; EPAConfidence = $null }  # /certsrv/
            CEP          = [PSCustomObject]@{ Available = $false; AuthMethods = ''; EPAEnabled = $null; EPAConfidence = $null }  # /ADPolicyProvider_CEP_*/
            CES          = [PSCustomObject]@{ Available = $false; AuthMethods = ''; EPAEnabled = $null; EPAConfidence = $null }  # /<CAName>_CES_*/
            NDES         = [PSCustomObject]@{ Available = $false; AuthMethods = ''; EPAEnabled = $null; EPAConfidence = $null }  # /CertSrv/mscep/
        }
        # Legacy EPA properties (for backward compatibility) - reflects first endpoint with NTLM
        EPAEnabled       = $null         # $true = EPA active (secure), $false = EPA not active (ESC8 vulnerable), $null = not tested
        EPAConfidence    = $null         # "High", "Medium", "Low", "Unknown"
        EPADiagnostic    = $null         # Diagnostic info for EPA test
        # NTLM information from Type2 challenge (populated when -TestEPA is used)
        NTLMInfo         = $null         # PSCustomObject with NTLM details from first successful EPA test
        Error            = $null
    }

    # Validate hostname
    if ([string]::IsNullOrWhiteSpace($targetHost)) {
        $result.Error = "Invalid or empty hostname"
        return $result
    }

    # Validate and sanitize CAName if provided (prevent path traversal and injection)
    $sanitizedCAName = $null
    if ($CAName) {
        # CA names should only contain alphanumeric, spaces, hyphens, and underscores
        # Reject anything that looks like path traversal or URL encoding
        if ($CAName -match '[/\\%<>"|?*:]' -or $CAName -match '\.\.') {
            Write-Log "[ScanADCS] WARNING: Invalid CAName '$CAName' - contains forbidden characters, skipping CES tests"
            $sanitizedCAName = $null
        }
        else {
            # URL-encode the CA name for safe use in URLs (handles spaces, etc.)
            $sanitizedCAName = [System.Uri]::EscapeDataString($CAName)
            Write-Log "[ScanADCS] Using CA name: $CAName (encoded: $sanitizedCAName)"
        }
    }

    Write-Log "[ScanADCS] Testing ADCS Web Enrollment for: $targetHost"

    # Track if server is reachable at all (for skip logic)
    $serverReachable = $false

    # ===== Test 1: HTTPS /certsrv/ =====
    $httpsUrl = "https://$targetHost/certsrv/"
    Write-Log "[ScanADCS] Testing HTTPS CertSrv: $httpsUrl"

    $httpsResult = Test-ADCSEndpoint -Url $httpsUrl -EndpointName "CertSrv" -TimeoutSeconds $TimeoutSeconds -UserAgent $UserAgent
    if ($httpsResult.Reachable) {
        $serverReachable = $true
    }
    if ($httpsResult.IsADCSEndpoint) {
        $result.HttpsAvailable = $true
        $result.HttpsStatusCode = $httpsResult.StatusCode
        $result.Success = $true
        $result.Endpoints.CertSrv.Available = $true
        $result.Endpoints.CertSrv.AuthMethods = $httpsResult.AuthMethods -join ', '

        if ($httpsResult.ServerHeader) {
            $result.ServerHeader = $httpsResult.ServerHeader
        }

        Write-Log "[ScanADCS] CertSrv HTTPS available (HTTP $($httpsResult.StatusCode)), Auth: $($httpsResult.AuthMethods -join ', ')"
    }
    elseif ($httpsResult.Reachable) {
        Write-Log "[ScanADCS] CertSrv HTTPS responded but is not ADCS (likely load balancer redirect)"
    }

    # ===== Test 2: HTTP /certsrv/ =====
    $httpUrl = "http://$targetHost/certsrv/"
    Write-Log "[ScanADCS] Testing HTTP CertSrv: $httpUrl"

    $httpResult = Test-ADCSEndpoint -Url $httpUrl -EndpointName "CertSrv" -TimeoutSeconds $TimeoutSeconds -UserAgent $UserAgent
    if ($httpResult.Reachable) {
        $serverReachable = $true
    }
    if ($httpResult.IsADCSEndpoint) {
        $result.HttpAvailable = $true
        $result.HttpStatusCode = $httpResult.StatusCode
        $result.Success = $true
        $result.Endpoints.CertSrv.Available = $true

        # Update auth methods if not already set from HTTPS
        if ([string]::IsNullOrEmpty($result.Endpoints.CertSrv.AuthMethods) -and $httpResult.AuthMethods.Count -gt 0) {
            $result.Endpoints.CertSrv.AuthMethods = $httpResult.AuthMethods -join ', '
        }
        if (-not $result.ServerHeader -and $httpResult.ServerHeader) {
            $result.ServerHeader = $httpResult.ServerHeader
        }

        Write-Log "[ScanADCS] CertSrv HTTP available (HTTP $($httpResult.StatusCode)), Auth: $($httpResult.AuthMethods -join ', ')"
    }
    elseif ($httpResult.Reachable) {
        Write-Log "[ScanADCS] CertSrv HTTP responded but is not ADCS (likely load balancer redirect)"
    }

    # ===== Test 3 & 4: Additional endpoints (only if server is reachable) =====
    # Skip CEP/CES/NDES tests if server not reachable at all
    # This avoids unnecessary timeouts against offline servers
    if ($serverReachable) {
        # ===== Test 3: CEP (Certificate Enrollment Policy) - HTTPS only =====
        # Default pattern: /ADPolicyProvider_CEP_Kerberos/service.svc
        $cepUrl = "https://$targetHost/ADPolicyProvider_CEP_Kerberos/service.svc"
        Write-Log "[ScanADCS] Testing CEP: $cepUrl"

        $cepResult = Test-ADCSEndpoint -Url $cepUrl -EndpointName "CEP" -TimeoutSeconds $TimeoutSeconds -UserAgent $UserAgent
        if ($cepResult.IsADCSEndpoint) {
            $result.Endpoints.CEP.Available = $true
            $result.Endpoints.CEP.AuthMethods = $cepResult.AuthMethods -join ', '
            $result.Success = $true
            Write-Log "[ScanADCS] CEP available (HTTP $($cepResult.StatusCode)), Auth: $($cepResult.AuthMethods -join ', ')"
        }
        elseif ($cepResult.Reachable) {
            Write-Log "[ScanADCS] CEP responded but is not ADCS (likely load balancer redirect)"
        }

        # ===== Test 4: CES (Certificate Enrollment Service) - requires CAName =====
        # CES URL pattern: /<CAName>_CES_<AuthType>/service.svc
        # Only test if CAName parameter is provided and validated
        if ($sanitizedCAName) {
            $cesUrl = "https://$targetHost/${sanitizedCAName}_CES_Kerberos/service.svc"
            Write-Log "[ScanADCS] Testing CES: $cesUrl"

            $cesResult = Test-ADCSEndpoint -Url $cesUrl -EndpointName "CES" -TimeoutSeconds $TimeoutSeconds -UserAgent $UserAgent
            if ($cesResult.IsADCSEndpoint) {
                $result.Endpoints.CES.Available = $true
                $result.Endpoints.CES.AuthMethods = $cesResult.AuthMethods -join ', '
                $result.Success = $true
                Write-Log "[ScanADCS] CES available (HTTP $($cesResult.StatusCode)), Auth: $($cesResult.AuthMethods -join ', ')"
            }
            elseif ($cesResult.Reachable) {
                Write-Log "[ScanADCS] CES responded but is not ADCS (likely load balancer redirect)"
            }
        } else {
            Write-Log "[ScanADCS] Skipping CES test - CAName parameter not provided"
        }

        # ===== Test 5: NDES (Network Device Enrollment Service) - HTTPS first, then HTTP =====
        $ndesUrl = "https://$targetHost/CertSrv/mscep/"
        Write-Log "[ScanADCS] Testing NDES HTTPS: $ndesUrl"

        $ndesResult = Test-ADCSEndpoint -Url $ndesUrl -EndpointName "NDES" -TimeoutSeconds $TimeoutSeconds -UserAgent $UserAgent
        if ($ndesResult.IsADCSEndpoint) {
            $result.Endpoints.NDES.Available = $true
            $result.Endpoints.NDES.AuthMethods = $ndesResult.AuthMethods -join ', '
            $result.Success = $true
            Write-Log "[ScanADCS] NDES HTTPS available (HTTP $($ndesResult.StatusCode)), Auth: $($ndesResult.AuthMethods -join ', ')"
        }
        elseif ($ndesResult.Reachable) {
            Write-Log "[ScanADCS] NDES HTTPS responded but is not ADCS (likely load balancer redirect)"
        }

        # Try HTTP fallback for NDES if HTTPS didn't find it
        if (-not $result.Endpoints.NDES.Available) {
            $ndesHttpUrl = "http://$targetHost/CertSrv/mscep/"
            Write-Log "[ScanADCS] Testing NDES HTTP fallback: $ndesHttpUrl"

            $ndesHttpResult = Test-ADCSEndpoint -Url $ndesHttpUrl -EndpointName "NDES" -TimeoutSeconds $TimeoutSeconds -UserAgent $UserAgent
            if ($ndesHttpResult.IsADCSEndpoint) {
                $result.Endpoints.NDES.Available = $true
                $result.Endpoints.NDES.AuthMethods = $ndesHttpResult.AuthMethods -join ', '
                $result.Success = $true
                Write-Log "[ScanADCS] NDES HTTP available (HTTP $($ndesHttpResult.StatusCode)), Auth: $($ndesHttpResult.AuthMethods -join ', ')"
            }
        }
    } else {
        Write-Log "[ScanADCS] Skipping CEP/CES/NDES tests - server not reachable"
    }

    # Set error if nothing found
    if (-not $result.Success) {
        $result.Error = "No ADCS web enrollment endpoints found (server may be offline or not running ADCS web services)"
    }

    # Log summary of available endpoints with their auth methods
    $availableEndpoints = @()
    foreach ($ep in @('CertSrv', 'CEP', 'CES', 'NDES')) {
        if ($result.Endpoints.$ep.Available) {
            $authStr = if ($result.Endpoints.$ep.AuthMethods) { " ($($result.Endpoints.$ep.AuthMethods))" } else { "" }
            $availableEndpoints += "$ep$authStr"
        }
    }
    if ($availableEndpoints.Count -gt 0) {
        Write-Log "[ScanADCS] Detection complete - Available endpoints: $($availableEndpoints -join ', ')"
    } else {
        Write-Log "[ScanADCS] Detection complete - No ADCS endpoints found"
    }

    # ===== Extended Protection for Authentication (EPA) Test =====
    # Test EPA for EACH endpoint separately because IIS allows different EPA settings per virtual directory
    # Only test if:
    # 1. -TestEPA switch is specified
    # 2. HTTPS is available (EPA only applies to TLS connections)
    # 3. NTLM is in the authentication methods (EPA binds NTLM to TLS channel)
    if ($TestEPA -and $result.Success) {
        Write-Log "[ScanADCS] Testing Extended Protection for Authentication (EPA) per endpoint..."

        # Use longer timeout for EPA test (NTLM handshake needs more time)
        $epaTimeout = [Math]::Max($TimeoutSeconds, 10)

        # Track if we've set the legacy EPA properties (first endpoint with NTLM)
        $legacyEPASet = $false

        # Test EPA for each available endpoint with NTLM over HTTPS
        foreach ($ep in @('CertSrv', 'CEP', 'CES', 'NDES')) {
            if ($result.Endpoints.$ep.Available -and $result.Endpoints.$ep.AuthMethods -match 'NTLM') {
                # Build test URL based on endpoint
                # CES URL requires the CA name which can be passed via -CAName parameter
                # The pattern is: <CAName>_CES_<AuthType>/service.svc
                $epaTestUrl = switch ($ep) {
                    'CertSrv' { "https://$targetHost/certsrv/" }
                    'CEP' { "https://$targetHost/ADPolicyProvider_CEP_Kerberos/service.svc" }
                    'CES' {
                        if ($sanitizedCAName) {
                            "https://$targetHost/${sanitizedCAName}_CES_Kerberos/service.svc"
                        } else {
                            $null  # Cannot construct CES URL without validated CA name
                        }
                    }
                    'NDES' { "https://$targetHost/CertSrv/mscep/" }
                }

                # Skip if we couldn't construct the URL (e.g., CES without CAName)
                if (-not $epaTestUrl) {
                    Write-Log "[ScanADCS] Skipping EPA test for $ep - URL cannot be determined without CA name parameter"
                    continue
                }

                Write-Log "[ScanADCS] Testing EPA for $ep at $epaTestUrl"
                $epaResult = Test-ExtendedProtection -Url $epaTestUrl -TimeoutSeconds $epaTimeout -UserAgent $UserAgent

                # Store EPA result in the endpoint object
                $result.Endpoints.$ep.EPAEnabled = $epaResult.EPAEnabled
                $result.Endpoints.$ep.EPAConfidence = $epaResult.Confidence

                if ($epaResult.Success) {
                    if ($epaResult.EPAEnabled -eq $true) {
                        Write-Log "[ScanADCS] $ep EPA ENABLED ($($epaResult.Confidence) confidence)"
                    }
                    elseif ($epaResult.EPAEnabled -eq $false) {
                        Write-Log "[ScanADCS] $ep EPA DISABLED ($($epaResult.Confidence) confidence) - ESC8 vulnerable!"
                    }
                    else {
                        Write-Log "[ScanADCS] $ep EPA status: $($epaResult.DiagnosticInfo)"
                    }
                }
                else {
                    Write-Log "[ScanADCS] $ep EPA test failed: $($epaResult.ErrorMessage)"
                }

                # Set legacy properties from first endpoint with NTLM (backward compatibility)
                if (-not $legacyEPASet) {
                    $result.EPAEnabled = $epaResult.EPAEnabled
                    $result.EPAConfidence = $epaResult.Confidence
                    $result.EPADiagnostic = $epaResult.DiagnosticInfo

                    # Capture NTLM information from first successful EPA test
                    if ($epaResult.Type2Received) {
                        $result.NTLMInfo = [PSCustomObject]@{
                            NbComputerName  = $epaResult.NbComputerName      # NetBIOS computer name
                            NbDomainName    = $epaResult.NbDomainName        # NetBIOS domain name
                            DnsComputerName = $epaResult.DnsComputerName     # DNS computer name (FQDN)
                            DnsDomainName   = $epaResult.DnsDomainName       # DNS domain name
                            DnsTreeName     = $epaResult.DnsTreeName         # DNS forest name
                            ServerTimestamp = $epaResult.ServerTimestamp     # Server time (DateTime)
                            NTLMChallenge   = $epaResult.NTLMChallenge       # NTLM challenge (hex)
                            SourceEndpoint  = $ep                            # Which endpoint provided this info
                        }
                        Write-Log "[ScanADCS] NTLM Info captured from $ep - Server: $($epaResult.DnsComputerName), Domain: $($epaResult.DnsDomainName)"
                    }

                    $legacyEPASet = $true
                }
            }
        }

        # If no NTLM endpoints found over HTTPS
        if (-not $legacyEPASet) {
            if (-not $result.HttpsAvailable) {
                $result.EPAEnabled = $false
                $result.EPAConfidence = "High"
                $result.EPADiagnostic = "HTTP only - no TLS channel for EPA to bind to"
                Write-Log "[ScanADCS] EPA not applicable - HTTP only (no TLS)"
            }
            else {
                $result.EPADiagnostic = "NTLM not offered over HTTPS - EPA test not applicable"
                Write-Log "[ScanADCS] EPA test skipped - no NTLM over HTTPS"
            }
        }
    }

    return $result
}

<#
.SYNOPSIS
    Tests a single ADCS endpoint for availability and authentication methods.
.DESCRIPTION
    Tests whether an HTTP endpoint is a real ADCS endpoint or just a load balancer redirect.

    Key validation logic for redirects (HTTP 301/302):
    - Load balancers often redirect ALL requests to a login page (generic redirect)
    - Real ADCS redirects go to ADCS-specific paths (e.g., /certsrv/default.asp)
    - We validate the Location header to distinguish between these cases

    ADCS-specific redirect patterns:
    - /certsrv/ (Certificate Services web enrollment)
    - /CertSrv/ (case variations)
    - /ADPolicyProvider_CEP (Certificate Enrollment Policy)
    - /CES_ (Certificate Enrollment Service)
    - /mscep/ (NDES - Network Device Enrollment Service)
#>
function Test-ADCSEndpoint {
    [CmdletBinding()]
    param(
        [string]$Url,
        [string]$EndpointName = "ADCS",
        [int]$TimeoutSeconds,
        [string]$UserAgent
    )

    $endpointResult = [PSCustomObject]@{
        Reachable        = $false      # Server responded (any HTTP response)
        IsADCSEndpoint   = $false      # Confirmed to be ADCS (not a load balancer redirect)
        StatusCode       = $null
        AuthMethods      = @()
        ServerHeader     = $null
        RedirectLocation = $null       # For debugging redirect issues
    }

    # Validate URL before creating WebRequest
    if ([string]::IsNullOrWhiteSpace($Url)) {
        Write-Log "[Test-ADCSEndpoint] ${EndpointName}: Empty URL provided"
        return $endpointResult
    }

    $response = $null

    # Use Script-scope redirect patterns defined at module level
    $adcsRedirectPatterns = $Script:ADCSRedirectPatterns

    try {
        $request = [System.Net.HttpWebRequest]::Create($Url)
        $request.Method = 'GET'
        $request.Timeout = $TimeoutSeconds * 1000
        $request.ReadWriteTimeout = $TimeoutSeconds * 1000
        $request.UserAgent = $UserAgent
        $request.AllowAutoRedirect = $false  # Don't follow redirects to capture auth headers

        $response = $request.GetResponse()
        $statusCode = [int]$response.StatusCode
        $endpointResult.Reachable = $true
        $endpointResult.StatusCode = $statusCode
        $endpointResult.ServerHeader = $response.Headers['Server']

        # Check if this is a redirect (301/302)
        if ($statusCode -in @(301, 302)) {
            $location = $response.Headers['Location']
            $endpointResult.RedirectLocation = $location

            Write-Log "[Test-ADCSEndpoint] ${EndpointName}: Got redirect (HTTP $statusCode), checking location: $location"

            # Validate if redirect goes to an ADCS-specific path
            $isADCSRedirect = $false
            if ($location) {
                foreach ($pattern in $adcsRedirectPatterns) {
                    if ($location.ToLower().Contains($pattern.ToLower())) {
                        $isADCSRedirect = $true
                        Write-Log "[Test-ADCSEndpoint] ${EndpointName}: Redirect to ADCS path (matched $pattern)"
                        break
                    }
                }
                if (-not $isADCSRedirect) {
                    Write-Log "[Test-ADCSEndpoint] ${EndpointName}: Redirect to non-ADCS path: $location"
                }
            }

            $endpointResult.IsADCSEndpoint = $isADCSRedirect
        }
        else {
            # Success (200 OK) - this IS an ADCS endpoint (unusual without auth, but possible)
            $endpointResult.IsADCSEndpoint = $true

            # Check for WWW-Authenticate header even on 200 OK
            # (Windows Integrated Auth may auto-authenticate and still include the header)
            $wwwAuth = $response.Headers['WWW-Authenticate']
            if ($wwwAuth) {
                $endpointResult.AuthMethods = Parse-WWWAuthenticateHeader -HeaderValue $wwwAuth
                Write-Log "[Test-ADCSEndpoint] ${EndpointName}: 200 OK with WWW-Authenticate: $($endpointResult.AuthMethods -join ', ')"
            }
        }
    }
    catch [System.Net.WebException] {
        $webEx = $_.Exception
        try {
            if ($webEx.Response) {
                $statusCode = [int]$webEx.Response.StatusCode
                $endpointResult.StatusCode = $statusCode

                # 401 Unauthorized = endpoint exists, requires auth (expected for certsrv)
                # 403 Forbidden = endpoint exists, access denied (may still have WWW-Authenticate)
                if ($statusCode -in @(401, 403)) {
                    $endpointResult.Reachable = $true

                    # Extract WWW-Authenticate header (contains auth methods)
                    $wwwAuth = $webEx.Response.Headers['WWW-Authenticate']
                    if ($wwwAuth) {
                        $endpointResult.AuthMethods = Parse-WWWAuthenticateHeader -HeaderValue $wwwAuth
                        $endpointResult.IsADCSEndpoint = $true
                    }
                    elseif ($statusCode -eq 403 -and $Url -notmatch '^https://') {
                        # HTTP 403 without WWW-Authenticate on plain HTTP:
                        # IIS returns this when "Require SSL" is configured (IIS sub-code 403.4).
                        # The 403.4 sub-code only appears in IIS server logs - the HTTP response
                        # itself only carries a plain 403 with no auth challenge and no SSL hint header.
                        # In this case the endpoint is NOT actually accessible via HTTP - mark as
                        # reachable (server responded) but NOT as an ADCS endpoint.
                        $endpointResult.IsADCSEndpoint = $false
                        Write-Log "[Test-ADCSEndpoint] ${EndpointName}: HTTP 403 without WWW-Authenticate on plain HTTP - likely IIS 403.4 (SSL Required), not counting as HTTP-available"
                    }
                    else {
                        # HTTPS 403 without WWW-Authenticate, or any other 403 with auth:
                        # Still an ADCS endpoint (auth required via TLS)
                        $endpointResult.IsADCSEndpoint = $true
                        Write-Log "[Test-ADCSEndpoint] ${EndpointName}: HTTP $statusCode without WWW-Authenticate (HTTPS or unknown context)"
                    }

                    # Capture server header
                    $endpointResult.ServerHeader = $webEx.Response.Headers['Server']
                }
                # 404 Not Found - Server is reachable but endpoint doesn't exist
                elseif ($statusCode -eq 404) {
                    $endpointResult.Reachable = $true
                    $endpointResult.IsADCSEndpoint = $false
                    $endpointResult.ServerHeader = $webEx.Response.Headers['Server']
                    Write-Log "[Test-ADCSEndpoint] ${EndpointName}: HTTP 404 - endpoint not found (server reachable)"
                }
                # 500/502/503 - Server errors indicate the endpoint exists but has issues
                # Still mark as reachable (server responded) but NOT as ADCS endpoint
                elseif ($statusCode -in @(500, 502, 503)) {
                    $endpointResult.Reachable = $true
                    $endpointResult.IsADCSEndpoint = $false
                    $endpointResult.ServerHeader = $webEx.Response.Headers['Server']
                    Write-Log "[Test-ADCSEndpoint] ${EndpointName}: Server error (HTTP $statusCode) - endpoint may exist but has issues"
                }
                # 301/302 Redirect - need to validate WHERE it redirects to
                elseif ($statusCode -in @(301, 302)) {
                    $endpointResult.Reachable = $true

                    # Get the redirect location
                    $location = $webEx.Response.Headers['Location']
                    $endpointResult.RedirectLocation = $location
                    $endpointResult.ServerHeader = $webEx.Response.Headers['Server']

                    Write-Log "[Test-ADCSEndpoint] ${EndpointName}: Got redirect (HTTP $statusCode), checking location: $location"

                    # Validate if redirect goes to an ADCS-specific path
                    $isADCSRedirect = $false
                    if ($location) {
                        foreach ($pattern in $adcsRedirectPatterns) {
                            if ($location.ToLower().Contains($pattern.ToLower())) {
                                $isADCSRedirect = $true
                                Write-Log "[Test-ADCSEndpoint] ${EndpointName}: Redirect to ADCS path (matched $pattern)"
                                break
                            }
                        }
                        if (-not $isADCSRedirect) {
                            Write-Log "[Test-ADCSEndpoint] ${EndpointName}: Redirect to non-ADCS path (load balancer?): $location"
                        }
                    }

                    $endpointResult.IsADCSEndpoint = $isADCSRedirect

                    # For real ADCS redirects, try to get auth methods from the redirect target
                    if ($isADCSRedirect -and $location) {
                        $wwwAuth = $webEx.Response.Headers['WWW-Authenticate']
                        if ($wwwAuth) {
                            $endpointResult.AuthMethods = Parse-WWWAuthenticateHeader -HeaderValue $wwwAuth
                        }
                    }
                }
            }
        }
        finally {
            # Dispose WebException response (both Close and Dispose)
            if ($webEx.Response) {
                try { $webEx.Response.Close() } catch { }
                try { $webEx.Response.Dispose() } catch { }
            }
        }
    }
    catch {
        Write-Log "[Test-ADCSEndpoint] ${EndpointName}: Error testing ${Url}: $_"
    }
    finally {
        if ($response) {
            try { $response.Close() } catch { }
            try { $response.Dispose() } catch { }
        }
    }

    return $endpointResult
}

<#
.SYNOPSIS
    Parses WWW-Authenticate header value and extracts authentication methods.
.DESCRIPTION
    Handles the complexities of WWW-Authenticate header parsing:
    - Multiple schemes in one header (comma-separated)
    - Schemes with parameters (e.g., 'Digest realm="test", qop=auth')
    - Multiple headers combined by WebHeaderCollection
    - NTLM/Negotiate with Base64 blob data (e.g., 'NTLM TlRMTVNT...')
    - Case-insensitive matching for scheme names
#>
function Parse-WWWAuthenticateHeader {
    [CmdletBinding()]
    param(
        [string]$HeaderValue
    )

    $authMethods = @()

    if ([string]::IsNullOrWhiteSpace($HeaderValue)) {
        return $authMethods
    }

    # Known authentication schemes (order matters - check specific schemes first)
    $knownSchemes = @('Negotiate', 'NTLM', 'Basic', 'Digest', 'Kerberos', 'Bearer')

    # Handle multiple comma-separated schemes and schemes with Base64 blobs
    # WWW-Authenticate can look like:
    # - "Negotiate, NTLM" (multiple schemes)
    # - "NTLM TlRMTVNTUAACAA..." (scheme with Base64 blob - Type2 challenge)
    # - "Negotiate TlRMTVNTUA..." (Negotiate with NTLM blob)
    # - "Digest realm=..., qop=auth" (scheme with parameters)

    foreach ($scheme in $knownSchemes) {
        # Case-insensitive match for scheme name
        # Pattern matches:
        # 1. Scheme at start of string: "NTLM ..." or "NTLM,"
        # 2. Scheme after comma/space: ", NTLM" or " NTLM"
        # 3. Scheme followed by space (blob), comma (next scheme), equals (params), or end
        # The negative lookbehind (?<![A-Za-z]) prevents matching "NTLM" inside "XNTLM" or similar
        if ($HeaderValue -imatch "(?:^|[\s,])$scheme(?:\s+[A-Za-z0-9+/=]+)?(?:[\s,]|$)") {
            $authMethods += $scheme
        }
        # Also check for scheme followed immediately by space and base64 blob (common for NTLM Type2)
        elseif ($HeaderValue -imatch "(?:^|[\s,])$scheme\s+[A-Za-z0-9+/]{10,}") {
            $authMethods += $scheme
        }
    }

    # If no known schemes found but header is not empty, log for debugging
    if ($authMethods.Count -eq 0 -and $HeaderValue.Length -gt 0) {
        Write-Log "[Parse-WWWAuthenticateHeader] Unknown auth header format: $($HeaderValue.Substring(0, [Math]::Min(50, $HeaderValue.Length)))..."
    }

    return $authMethods | Select-Object -Unique
}

#endregion
