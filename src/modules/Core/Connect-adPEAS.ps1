function Connect-adPEAS {
<#
.SYNOPSIS
    Central authentication function for adPEAS v2.

.DESCRIPTION
    Unified entry point for all authentication methods in adPEAS v2.
    Supports various authentication mechanisms:
    - Windows Authentication (Current User Context)
    - PSCredential Object (classic)
    - Username/Password (Convenience)
    - PKINIT Certificate-based (Kerberos)
    - Pass-the-Cert / Schannel (LDAPS with client certificate, no Kerberos)
    - NT-Hash (Overpass-the-Hash)
    - AES256 Key (Pass-the-Key)
    - AES128 Key (Pass-the-Key)
    - Kirbi Ticket File (.kirbi)
    - Ccache Ticket File (.ccache)

    KERBEROS BY DEFAULT:
    All authentication methods attempt Kerberos first (TGT ? TGS ? PTT), with automatic fallback to SimpleBind/NTLM if Kerberos fails.
    Use -ForceSimpleBind to skip Kerberos entirely.
    Use -ForceKerberos to fail if Kerberos is unavailable.

    This function:
    - Automatically selects the correct auth method based on parameters
    - Attempts Kerberos authentication first (imports ticket into session)
    - Falls back to SimpleBind/NTLM if Kerberos fails
    - Establishes LDAP/LDAPS connection
    - Validates the connection with a test query
    - Displays login status and session information

    IMPORTANT: Domain parameter is ALWAYS required (explicit intention)!

.PARAMETER Domain
    The target domain (FQDN).
    MANDATORY - Explicit specification required for security tool.

.PARAMETER Server
    Specific Domain Controller (FQDN or IP).
    Optional - Default: Automatic via Domain

.PARAMETER UseWindowsAuth
    Uses Windows Authentication (current user context).
    Parameter-Set: WindowsAuth

.PARAMETER Credential
    PSCredential object for alternative authentication.
    Parameter-Set: PSCredential

.PARAMETER Username
    Username for authentication.
    Format: "domain\username" or "username@domain.com"
    Parameter-Set: UsernamePassword

.PARAMETER Password
    Password for authentication (SecureString or plain text).
    Parameter-Set: UsernamePassword
    Optional - Allows empty passwords for accounts with PASSWD_NOTREQD flag (userAccountControl 0x0020)

.PARAMETER Certificate
    Path to PKCS#12 certificate (.pfx/.p12) OR Base64-encoded PFX data for PKINIT authentication.
    The function auto-detects whether the input is Base64 or a file path.
    Parameter-Set: Certificate

.PARAMETER CertificatePassword
    Password for the certificate (SecureString or plain text).
    Parameter-Set: Certificate
    Optional - Default: empty string (for unprotected PFX files)

.PARAMETER ForcePassTheCert
    Use Schannel (TLS client certificate) authentication instead of PKINIT (Kerberos).
    The certificate is presented directly in the TLS handshake to LDAPS (port 636).
    Parameter-Set: Certificate

    Advantages over PKINIT:
    - Works when port 88 (Kerberos) is blocked (SOCKS proxy, SSH tunnel, firewall)
    - No PTT injection needed (no LSA API call, no admin rights)
    - Works with certificates without Smart Card Logon EKU (e.g., from ESC8 relay)
    - Immune to LDAP Channel Binding and Signing requirements (TLS provides both)

    LDAPS is automatically enabled when -ForcePassTheCert is used.

.PARAMETER NTHash
    NT-Hash (NTLM hash) for Overpass-the-Hash authentication.
    Format: 32 hex characters (e.g., "32ED87BDB5FDC5E9CBA88547376818D4")
    Parameter-Set: NTHash
    Requires: -Username

    Primary: Kerberos TGT + TGS for LDAP + Pass-the-Ticket
    No fallback: requires Kerberos (port 88 must be reachable)

.PARAMETER AES256Key
    AES256 key for Pass-the-Key authentication.
    Format: 64 hex characters
    Parameter-Set: AES256
    Requires: -Username

    Primary: Kerberos TGT + TGS for LDAP + Pass-the-Ticket
    No fallback: requires Kerberos (port 88 must be reachable)

.PARAMETER AES128Key
    AES128 key for Pass-the-Key authentication.
    Format: 32 hex characters
    Parameter-Set: AES128
    Requires: -Username

    Primary: Kerberos TGT + TGS for LDAP + Pass-the-Ticket
    No fallback: requires Kerberos (port 88 must be reachable)

.PARAMETER Kirbi
    Path to a .kirbi file OR Base64-encoded kirbi data containing a Kerberos ticket (TGT or TGS).
    The function auto-detects whether the input is Base64 or a file path.
    Parameter-Set: Kirbi

    Uses Pass-the-Ticket to import the ticket into the Windows session.
    This is for tickets exported by tools like Rubeus, Mimikatz, or adPEAS.
    No fallback available - requires valid ticket data.

.PARAMETER Ccache
    Path to a .ccache file OR Base64-encoded ccache data containing a Kerberos ticket.
    The function auto-detects whether the input is Base64 or a file path.
    Parameter-Set: Ccache

    Uses Pass-the-Ticket to import the ticket into the Windows session.
    This is for tickets from Linux systems (MIT Kerberos format).
    No fallback available - requires valid ticket data.

.PARAMETER ForceNTLM
    Force NTLM impersonation, skipping Kerberos entirely.
    Only available for Username/Password and PSCredential authentication.

    This method uses LogonUser() with LOGON32_LOGON_NEW_CREDENTIALS (similar to "runas /netonly"):
    - Does NOT modify the Kerberos ticket cache
    - Original Kerberos tickets remain intact
    - Network operations use NTLM Challenge/Response authentication
    - Supports LDAP Signing (unlike SimpleBind)
    - Works even when LDAP Signing is enforced on the DC

    Advantages over SimpleBind:
    - Credentials never sent in clear text
    - LDAP Signing is supported
    - No LDAPS required for security

    Disadvantages:
    - Only works with Username/Password (not Hash/Key/Cert)
    - NTLM may be disabled in hardened environments

.PARAMETER ForceSimpleBind
    Force SimpleBind authentication, skipping Kerberos entirely.
    Applies to ALL authentication methods (Password, PSCredential, WindowsAuth, Hash/Key).
    Useful when Kerberos is known to be unavailable or port 88 is blocked.

.PARAMETER ForceKerberos
    Force Kerberos authentication without fallback.
    If Kerberos fails, the connection fails completely (no SimpleBind/NTLM fallback).
    Applies to ALL authentication methods.
    Use this when you require Kerberos specifically (e.g., for security reasons).

.PARAMETER BuildCompletionCache
    Build tab-completion cache for Get-Domain* functions.
    Queries AD for all Users, Computers, Groups, and GPOs and caches their names.
    Enables tab-completion for -Identity parameter in Get-DomainUser, Get-DomainComputer, Get-DomainGroup, and Get-DomainGPO functions.

    Note: Initial cache build may take a few seconds depending on domain size.
    Cache is stored in memory and cleared when PowerShell session ends.

    Example usage after connection:
    - Get-DomainUser -Identity adm[TAB] -> Get-DomainUser -Identity "administrator"
    - Get-DomainGPO -Identity Def[TAB] -> Get-DomainGPO -Identity "Default Domain Policy"

.PARAMETER UseLDAPS
    Forces LDAPS (no fallback to LDAP).

.PARAMETER IgnoreSSLErrors
    Ignores SSL certificate errors for LDAPS connections (self-signed certs, expired certs, hostname mismatches, untrusted CAs, etc.).
    Default: $true (for maximum compatibility in pentesting environments)
    Can be explicitly disabled with -IgnoreSSLErrors:$false

    Uses LdapConnection.SessionOptions.VerifyServerCertificate callback to bypass all certificate validation when enabled.
    This covers all SSL/TLS error types including name mismatches (e.g., connecting via IP when cert has FQDN).

.PARAMETER DnsServer
    Custom DNS server to use for resolving AD hostnames.
    Essential for non-domain-joined systems or VPN scenarios where system DNS cannot resolve the target AD domain.

    When specified:
    - DC hostname resolution uses this DNS server
    - Resolved IPs are cached for SMB operations
    - System DNS is used as fallback if custom DNS fails

    Example: -DnsServer "10.10.10.1"

.PARAMETER PatchHostsFile
    Automatically add resolved hostnames to Windows hosts file.
    Requires Administrator privileges.

    This enables full system-wide DNS resolution for AD hostnames, including Kerberos SPN resolution and SMB share access.

    Entries are automatically cleaned up by Disconnect-adPEAS.
    WARNING: Modifies system hosts file. Use with caution in production environments.

.PARAMETER TimeoutSeconds
    Timeout in seconds for LDAP operations.
    Default: 30 seconds
    Valid range: 5-600 seconds. Increase for high-latency connections (SOCKS tunnels, VPN).
    Example: -TimeoutSeconds 120

    Lower values = faster failure detection (useful for fast networks)
    Higher values = more tolerance for slow/high-latency networks

    Example: -TimeoutSeconds 10 (for fast local networks)
    Example: -TimeoutSeconds 60 (for slow VPN connections)

.EXAMPLE
    Connect-adPEAS -Domain "contoso.com" -UseWindowsAuth
    Connects with Windows Authentication (current user).

.EXAMPLE
    Connect-adPEAS -Domain "contoso.com" -Credential (Get-Credential)
    Connects with PSCredential object.

.EXAMPLE
    Connect-adPEAS -Domain "contoso.com" -Username "admin" -Password "P@ssw0rd!"
    Connects with Username/Password.

.EXAMPLE
    Connect-adPEAS -Domain "contoso.com" -Certificate "user.pfx" -CertificatePassword "pass"
    Connects with PKINIT certificate from file (protected PFX).

.EXAMPLE
    Connect-adPEAS -Domain "contoso.com" -Certificate "user.pfx"
    Connects with PKINIT certificate from file (unprotected PFX without password).

.EXAMPLE
    Connect-adPEAS -Domain "contoso.com" -Certificate "MIIKwgYJKoZI..." -CertificatePassword "pass"
    Connects with PKINIT certificate from Base64-encoded PFX data.

.EXAMPLE
    Connect-adPEAS -Domain "contoso.com" -Certificate "user.pfx" -ForcePassTheCert
    Connects with Pass-the-Cert (Schannel) - direct LDAPS bind with client certificate, no Kerberos.
    Works when port 88 is blocked or certificate lacks Smart Card Logon EKU.

.EXAMPLE
    Connect-adPEAS -Domain "contoso.com" -Server "dc01.contoso.com" -Credential $cred
    Connects with specific DC.

.EXAMPLE
    Connect-adPEAS -Domain "contoso.com" -UseWindowsAuth -IgnoreSSLErrors:$false
    Connects with Windows Auth and enforces SSL certificate validation.

.EXAMPLE
    Connect-adPEAS -Domain "contoso.com" -Username "admin" -NTHash "32ED87BDB5FDC5E9CBA88547376818D4"
    Connects using Overpass-the-Hash (Kerberos TGT + LDAP TGS + PTT).
    No fallback - requires Kerberos (port 88 must be reachable).

.EXAMPLE
    Connect-adPEAS -Domain "contoso.com" -Username "admin" -AES256Key "4a3b2c1d5e6f..."
    Connects using Pass-the-Key with AES256.
    No fallback - requires Kerberos (port 88 must be reachable).

.EXAMPLE
    Connect-adPEAS -Domain "contoso.com" -Username "admin" -NTHash "..." -ForceSimpleBind
    Skips Kerberos and connects directly via SimpleBind with the hash.

.EXAMPLE
    Connect-adPEAS -Domain "contoso.com" -Username "admin" -NTHash "..." -ForceKerberos
    Requires Kerberos authentication - fails if Kerberos is unavailable.

.EXAMPLE
    Connect-adPEAS -Domain "contoso.com" -Username "admin" -Password "P@ssw0rd" -ForceNTLM
    Connects using NTLM impersonation (runas /netonly style).
    Does NOT modify Kerberos ticket cache - original tickets remain intact.
    Supports LDAP Signing and works without LDAPS.

.EXAMPLE
    Connect-adPEAS -Domain "contoso.com" -Credential (Get-Credential) -ForceNTLM
    Connects using NTLM impersonation with PSCredential object.

.EXAMPLE
    Connect-adPEAS -Domain "contoso.com" -Kirbi "ticket.kirbi"
    Connects using a .kirbi ticket file (Pass-the-Ticket).

.EXAMPLE
    Connect-adPEAS -Domain "contoso.com" -Kirbi "YIIKwgYJKoZIhvc..."
    Connects using a Base64-encoded kirbi ticket (Pass-the-Ticket).

.EXAMPLE
    Connect-adPEAS -Domain "contoso.com" -Ccache "/tmp/krb5cc_1000"
    Connects using a .ccache ticket file from Linux (Pass-the-Ticket).

.EXAMPLE
    Connect-adPEAS -Domain "contoso.com" -Credential (Get-Credential) -BuildCompletionCache
    Connects and builds tab-completion cache for Get-Domain* functions.
    After connection, use TAB to autocomplete Identity parameters.

.OUTPUTS
    Hashtable with connection details or $null on error

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
    [CmdletBinding(DefaultParameterSetName='WindowsAuth')]
    param(
        [Parameter(Mandatory=$false, ParameterSetName='WindowsAuth')]
        [Parameter(Mandatory=$true, ParameterSetName='PSCredential')]
        [Parameter(Mandatory=$true, ParameterSetName='UsernamePassword')]
        [Parameter(Mandatory=$true, ParameterSetName='Certificate')]
        [Parameter(Mandatory=$true, ParameterSetName='NTHash')]
        [Parameter(Mandatory=$true, ParameterSetName='AES256')]
        [Parameter(Mandatory=$true, ParameterSetName='AES128')]
        [Parameter(Mandatory=$true, ParameterSetName='Kirbi')]
        [Parameter(Mandatory=$true, ParameterSetName='Ccache')]
        [AllowEmptyString()]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [switch]$UseLDAPS,

        [Parameter(Mandatory=$false)]
        [bool]$IgnoreSSLErrors = $true,

        [Parameter(Mandatory=$false)]
        [string]$DnsServer,

        [Parameter(Mandatory=$false)]
        [switch]$PatchHostsFile,

        [Parameter(Mandatory=$false)]
        [switch]$Quiet,

        # Windows Authentication Parameter-Set (Default)
        [Parameter(Mandatory=$false, ParameterSetName='WindowsAuth')]
        [switch]$UseWindowsAuth,

        # PSCredential Parameter-Set
        [Parameter(Mandatory=$true, ParameterSetName='PSCredential')]
        [System.Management.Automation.PSCredential]$Credential,

        # Username/Password Parameter-Set
        # For Certificate: optional override to select identity when cert has multiple SANs
        [Parameter(Mandatory=$true, ParameterSetName='UsernamePassword')]
        [Parameter(Mandatory=$true, ParameterSetName='NTHash')]
        [Parameter(Mandatory=$true, ParameterSetName='AES256')]
        [Parameter(Mandatory=$true, ParameterSetName='AES128')]
        [Parameter(Mandatory=$false, ParameterSetName='Certificate')]
        [Parameter(Mandatory=$false, ParameterSetName='Kirbi')]
        [Parameter(Mandatory=$false, ParameterSetName='Ccache')]
        [AllowEmptyString()]
        [string]$Username,

        [Parameter(Mandatory=$false, ParameterSetName='UsernamePassword')]
        $Password,  # Accepts SecureString or String (allows empty passwords for PASSWD_NOTREQD accounts)

        # Certificate Parameter-Set (PKINIT)
        [Parameter(Mandatory=$true, ParameterSetName='Certificate')]
        [AllowEmptyString()]
        [string]$Certificate,

        [Parameter(Mandatory=$false, ParameterSetName='Certificate')]
        $CertificatePassword = "",  # Accepts SecureString or String. Default: empty (for unprotected PFX)

        # Pass-the-Cert: Use Schannel (TLS client certificate) instead of PKINIT (Kerberos)
        # Bypasses Kerberos entirely - works when port 88 is blocked, no Smart Card Logon EKU needed
        [Parameter(Mandatory=$false, ParameterSetName='Certificate')]
        [switch]$ForcePassTheCert,

        # NTHash Parameter-Set (Overpass-the-Hash)
        [Parameter(Mandatory=$true, ParameterSetName='NTHash')]
        [AllowEmptyString()]
        [string]$NTHash,

        # AES256 Parameter-Set (Pass-the-Key)
        [Parameter(Mandatory=$true, ParameterSetName='AES256')]
        [AllowEmptyString()]
        [string]$AES256Key,

        # AES128 Parameter-Set (Pass-the-Key)
        [Parameter(Mandatory=$true, ParameterSetName='AES128')]
        [AllowEmptyString()]
        [string]$AES128Key,

        # Kirbi Parameter-Set (Ticket File)
        [Parameter(Mandatory=$true, ParameterSetName='Kirbi')]
        [AllowEmptyString()]
        [string]$Kirbi,

        # Ccache Parameter-Set (Ticket File)
        [Parameter(Mandatory=$true, ParameterSetName='Ccache')]
        [AllowEmptyString()]
        [string]$Ccache,

        # Force NTLM Impersonation (only for Username/Password and PSCredential)
        [Parameter(Mandatory=$false, ParameterSetName='PSCredential')]
        [Parameter(Mandatory=$false, ParameterSetName='UsernamePassword')]
        [switch]$ForceNTLM,

        # Force SimpleBind (applies to ALL parameter sets)
        [Parameter(Mandatory=$false, ParameterSetName='WindowsAuth')]
        [Parameter(Mandatory=$false, ParameterSetName='PSCredential')]
        [Parameter(Mandatory=$false, ParameterSetName='UsernamePassword')]
        [Parameter(Mandatory=$false, ParameterSetName='Certificate')]
        [Parameter(Mandatory=$false, ParameterSetName='NTHash')]
        [Parameter(Mandatory=$false, ParameterSetName='AES256')]
        [Parameter(Mandatory=$false, ParameterSetName='AES128')]
        [Parameter(Mandatory=$false, ParameterSetName='Kirbi')]
        [Parameter(Mandatory=$false, ParameterSetName='Ccache')]
        [switch]$ForceSimpleBind,

        # Force Kerberos (no fallback, applies to ALL parameter sets)
        [Parameter(Mandatory=$false, ParameterSetName='WindowsAuth')]
        [Parameter(Mandatory=$false, ParameterSetName='PSCredential')]
        [Parameter(Mandatory=$false, ParameterSetName='UsernamePassword')]
        [Parameter(Mandatory=$false, ParameterSetName='Certificate')]
        [Parameter(Mandatory=$false, ParameterSetName='NTHash')]
        [Parameter(Mandatory=$false, ParameterSetName='AES256')]
        [Parameter(Mandatory=$false, ParameterSetName='AES128')]
        [Parameter(Mandatory=$false, ParameterSetName='Kirbi')]
        [Parameter(Mandatory=$false, ParameterSetName='Ccache')]
        [switch]$ForceKerberos,

        # License file path (applies to ALL parameter sets)
        # Loads license JSON and stores it for disclaimer display by Invoke-adPEAS
        [Parameter(Mandatory=$false, ParameterSetName='WindowsAuth')]
        [Parameter(Mandatory=$false, ParameterSetName='PSCredential')]
        [Parameter(Mandatory=$false, ParameterSetName='UsernamePassword')]
        [Parameter(Mandatory=$false, ParameterSetName='Certificate')]
        [Parameter(Mandatory=$false, ParameterSetName='NTHash')]
        [Parameter(Mandatory=$false, ParameterSetName='AES256')]
        [Parameter(Mandatory=$false, ParameterSetName='AES128')]
        [Parameter(Mandatory=$false, ParameterSetName='Kirbi')]
        [Parameter(Mandatory=$false, ParameterSetName='Ccache')]
        [string]$License,

        # Tab-Completion Cache (applies to ALL parameter sets)
        [Parameter(Mandatory=$false, ParameterSetName='WindowsAuth')]
        [Parameter(Mandatory=$false, ParameterSetName='PSCredential')]
        [Parameter(Mandatory=$false, ParameterSetName='UsernamePassword')]
        [Parameter(Mandatory=$false, ParameterSetName='Certificate')]
        [Parameter(Mandatory=$false, ParameterSetName='NTHash')]
        [Parameter(Mandatory=$false, ParameterSetName='AES256')]
        [Parameter(Mandatory=$false, ParameterSetName='AES128')]
        [Parameter(Mandatory=$false, ParameterSetName='Kirbi')]
        [Parameter(Mandatory=$false, ParameterSetName='Ccache')]
        [switch]$BuildCompletionCache,

        # LDAP Operation Timeout (applies to ALL parameter sets)
        [Parameter(Mandatory=$false)]
        [ValidateRange(5, 600)]
        [int]$TimeoutSeconds = 30
    )

    begin {
        Write-Log "[Connect-adPEAS] Starting authentication process..."

        # ===== License Loading =====
        # Store license JSON for later use by Invoke-adPEAS disclaimer display
        if ($PSBoundParameters.ContainsKey('License') -and $License) {
            if (Test-Path $License -ErrorAction SilentlyContinue) {
                $Script:RuntimeLicense = Get-Content $License -Raw -Encoding UTF8
                Write-Log "[Connect-adPEAS] Loaded runtime license from: $License"
            }
            else {
                Write-Warning "[Connect-adPEAS] License file not found: $License"
            }
        }

        # ===== Automatic Session Cleanup =====
        # Clean up any existing session BEFORE establishing a new one.
        # This is critical for NTLM impersonation which creates a security context that persists until explicitly reverted.
        # Without cleanup, subsequent Connect-adPEAS calls would still run in the old impersonated context.
        $existingSession = $Script:LDAPContext -or $Script:LdapConnection -or
                          ($Script:NTLMTokenHandle -and $Script:NTLMTokenHandle -ne [IntPtr]::Zero)

        if ($existingSession) {
            Write-Log "[Connect-adPEAS] Existing session detected - performing automatic cleanup..."

            # Step 1: Revert NTLM impersonation (MUST be done first!)
            if ($Script:NTLMTokenHandle -and $Script:NTLMTokenHandle -ne [IntPtr]::Zero) {
                Write-Log "[Connect-adPEAS] Reverting existing NTLM impersonation..."
                try {
                    Invoke-RevertToSelf -TokenHandle $Script:NTLMTokenHandle
                    Write-Log "[Connect-adPEAS] NTLM impersonation reverted successfully"
                }
                catch {
                    Write-Log "[Connect-adPEAS] Warning: Failed to revert NTLM impersonation: $_"
                }
                $Script:NTLMTokenHandle = [IntPtr]::Zero
            }

            # Step 2: Dispose LDAP connection
            if ($Script:LdapConnection) {
                try {
                    $Script:LdapConnection.Dispose()
                    Write-Log "[Connect-adPEAS] Previous LdapConnection disposed"
                }
                catch {
                    # Ignore disposal errors (may already be disposed)
                    Write-Log "[Connect-adPEAS] Note: LdapConnection disposal: $_"
                }
            }

            # Step 3: Clean up hosts file entries (if any)
            if ($Script:LDAPContext -and $Script:LDAPContext['HostsEntries'] -and $Script:LDAPContext['HostsEntries'].Count -gt 0) {
                try {
                    $hostsResult = Remove-adPEASHostsEntry
                    if ($hostsResult.Success -and $hostsResult.RemovedCount -gt 0) {
                        Write-Log "[Connect-adPEAS] Cleaned up $($hostsResult.RemovedCount) hosts file entries from previous session"
                    }
                }
                catch {
                    Write-Log "[Connect-adPEAS] Warning: Hosts file cleanup failed: $_"
                }
            }

            # Step 4: Clear all session variables and caches
            $Script:LdapConnection = $null
            $Script:LDAPContext = $null
            $Script:LDAPCredential = $null
            $Script:AuthInfo = $null

            # Clear output file paths (may be stale from previous Invoke-adPEAS)
            $Script:adPEAS_Outputfile = $null
            $Script:HTMLOutputPath = $null

            # Clear caches
            if ($Script:PrivilegedCheckCache) { $Script:PrivilegedCheckCache = @{} }
            if ($Script:SIDResolutionCache) { $Script:SIDResolutionCache = @{} }
            if ($Script:SIDVerboseCache) { $Script:SIDVerboseCache = @{} }
            if ($Script:NameToSIDCache) { $Script:NameToSIDCache = @{} }
            if ($Script:CompletionCache) {
                try { Clear-CompletionCache } catch { }
            }

            Write-Log "[Connect-adPEAS] Previous session cleanup completed"
        }

        # Create readable parameter set name for verbose output
        $ParamSetDisplay = switch ($PSCmdlet.ParameterSetName) {
            'PSCredential' { 'PSCredential Object' }
            'UsernamePassword' { 'Username/Password' }
            'Certificate' { 'Certificate (PKINIT)' }
            'WindowsAuth' { 'Windows Authentication' }
            'NTHash' { 'NT-Hash (Overpass-the-Hash)' }
            'AES256' { 'AES256 Key (Pass-the-Key)' }
            'AES128' { 'AES128 Key (Pass-the-Key)' }
            'Kirbi' { 'Kirbi Ticket File (Pass-the-Ticket)' }
            'Ccache' { 'Ccache Ticket File (Pass-the-Ticket)' }
            default { $PSCmdlet.ParameterSetName }
        }
        Write-Log "[Connect-adPEAS] Parameter Set: $ParamSetDisplay"
    }

    process {
        try {
            # ===== ISE Compatibility Warning =====
            if ($Host.Name -eq 'Windows PowerShell ISE Host') {
                Write-Warning "PowerShell ISE is deprecated and not supported by adPEAS. Console output may be garbled. Use powershell.exe or VS Code instead."
            }

            # ===== Determine Authentication Method =====
            $AuthMethod = $PSCmdlet.ParameterSetName

            # ===== Validate Mutually Exclusive Parameters =====
            if ($ForceNTLM -and $ForceKerberos) {
                Show-ConnectionError -ErrorType "GenericError" -Details "-ForceNTLM and -ForceKerberos are mutually exclusive" -NoThrow
                return $null
            }
            if ($ForceSimpleBind -and $ForceKerberos) {
                Show-ConnectionError -ErrorType "GenericError" -Details "-ForceSimpleBind and -ForceKerberos are mutually exclusive" -NoThrow
                return $null
            }
            if ($ForceNTLM -and $ForceSimpleBind) {
                Show-ConnectionError -ErrorType "GenericError" -Details "-ForceNTLM and -ForceSimpleBind are mutually exclusive" -NoThrow
                return $null
            }

            # ===== Validate Required String Parameters =====
            # [AllowEmptyString()] lets PowerShell accept "" without ugly ParameterBindingValidation errors.
            # We catch empty values here with clean Show-ConnectionError messages instead.
            if ($PSBoundParameters.ContainsKey('Domain') -and [string]::IsNullOrWhiteSpace($Domain)) {
                Show-ConnectionError -ErrorType "GenericError" -Details "Domain name must not be empty" -NoThrow
                return $null
            }
            if ($AuthMethod -in @('UsernamePassword','NTHash','AES256','AES128') -and [string]::IsNullOrWhiteSpace($Username)) {
                Show-ConnectionError -ErrorType "GenericError" -Details "Username must not be empty" -NoThrow
                return $null
            }
            if ($AuthMethod -eq 'Certificate' -and [string]::IsNullOrWhiteSpace($Certificate)) {
                Show-ConnectionError -ErrorType "GenericError" -Details "Certificate path or Base64 string must not be empty" -NoThrow
                return $null
            }
            if ($AuthMethod -eq 'Kirbi' -and [string]::IsNullOrWhiteSpace($Kirbi)) {
                Show-ConnectionError -ErrorType "GenericError" -Details "Kirbi ticket file path or Base64 string must not be empty" -NoThrow
                return $null
            }
            if ($AuthMethod -eq 'Ccache' -and [string]::IsNullOrWhiteSpace($Ccache)) {
                Show-ConnectionError -ErrorType "GenericError" -Details "Ccache ticket file path must not be empty" -NoThrow
                return $null
            }

            # ===== Validate Hash/Key Input =====
            if ($AuthMethod -eq 'NTHash') {
                if ($NTHash -notmatch '^[0-9a-fA-F]{32}$') {
                    $Detail = if ($NTHash.Length -ne 32) { "Expected 32 hex chars, got $($NTHash.Length)" } else { "Contains non-hex characters" }
                    Show-ConnectionError -ErrorType "GenericError" -Details "Invalid NT-Hash format: $Detail" -NoThrow
                    return $null
                }
            }
            elseif ($AuthMethod -eq 'AES256') {
                if ($AES256Key -notmatch '^[0-9a-fA-F]{64}$') {
                    $Detail = if ($AES256Key.Length -ne 64) { "Expected 64 hex chars, got $($AES256Key.Length)" } else { "Contains non-hex characters" }
                    Show-ConnectionError -ErrorType "GenericError" -Details "Invalid AES256 key format: $Detail" -NoThrow
                    return $null
                }
            }
            elseif ($AuthMethod -eq 'AES128') {
                if ($AES128Key -notmatch '^[0-9a-fA-F]{32}$') {
                    $Detail = if ($AES128Key.Length -ne 32) { "Expected 32 hex chars, got $($AES128Key.Length)" } else { "Contains non-hex characters" }
                    Show-ConnectionError -ErrorType "GenericError" -Details "Invalid AES128 key format: $Detail" -NoThrow
                    return $null
                }
            }

            # ===== Initialize Auth Info Tracking =====
            # These will be populated based on actual auth method used
            $Script:AuthInfo = @{
                Method = $null              # 'Kerberos' or 'SimpleBind' or 'WindowsSSPI' or 'NTLM Impersonation'
                ParameterSet = $AuthMethod  # Original parameter set name
                KerberosUsed = $false       # Was Kerberos actually used?
                TGTInfo = $null             # TGT details if Kerberos was used
                NTLMImpersonation = $ForceNTLM.IsPresent  # Track if NTLM impersonation was requested
            }

            # ===== Initialize LDAPContext Early =====
            # Must be done BEFORE any Resolve-adPEASName calls so that UseLDAPS is available
            if (-not $Script:LDAPContext) {
                $Script:LDAPContext = @{}
            }

            # Store UseLDAPS for use by Resolve-adPEASName (DC reachability checks)
            if ($UseLDAPS) {
                $Script:LDAPContext['UseLDAPS'] = $true
                Write-Log "[Connect-adPEAS] LDAPS mode enabled - DC reachability will check port 636"
            }

            # ===== Custom DNS Server Handling =====
            if ($DnsServer) {
                Write-Log "[Connect-adPEAS] Custom DNS server specified: $DnsServer"

                # Store DNS server for use by other functions
                $Script:LDAPContext['DnsServer'] = $DnsServer
                # Use case-insensitive dictionary for DNS cache (hostnames are case-insensitive)
                $Script:LDAPContext['DnsCache'] = [System.Collections.Generic.Dictionary[string,string]]::new([System.StringComparer]::OrdinalIgnoreCase)

                # Validate DNS server can resolve the target domain
                try {
                    $null = Resolve-DnsName -Name $Domain -Server $DnsServer -Type A -DnsOnly -ErrorAction Stop
                    Write-Log "[Connect-adPEAS] Custom DNS server can resolve $Domain"
                }
                catch {
                    Write-Warning "[Connect-adPEAS] DNS server $DnsServer not reachable or cannot resolve '$Domain'"
                }

                # If PatchHostsFile is requested, verify admin privileges
                if ($PatchHostsFile) {
                    $isAdmin = Test-adPEASAdminPrivileges
                    if (-not $isAdmin) {
                        Write-Warning "[Connect-adPEAS] -PatchHostsFile requires Administrator privileges!"
                        Write-Warning "[Connect-adPEAS] Hosts file patching will be skipped. Run as Administrator for full functionality."
                        $PatchHostsFile = $false
                    }
                    else {
                        Write-Log "[Connect-adPEAS] Administrator privileges confirmed for hosts file patching"
                        $Script:LDAPContext['PatchHostsFile'] = $true

                        # ===== EARLY Hosts File Patching =====
                        # Kerberos PTT requires Windows to resolve the DC hostname for SPN matching.
                        # Without hosts file entries, the LDAP connect after PTT fails with "Invalid credentials" because Windows cannot resolve the DC hostname via system DNS.
                        Write-Log "[Connect-adPEAS] Early hosts file patching for Kerberos authentication..."

                        # First, resolve the server/domain to get IP
                        $earlyResolveTarget = if ($Server) { $Server } else { $Domain }
                        $resolvedIP = Resolve-adPEASName -Name $earlyResolveTarget -DnsServer $DnsServer

                        if ($resolvedIP) {
                            $hostsPatched = @()

                            # Patch the server hostname if provided
                            if ($Server) {
                                $patchResult = Add-adPEASHostsEntry -IPAddress $resolvedIP -Hostname $Server -Force
                                if ($patchResult.Success) {
                                    $hostsPatched += $Server
                                    Write-Log "[Connect-adPEAS] Early hosts entry: $resolvedIP -> $Server"
                                }
                                # Brief delay to ensure file handle is fully released before next write
                                Start-Sleep -Milliseconds 50
                            }

                            # Also patch domain name -> DC IP (if different from server)
                            if ($Domain -ne $Server) {
                                $patchResult = Add-adPEASHostsEntry -IPAddress $resolvedIP -Hostname $Domain -Force
                                if ($patchResult.Success) {
                                    $hostsPatched += $Domain
                                    Write-Log "[Connect-adPEAS] Early hosts entry: $resolvedIP -> $Domain"
                                }
                            }

                            # Store for cleanup later
                            $Script:LDAPContext['HostsEntries'] = $hostsPatched
                            $Script:LDAPContext['EarlyHostsPatched'] = $true

                            if ($hostsPatched.Count -gt 0) {
                                Show-Line "Patched hosts file with $($hostsPatched.Count) entries (cleanup on Disconnect-adPEAS)" -Class Info
                            }
                        }
                        else {
                            Write-Warning "[Connect-adPEAS] Could not resolve $earlyResolveTarget via custom DNS - hosts patching skipped"
                        }
                    }
                }
            }

            # ===== Get Domain if not specified (WindowsAuth only) =====
            if ($AuthMethod -eq 'WindowsAuth' -and -not $Domain) {
                try {
                    $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
                    Write-Log "[Connect-adPEAS] No domain specified, using current domain: $Domain"
                } catch {
                    Show-ConnectionError -ErrorType "DomainError" -Details "Specify domain with -Domain parameter" -NoThrow
                    return $null
                }
            }

            Write-Log "[Connect-adPEAS] Establishing connection..."

            # Create readable authentication method name for verbose output
            $AuthMethodDisplay = switch ($AuthMethod) {
                'PSCredential' { 'PSCredential Object' }
                'UsernamePassword' { 'Username/Password' }
                'Certificate' { if ($ForcePassTheCert) { 'Certificate (Pass-the-Cert/Schannel)' } else { 'Certificate (PKINIT)' } }
                'WindowsAuth' { 'Windows Authentication' }
                'NTHash' { 'NT-Hash (Overpass-the-Hash)' }
                'AES256' { 'AES256 Key (Pass-the-Key)' }
                'AES128' { 'AES128 Key (Pass-the-Key)' }
                'Kirbi' { 'Kirbi Ticket File (Pass-the-Ticket)' }
                'Ccache' { 'Ccache Ticket File (Pass-the-Ticket)' }
                default { $AuthMethod }
            }
            Write-Log "[Connect-adPEAS] Authentication Method: $AuthMethodDisplay"

            # ===== Parameter-Set Specific Handling =====
            switch ($AuthMethod) {
                { $_ -in @('PSCredential', 'UsernamePassword') } {
                    # ===== Credential Preparation (auth-method-specific) =====
                    # Both cases produce the same three variables:
                    #   $SamAccountName  - for Kerberos auth
                    #   $PlainPassword   - for Kerberos auth
                    #   $CredObject      - PSCredential for NTLM impersonation and SimpleBind

                    if ($AuthMethod -eq 'PSCredential') {
                        Write-Log "[Connect-adPEAS] Domain: $Domain"
                        if ($Server) { Write-Log "[Connect-adPEAS] Server: $Server" }
                        Write-Log "[Connect-adPEAS] Username: $($Credential.UserName)"

                        # Extract password from credential for Kerberos (with proper memory cleanup)
                        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)
                        try {
                            $PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
                        }
                        finally {
                            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
                        }

                        # Extract sAMAccountName and detect cross-domain authentication
                        $CredUsername = $Credential.UserName
                        $SamAccountName = $CredUsername
                        $UserRealm = $null  # null = same as target domain

                        if ($CredUsername -match '^([^\\]+)\\(.+)$') {
                            $UserDomainPrefix = $Matches[1]
                            $SamAccountName = $Matches[2]

                            # Check if user domain differs from target domain
                            $targetPrefix = ($Domain -split '\.')[0]
                            if ($UserDomainPrefix -ine $targetPrefix -and $UserDomainPrefix -ine $Domain) {
                                $UserRealm = $UserDomainPrefix
                                if ($UserRealm -match '\.') {
                                    Write-Log "[Connect-adPEAS] Cross-domain detected: user in '$UserRealm' (FQDN), target '$Domain'"
                                } else {
                                    Write-Log "[Connect-adPEAS] Cross-domain detected: user in '$UserRealm' (NetBIOS), target '$Domain'"
                                }
                            }
                        }
                        elseif ($CredUsername -match '^(.+)@([^@]+)$') {
                            $SamAccountName = $Matches[1]
                            $upnDomain = $Matches[2]
                            if ($upnDomain -ine $Domain) {
                                $UserRealm = $upnDomain
                                Write-Log "[Connect-adPEAS] Cross-domain detected: user UPN realm '$UserRealm', target '$Domain'"
                            }
                        }

                        $CredObject = $Credential
                    }
                    else {
                        # UsernamePassword
                        Write-Log "[Connect-adPEAS] Domain: $Domain"
                        if ($Server) { Write-Log "[Connect-adPEAS] Server: $Server" }
                        Write-Log "[Connect-adPEAS] Username: $Username"

                        # Convert Password to plain string for Kerberos, SecureString for SimpleBind
                        # Handle various input types: String, SecureString, numeric, or $null (empty password)
                        if ($null -eq $Password -or $Password -eq '') {
                            # Empty password (PASSWD_NOTREQD accounts)
                            $PlainPassword = ""
                            # Create empty SecureString manually (ConvertTo-SecureString rejects empty string in some PS versions)
                            $SecurePassword = New-Object System.Security.SecureString
                            Write-Log "[Connect-adPEAS] Empty password provided (PASSWD_NOTREQD account)"
                        }
                        elseif ($Password -is [string]) {
                            $PlainPassword = $Password
                            $SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
                        }
                        elseif ($Password -is [System.Security.SecureString]) {
                            $SecurePassword = $Password
                            # Extract plain password with proper memory cleanup
                            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
                            try {
                                $PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
                            }
                            finally {
                                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
                            }
                        }
                        elseif ($Password -is [int] -or $Password -is [long] -or $Password -is [double]) {
                            # Numeric password (PowerShell auto-parses "12345" as int) - convert to string
                            $PlainPassword = $Password.ToString()
                            $SecurePassword = ConvertTo-SecureString -String $PlainPassword -AsPlainText -Force
                            Write-Log "[Connect-adPEAS] Password was numeric, converted to string"
                        }
                        else {
                            throw "Password must be either String, SecureString, or empty"
                        }

                        # Normalize Username for credential creation
                        # If no domain prefix/suffix, add NetBIOS domain prefix for SMB compatibility
                        $CredentialUsername = $Username
                        if ($Username -notmatch '\\' -and $Username -notmatch '@') {
                            $NetBIOSDomain = ($Domain -split '\.')[0].ToUpper()
                            $CredentialUsername = "$NetBIOSDomain\$Username"
                            Write-Log "[Connect-adPEAS] Username normalized for SMB: $Username -> $CredentialUsername"
                        }

                        # Create PSCredential for NTLM impersonation and SimpleBind fallback
                        $CredObject = New-Object System.Management.Automation.PSCredential($CredentialUsername, $SecurePassword)

                        # Extract sAMAccountName and detect cross-domain authentication
                        # Cross-domain: user realm differs from target domain (e.g., contoso.com\b.pitt -> dev.contoso.com)
                        $SamAccountName = $Username
                        $UserRealm = $null  # null = same as target domain, set when cross-domain detected

                        if ($Username -match '^([^\\]+)\\(.+)$') {
                            $UserDomainPrefix = $Matches[1]
                            $SamAccountName = $Matches[2]

                            # Check if user domain differs from target domain
                            $targetPrefix = ($Domain -split '\.')[0]
                            if ($UserDomainPrefix -ine $targetPrefix -and $UserDomainPrefix -ine $Domain) {
                                $UserRealm = $UserDomainPrefix
                                if ($UserRealm -match '\.') {
                                    Write-Log "[Connect-adPEAS] Cross-domain detected: user in '$UserRealm' (FQDN), target '$Domain'"
                                } else {
                                    Write-Log "[Connect-adPEAS] Cross-domain detected: user in '$UserRealm' (NetBIOS), target '$Domain'"
                                }
                            }
                        }
                        elseif ($Username -match '^(.+)@([^@]+)$') {
                            $SamAccountName = $Matches[1]
                            $upnDomain = $Matches[2]
                            if ($upnDomain -ine $Domain) {
                                $UserRealm = $upnDomain
                                Write-Log "[Connect-adPEAS] Cross-domain detected: user UPN realm '$UserRealm', target '$Domain'"
                            }
                        }
                    }

                    # ===== Shared Auth Flow: Kerberos -> NTLM Impersonation -> SimpleBind =====

                    # Resolve DC hostname and IP using unified resolver
                    if ($Server) {
                        $ResolvedIP = Resolve-adPEASName -Name $Server
                        $DCResolution = [PSCustomObject]@{ Hostname = $Server; IP = $ResolvedIP }

                        # If explicit -Server was given but DNS fails, terminate immediately
                        # No point trying Kerberos/NTLM/SimpleBind if we can't resolve the server
                        if (-not $ResolvedIP) {
                            Show-ConnectionError -ErrorType "DomainError" -Details "Server '$Server' could not be resolved - check DNS or use an IP address" -NoThrow
                            return $null
                        }
                    } else {
                        $DCResolution = Resolve-adPEASName -Domain $Domain

                        # If domain-based DC discovery fails, terminate immediately
                        if (-not $DCResolution -or -not $DCResolution.Hostname) {
                            Show-ConnectionError -ErrorType "DomainError" -Details "Could not discover a Domain Controller for '$Domain' - DNS resolution failed. Use -Server to specify a DC manually." -NoThrow
                            return $null
                        }
                    }

                    $KerberosAuthSuccess = $false
                    $Connection = $null

                    # ===== Explicit NTLM (if requested) =====
                    if ($ForceNTLM) {
                        Write-Log "[Connect-adPEAS] Using explicit NTLM authentication (AuthType::Ntlm)..."

                        $ConnParams = @{}
                        $ConnParams['Domain'] = $Domain
                        if ($Server) {
                            $ConnParams['Server'] = $Server
                        } elseif ($DCResolution -and $DCResolution.Hostname) {
                            $ConnParams['Server'] = $DCResolution.Hostname
                            Write-Log "[Connect-adPEAS] ForceNTLM: Using discovered DC: $($DCResolution.Hostname)"
                        }
                        if ($UseLDAPS) { $ConnParams['UseLDAPS'] = $true }
                        $ConnParams['IgnoreSSLErrors'] = $IgnoreSSLErrors
                        $ConnParams['TimeoutSeconds'] = $TimeoutSeconds
                        $ConnParams['Credential'] = $CredObject
                        $ConnParams['ForceNTLM'] = $true

                        $Connection = Connect-LDAP @ConnParams

                        if (-not $Connection) {
                            return $null
                        }

                        # Track auth info
                        $Script:AuthInfo.Method = 'NTLM'
                        $Script:AuthInfo.KerberosUsed = $false
                        $Script:AuthInfo.NTLMImpersonation = $false
                        $Script:LDAPContext['Credential'] = $CredObject
                    }
                    # ===== Primary: Kerberos Authentication =====
                    # Cross-domain with NetBIOS prefix (e.g., CONTOSO\b.pitt): skip Kerberos
                    # Cannot discover KDC for NetBIOS name, go directly to NTLM/SimpleBind
                    elseif (-not $ForceSimpleBind -and $UserRealm -and $UserRealm -notmatch '\.') {
                        Write-Log "[Connect-adPEAS] Cross-domain with NetBIOS prefix '$UserRealm' - skipping Kerberos (cannot discover KDC)"
                        Show-Line "Cross-domain authentication (NetBIOS): using NTLM/SimpleBind" -Class Hint
                        # Fall through to NTLM Impersonation / SimpleBind below
                    }
                    elseif (-not $ForceSimpleBind) {
                        Write-Log "[Connect-adPEAS] Attempting Kerberos authentication..."

                        # Cross-domain with FQDN UserRealm: resolve KDC for user's realm
                        $UserRealmDC = $null
                        if ($UserRealm -and $UserRealm -match '\.') {
                            Write-Log "[Connect-adPEAS] Cross-domain: discovering KDC for user realm '$UserRealm'..."
                            $UserRealmDC = Resolve-adPEASName -Domain $UserRealm
                            if (-not $UserRealmDC -or -not $UserRealmDC.IP) {
                                Write-Log "[Connect-adPEAS] Cross-domain: could not discover KDC for '$UserRealm' - falling back to NTLM/SimpleBind"
                                Show-Line "Cross-domain: could not find KDC for '$UserRealm' - using NTLM/SimpleBind" -Class Hint
                                # Set flag to skip Kerberos and fall through to NTLM/SimpleBind
                                $UserRealmDC = $null
                                $UserRealm = $null  # Clear to prevent cross-domain Kerberos attempt
                            } else {
                                Write-Log "[Connect-adPEAS] Cross-domain: found KDC for '$UserRealm': $($UserRealmDC.Hostname) ($($UserRealmDC.IP))"
                            }
                        }

                        $KerbFlowParams = @{
                            SamAccountName = $SamAccountName
                            Domain = $Domain
                            DCHostname = $DCResolution.Hostname
                            Password = $PlainPassword
                            IgnoreSSLErrors = $IgnoreSSLErrors
                        }
                        if ($DCResolution.IP) { $KerbFlowParams['DCIP'] = $DCResolution.IP }
                        if ($Server) { $KerbFlowParams['Server'] = $Server }
                        if ($UseLDAPS) { $KerbFlowParams['UseLDAPS'] = $true }


                        # Cross-domain: pass user realm info so TGT is requested from correct KDC
                        if ($UserRealm -and $UserRealmDC) {
                            $KerbFlowParams['UserRealm'] = $UserRealm
                            $KerbFlowParams['UserRealmKDC'] = $UserRealmDC.IP
                        }

                        $KerbFlowResult = Invoke-KerberosAuthFlow @KerbFlowParams

                        if ($KerbFlowResult.Success) {
                            $KerberosAuthSuccess = $true
                            $Connection = $KerbFlowResult.Connection
                            Write-Log "[Connect-adPEAS] Kerberos authentication completed successfully"

                            $Script:AuthInfo.Method = 'Kerberos'
                            $Script:AuthInfo.KerberosUsed = $true
                            $Script:AuthInfo.TGTInfo = @{
                                UserName = $KerbFlowResult.TGTResult.UserName
                                Domain = $KerbFlowResult.TGTResult.Domain
                                EncryptionType = $KerbFlowResult.TGTResult.EncryptionType
                                Method = $KerbFlowResult.TGTResult.Method
                                AuthTime = $KerbFlowResult.TGTResult.AuthTime
                                StartTime = $KerbFlowResult.TGTResult.StartTime
                                EndTime = $KerbFlowResult.TGTResult.EndTime
                                RenewTill = $KerbFlowResult.TGTResult.RenewTill
                                ClockSkew = $KerbFlowResult.TGTResult.ClockSkew
                            }
                        }
                        else {
                            $ErrorMessage = $KerbFlowResult.Error
                            $KdcErrorCode = $KerbFlowResult.ErrorCode
                            Write-Log "[Connect-adPEAS] Kerberos authentication failed: $ErrorMessage (ErrorCode: $KdcErrorCode)"

                            # KDC errors indicate authentication/credential issues - fallback makes no sense
                            # Exception: cross-domain auth may get Error 6 (user not found) if TGS fails,
                            # which is expected - allow NTLM/SimpleBind fallback in that case
                            $IsCrossDomain = $null -ne $UserRealm
                            if ($null -ne $KdcErrorCode -and $KdcErrorCode -in $Script:KDC_FATAL_ERROR_CODES -and -not $IsCrossDomain) {
                                Show-ConnectionError -ErrorType "KerberosError" -ErrorCode $KdcErrorCode -ErrorCodeType "Kerberos" -NoThrow
                                return $null
                            }
                            if ($IsCrossDomain) {
                                Write-Log "[Connect-adPEAS] Cross-domain: Kerberos failed, allowing NTLM/SimpleBind fallback"
                                Show-Line "Cross-domain authentication: falling back to NTLM/SimpleBind" -Class Hint
                            }

                            # Check if this is a DNS resolution issue (custom DNS without hosts patching)
                            $IsDnsResolutionIssue = $ErrorMessage -match "Kerberos tickets obtained successfully.*LDAP connection failed"
                            if ($IsDnsResolutionIssue) {
                                Show-Line "Kerberos TGT/TGS acquired successfully, but LDAP requires hostname resolution" -Class Note
                                Show-Line "Use -PatchHostsFile for full Kerberos authentication" -Class Note
                                Write-Log "[Connect-adPEAS] Custom DNS active without hosts patching - SimpleBind fallback"
                            }

                            # Technical error (PTT failed, LDAP without Kerberos, etc.) - fallback is OK
                            $IsPTTError = $ErrorMessage -match "non-domain-joined|Remote Credential Guard|Ticket import failed|ticket not used|ticket not usable"
                            if ($IsPTTError) {
                                Write-Log "[Connect-adPEAS] Kerberos PTT not available on this system - using SimpleBind"
                            }

                            if ($ForceKerberos) {
                                if ($KerbFlowResult.IsNetworkError) {
                                    $NetworkServer = if ($KerbFlowResult.NetworkErrorServer) { $KerbFlowResult.NetworkErrorServer } else { $Server }
                                    Show-ConnectionError -ErrorType "NetworkError" -Details "Port 88 (Kerberos) unreachable on $NetworkServer" -NoThrow
                                }
                                else {
                                    if ($null -ne $KdcErrorCode) {
                                        Show-ConnectionError -ErrorType "KerberosError" -ErrorCode $KdcErrorCode -ErrorCodeType "Kerberos" -NoThrow
                                    } else {
                                        Show-ConnectionError -ErrorType "KerberosError" -Details $ErrorMessage -NoThrow
                                    }
                                }
                                return $null
                            }

                            Write-Log "[Connect-adPEAS] Kerberos PTT failed - trying NTLM impersonation fallback..."
                            Show-Line "Kerberos failed - trying NTLM impersonation" -Class Info
                        }
                    }
                    else {
                        Write-Log "[Connect-adPEAS] ForceSimpleBind specified, skipping Kerberos"
                    }

                    # ===== Fallback: Explicit NTLM -> SimpleBind =====
                    if (-not $KerberosAuthSuccess -and -not $ForceNTLM) {
                        # Try explicit NTLM first (better than SimpleBind: supports LDAP signing)
                        if (-not $ForceSimpleBind) {
                            Write-Log "[Connect-adPEAS] Attempting explicit NTLM fallback (AuthType::Ntlm)..."

                            $ConnParams = @{}
                            $ConnParams['Domain'] = $Domain
                            if ($Server) {
                                $ConnParams['Server'] = $Server
                            } elseif ($DCResolution -and $DCResolution.Hostname) {
                                $ConnParams['Server'] = $DCResolution.Hostname
                                Write-Log "[Connect-adPEAS] NTLM fallback: Using discovered DC: $($DCResolution.Hostname)"
                            }
                            if ($UseLDAPS) { $ConnParams['UseLDAPS'] = $true }
                            $ConnParams['IgnoreSSLErrors'] = $IgnoreSSLErrors
                            $ConnParams['TimeoutSeconds'] = $TimeoutSeconds
                            $ConnParams['Credential'] = $CredObject
                            $ConnParams['ForceNTLM'] = $true

                            $Connection = Connect-LDAP @ConnParams

                            if (-not $Connection) {
                                Write-Log "[Connect-adPEAS] LDAP connection failed with explicit NTLM - trying SimpleBind..."
                                Show-Line "NTLM failed - falling back to SimpleBind" -Class Hint
                                # Fall through to SimpleBind below
                            }
                            else {
                                $Script:AuthInfo.Method = 'NTLM'
                                $Script:AuthInfo.KerberosUsed = $false
                                $Script:AuthInfo.NTLMImpersonation = $false
                                $Script:LDAPContext['Credential'] = $CredObject

                                Show-Line "Connected via NTLM (supports LDAP signing)" -Class Hint
                            }
                        }

                        # Final fallback: SimpleBind
                        if (-not $Connection) {
                            Write-Log "[Connect-adPEAS] Using SimpleBind authentication..."

                            $ConnParams = @{}
                            $ConnParams['Domain'] = $Domain
                            if ($Server) {
                                $ConnParams['Server'] = $Server
                            } elseif ($DCResolution -and $DCResolution.Hostname) {
                                $ConnParams['Server'] = $DCResolution.Hostname
                                Write-Log "[Connect-adPEAS] Using discovered DC: $($DCResolution.Hostname)"
                            }
                            if ($UseLDAPS) { $ConnParams['UseLDAPS'] = $true }

                            $ConnParams['IgnoreSSLErrors'] = $IgnoreSSLErrors
                            $ConnParams['TimeoutSeconds'] = $TimeoutSeconds
                            $ConnParams['Credential'] = $CredObject

                            # Suppress error display on first attempt when LDAPS auto-upgrade might trigger
                            if (-not $UseLDAPS) {
                                $ConnParams['SuppressErrorDisplay'] = $true
                            }
                            $Connection = Connect-LDAP @ConnParams
                            $ConnParams.Remove('SuppressErrorDisplay')

                            # Auto-upgrade to LDAPS when SimpleBind fails with LDAP_STRONG_AUTH_REQUIRED (error 8)
                            # This happens when LDAP Channel Binding or LDAP Signing is enforced by domain policy

                            # Reclassify LDAP OperationsError (1) as AuthenticationFailed for SimpleBind
                            # Empty password → anonymous bind succeeds → search fails with OperationsError = auth failure
                            if (-not $Connection -and $Script:LastLDAPErrorCode -eq 1) {
                                $Script:ConnectionState = "AuthenticationFailed"
                            }

                            # If it's a different error, show the suppressed error message now
                            if (-not $Connection -and -not $UseLDAPS -and $Script:LastLDAPErrorCode -ne 8) {
                                if ($Script:ConnectionState) {
                                    if ($null -ne $Script:LastLDAPErrorCode) {
                                        Show-ConnectionError -ErrorType $Script:ConnectionState -ErrorCode $Script:LastLDAPErrorCode -ErrorCodeType "LDAP" -NoThrow
                                    } else {
                                        Show-ConnectionError -ErrorType $Script:ConnectionState -Details $Script:LastLDAPErrorDetails -NoThrow
                                    }
                                }
                            }
                            if (-not $Connection -and -not $UseLDAPS -and $Script:LastLDAPErrorCode -eq 8) {
                                Write-Log "[Connect-adPEAS] SimpleBind failed with LDAP_STRONG_AUTH_REQUIRED - auto-upgrading to LDAPS..."
                                Show-Line "LDAP signing/channel binding required - auto-upgrading to LDAPS" -Class Hint

                                $ConnParams['UseLDAPS'] = $true
                                $Connection = Connect-LDAP @ConnParams
                            }

                            if (-not $Connection) {
                                return $null
                            }

                            $Script:AuthInfo.Method = 'SimpleBind'
                            $Script:AuthInfo.KerberosUsed = $false
                        }
                    }
                }

                'Certificate' {
                    Write-Log "[Connect-adPEAS] Domain: $Domain"
                    if ($Server) {
                        Write-Log "[Connect-adPEAS] Server: $Server"
                    }
                    Write-Log "[Connect-adPEAS] Certificate: $Certificate"

                    # Convert CertificatePassword to plain string for Invoke-KerberosAuth (with proper memory cleanup)
                    if ($CertificatePassword -is [System.Security.SecureString]) {
                        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($CertificatePassword)
                        try {
                            $PlainCertPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
                        }
                        finally {
                            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
                        }
                    }
                    elseif ($CertificatePassword -is [string]) {
                        $PlainCertPassword = $CertificatePassword
                    }
                    else {
                        throw "CertificatePassword must be either String or SecureString"
                    }

                    # Load certificate - handle both Base64 and file path via helper
                    try {
                        $certResult = ConvertFrom-Base64OrFile -InputValue $Certificate -ExpectedFormat "Certificate" -ParameterName "Certificate"

                        if (-not $certResult.Success) {
                            throw $certResult.Error
                        }

                        Write-Log "[Connect-adPEAS] Certificate loaded from $($certResult.Source): $($certResult.Data.Length) bytes ($($certResult.Format))"

                        # Load X509Certificate2 from bytes
                        $Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
                            $certResult.Data,
                            $PlainCertPassword,
                            [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
                        )
                    }
                    catch {
                        $Script:ConnectionState = "CertificateLoadFailed"

                        # Use HResult for structured error classification via central lookup
                        $errorHResult = $_.Exception.HResult
                        $errorMsg = $_.Exception.Message

                        Write-Log "[Connect-adPEAS] Certificate load error - HResult: 0x$($errorHResult.ToString('X8')), Message: $errorMsg"

                        # Pass HRESULT code for central lookup; Details as fallback for unknown HRESULTs
                        Show-ConnectionError -ErrorType "PFXLoadError" -ErrorCode $errorHResult -ErrorCodeType "HRESULT" -Details $errorMsg -NoThrow
                        throw "Certificate load failed"
                    }

                    if ($ForcePassTheCert) {
                        # ===== Pass-the-Cert (Schannel) =====
                        # Direct LDAPS bind with client certificate - no Kerberos involved
                        # Works when: Port 88 blocked, no Smart Card Logon EKU, no admin rights for PTT
                        Write-Log "[Connect-adPEAS] Using Pass-the-Cert (Schannel) - bypassing Kerberos"

                        # Force LDAPS (Schannel requires TLS)
                        if (-not $UseLDAPS) {
                            $UseLDAPS = $true
                            Write-Log "[Connect-adPEAS] LDAPS automatically enabled for Pass-the-Cert"
                        }

                        # Extract display identity from cert (for console output only, not for auth)
                        $CertDisplayName = "Certificate-based (Schannel)"
                        foreach ($ext in $Cert.Extensions) {
                            if ($ext.Oid.Value -eq "2.5.29.17") {
                                $san = $ext.Format($false)
                                if ($san -match "Principal Name[=:]([^,\r\n]+)") {
                                    $CertDisplayName = $Matches[1].Trim()
                                    break
                                }
                            }
                        }
                        if ($CertDisplayName -eq "Certificate-based (Schannel)" -and $Cert.Subject -match "CN=([^,]+)") {
                            $CertDisplayName = $Matches[1]
                        }
                        Write-Log "[Connect-adPEAS] Certificate display identity: $CertDisplayName"

                        # Resolve DC hostname using unified resolver
                        if ($Server) {
                            $ResolvedIP = Resolve-adPEASName -Name $Server
                            if (-not $ResolvedIP) {
                                Show-ConnectionError -ErrorType "DomainError" -Details "Server '$Server' could not be resolved - check DNS or use an IP address" -NoThrow
                                return $null
                            }
                        }

                        # Connect to LDAP with client certificate
                        $ConnParams = @{
                            Domain = $Domain
                            ClientCertificate = $Cert
                            UseLDAPS = $true
                            IgnoreSSLErrors = $IgnoreSSLErrors
                            TimeoutSeconds = $TimeoutSeconds
                        }
                        if ($Server) { $ConnParams['Server'] = $Server }

                        $Connection = Connect-LDAP @ConnParams

                        if (-not $Connection) {
                            return $null
                        }

                        # Track auth info - Schannel, no Kerberos
                        $Script:AuthInfo.Method = 'Schannel'
                        $Script:AuthInfo.KerberosUsed = $false

                    } else {
                    # ===== PKINIT Flow (existing) =====

                    # Extract all identities from certificate (multi-identity support)
                    # Certificates can contain multiple SANs (UPN + DNS, multiple UPNs, etc.)
                    # The user can select which identity to authenticate as via -Username
                    $certIdentities = @()

                    # 1. Collect all UPNs from SAN
                    foreach ($ext in $Cert.Extensions) {
                        if ($ext.Oid.Value -eq "2.5.29.17") {  # Subject Alternative Name
                            $san = $ext.Format($false)
                            Write-Log "[Connect-adPEAS] SAN Extension content: $san"

                            # Match all UPNs - Format: "Principal Name=user@domain.com" (may appear multiple times)
                            $upnMatches = [regex]::Matches($san, "Principal Name[=:]([^,\r\n]+)")
                            foreach ($m in $upnMatches) {
                                $upnValue = $m.Groups[1].Value.Trim()
                                if ($upnValue -match "^([^@]+)@") {
                                    $certIdentities += [PSCustomObject]@{
                                        Type = "UPN"
                                        Value = $upnValue
                                        CName = $Matches[1]  # username part without domain
                                    }
                                    Write-Log "[Connect-adPEAS] Found UPN identity: $upnValue -> cname: $($Matches[1])"
                                }
                            }

                            # Match all DNS names - Format: "DNS Name=srv-dc.contoso.com"
                            $dnsMatches = [regex]::Matches($san, "DNS Name=([^,\r\n]+)")
                            foreach ($m in $dnsMatches) {
                                $dnsValue = $m.Groups[1].Value.Trim()
                                $hostPart = ($dnsValue -split '\.')[0]
                                $certIdentities += [PSCustomObject]@{
                                    Type = "DNS"
                                    Value = $dnsValue
                                    CName = "$hostPart`$"  # computer account
                                }
                                Write-Log "[Connect-adPEAS] Found DNS identity: $dnsValue -> cname: $hostPart`$"
                            }
                        }
                    }

                    # 2. CN from Subject as fallback (only if no SAN identities found)
                    if ($certIdentities.Count -eq 0) {
                        if ($Cert.Subject -match "CN=([^,]+)") {
                            $cnValue = $Matches[1]
                            Write-Log "[Connect-adPEAS] No SAN identities, falling back to CN: $cnValue"

                            if ($cnValue -match "^([^.]+)\.(.+\..+)$") {
                                # FQDN format (e.g. DC01.contoso.com) -> computer account
                                $certIdentities += [PSCustomObject]@{
                                    Type = "CN"
                                    Value = $cnValue
                                    CName = "$($Matches[1])`$"
                                }
                            } else {
                                # Simple CN -> user account
                                $certIdentities += [PSCustomObject]@{
                                    Type = "CN"
                                    Value = $cnValue
                                    CName = $cnValue
                                }
                            }
                        }
                    }

                    if ($certIdentities.Count -eq 0) {
                        $Script:ConnectionState = "CertificateUsernameFailed"
                        Show-ConnectionError -ErrorType "GenericError" -Details "Could not extract identity from certificate. Certificate must have UPN or DNS in SAN, or CN in Subject." -NoThrow
                        throw "Certificate username extraction failed"
                    }

                    # 3. Identity selection
                    $CertUserName = $null

                    if ($Username) {
                        # Manual override via -Username parameter
                        # Map the provided value to a cname
                        if ($Username -match '@') {
                            # UPN format (user@domain.com) -> extract username part
                            $CertUserName = ($Username -split '@')[0]
                        } elseif ($Username -match '\..*\.') {
                            # FQDN format (srv-dc.contoso.com) -> computer account
                            $CertUserName = "$(($Username -split '\.')[0])`$"
                        } elseif ($Username -match '\$$') {
                            # Explicit computer account (SRV-DC$) -> use as-is
                            $CertUserName = $Username
                        } else {
                            # Simple name - check if it matches a DNS identity (-> computer) or use as-is (-> user)
                            $dnsMatch = $certIdentities | Where-Object { $_.Type -eq 'DNS' -and ($_.Value -split '\.')[0] -eq $Username }
                            if ($dnsMatch) {
                                $CertUserName = "$Username`$"
                            } else {
                                $CertUserName = $Username
                            }
                        }

                        # Display all identities + selected override
                        if ($certIdentities.Count -gt 1) {
                            Show-Line "Certificate contains multiple identities" -Class Note
                            $idx = 1
                            foreach ($id in $certIdentities) {
                                Show-KeyValue "    [$idx] $($id.Type):" $id.Value
                                $idx++
                            }
                        }
                        Show-KeyValue "Using specified identity:" $CertUserName -Class Note
                        Write-Log "[Connect-adPEAS] Manual identity override: $Username -> cname: $CertUserName"

                    } elseif ($certIdentities.Count -eq 1) {
                        # Single identity - auto-select (no extra output, same as before)
                        $CertUserName = $certIdentities[0].CName
                        Write-Log "[Connect-adPEAS] Single identity in certificate: $($certIdentities[0].Type)=$($certIdentities[0].Value) -> cname: $CertUserName"

                    } else {
                        # Multiple identities - show all, auto-select first, hint about -Username
                        Show-Line "Certificate contains multiple identities" -Class Note
                        $idx = 1
                        foreach ($id in $certIdentities) {
                            Show-KeyValue "    [$idx] $($id.Type):" $id.Value
                            $idx++
                        }

                        # Auto-select first identity (UPNs come before DNS in the list)
                        $CertUserName = $certIdentities[0].CName
                        Show-KeyValue "Using identity [1]:" $CertUserName -Class Note
                        Show-Line "To select a different identity, use: -Username <name>" -Class Note

                        Write-Log "[Connect-adPEAS] Multiple identities found ($($certIdentities.Count)), auto-selected first: $($certIdentities[0].Type)=$($certIdentities[0].Value) -> cname: $CertUserName"
                    }

                    Write-Log "[Connect-adPEAS] Username from certificate: $CertUserName"

                    # Resolve DC hostname and IP using unified resolver
                    # If -Server is explicit, just resolve that hostname to IP (skip DC discovery)
                    # If -Server is not set, use domain-based DC discovery via SRV records
                    if ($Server) {
                        $ResolvedIP = Resolve-adPEASName -Name $Server
                        $DCResolution = [PSCustomObject]@{ Hostname = $Server; IP = $ResolvedIP }

                        if (-not $ResolvedIP) {
                            Show-ConnectionError -ErrorType "DomainError" -Details "Server '$Server' could not be resolved - check DNS or use an IP address" -NoThrow
                            return $null
                        }
                    } else {
                        $DCResolution = Resolve-adPEASName -Domain $Domain

                        # If domain-based DC discovery fails, terminate immediately
                        if (-not $DCResolution -or -not $DCResolution.Hostname) {
                            Show-ConnectionError -ErrorType "DomainError" -Details "Could not discover a Domain Controller for '$Domain' - DNS resolution failed. Use -Server to specify a DC manually." -NoThrow
                            return $null
                        }
                    }

                    # Determine DC for PKINIT - use resolved IP if available (custom DNS scenario)
                    $PKINITServer = if ($DCResolution.IP) {
                        Write-Log "[Connect-adPEAS] Using resolved IP for PKINIT: $($DCResolution.IP)"
                        $DCResolution.IP
                    } elseif ($Server) {
                        $Server
                    } else {
                        $Domain
                    }

                    # Step 1: PKINIT Authentication using unified Invoke-KerberosAuth
                    # Pass the already-loaded certificate object (avoids re-loading)
                    Write-Log "[Connect-adPEAS] Step 1: Performing PKINIT authentication..."
                    Write-Log "[Connect-adPEAS] PKINIT Target: $PKINITServer"
                    Write-Log "[Connect-adPEAS] PKINIT User: $CertUserName"
                    Write-Log "[Connect-adPEAS] PKINIT Domain: $Domain"
                    Write-Log "[Connect-adPEAS] Certificate Subject: $($Cert.Subject)"
                    Write-Log "[Connect-adPEAS] Certificate Issuer: $($Cert.Issuer)"
                    Write-Log "[Connect-adPEAS] Certificate Thumbprint: $($Cert.Thumbprint)"
                    Write-Log "[Connect-adPEAS] Certificate Has Private Key: $($Cert.HasPrivateKey)"
                    Write-Log "[Connect-adPEAS] Certificate Valid From: $($Cert.NotBefore) To: $($Cert.NotAfter)"

                    $PKINITResult = Invoke-KerberosAuth -UserName $CertUserName -Domain $Domain -DomainController $PKINITServer -Certificate $Cert

                    if (-not $PKINITResult -or -not $PKINITResult.Success) {
                        $ErrorMsg = if ($PKINITResult.Error) { $PKINITResult.Error } elseif ($PKINITResult.Message) { $PKINITResult.Message } else { "Unknown PKINIT error" }
                        Write-Log "[Connect-adPEAS] PKINIT Result: $($PKINITResult | ConvertTo-Json -Depth 2 -Compress)"
                        $Script:ConnectionState = "PKINITFailed"

                        # Use structured error code from result object (no fragile regex extraction)
                        $KdcErrorCode = $PKINITResult.ErrorCode
                        if ($null -ne $KdcErrorCode) {
                            Show-ConnectionError -ErrorType "KerberosError" -ErrorCode $KdcErrorCode -ErrorCodeType "Kerberos" -NoThrow
                        } else {
                            Show-ConnectionError -ErrorType "KerberosError" -Details $ErrorMsg -NoThrow
                        }
                        return $null
                    }

                    Write-Log "[Connect-adPEAS] PKINIT authentication successful"
                    Write-Log "[Connect-adPEAS] PKINIT Method: $($PKINITResult.Method)"
                    Write-Log "[Connect-adPEAS] PKINIT Encryption: $($PKINITResult.EncryptionType)"

                    # Step 2: Import TGT into Windows session (Pass-the-Ticket)
                    # The PKINIT result contains the TGT which needs to be injected into Windows so that subsequent LDAP connections can use Kerberos auth automatically
                    Write-Log "[Connect-adPEAS] Step 2: Importing TGT into Windows session..."

                    $PTTSuccess = $false
                    if ($PKINITResult.TicketBytes -and $PKINITResult.SessionKeyBytes) {
                        try {
                            # Get realm from PKINIT result (uppercase domain)
                            $Realm = if ($PKINITResult.Domain) { $PKINITResult.Domain.ToUpper() } else { $Domain.ToUpper() }

                            Write-Log "[Connect-adPEAS] PTT Realm: $Realm"
                            Write-Log "[Connect-adPEAS] PTT ClientName: $CertUserName"
                            Write-Log "[Connect-adPEAS] PTT TicketBytes: $($PKINITResult.TicketBytes.Length) bytes"
                            Write-Log "[Connect-adPEAS] PTT SessionKeyBytes: $($PKINITResult.SessionKeyBytes.Length) bytes"
                            if ($PKINITResult.TicketFlags) {
                                $flagsHex = ($PKINITResult.TicketFlags | ForEach-Object { $_.ToString('X2') }) -join ''
                                Write-Log "[Connect-adPEAS] PTT TicketFlags: 0x$flagsHex"
                            }

                            # Build parameters for Import-KerberosTicket
                            $pttParams = @{
                                TicketBytes = $PKINITResult.TicketBytes
                                SessionKey = $PKINITResult.SessionKeyBytes
                                SessionKeyType = $PKINITResult.EncryptionType
                                Realm = $Realm
                                ClientName = $CertUserName
                                ServerName = "krbtgt"
                                ServerInstance = $Realm
                            }
                            # Add actual ticket times from EncKDCRepPart (critical for Windows LSA to accept)
                            if ($PKINITResult.StartTime) { $pttParams['StartTime'] = $PKINITResult.StartTime }
                            if ($PKINITResult.EndTime) { $pttParams['EndTime'] = $PKINITResult.EndTime }
                            if ($PKINITResult.RenewTill) { $pttParams['RenewTill'] = $PKINITResult.RenewTill }
                            if ($PKINITResult.TicketFlags) { $pttParams['TicketFlags'] = $PKINITResult.TicketFlags }

                            $PTTResult = Import-KerberosTicket @pttParams

                            if ($PTTResult -and $PTTResult.Success) {
                                Write-Log "[Connect-adPEAS] TGT imported successfully (Pass-the-Ticket)"
                                $PTTSuccess = $true
                            } else {
                                $PTTError = if ($PTTResult.Error) { $PTTResult.Error } else { "Unknown error" }
                                Write-Warning "[Connect-adPEAS] Failed to import TGT: $PTTError"
                                Write-Log "[Connect-adPEAS] Continuing without PTT - LDAP may require alternative auth"
                            }
                        }
                        catch {
                            Write-Warning "[Connect-adPEAS] PTT failed: $_"
                            Write-Log "[Connect-adPEAS] Continuing without PTT - LDAP may require alternative auth"
                        }
                    } else {
                        Write-Log "[Connect-adPEAS] No TGT bytes available for PTT (ticket/session key missing)"
                        if ($PKINITResult.TicketBytes) {
                            Write-Log "[Connect-adPEAS] TicketBytes: $($PKINITResult.TicketBytes.Length) bytes"
                        } else {
                            Write-Log "[Connect-adPEAS] TicketBytes: null/empty"
                        }
                        if ($PKINITResult.SessionKeyBytes) {
                            Write-Log "[Connect-adPEAS] SessionKeyBytes: $($PKINITResult.SessionKeyBytes.Length) bytes"
                        } else {
                            Write-Log "[Connect-adPEAS] SessionKeyBytes: null/empty"
                        }
                    }

                    # Step 3: Connect to LDAP using Kerberos TGT from Windows session
                    Write-Log "[Connect-adPEAS] Step 3: Establishing LDAP connection..."
                    $ConnParams = @{}
                    $ConnParams['Domain'] = $Domain  # Domain is always provided now
                    if ($Server) { $ConnParams['Server'] = $Server }
                    if ($UseLDAPS) { $ConnParams['UseLDAPS'] = $true }

                    $ConnParams['IgnoreSSLErrors'] = $IgnoreSSLErrors
                    $ConnParams['TimeoutSeconds'] = $TimeoutSeconds
                    # Note: No Credential needed - uses Kerberos TGT from Windows session (PTT)

                    $Connection = Connect-LDAP @ConnParams

                    # Connect-LDAP already showed error if it failed
                    if (-not $Connection) {
                        return $null
                    }

                    # Track auth info - PKINIT always uses Kerberos
                    $Script:AuthInfo.Method = 'Kerberos'
                    $Script:AuthInfo.KerberosUsed = $true
                    $Script:AuthInfo.TGTInfo = @{
                        UserName       = $PKINITResult.UserName
                        Domain         = $PKINITResult.Domain
                        EncryptionType = $PKINITResult.EncryptionType
                        Method         = $PKINITResult.Method
                        AuthTime       = $PKINITResult.AuthTime
                        StartTime      = $PKINITResult.StartTime
                        EndTime        = $PKINITResult.EndTime
                        RenewTill      = $PKINITResult.RenewTill
                        ClockSkew      = $PKINITResult.ClockSkew
                    }

                    # UnPAC-the-hash: Recover NT hash from PKINIT via U2U TGS-REQ
                    if ($PKINITResult.ASRepReplyKey -and $PKINITResult.TicketBytes -and $PKINITResult.SessionKeyBytes) {
                        try {
                            Write-Log "[Connect-adPEAS] Attempting UnPAC-the-hash to recover NT hash..."
                            $unPACResult = Invoke-UnPACTheHash `
                                -TGT $PKINITResult.TicketBytes `
                                -SessionKey $PKINITResult.SessionKeyBytes `
                                -SessionKeyType $PKINITResult.EncryptionType `
                                -ASRepReplyKey $PKINITResult.ASRepReplyKey `
                                -UserName $CertUserName `
                                -Domain $Domain `
                                -DomainController $PKINITServer

                            if ($unPACResult.Success) {
                                $Script:AuthInfo.TGTInfo['NTHash'] = $unPACResult.NTHash
                                if ($unPACResult.LMHash) {
                                    $Script:AuthInfo.TGTInfo['LMHash'] = $unPACResult.LMHash
                                }
                                Write-Log "[Connect-adPEAS] UnPAC-the-hash successful: NT hash recovered"
                            } else {
                                Write-Log "[Connect-adPEAS] UnPAC-the-hash: $($unPACResult.Message)" -Level Warning
                            }
                        }
                        catch {
                            Write-Log "[Connect-adPEAS] UnPAC-the-hash failed: $_" -Level Warning
                        }
                    }
                    } # end else (PKINIT flow)
                }

                'WindowsAuth' {
                    Write-Log "[Connect-adPEAS] Domain: $Domain"
                    if ($Server) {
                        Write-Log "[Connect-adPEAS] Server: $Server"
                    }
                    Write-Log "[Connect-adPEAS] Username: $env:USERDOMAIN\$env:USERNAME"

                    # Windows Authentication uses SSPI which automatically selects Kerberos when available and falls back to NTLM when Kerberos is not possible
                    # -ForceSimpleBind has no effect here (Windows handles auth negotiation)
                    # -ForceKerberos has no effect here (controlled by Windows/GPO)

                    if ($ForceSimpleBind) {
                        Write-Warning "[!] -ForceSimpleBind has no effect with WindowsAuth"
                        Write-Warning "[!] Windows Auth automatically negotiates Kerberos/NTLM via SSPI"
                        Write-Warning "[!] To force a specific auth method, use -Username/-Password or -Credential"
                    }

                    if ($ForceKerberos) {
                        Write-Warning "[!] -ForceKerberos has no effect with WindowsAuth"
                        Write-Warning "[!] Windows Auth negotiation is controlled by system/GPO settings"
                        Write-Warning "[!] To enforce Kerberos, use -Username/-Password with -ForceKerberos"
                    }

                    Write-Log "[Connect-adPEAS] Using Windows Authentication (SSPI - Kerberos/NTLM negotiation)"

                    # Build connection parameters
                    $ConnParams = @{}
                    $ConnParams['Domain'] = $Domain
                    if ($Server) { $ConnParams['Server'] = $Server }
                    if ($UseLDAPS) { $ConnParams['UseLDAPS'] = $true }

                    $ConnParams['IgnoreSSLErrors'] = $IgnoreSSLErrors
                    $ConnParams['TimeoutSeconds'] = $TimeoutSeconds

                    # Connect (no credentials = use current Windows identity via SSPI)
                    $Connection = Connect-LDAP @ConnParams

                    # Connect-LDAP already showed error if it failed
                    if (-not $Connection) {
                        return $null
                    }

                    # Track auth info - WindowsAuth uses SSPI (Kerberos/NTLM negotiation)
                    # Connect-LDAP now detects if Kerberos was used via "Who Am I?" operation
                    if ($Connection -and $Connection.DetectedKerberos) {
                        $Script:AuthInfo.Method = 'Kerberos'
                        $Script:AuthInfo.KerberosUsed = $true
                        Write-Log "[Connect-adPEAS] Kerberos authentication detected by LDAP layer"
                    } else {
                        $Script:AuthInfo.Method = 'WindowsSSPI'
                        $Script:AuthInfo.KerberosUsed = $false  # Unknown - could be Kerberos or NTLM
                    }
                }

                { $_ -in @('NTHash', 'AES256', 'AES128') } {
                    # Hash/Key-based authentication (Overpass-the-Hash / Pass-the-Key)
                    # Primary: Kerberos TGT + TGS for LDAP + Pass-the-Ticket
                    # No fallback - hash/key auth requires Kerberos

                    Write-Log "[Connect-adPEAS] Domain: $Domain"
                    if ($Server) {
                        Write-Log "[Connect-adPEAS] Server: $Server"
                    }
                    Write-Log "[Connect-adPEAS] Username: $Username"
                    Write-Log "[Connect-adPEAS] Auth Type: $AuthMethod"

                    # Extract sAMAccountName and detect cross-domain authentication
                    $SamAccountName = $Username
                    $UserRealm = $null  # null = same as target domain

                    if ($Username -match '^([^\\]+)\\(.+)$') {
                        $UserDomainPrefix = $Matches[1]
                        $SamAccountName = $Matches[2]

                        $targetPrefix = ($Domain -split '\.')[0]
                        if ($UserDomainPrefix -ine $targetPrefix -and $UserDomainPrefix -ine $Domain) {
                            $UserRealm = $UserDomainPrefix
                            if ($UserRealm -match '\.') {
                                Write-Log "[Connect-adPEAS] Cross-domain detected: user in '$UserRealm' (FQDN), target '$Domain'"
                            } else {
                                Write-Log "[Connect-adPEAS] Cross-domain detected: user in '$UserRealm' (NetBIOS), target '$Domain'"
                            }
                        }
                    }
                    elseif ($Username -match '^(.+)@([^@]+)$') {
                        $SamAccountName = $Matches[1]
                        $upnDomain = $Matches[2]
                        if ($upnDomain -ine $Domain) {
                            $UserRealm = $upnDomain
                            Write-Log "[Connect-adPEAS] Cross-domain detected: user UPN realm '$UserRealm', target '$Domain'"
                        }
                    }
                    Write-Log "[Connect-adPEAS] Extracted sAMAccountName: $SamAccountName"

                    $KerberosAuthSuccess = $false
                    $Connection = $null
                    $KerberosError = $null

                    # Resolve DC hostname and IP using unified resolver
                    # If -Server is explicit, just resolve that hostname to IP (skip DC discovery)
                    # If -Server is not set, use domain-based DC discovery via SRV records
                    if ($Server) {
                        $ResolvedIP = Resolve-adPEASName -Name $Server
                        $DCResolution = [PSCustomObject]@{ Hostname = $Server; IP = $ResolvedIP }

                        if (-not $ResolvedIP) {
                            Show-ConnectionError -ErrorType "DomainError" -Details "Server '$Server' could not be resolved - check DNS or use an IP address" -NoThrow
                            return $null
                        }
                    } else {
                        $DCResolution = Resolve-adPEASName -Domain $Domain

                        # If domain-based DC discovery fails, terminate immediately
                        if (-not $DCResolution -or -not $DCResolution.Hostname) {
                            Show-ConnectionError -ErrorType "DomainError" -Details "Could not discover a Domain Controller for '$Domain' - DNS resolution failed. Use -Server to specify a DC manually." -NoThrow
                            return $null
                        }
                    }

                    # ===== Primary: Kerberos Authentication =====
                    if (-not $ForceSimpleBind) {
                        Write-Log "[Connect-adPEAS] Attempting Kerberos authentication ($AuthMethod)..."

                        # Cross-domain with FQDN UserRealm: resolve KDC for user's realm
                        $UserRealmDC = $null
                        if ($UserRealm -and $UserRealm -match '\.') {
                            Write-Log "[Connect-adPEAS] Cross-domain: discovering KDC for user realm '$UserRealm'..."
                            $UserRealmDC = Resolve-adPEASName -Domain $UserRealm
                            if (-not $UserRealmDC -or -not $UserRealmDC.IP) {
                                Write-Log "[Connect-adPEAS] Cross-domain: could not discover KDC for '$UserRealm'"
                                Show-ConnectionError -ErrorType "KerberosError" -Details "Could not discover KDC for user realm '$UserRealm'" -NoThrow
                                return $null
                            }
                            Write-Log "[Connect-adPEAS] Cross-domain: found KDC for '$UserRealm': $($UserRealmDC.Hostname) ($($UserRealmDC.IP))"
                        }
                        elseif ($UserRealm -and $UserRealm -notmatch '\.') {
                            # NetBIOS prefix with hash auth - cannot discover KDC and no SimpleBind fallback
                            Write-Log "[Connect-adPEAS] Cross-domain with NetBIOS prefix '$UserRealm' and hash auth - cannot discover KDC"
                            Show-ConnectionError -ErrorType "KerberosError" -Details "Cross-domain with NetBIOS prefix '$UserRealm' requires FQDN (e.g., contoso.com\\$SamAccountName)" -NoThrow
                            return $null
                        }

                        # Use helper function for Kerberos auth flow
                        $KerbFlowParams = @{
                            SamAccountName = $SamAccountName
                            Domain = $Domain
                            DCHostname = $DCResolution.Hostname
                            IgnoreSSLErrors = $IgnoreSSLErrors
                        }
                        # Pass resolved IP for custom DNS scenarios (system DNS may not resolve DC hostname)
                        if ($DCResolution.IP) { $KerbFlowParams['DCIP'] = $DCResolution.IP }
                        if ($Server) { $KerbFlowParams['Server'] = $Server }
                        if ($UseLDAPS) { $KerbFlowParams['UseLDAPS'] = $true }


                        # Cross-domain: pass user realm info so TGT is requested from correct KDC
                        if ($UserRealm -and $UserRealmDC) {
                            $KerbFlowParams['UserRealm'] = $UserRealm
                            $KerbFlowParams['UserRealmKDC'] = $UserRealmDC.IP
                        }

                        # Add the appropriate key based on auth method
                        switch ($AuthMethod) {
                            'NTHash' { $KerbFlowParams['NTHash'] = $NTHash }
                            'AES256' { $KerbFlowParams['AES256Key'] = $AES256Key }
                            'AES128' { $KerbFlowParams['AES128Key'] = $AES128Key }
                        }

                        $KerbFlowResult = Invoke-KerberosAuthFlow @KerbFlowParams

                        if ($KerbFlowResult.Success) {
                            $KerberosAuthSuccess = $true
                            $Connection = $KerbFlowResult.Connection
                            Write-Log "[Connect-adPEAS] Kerberos authentication completed successfully"

                            # Track auth info
                            $Script:AuthInfo.Method = 'Kerberos'
                            $Script:AuthInfo.KerberosUsed = $true
                            $Script:AuthInfo.TGTInfo = @{
                                UserName = $KerbFlowResult.TGTResult.UserName
                                Domain = $KerbFlowResult.TGTResult.Domain
                                EncryptionType = $KerbFlowResult.TGTResult.EncryptionType
                                Method = $KerbFlowResult.TGTResult.Method
                                AuthTime = $KerbFlowResult.TGTResult.AuthTime
                                StartTime = $KerbFlowResult.TGTResult.StartTime
                                EndTime = $KerbFlowResult.TGTResult.EndTime
                                RenewTill = $KerbFlowResult.TGTResult.RenewTill
                                ClockSkew = $KerbFlowResult.TGTResult.ClockSkew
                            }
                        }
                        else {
                            $KerberosError = $KerbFlowResult.Error
                            $KerberosErrorCode = $KerbFlowResult.ErrorCode
                            Write-Log "[Connect-adPEAS] Kerberos authentication failed: $KerberosError"
                        }
                    }
                    else {
                        Write-Log "[Connect-adPEAS] ForceSimpleBind specified, skipping Kerberos"
                        $KerberosError = "Skipped (ForceSimpleBind)"
                    }

                    # ===== Hash auth failed =====
                    if (-not $KerberosAuthSuccess) {
                        $Script:ConnectionState = "HashAuthFailed"
                        if ($null -ne $KerberosErrorCode) {
                            Show-ConnectionError -ErrorType "KerberosError" -ErrorCode $KerberosErrorCode -ErrorCodeType "Kerberos" -NoThrow
                        } else {
                            Show-ConnectionError -ErrorType "KerberosError" -Details $KerberosError -NoThrow
                        }
                        return $null
                    }
                }

                { $_ -in @('Kirbi', 'Ccache') } {
                    # Ticket-based authentication (Pass-the-Ticket)
                    # Accepts file path OR Base64-encoded data
                    # No fallback available - requires valid ticket data

                    # Warn about ignored parameters
                    if ($Username) {
                        Write-Warning "[!] -Username is ignored for ticket-based auth (identity is embedded in ticket)"
                    }

                    $TicketInput = if ($AuthMethod -eq 'Kirbi') { $Kirbi } else { $Ccache }
                    Write-Log "[Connect-adPEAS] Domain: $Domain"
                    if ($Server) {
                        Write-Log "[Connect-adPEAS] Server: $Server"
                    }
                    Write-Log "[Connect-adPEAS] Ticket Input: $($TicketInput.Substring(0, [Math]::Min(50, $TicketInput.Length)))..."

                    $Connection = $null

                    try {
                        # Load and import the ticket
                        Write-Log "[Connect-adPEAS] Step 1: Loading ticket..."

                        $ImportParams = @{}
                        if ($AuthMethod -eq 'Kirbi') {
                            $ImportParams['Kirbi'] = $Kirbi
                        }
                        else {
                            $ImportParams['Ccache'] = $Ccache
                        }

                        $PTTResult = Import-KerberosTicket @ImportParams

                        if (-not $PTTResult -or -not $PTTResult.Success) {
                            $ErrorMsg = if ($PTTResult.Error) { $PTTResult.Error } else { "Unknown error" }
                            throw "Ticket import failed: $ErrorMsg"
                        }

                        Write-Log "[Connect-adPEAS] Ticket imported successfully"

                        # Connect to LDAP using Kerberos (ticket now in session)
                        Write-Log "[Connect-adPEAS] Step 2: Establishing LDAP connection with Kerberos..."

                        $ConnParams = @{}
                        $ConnParams['Domain'] = $Domain
                        if ($Server) { $ConnParams['Server'] = $Server }
                        if ($UseLDAPS) { $ConnParams['UseLDAPS'] = $true }
    
                        $ConnParams['IgnoreSSLErrors'] = $IgnoreSSLErrors
                        $ConnParams['TimeoutSeconds'] = $TimeoutSeconds
                        # No Credential - uses Kerberos ticket from session

                        $Connection = Connect-LDAP @ConnParams

                        if ($Connection) {
                            Write-Log "[Connect-adPEAS] Kerberos authentication completed successfully"

                            # Track auth info
                            $Script:AuthInfo.Method = 'Kerberos'
                            $Script:AuthInfo.KerberosUsed = $true
                            # For imported tickets, estimate clock skew from AuthTime
                            $importedClockSkew = $null
                            if ($PTTResult.AuthTime) {
                                $importedClockSkew = $PTTResult.AuthTime - [DateTime]::UtcNow
                            }
                            $Script:AuthInfo.TGTInfo = @{
                                UserName = $PTTResult.UserName
                                Domain = $PTTResult.Realm
                                EncryptionType = $PTTResult.EncryptionType
                                Method = if ($AuthMethod -eq 'Kirbi') { 'Kirbi' } else { 'Ccache' }
                                AuthTime = $PTTResult.AuthTime
                                StartTime = $PTTResult.StartTime
                                EndTime = $PTTResult.EndTime
                                RenewTill = $PTTResult.RenewTill
                                ClockSkew = $importedClockSkew
                            }
                        }
                    }
                    catch {
                        $TicketError = $_.Exception.Message
                        # Show error if it's from ticket import/validation, not from Connect-LDAP
                        if ($TicketError -match "Ticket import failed|Invalid kirbi|Invalid ccache|input error") {
                            Show-ConnectionError -ErrorType "TicketImportError" -Details $TicketError -NoThrow
                        }
                        $Script:ConnectionState = "TicketAuthFailed"
                        return $null
                    }

                    # Connect-LDAP already showed error if it failed
                    if (-not $Connection) {
                        $Script:ConnectionState = "TicketAuthFailed"
                        return $null
                    }
                }
            }

            # ===== Connection Validation =====
            Write-Log "[Connect-adPEAS] Validating connection..."

            # Test connection with a simple query
            $TestQuery = Invoke-LDAPSearch -Filter "(objectClass=domain)" -SearchBase $Connection.DomainDN -Properties "name" -Scope Base

            if (-not $TestQuery) {
                throw "Connection validation failed - could not query domain object"
            }

            # ===== Store Auth Info in LDAPContext =====
            # Add auth info to the LDAPContext for display by Get-adPEASSession
            $Script:LDAPContext['AuthMethod'] = $Script:AuthInfo.Method
            $Script:LDAPContext['KerberosUsed'] = $Script:AuthInfo.KerberosUsed
            $Script:LDAPContext['TGTInfo'] = $Script:AuthInfo.TGTInfo
            $Script:LDAPContext['ParameterSet'] = $Script:AuthInfo.ParameterSet
            $Script:LDAPContext['SessionStartTime'] = Get-Date

            # Store authenticated username for reports (use LDAP-verified identity)
            if ($Connection.AuthenticatedUser) {
                $Script:LDAPContext['Username'] = $Connection.AuthenticatedUser
            }
            elseif ($Connection.Credential) {
                $Script:LDAPContext['Username'] = $Connection.Credential.UserName
            }
            elseif ($Username) {
                # For hash/key-based auth where username was provided
                $Script:LDAPContext['Username'] = $Username
            }

            # Store Domain SID (already retrieved by Connect-LDAP)
            if ($Connection.DomainSID) {
                $Script:LDAPContext['DomainSID'] = $Connection.DomainSID
                Write-Log "[Connect-adPEAS] Domain SID: $($Connection.DomainSID)"
            }

            # Store Credential in LDAPContext for later use
            if (-not $Script:LDAPContext['Credential']) {
                if ($CredObject) {
                    $Script:LDAPContext['Credential'] = $CredObject
                    Write-Log "[Connect-adPEAS] Stored credential in LDAPContext for later use"
                }
                elseif ($Credential) {
                    $Script:LDAPContext['Credential'] = $Credential
                    Write-Log "[Connect-adPEAS] Stored credential in LDAPContext for later use"
                }
            }

            # Store Certificate in LDAPContext for session reuse by Invoke-adPEAS
            if ($Certificate) {
                $Script:LDAPContext['Certificate'] = $Certificate
                if ($CertificatePassword) {
                    $Script:LDAPContext['CertificatePassword'] = $CertificatePassword
                }
                if ($ForcePassTheCert) {
                    $Script:LDAPContext['ForcePassTheCert'] = $true
                }
                Write-Log "[Connect-adPEAS] Stored certificate in LDAPContext for later use"
            }

            # ===== Hosts File Patching (if custom DNS and PatchHostsFile, and not already done early) =====
            if ($Script:LDAPContext['PatchHostsFile'] -and $Script:LDAPContext['DnsServer'] -and -not $Script:LDAPContext['EarlyHostsPatched']) {
                # This code path is for cases where early patching didn't happen (shouldn't occur with current logic)
                Write-Log "[Connect-adPEAS] Late hosts file patching (fallback)..."

                $hostsPatched = @()

                # Patch domain name -> DC IP
                if ($Connection.Server -and $Script:LDAPContext['DnsCache']) {
                    # Get the DC hostname from the connection
                    $dcHostname = $Connection.Server
                    # Use lowercase key for case-insensitive cache lookup
                    $dcHostnameLowerForPatch = $dcHostname.ToLower()

                    # Try to get IP from cache or resolve it
                    $dcIP = $null
                    if ($Script:LDAPContext['DnsCache'].ContainsKey($dcHostnameLowerForPatch)) {
                        $dcIP = $Script:LDAPContext['DnsCache'][$dcHostnameLowerForPatch]
                    }
                    else {
                        # Try to resolve using custom DNS
                        $dcIP = Resolve-adPEASName -Name $dcHostname
                    }

                    if ($dcIP) {
                        # Patch DC hostname
                        $patchResult = Add-adPEASHostsEntry -IPAddress $dcIP -Hostname $dcHostname -Force
                        if ($patchResult.Success) {
                            $hostsPatched += $dcHostname
                            Write-Log "[Connect-adPEAS] Added hosts entry: $dcIP -> $dcHostname"
                        }

                        # Also patch domain name if different from DC hostname
                        if ($Domain -ne $dcHostname) {
                            $patchResult = Add-adPEASHostsEntry -IPAddress $dcIP -Hostname $Domain -Force
                            if ($patchResult.Success) {
                                $hostsPatched += $Domain
                                Write-Log "[Connect-adPEAS] Added hosts entry: $dcIP -> $Domain"
                            }
                        }
                    }
                }

                # Store patched hosts for cleanup
                $Script:LDAPContext['HostsEntries'] = $hostsPatched

                if ($hostsPatched.Count -gt 0) {
                    Show-Line "Patched hosts file with $($hostsPatched.Count) entries (cleanup on Disconnect-adPEAS)" -Class Info
                }
            }
            elseif ($Script:LDAPContext['EarlyHostsPatched'] -and $Connection.Server) {
                # Early patching was done, but we may need to add the actual DC hostname if it differs
                # from what we patched early (we patched -Server, but Connect-LDAP may have resolved to different hostname)
                $dcHostname = $Connection.Server
                $alreadyPatched = $Script:LDAPContext['HostsEntries'] -contains $dcHostname

                if (-not $alreadyPatched) {
                    $dcHostnameLower = $dcHostname.ToLower()
                    $dcIP = $null

                    if ($Script:LDAPContext['DnsCache'] -and $Script:LDAPContext['DnsCache'].ContainsKey($dcHostnameLower)) {
                        $dcIP = $Script:LDAPContext['DnsCache'][$dcHostnameLower]
                    }
                    elseif ($Script:LDAPContext['ServerIP']) {
                        $dcIP = $Script:LDAPContext['ServerIP']
                    }

                    if ($dcIP) {
                        $patchResult = Add-adPEASHostsEntry -IPAddress $dcIP -Hostname $dcHostname -Force
                        if ($patchResult.Success) {
                            $Script:LDAPContext['HostsEntries'] += $dcHostname
                            Write-Log "[Connect-adPEAS] Added additional hosts entry: $dcIP -> $dcHostname"
                        }
                    }
                }
            }

            # Store resolved DC IP for SMB access (even without hosts patching)
            if ($Script:LDAPContext['DnsServer'] -and $Connection.Server) {
                $dcHostname = $Connection.Server
                # Normalize to lowercase for case-insensitive cache lookup
                $dcHostnameLower = $dcHostname.ToLower()
                $domainLower = $Domain.ToLower()
                $dcIP = $null

                Write-Log "[Connect-adPEAS] Looking up DC IP for: $dcHostname (normalized: $dcHostnameLower)"

                # Try multiple sources for the DC IP
                # Source 1: Check if DC hostname is directly in cache (case-insensitive)
                if ($Script:LDAPContext['DnsCache'] -and $Script:LDAPContext['DnsCache'].ContainsKey($dcHostnameLower)) {
                    $dcIP = $Script:LDAPContext['DnsCache'][$dcHostnameLower]
                    Write-Log "[Connect-adPEAS] Found DC IP in DnsCache: $dcIP"
                }
                # Source 2: Check if domain name is in cache (DC IP is same as domain IP)
                elseif ($Script:LDAPContext['DnsCache'] -and $Script:LDAPContext['DnsCache'].ContainsKey($domainLower)) {
                    $dcIP = $Script:LDAPContext['DnsCache'][$domainLower]
                    Write-Log "[Connect-adPEAS] Using domain IP as DC IP: $dcIP"
                    # Also cache the DC hostname -> IP mapping for future use (lowercase key)
                    $Script:LDAPContext['DnsCache'][$dcHostnameLower] = $dcIP
                }
                # Source 3: Resolve DC hostname via custom DNS
                else {
                    Write-Log "[Connect-adPEAS] Resolving DC hostname via custom DNS: $dcHostname"
                    $dcIP = Resolve-adPEASName -Name $dcHostname -DnsServer $Script:LDAPContext['DnsServer']
                    if ($dcIP) {
                        Write-Log "[Connect-adPEAS] Resolved DC IP: $dcIP"
                    }
                    else {
                        Write-Log "[Connect-adPEAS] WARNING: Could not resolve DC hostname $dcHostname"
                    }
                }

                if ($dcIP) {
                    $Script:LDAPContext['ServerIP'] = $dcIP
                    Write-Log "[Connect-adPEAS] Stored DC IP for SMB access: $($Script:LDAPContext['ServerIP'])"
                }
            }

            # ===== Success Output (Verbose) =====
            Write-Log "[Connect-adPEAS] CONNECTION SUCCESSFUL"
            Write-Log "[Connect-adPEAS] Domain: $($Connection.Domain)"
            Write-Log "[Connect-adPEAS] Server: $($Connection.Server)"
            Write-Log "[Connect-adPEAS] Protocol: $($Connection.Protocol) (Port $($Connection.Port))"

            # Display authenticated user (LDAP-verified if available)
            if ($Connection.AuthenticatedUser) {
                # LDAP-verified identity
                Write-Log "[Connect-adPEAS] Authenticated as: $($Connection.AuthenticatedUser)"

                # Show identity mismatch warning if detected
                if ($Connection.IdentityMismatch) {
                    Write-Warning "[Connect-adPEAS] Identity Mismatch Detected (see warning above)"
                }
            }
            else {
                # Fallback if LDAP verification failed
                if ($Connection.Credential) {
                    $DisplayUser = $Connection.Credential.UserName
                }
                elseif ($AuthMethod -eq 'Certificate' -and $ForcePassTheCert) {
                    $DisplayUser = "Certificate-based (Pass-the-Cert)"
                }
                elseif ($AuthMethod -eq 'Certificate') {
                    $DisplayUser = "Certificate-based (PKINIT)"
                }
                elseif ($AuthMethod -in @('NTHash', 'AES256', 'AES128')) {
                    $DisplayUser = "$Username (Hash/Key-based)"
                }
                elseif ($AuthMethod -in @('Kirbi', 'Ccache')) {
                    $DisplayUser = "Ticket-based (PTT)"
                }
                else {
                    $DisplayUser = "$env:USERDOMAIN\$env:USERNAME"
                }
                Write-Log "[Connect-adPEAS] Authenticated as: $DisplayUser"
            }

            # Functional Level Info
            $FLMapping = @{
                0 = "Windows 2000"
                1 = "Windows 2003 Interim"
                2 = "Windows 2003"
                3 = "Windows 2008"
                4 = "Windows 2008 R2"
                5 = "Windows 2012"
                6 = "Windows 2012 R2"
                7 = "Windows 2016"
                10 = "Windows 2025"
            }
            $DomainFL = $FLMapping[[int]$Connection.DomainFunctionality]
            Write-Log "[Connect-adPEAS] Domain Functional Level: $DomainFL"

            # Build tab-completion cache if requested
            if ($BuildCompletionCache) {
                Show-EmptyLine
                Show-Line "Building tab-completion cache..." -Class Info
                Build-CompletionCache
                $stats = Get-CompletionCacheStats
                Show-Line "Cached: $($stats.Users) users, $($stats.Computers) computers, $($stats.Groups) groups, $($stats.GPOs) GPOs" -Class Hint
            }

            if (-not $Quiet) {
                Get-adPEASSession
                return
            }
            else {
                return $Connection
            }

        }
        catch {
            # Display error to user if not already shown via Show-ConnectionError
            $ErrorDetail = $_.Exception.Message
            Write-Log "[Connect-adPEAS] Connection failed: $ErrorDetail"
            Write-Log "[Connect-adPEAS] ConnectionState: $Script:ConnectionState"

            # Show error to user (Show-ConnectionError may not have been called for all error types)
            Show-ConnectionError -ErrorType "GenericError" -Details $ErrorDetail -NoThrow
            return $null
        }
    }

    end {
        if ($Script:LdapConnection) {
            Write-Log "[Connect-adPEAS] Authentication process completed"
        }
    }
}
