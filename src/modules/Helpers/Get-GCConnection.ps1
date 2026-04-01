function Get-GCConnection {
    <#
    .SYNOPSIS
        Returns a lazy-initialized Global Catalog (GC) LdapConnection for cross-domain lookups.

    .DESCRIPTION
        Creates and caches an LdapConnection to the Global Catalog (port 3268/3269) using Connect-LDAP -AsGlobalCatalog.
        This ensures all central infrastructure (custom DNS, SSL handling, timeouts, error classification) is reused from the main LDAP connector.

        The GC connection is cached in $Script:GCConnection and reused across the session.
        It is automatically disposed by Disconnect-adPEAS.

        Tries multiple targets in order:
        1. Current DC ($Script:LDAPContext.Server)
        2. Root domain FQDN (derived from RootDomainNamingContext)
        3. Current domain FQDN ($Script:LDAPContext.Domain)

    .OUTPUTS
        System.DirectoryServices.Protocols.LdapConnection or $null if unavailable
    #>
    [CmdletBinding()]
    param()

    # Return cached connection if available
    if ($Script:GCConnection) {
        return $Script:GCConnection
    }

    # Prerequisites: main connection must exist (GC is auxiliary)
    if (-not $Script:LdapConnection -or
        -not ($Script:LDAPContext -is [hashtable]) -or
        -not $Script:LDAPContext.ContainsKey('Domain') -or
        -not $Script:LDAPContext.ContainsKey('Server')) {
        Write-Log "[Get-GCConnection] Prerequisites not met - main connection incomplete"
        return $null
    }

    # Build target list: current server, root domain, domain FQDN
    $targets = @()
    if ($Script:LDAPContext.ContainsKey('Server') -and $Script:LDAPContext['Server']) {
        $targets += $Script:LDAPContext['Server']
    }

    # Derive root domain FQDN from RootDomainNamingContext (e.g., "DC=contoso,DC=com" -> "contoso.com")
    # Critical for child domains where the child DC may not be a GC server
    $rootDomainFQDN = $null
    if ($Script:LDAPContext.ContainsKey('RootDomainNamingContext') -and $Script:LDAPContext['RootDomainNamingContext']) {
        $dcParts = @()
        $rnc = $Script:LDAPContext['RootDomainNamingContext']
        while ($rnc -match '^DC=([^,]+),?(.*)$') {
            $dcParts += $Matches[1]
            $rnc = $Matches[2]
        }
        if ($dcParts.Count -gt 0) {
            $rootDomainFQDN = ($dcParts -join '.')
        }
    }

    if ($rootDomainFQDN -and
        $rootDomainFQDN -ne $Script:LDAPContext['Server'] -and
        $rootDomainFQDN -ne $Script:LDAPContext['Domain']) {
        $targets += $rootDomainFQDN
        Write-Log "[Get-GCConnection] Added root domain $rootDomainFQDN as GC target"
    }

    if ($Script:LDAPContext.ContainsKey('Domain') -and
        $Script:LDAPContext['Domain'] -and
        $Script:LDAPContext['Domain'] -ne $Script:LDAPContext['Server']) {
        $targets += $Script:LDAPContext['Domain']
    }

    # Build common parameters from existing session for Connect-LDAP -AsGlobalCatalog
    $ConnectParams = @{
        Domain          = $Script:LDAPContext['Domain']
        AsGlobalCatalog = $true
        IgnoreSSLErrors = $true
        TimeoutSeconds  = 5
    }
    if ($Script:LDAPContext.ContainsKey('UseLDAPS') -and $Script:LDAPContext['UseLDAPS']) {
        $ConnectParams['UseLDAPS'] = $true
    }

    # Auth: pass Credential or ClientCertificate based on session auth method
    if ($Script:LDAPContext.ContainsKey('AuthMethod') -and
        $Script:LDAPContext['AuthMethod'] -eq 'Schannel' -and
        $Script:LDAPContext.ContainsKey('ClientCertificate') -and
        $Script:LDAPContext['ClientCertificate']) {
        # Schannel: pass client certificate for GC connection (no Kerberos tickets, no credentials)
        $ConnectParams['ClientCertificate'] = $Script:LDAPContext['ClientCertificate']
        $ConnectParams['UseLDAPS'] = $true
    }
    else {
        $kerbUsed = $Script:LDAPContext.ContainsKey('KerberosUsed') -and ($Script:LDAPContext['KerberosUsed'] -eq $true)
        $winAuth = $Script:LDAPContext.ContainsKey('AuthMethod') -and ($Script:LDAPContext['AuthMethod'] -eq 'WindowsAuth')
        $useNegotiate = $kerbUsed -or $winAuth

        if (-not $useNegotiate -and $Script:LDAPCredential) {
            $ConnectParams['Credential'] = $Script:LDAPCredential
        }
    }

    foreach ($GCTarget in $targets) {
        Write-Log "[Get-GCConnection] Trying GC target: $GCTarget"
        $ConnectParams['Server'] = $GCTarget

        $GCConn = Connect-LDAP @ConnectParams
        if ($GCConn) {
            Write-Log "[Get-GCConnection] GC connection established to $GCTarget"
            $Script:GCConnection = $GCConn
            return $GCConn
        }
    }

    Write-Log "[Get-GCConnection] All GC connection attempts failed - cross-domain resolution unavailable"
    return $null
}


function Resolve-SIDViaGC {
    <#
    .SYNOPSIS
        Attempts to resolve a SID via the Global Catalog for cross-domain/forest resolution.

    .DESCRIPTION
        Queries the Global Catalog (port 3268/3269) which contains a forest-wide read-only
        index of all objects. This enables resolving SIDs from any domain in the forest.

        Uses Invoke-LDAPSearch with -LdapConnection for full attribute conversion.

    .PARAMETER SIDHex
        The SID in LDAP hex format (\XX\XX\XX...) for the objectSid query.

    .PARAMETER SID
        The SID as string for logging and caching.

    .OUTPUTS
        String in "DOMAIN\sAMAccountName" format, or $null if resolution fails.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SIDHex,

        [Parameter(Mandatory=$true)]
        [string]$SID
    )

    try {
        $gcConn = Get-GCConnection
        if (-not $gcConn) { return $null }

        Write-Log "[Resolve-SIDViaGC] Attempting GC lookup for: $SID"

        # Use Invoke-LDAPSearch with GC connection
        # CRITICAL: Use -Raw flag to prevent infinite recursion via msDS-AllowedToActOnBehalfOfOtherIdentity
        # -Raw skips all attribute conversions (including Security Descriptor parsing which would call
        # ConvertFrom-SID → Resolve-SIDViaGC again → infinite loop)
        # We only need sAMAccountName + distinguishedName for SID resolution
        # With -Raw, explicit attribute list works correctly (no S.DS.P GC port 3268 bug)
        # Force array wrapping to prevent PowerShell unwrapping single results to scalar
        $gcResults = @(Invoke-LDAPSearch -Filter "(objectSid=$SIDHex)" -Properties @("sAMAccountName","distinguishedName") -SizeLimit 1 -LdapConnection $gcConn -Raw)

        $gcResult = if ($gcResults -and $gcResults.Count -gt 0) { $gcResults[0] } else { $null }

        if ($gcResult) {
            # Raw mode: attributes are returned as-is (strings for text, byte[] for binary)
            $accountName = $gcResult.sAMAccountName
            $gcDN = $gcResult.distinguishedName

            if ($accountName -and $gcDN) {
                # Extract domain NetBIOS name from DN (first DC= component)
                if ($gcDN -match 'DC=([^,]+)') {
                    $gcDomainName = $Matches[1].ToUpper()
                } else {
                    $gcDomainName = "FOREST"
                }

                $resolvedName = "${gcDomainName}\$accountName"
                Write-Log "[Resolve-SIDViaGC] Resolved: $SID -> $resolvedName (via GC)"
                return $resolvedName
            }
        }

        Write-Log "[Resolve-SIDViaGC] No usable results from GC for $SID"
        return $null
    } catch {
        Write-Log "[Resolve-SIDViaGC] Failed for ${SID}: $($_.Exception.Message)"

        # Reset stale GC connection so next call retries
        if ($_.Exception.InnerException -is [System.DirectoryServices.Protocols.LdapException] -or
            $_.Exception -is [System.ObjectDisposedException]) {
            try { if ($Script:GCConnection) { $Script:GCConnection.Dispose() } } catch { }
            $Script:GCConnection = $null
            Write-Log "[Resolve-SIDViaGC] Reset stale GC connection"
        }

        return $null
    }
}
