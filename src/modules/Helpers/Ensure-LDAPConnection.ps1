<#
.SYNOPSIS
    Ensures that an LDAP connection to the Domain Controller exists.

.DESCRIPTION
    This helper function ensures the correct LDAP connection is active.

    Simple logic:
    - Determine target Domain/Server/Credential (use auto-discovery if not specified)
    - Compare with existing connection
    - If ANY difference -> establish new connection

    This guarantees that queries always go to the expected target.

.PARAMETER Domain
    The target domain to query. If not specified, uses current domain.

.PARAMETER Server
    Specific Domain Controller (FQDN or IP). If not specified, uses auto-discovery.

.PARAMETER Credential
    Alternative credentials for domain queries.

.EXAMPLE
    Ensure-LDAPConnection
    Ensures connection to current domain with auto-discovery.

.EXAMPLE
    Ensure-LDAPConnection -Server "dc01.contoso.com"
    Ensures connection to specific DC.

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

function Ensure-LDAPConnection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential
    )

    # Check if ANY parameters were explicitly provided
    $HasExplicitParams = $PSBoundParameters.ContainsKey('Domain') -or
                        $PSBoundParameters.ContainsKey('Server') -or
                        $PSBoundParameters.ContainsKey('Credential')

    # If NO parameters AND existing session -> ALWAYS reuse existing session
    # UNIFIED: LDAPContext is set for both LDAP and LDAPS connections
    # The actual connection is in $Script:LdapConnection (LdapConnection)
    if (-not $HasExplicitParams -and $Script:LDAPContext) {
        # Quick-exit if session was already marked invalid (avoids repeated error messages)
        if ($Script:LDAPContext['SessionInvalid']) {
            Write-Log "[Ensure-LDAPConnection] Session already marked invalid - skipping"
            return $false
        }

        # Use centrally determined authenticated user from Connect-LDAP
        $UsernameDisplay = $Script:LDAPContext.AuthenticatedUser
        Write-Log "[Ensure-LDAPConnection] No parameters specified - reusing existing session: Domain=$($Script:LDAPContext.Domain), Server=$($Script:LDAPContext.Server), User=$UsernameDisplay"

        # Health-Check: For Kerberos-based auth methods, verify TGT still exists
        # This catches scenarios like "klist purge" or expired tickets
        $AuthMethod = $Script:LDAPContext['AuthMethod']
        $KerberosAuthMethods = @('Kerberos', 'PKINIT', 'OverpassTheHash', 'PassTheKey', 'PassTheTicket')

        if ($AuthMethod -in $KerberosAuthMethods) {
            $ticketCheck = Test-KerberosTGTExists -Detailed
            if (-not $ticketCheck.Valid) {
                # Build detailed error message
                $errorDetails = "Kerberos TGT no longer valid"
                if ($ticketCheck.TicketCount -eq 0) {
                    $errorDetails = "No Kerberos tickets in cache (purged or never obtained)"
                } elseif ($ticketCheck.Expired) {
                    $expiredTime = if ($ticketCheck.EndTime) { $ticketCheck.EndTime.ToString('yyyy-MM-dd HH:mm:ss') } else { "unknown" }
                    $errorDetails = "Kerberos TGT expired at $expiredTime"
                } elseif ($ticketCheck.ClientMatch -eq $false) {
                    $errorDetails = "Kerberos TGT client mismatch (TGT=$($ticketCheck.ClientName), Expected=$($Script:LDAPContext.TGTInfo.UserName))"
                }
                $errorDetails += ". Re-authenticate with Connect-adPEAS."

                Write-Log "[Ensure-LDAPConnection] TGT validation failed: $errorDetails"

                # Show user-friendly error with hints
                Show-ConnectionError -ErrorType "AuthenticationFailed" -Details $errorDetails -NoThrow

                # Mark session as invalid to prevent repeated error messages on subsequent checks
                $Script:LDAPContext['SessionInvalid'] = $true
                Show-Line "Aborting scan - LDAP session is no longer valid. Re-authenticate with Connect-adPEAS." -Class Finding

                # Return false - caller should handle this gracefully
                return $false
            }
        }

        return $true
    }

    # If NO parameters AND NO session -> Error with instructions
    if (-not $HasExplicitParams -and -not $Script:LDAPContext) {
        # Get calling function name for context
        $CallingFunction = (Get-PSCallStack)[1].Command
        Show-NoSessionError -Context $CallingFunction
        # Return $false to indicate failure (caller must handle)
        return $false
    }

    # Determine target domain (auto-discover if not specified)
    $TargetDomain = $Domain
    if (-not $TargetDomain) {
        try {
            $CurrentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $TargetDomain = $CurrentDomain.Name
        } catch {
            throw "Could not detect current domain. Please specify -Domain parameter."
        }
    }

    # Determine target server (null = auto-discovery)
    $TargetServer = $Server

    # Check if we need a new connection
    $NeedNewConnection = $false

    if (-not $Script:LDAPContext) {
        # No connection exists
        $NeedNewConnection = $true
        Write-Log "[Ensure-LDAPConnection] No existing connection - establishing new connection"
    } else {
        # Connection exists - check if parameters match EXACTLY

        # Compare Domain (only if explicitly specified)
        if ($Domain -and $Script:LDAPContext.Domain -ne $TargetDomain) {
            $NeedNewConnection = $true
            Write-Log "[Ensure-LDAPConnection] Domain mismatch: Current=$($Script:LDAPContext.Domain), Target=$TargetDomain"
        }

        # Compare Server (only if explicitly specified)
        if ($TargetServer -and $Script:LDAPContext.Server -ne $TargetServer) {
            $NeedNewConnection = $true
            Write-Log "[Ensure-LDAPConnection] Server mismatch: Current=$($Script:LDAPContext.Server), Target=$TargetServer"
        }

        # If credential parameter is provided, always reconnect (safe approach)
        if ($Credential) {
            $NeedNewConnection = $true
            Write-Log "[Ensure-LDAPConnection] Credential parameter specified - establishing new connection"
        }

        if (-not $NeedNewConnection) {
            # Use centrally determined authenticated user from Connect-LDAP
            $UsernameDisplay = $Script:LDAPContext.AuthenticatedUser
            Write-Log "[Ensure-LDAPConnection] Using existing connection: Domain=$($Script:LDAPContext.Domain), Server=$($Script:LDAPContext.Server), User=$UsernameDisplay"
        }
    }

    # Establish new connection if needed
    if ($NeedNewConnection) {
        $ServerDisplay = if ($TargetServer) { $TargetServer } else { 'auto-discovery' }
        Write-Log "[Ensure-LDAPConnection] Establishing new connection to: Domain=$TargetDomain, Server=$ServerDisplay"

        try {
            $ConnectionParams = @{}
            if ($TargetDomain) { $ConnectionParams['Domain'] = $TargetDomain }
            if ($TargetServer) { $ConnectionParams['Server'] = $TargetServer }
            if ($Credential) { $ConnectionParams['Credential'] = $Credential }

            # Pass stored client certificate for Schannel reconnection
            if ($Script:LDAPContext -and $Script:LDAPContext['ClientCertificate']) {
                $ConnectionParams['ClientCertificate'] = $Script:LDAPContext['ClientCertificate']
                $ConnectionParams['UseLDAPS'] = $true  # Schannel requires LDAPS
            }

            Connect-LDAP @ConnectionParams | Out-Null

            # Use centrally determined authenticated user from Connect-LDAP
            $UsernameDisplay = $Script:LDAPContext.AuthenticatedUser
            Write-Log "[Ensure-LDAPConnection] Successfully connected: Domain=$($Script:LDAPContext.Domain), Server=$($Script:LDAPContext.Server), User=$UsernameDisplay"
        } catch {
            # Re-throw error from Connect-LDAP without adding wrapper
            throw
        }
    }
    return $true
}
