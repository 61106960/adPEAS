<#
.SYNOPSIS
    Performs the complete Kerberos authentication flow (TGT -> TGS -> PTT -> LDAP/SMB).

.DESCRIPTION
    This internal helper function encapsulates the complete Kerberos authentication flow:
    1. Request TGT via Invoke-KerberosAuth (using password, hash, or key)
    2. Import TGT via Import-KerberosTicket (Pass-the-Ticket)
    3. Request and import LDAP service ticket (TGS) for LDAP connections
    4. Request and import CIFS service ticket for SMB/SYSVOL access (non-fatal if fails)
    5. Establish LDAP connection using the imported Kerberos ticket

    This function is used internally by Connect-adPEAS to avoid code duplication across different authentication parameter sets (PSCredential, UsernamePassword, NTHash, AES).

.PARAMETER SamAccountName
    The sAMAccountName of the user (without domain prefix).

.PARAMETER Domain
    The target domain FQDN.

.PARAMETER Server
    Optional. Specific Domain Controller to use.

.PARAMETER DCHostname
    The DC hostname for SPN construction (e.g., dc01.contoso.com).

.PARAMETER DCIP
    The DC IP address for KDC connection (bypasses system DNS).

.PARAMETER Password
    Plain text password for password-based authentication.

.PARAMETER NTHash
    NT-Hash for Overpass-the-Hash authentication.

.PARAMETER AES256Key
    AES256 key for Pass-the-Key authentication.

.PARAMETER AES128Key
    AES128 key for Pass-the-Key authentication.

.PARAMETER UseLDAPS
    Use LDAPS instead of LDAP.

.PARAMETER IgnoreSSLErrors
    Ignore SSL certificate errors.

.EXAMPLE
    $Result = Invoke-KerberosAuthFlow -SamAccountName "admin" -Domain "contoso.com" -DCHostname "dc01.contoso.com" -DCIP "10.0.0.1" -Password "P@ssw0rd!"

.OUTPUTS
    [PSCustomObject] with properties:
    - Success: $true if authentication succeeded
    - Connection: The LDAP connection object (if successful)
    - TGTResult: The TGT result object (for auth info tracking)
    - Error: Error message (if failed)

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

function Invoke-KerberosAuthFlow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SamAccountName,

        [Parameter(Mandatory=$true)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$true)]
        [string]$DCHostname,

        [Parameter(Mandatory=$false)]
        [string]$DCIP,

        [Parameter(Mandatory=$false)]
        [string]$Password,

        [Parameter(Mandatory=$false)]
        [string]$NTHash,

        [Parameter(Mandatory=$false)]
        [string]$AES256Key,

        [Parameter(Mandatory=$false)]
        [string]$AES128Key,

        [Parameter(Mandatory=$false)]
        [switch]$UseLDAPS,

        [Parameter(Mandatory=$false)]
        [switch]$IgnoreSSLErrors,

        [Parameter(Mandatory=$false)]
        [string]$UserRealm,

        [Parameter(Mandatory=$false)]
        [string]$UserRealmKDC
    )

    begin {
        # Helper function to request and import a service ticket (reduces code duplication)
        function Request-AndImportServiceTicket {
            param(
                [Parameter(Mandatory=$true)]
                [byte[]]$TGTBytes,

                [Parameter(Mandatory=$true)]
                [byte[]]$SessionKeyBytes,

                [Parameter(Mandatory=$true)]
                [int]$SessionKeyType,

                [Parameter(Mandatory=$true)]
                [string]$ServicePrincipalName,

                [Parameter(Mandatory=$true)]
                [string]$TargetDomain,

                [Parameter(Mandatory=$true)]
                [string]$KdcServer,

                [Parameter(Mandatory=$true)]
                [string]$ClientName,

                [Parameter(Mandatory=$false)]
                [switch]$NonFatal
            )

            $ServiceResult = [PSCustomObject]@{
                Success = $false
                TGSResult = $null
                ImportResult = $null
                Error = $null
            }

            # Parse SPN into service name and instance
            $spnParts = $ServicePrincipalName -split '/'
            if ($spnParts.Count -lt 2 -or [string]::IsNullOrEmpty($spnParts[1])) {
                $ServiceResult.Error = "Invalid SPN format: '$ServicePrincipalName' - expected 'service/hostname'"
                return $ServiceResult
            }
            $serviceName = $spnParts[0]
            $serviceInstance = $spnParts[1]

            # Request service ticket
            Write-Log "[Request-AndImportServiceTicket] Requesting TGS for SPN: $ServicePrincipalName"
            $TGSResult = Request-ServiceTicket -TGT $TGTBytes `
                                              -SessionKey $SessionKeyBytes `
                                              -SessionKeyType $SessionKeyType `
                                              -ServicePrincipalName $ServicePrincipalName `
                                              -Domain $TargetDomain `
                                              -DomainController $KdcServer `
                                              -UserName $ClientName

            if (-not $TGSResult -or -not $TGSResult.Success) {
                $ServiceResult.Error = if ($TGSResult.Error) { $TGSResult.Error } else { "TGS request failed" }
                return $ServiceResult
            }

            $ServiceResult.TGSResult = $TGSResult
            Write-Log "[Request-AndImportServiceTicket] Service ticket acquired for $serviceName"

            # Import service ticket
            Write-Log "[Request-AndImportServiceTicket] Importing $serviceName service ticket..."
            $importParams = @{
                TicketBytes    = $TGSResult.TicketBytes
                SessionKey     = $TGSResult.SessionKeyBytes
                SessionKeyType = $TGSResult.SessionKeyType    # Bug fix: was EncryptionType (ticket etype), must be SessionKeyType
                Realm          = $TargetDomain.ToUpper()
                ClientName     = $ClientName
                ServerName     = $serviceName
                ServerInstance = $serviceInstance
            }
            if ($TGSResult.TicketFlags) { $importParams['TicketFlags'] = $TGSResult.TicketFlags }
            if ($TGSResult.AuthTime)    { $importParams['AuthTime']    = $TGSResult.AuthTime }
            if ($TGSResult.StartTime)   { $importParams['StartTime']   = $TGSResult.StartTime }
            if ($TGSResult.EndTime)     { $importParams['EndTime']     = $TGSResult.EndTime }
            if ($TGSResult.RenewTill)   { $importParams['RenewTill']   = $TGSResult.RenewTill }

            $ImportResult = Import-KerberosTicket @importParams

            if (-not $ImportResult -or -not $ImportResult.Success) {
                $ServiceResult.Error = if ($ImportResult.Error) { $ImportResult.Error } else { "Ticket import failed" }
                $ServiceResult.ImportResult = $ImportResult
                return $ServiceResult
            }

            $ServiceResult.ImportResult = $ImportResult
            $ServiceResult.Success = $true
            Write-Log "[Request-AndImportServiceTicket] $serviceName service ticket imported into session"
            return $ServiceResult
        }
    }

    process {
        $Result = [PSCustomObject]@{
            Success = $false
            Connection = $null
            TGTResult = $null
            Error = $null
            ErrorCode = $null  # KDC error code for structured error handling
            IsNetworkError = $false  # True if failure was due to network issues (not auth)
            NetworkErrorServer = $null
            NetworkErrorPort = $null
        }

        try {
            # Use IP address for KDC connection if available (custom DNS scenario)
            # This is required when system DNS cannot resolve the DC hostname
            $KdcTarget = if ($DCIP) {
                Write-Log "[Invoke-KerberosAuthFlow] Using IP for KDC: $DCIP (hostname: $DCHostname)"
                $DCIP
            } else {
                $DCHostname
            }

            # Cross-domain: determine which KDC to use for TGT vs TGS
            # TGT must come from user's realm KDC, TGS from target domain KDC
            $IsCrossDomain = $false
            $TgtKdcTarget = $KdcTarget  # Default: same KDC for everything
            $TgtRealm = $Domain         # Default: target domain as realm

            if ($UserRealm -and $UserRealmKDC) {
                $IsCrossDomain = $true
                $TgtKdcTarget = $UserRealmKDC  # TGT from user's realm KDC
                $TgtRealm = $UserRealm         # User's realm for AS-REQ
                Write-Log "[Invoke-KerberosAuthFlow] Cross-domain: TGT from $TgtKdcTarget (realm: $TgtRealm), TGS from $KdcTarget (realm: $Domain)"
            }

            # ===== Step 0: Test Kerberos port reachability (port 88) =====
            # For cross-domain: test BOTH KDCs (user realm for TGT + target domain for TGS)
            $KdcReachable = $false
            Write-Log "[Invoke-KerberosAuthFlow] Testing port reachability to: $TgtKdcTarget"

            try {
                $TcpClient = New-Object System.Net.Sockets.TcpClient
                $ConnectTask = $TcpClient.BeginConnect($TgtKdcTarget, 88, $null, $null)
                $WaitHandle = $ConnectTask.AsyncWaitHandle

                if ($WaitHandle.WaitOne(2000, $false)) {
                    $TcpClient.EndConnect($ConnectTask)
                    $KdcReachable = $true
                    Write-Log "[Invoke-KerberosAuthFlow] KDC is reachable on port 88"
                }
                $TcpClient.Close()
            } catch {
                Write-Log "[Invoke-KerberosAuthFlow] Port test failed: $_"
            }

            if (-not $KdcReachable) {
                $Result.IsNetworkError = $true
                $Result.NetworkErrorServer = $TgtKdcTarget
                $Result.NetworkErrorPort = 88
                $Result.Error = "Port 88 (Kerberos) unreachable on $TgtKdcTarget"
                throw $Result.Error
            }

            # For cross-domain: also test target domain KDC reachability (needed for TGS)
            if ($IsCrossDomain -and $KdcTarget -ne $TgtKdcTarget) {
                Write-Log "[Invoke-KerberosAuthFlow] Cross-domain: testing target KDC reachability: $KdcTarget"
                $TargetKdcReachable = $false
                try {
                    $TcpClient2 = New-Object System.Net.Sockets.TcpClient
                    $ConnectTask2 = $TcpClient2.BeginConnect($KdcTarget, 88, $null, $null)
                    $WaitHandle2 = $ConnectTask2.AsyncWaitHandle
                    if ($WaitHandle2.WaitOne(2000, $false)) {
                        $TcpClient2.EndConnect($ConnectTask2)
                        $TargetKdcReachable = $true
                        Write-Log "[Invoke-KerberosAuthFlow] Target KDC is reachable on port 88"
                    }
                    $TcpClient2.Close()
                } catch {
                    Write-Log "[Invoke-KerberosAuthFlow] Target KDC port test failed: $_"
                }
                if (-not $TargetKdcReachable) {
                    Write-Log "[Invoke-KerberosAuthFlow] Target KDC unreachable - TGS will likely fail, but continuing with TGT"
                }
            }

            # ===== Step 1: Get TGT via Invoke-KerberosAuth =====
            Write-Log "[Invoke-KerberosAuthFlow] Step 1: Requesting TGT..."
            if ($IsCrossDomain) {
                Write-Log "[Invoke-KerberosAuthFlow] Cross-domain: requesting TGT from $TgtRealm KDC ($TgtKdcTarget)"
            }

            $KerbAuthParams = @{
                UserName = $SamAccountName
                Domain = $TgtRealm           # User's realm (or target domain if same-domain)
                DomainController = $TgtKdcTarget  # User's realm KDC (or target KDC if same-domain)
            }

            # Add authentication material based on what was provided
            # For password-based auth, we implement EType fallback (AES256 → AES128 → RC4)
            # For hash/key-based auth, the EType is fixed by the key type
            if ($PSBoundParameters.ContainsKey('Password')) {
                $KerbAuthParams['Password'] = $Password
                Write-Log "[Invoke-KerberosAuthFlow] Using password-based authentication"

                # EType fallback order for password-based auth
                # Try AES256 first (most secure), then AES128, then RC4 (legacy compatibility)
                $ETypeFallbackOrder = @(18, 17, 23)  # AES256, AES128, RC4-HMAC
                $ETypeNames = @{ 18 = "AES256"; 17 = "AES128"; 23 = "RC4-HMAC" }
                $TGTResult = $null
                $LastErrorCode = $null
                $LastError = $null

                foreach ($eType in $ETypeFallbackOrder) {
                    $KerbAuthParams['PreferredEType'] = $eType
                    Write-Log "[Invoke-KerberosAuthFlow] Trying EType $eType ($($ETypeNames[$eType]))..."

                    $TGTResult = Invoke-KerberosAuth @KerbAuthParams

                    if ($TGTResult -and $TGTResult.Success) {
                        Write-Log "[Invoke-KerberosAuthFlow] TGT acquired with EType $eType ($($ETypeNames[$eType]))"
                        break
                    }

                    # Check if error is ETYPE_NOSUPP (14) - try next EType
                    if ($TGTResult -and $TGTResult.ErrorCode -eq $Script:KDC_ERR_ETYPE_NOSUPP) {
                        Write-Log "[Invoke-KerberosAuthFlow] KDC does not support EType $eType ($($ETypeNames[$eType])), trying next..."
                        $LastErrorCode = $TGTResult.ErrorCode
                        $LastError = $TGTResult.Error
                        continue
                    }

                    # Any other error - stop trying (credentials may be wrong, user locked, etc.)
                    $LastErrorCode = $TGTResult.ErrorCode
                    $LastError = $TGTResult.Error
                    Write-Log "[Invoke-KerberosAuthFlow] TGT request failed with error code $LastErrorCode - not retrying with other ETypes"
                    break
                }

                # If all ETYPEs failed, report the last error
                if (-not $TGTResult -or -not $TGTResult.Success) {
                    $ErrorMsg = if ($LastError) { $LastError } else { "Unknown error" }
                    $Result.ErrorCode = $LastErrorCode
                    # Propagate network error info from TGTResult
                    if ($TGTResult -and $TGTResult.IsNetworkError) {
                        $Result.IsNetworkError = $true
                        $Result.NetworkErrorServer = $TGTResult.NetworkErrorServer
                        $Result.NetworkErrorPort = $TGTResult.NetworkErrorPort
                    }
                    throw "TGT request failed (tried ETypes: AES256, AES128, RC4): $ErrorMsg"
                }
            }
            elseif ($NTHash) {
                $KerbAuthParams['NTHash'] = $NTHash
                Write-Log "[Invoke-KerberosAuthFlow] Using NT-Hash (Overpass-the-Hash) - EType fixed to RC4-HMAC"

                $TGTResult = Invoke-KerberosAuth @KerbAuthParams

                if (-not $TGTResult -or -not $TGTResult.Success) {
                    $ErrorMsg = if ($TGTResult.Error) { $TGTResult.Error } else { "Unknown error" }
                    $Result.ErrorCode = $TGTResult.ErrorCode
                    # Propagate network error info from TGTResult
                    if ($TGTResult -and $TGTResult.IsNetworkError) {
                        $Result.IsNetworkError = $true
                        $Result.NetworkErrorServer = $TGTResult.NetworkErrorServer
                        $Result.NetworkErrorPort = $TGTResult.NetworkErrorPort
                    }
                    throw "TGT request failed: $ErrorMsg"
                }
            }
            elseif ($AES256Key) {
                $KerbAuthParams['AES256Key'] = $AES256Key
                Write-Log "[Invoke-KerberosAuthFlow] Using AES256 Key (Pass-the-Key) - EType fixed to AES256"

                $TGTResult = Invoke-KerberosAuth @KerbAuthParams

                if (-not $TGTResult -or -not $TGTResult.Success) {
                    $ErrorMsg = if ($TGTResult.Error) { $TGTResult.Error } else { "Unknown error" }
                    $Result.ErrorCode = $TGTResult.ErrorCode
                    # Propagate network error info from TGTResult
                    if ($TGTResult -and $TGTResult.IsNetworkError) {
                        $Result.IsNetworkError = $true
                        $Result.NetworkErrorServer = $TGTResult.NetworkErrorServer
                        $Result.NetworkErrorPort = $TGTResult.NetworkErrorPort
                    }
                    throw "TGT request failed: $ErrorMsg"
                }
            }
            elseif ($AES128Key) {
                $KerbAuthParams['AES128Key'] = $AES128Key
                Write-Log "[Invoke-KerberosAuthFlow] Using AES128 Key (Pass-the-Key) - EType fixed to AES128"

                $TGTResult = Invoke-KerberosAuth @KerbAuthParams

                if (-not $TGTResult -or -not $TGTResult.Success) {
                    $ErrorMsg = if ($TGTResult.Error) { $TGTResult.Error } else { "Unknown error" }
                    $Result.ErrorCode = $TGTResult.ErrorCode
                    # Propagate network error info from TGTResult
                    if ($TGTResult -and $TGTResult.IsNetworkError) {
                        $Result.IsNetworkError = $true
                        $Result.NetworkErrorServer = $TGTResult.NetworkErrorServer
                        $Result.NetworkErrorPort = $TGTResult.NetworkErrorPort
                    }
                    throw "TGT request failed: $ErrorMsg"
                }
            }
            else {
                throw "No authentication material provided (Password, NTHash, AES256Key, or AES128Key required)"
            }

            # Validate SessionKeyBytes - required for TGS requests
            if (-not $TGTResult.SessionKeyBytes -or $TGTResult.SessionKeyBytes.Length -eq 0) {
                throw "TGT request succeeded but SessionKeyBytes is missing or empty (AS-REP decryption may have failed)"
            }

            Write-Log "[Invoke-KerberosAuthFlow] TGT acquired successfully"
            $Result.TGTResult = $TGTResult

            # ===== Step 2: Import TGT via Pass-the-Ticket =====
            Write-Log "[Invoke-KerberosAuthFlow] Step 2: Importing TGT (Pass-the-Ticket)..."

            # Import TGT first (allows Windows to request additional service tickets if needed)
            # For cross-domain: TGT realm is user's realm, not target domain
            $pttParams = @{
                TicketBytes    = $TGTResult.TicketBytes
                SessionKey     = $TGTResult.SessionKeyBytes
                SessionKeyType = $TGTResult.EncryptionType
                Realm          = $TgtRealm.ToUpper()
                ClientName     = $SamAccountName
                ServerName     = "krbtgt"
                ServerInstance = $TgtRealm.ToUpper()
                AuthTime       = $TGTResult.AuthTime
                StartTime      = $TGTResult.StartTime
                EndTime        = $TGTResult.EndTime
                RenewTill      = $TGTResult.RenewTill
            }
            if ($TGTResult.TicketFlags) { $pttParams['TicketFlags'] = $TGTResult.TicketFlags }

            $PTTResult = Import-KerberosTicket @pttParams

            if (-not $PTTResult -or -not $PTTResult.Success) {
                $ErrorMsg = if ($PTTResult.Error) { $PTTResult.Error } else { "Unknown error" }
                throw "TGT import failed: $ErrorMsg"
            }
            Write-Log "[Invoke-KerberosAuthFlow] TGT imported into session"

            # ===== Step 3: Request and import LDAP service ticket =====
            # For cross-domain: we request TGS from the TARGET domain KDC (not user's realm KDC)
            # The target KDC validates the cross-realm TGT via trust relationship
            # If this fails (referral needed), Windows PTT handles it natively when we connect LDAP
            Write-Log "[Invoke-KerberosAuthFlow] Step 3: Requesting and importing LDAP service ticket..."

            $LDAPServiceSPN = "ldap/$DCHostname"
            $TgsKdcServer = $KdcTarget  # Always target domain KDC for TGS
            if ($IsCrossDomain) {
                Write-Log "[Invoke-KerberosAuthFlow] Cross-domain: requesting TGS from target KDC ($KdcTarget) for SPN $LDAPServiceSPN"
            }

            $LDAPTicketResult = Request-AndImportServiceTicket -TGTBytes $TGTResult.TicketBytes `
                                                               -SessionKeyBytes $TGTResult.SessionKeyBytes `
                                                               -SessionKeyType $TGTResult.EncryptionType `
                                                               -ServicePrincipalName $LDAPServiceSPN `
                                                               -TargetDomain $Domain `
                                                               -KdcServer $TgsKdcServer `
                                                               -ClientName $SamAccountName

            if (-not $LDAPTicketResult.Success) {
                if ($IsCrossDomain) {
                    # Cross-domain TGS failure is expected (no referral chasing implemented)
                    # Fall through to LDAP connect - Windows may handle it natively via PTT
                    Write-Log "[Invoke-KerberosAuthFlow] Cross-domain: TGS failed ($($LDAPTicketResult.Error)) - Windows PTT may handle cross-realm TGS natively"
                } else {
                    throw "LDAP service ticket failed: $($LDAPTicketResult.Error)"
                }
            } else {
                Write-Log "[Invoke-KerberosAuthFlow] LDAP service ticket acquired and imported"
            }

            # ===== Step 4: Request and import CIFS service ticket (for SMB/SYSVOL access) =====
            Write-Log "[Invoke-KerberosAuthFlow] Step 4: Requesting CIFS service ticket for SMB access..."

            $CIFSServiceSPN = "cifs/$DCHostname"
            $CIFSTicketResult = Request-AndImportServiceTicket -TGTBytes $TGTResult.TicketBytes `
                                                               -SessionKeyBytes $TGTResult.SessionKeyBytes `
                                                               -SessionKeyType $TGTResult.EncryptionType `
                                                               -ServicePrincipalName $CIFSServiceSPN `
                                                               -TargetDomain $Domain `
                                                               -KdcServer $TgsKdcServer `
                                                               -ClientName $SamAccountName `
                                                               -NonFatal

            if (-not $CIFSTicketResult.Success) {
                # CIFS ticket failure is non-fatal - LDAP still works, just SMB/SYSVOL won't
                Write-Log "[Invoke-KerberosAuthFlow] CIFS service ticket failed (SMB access may not work): $($CIFSTicketResult.Error)"
            }
            else {
                Write-Log "[Invoke-KerberosAuthFlow] CIFS service ticket acquired and imported"
            }

            # ===== Step 5: Connect to LDAP using Kerberos =====
            # NOTE: On non-domain-joined machines, the imported Kerberos ticket may NOT be automatically used by System.DirectoryServices.DirectoryEntry.
            # In this case, we return a specific error to trigger SimpleBind fallback.
            Write-Log "[Invoke-KerberosAuthFlow] Step 5: Establishing LDAP connection with Kerberos..."

            # Check if hosts file was patched - required for Kerberos SPN matching when using custom DNS without hosts file patching
            $HostsPatched = $Script:LDAPContext -and $Script:LDAPContext['EarlyHostsPatched']
            $UsingCustomDns = $Script:LDAPContext -and $Script:LDAPContext['DnsServer']

            if ($UsingCustomDns -and -not $HostsPatched) {
                Write-Log "[Invoke-KerberosAuthFlow] WARNING: Custom DNS active but hosts file not patched"
                Write-Log "[Invoke-KerberosAuthFlow] Kerberos tickets were obtained but may not be usable"
            }

            $ConnParams = @{}
            $ConnParams['Domain'] = $Domain
            # For Kerberos authentication, we MUST connect to the DC hostname that matches the SPN
            # (e.g., ldap/srv-dc.praxis.local). Connecting to the domain name won't work because
            # Windows can't match the SPN. Use explicit Server if provided, otherwise use DCHostname.
            if ($Server) {
                $ConnParams['Server'] = $Server
            } else {
                $ConnParams['Server'] = $DCHostname
                Write-Log "[Invoke-KerberosAuthFlow] Using DC hostname for LDAP: $DCHostname (required for Kerberos SPN matching)"
            }
            if ($UseLDAPS) { $ConnParams['UseLDAPS'] = $true }
            $ConnParams['IgnoreSSLErrors'] = $IgnoreSSLErrors
            # No Credential - attempts to use Kerberos ticket from session

            $Connection = Connect-LDAP @ConnParams

            if ($Connection) {
                # Verify we actually connected with the expected identity. On non-domain-joined machines, LDAP might fall back to anonymous or fail silently
                if ($Connection.AuthenticatedUser -and $Connection.AuthenticatedUser -notmatch '^\[') {
                    Write-Log "[Invoke-KerberosAuthFlow] Kerberos authentication completed successfully"
                    $Result.Success = $true
                    $Result.Connection = $Connection
                }
                else {
                    # Connection succeeded but identity is unknown or anonymous. This typically means the Kerberos ticket wasn't used
                    Write-Log "[Invoke-KerberosAuthFlow] LDAP connected but Kerberos ticket may not have been used"
                    throw "LDAP connection established but Kerberos ticket not used (non-domain-joined machine?)"
                }
            }
            else {
                # LDAP connection failed - determine the cause
                # Check if this is a hostname resolution issue (custom DNS without hosts patching)
                if ($UsingCustomDns -and -not $HostsPatched) {
                    # TGT, TGS, PTT all succeeded but LDAP failed
                    # This is almost certainly because Windows can't resolve the DC hostname
                    # to use the Kerberos ticket (SPN matching requires hostname resolution)
                    $DnsHint = "Kerberos tickets obtained successfully, but LDAP connection failed. " +
                               "This is likely because Windows cannot resolve '$DCHostname' via system DNS. " +
                               "The Kerberos ticket was issued for SPN 'ldap/$DCHostname' but Windows cannot " +
                               "match it without hostname resolution. Use -PatchHostsFile to enable Kerberos authentication, " +
                               "or the connection will fall back to SimpleBind."
                    throw $DnsHint
                }
                else {
                    throw "LDAP connection failed after ticket import (Kerberos ticket not usable on this system)"
                }
            }
        }
        catch {
            $Result.Error = $_.Exception.Message
            Write-Log "[Invoke-KerberosAuthFlow] Authentication failed: $($Result.Error)"
        }

        return $Result
    }
}
