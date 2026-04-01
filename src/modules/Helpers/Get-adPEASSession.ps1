function Get-adPEASSession {
<#
.SYNOPSIS
    Shows information about the current adPEAS session or tests connection health.

.DESCRIPTION
    Displays detailed information about the current LDAP connection and session.
    Shows Domain, Server, Protocol, Authentication and Session duration.

    With -TestConnection switch, performs a health check on the active session:
    - Checks session variables
    - Validates LDAP connection object
    - Executes test query to verify connectivity
    - Measures query latency

.PARAMETER TestConnection
    Performs a connection health check instead of showing session info.
    Tests if the session is still active and responsive.
    Shows detailed diagnostic information including domain, server, latency.

.PARAMETER Quiet
    Suppresses all output during TestConnection.
    Only returns $true/$false without displaying test results.
    Useful when called programmatically (e.g., from Invoke-adPEAS).

.EXAMPLE
    Get-adPEASSession
    Shows current session information.

.EXAMPLE
    Get-adPEASSession -TestConnection
    Performs connection health check with diagnostic details.

.EXAMPLE
    Get-adPEASSession -TestConnection -Quiet
    Performs silent health check, returns only $true/$false.

.EXAMPLE
    if (Get-adPEASSession -TestConnection -Quiet) {
        Write-Host "Connection is healthy"
    }

.OUTPUTS
    Without -TestConnection: Displays session information to console
    With -TestConnection: $true if connection is healthy, $false if problems exist

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [switch]$TestConnection,

        [Parameter(Mandatory=$false)]
        [switch]$Quiet
    )

    process {
        # Check if session exists (common check for both modes)
        # LdapConnection is used for ALL LDAP operations (queries and modifications)
        $hasLdapConnection = ($null -ne $Script:LdapConnection)

        if (-not $Script:LDAPContext -or -not $hasLdapConnection) {
            if ($TestConnection) {
                if (-not $Quiet) {
                    Show-SubHeader "Checking connection health..."
                    Show-KeyValue "Session Variables:" "FAIL: No active session found" -Class Finding
                    return
                }
                return $false
            } else {
                Show-NoSessionError -Context "Get-adPEASSession"
                return $null
            }
        }

        # Test Connection Health
        if ($TestConnection) {
            try {
                # Only show output if not in Quiet mode
                if (-not $Quiet) {
                    Show-Line "Health:" -Class Hint
                    Show-SubHeader "Checking connection health..."
                }

                $testResults = @{
                    SessionExists = $true
                    ConnectionValid = $false
                    QuerySuccessful = $false
                    Latency = $null
                    HealthStatus = "Unknown"
                    Errors = @()
                }

                # Test 1: Session variables (already checked above)
                if (-not $Quiet) {
                    Show-KeyValue "Session Variables:" "PASS" -Class Standard
                }

                # Test 2: Check if connection object is valid
                # LdapConnection is the only connection object used for all operations
                if ($hasLdapConnection) {
                    $protocol = if ($Script:LDAPContext.UseLDAPS) { "LDAPS" } else { "LDAP" }
                    if (-not $Quiet) {
                        Show-KeyValue "LDAP Connection Object:" "PASS (LdapConnection for $protocol)" -Class Standard
                    }
                }
                else {
                    if (-not $Quiet) {
                        Show-KeyValue "LDAP Connection Object:" "FAIL: No connection object found" -Class Finding
                        return
                    }
                    return $false
                }

                # Test 3: Execute test query
                $queryStartTime = Get-Date

                try {
                    $testQuery = Invoke-LDAPSearch -Filter "(objectClass=domain)" -SearchBase $Script:LDAPContext.DomainDN -Properties "name" -Scope Base

                    if (-not $testQuery) {
                        if (-not $Quiet) {
                            Show-KeyValue "LDAP Query Execution:" "FAIL: Test query returned no results" -Class Finding
                            return
                        }
                        return $false
                    }

                    $queryEndTime = Get-Date
                    $latency = ($queryEndTime - $queryStartTime).TotalMilliseconds

                    if (-not $Quiet) {
                        Show-KeyValue "LDAP Query Execution:" "PASS (Latency: $([math]::Round($latency, 2)) ms)" -Class Standard
                    }
                    $testResults.QuerySuccessful = $true
                    $testResults.Latency = [math]::Round($latency, 2)

                }
                catch {
                    if (-not $Quiet) {
                        Show-KeyValue "LDAP Query Execution:" "FAIL: $($_.Exception.Message)" -Class Finding
                        return
                    }
                    return $false
                }

                # All tests passed
                $testResults.HealthStatus = "Healthy"

                if (-not $Quiet) {
                    Show-KeyValue "Result:" "PASS (All tests passed - Connection is healthy)" -Class Note
                    Show-EmptyLine
                    return
                }

                return $true
            }
            catch {
                if (-not $Quiet) {
                    Show-KeyValue "Unexpected Error:" "FAIL: $($_.Exception.Message)" -Class Finding
                    Show-EmptyLine
                    return
                }
                return $false
            }
        }

        # Show Session Information (default)
        else {
            # Use SubHeader for session info (big ===== headers reserved for Invoke-adPEAS modules)
            Show-SubHeader "Displaying active session information..."

            # Connection Details
            Show-Line "Connection:" -Class Hint
            Show-KeyValue "Domain:" $Script:LDAPContext.Domain

            # Display Domain SID
            if ($Script:LDAPContext.DomainSID) {
                Show-KeyValue "Domain SID:" $Script:LDAPContext.DomainSID
            }

            Show-KeyValue "Server:" $Script:LDAPContext.Server
            if ($Script:LDAPContext['ServerIP']) {
                Show-KeyValue "Server IP:" $Script:LDAPContext['ServerIP']
            }
            Show-KeyValue "Protocol:" "$($Script:LDAPContext.Protocol) (Port $($Script:LDAPContext.Port))"
            Show-KeyValue "Domain DN:" $Script:LDAPContext.DomainDN

            # Authentication Details
            Show-EmptyLine
            Show-Line "Authentication:" -Class Hint

            if ($Script:LDAPContext.KerberosUsed -and $Script:LDAPContext.TGTInfo -and $Script:LDAPContext.TGTInfo.UserName) {
                # For Kerberos auth (Hash/Key/PKINIT), show TGT user
                $TGTUser = "$($Script:LDAPContext.TGTInfo.UserName)@$($Script:LDAPContext.TGTInfo.Domain)"
                Show-KeyValue "Authenticated as:" $TGTUser

                # Show User SID if available
                if ($Script:LDAPContext.AuthenticatedUserSID) {
                    Show-KeyValue "User SID:" $Script:LDAPContext.AuthenticatedUserSID
                }

                # Show NT-Hash if recovered via UnPAC-the-hash (PKINIT only)
                if ($Script:LDAPContext.TGTInfo.NTHash) {
                    Show-KeyValue "NT-Hash:" $Script:LDAPContext.TGTInfo.NTHash
                }
            }
            elseif ($Script:LDAPContext.AuthenticatedUser) {
                Show-KeyValue "Authenticated as:" $Script:LDAPContext.AuthenticatedUser

                # Show User SID if available
                if ($Script:LDAPContext.AuthenticatedUserSID) {
                    Show-KeyValue "User SID:" $Script:LDAPContext.AuthenticatedUserSID
                }

                if ($Script:LDAPContext.IdentityMismatch) {
                    Show-KeyValue "Local Identity:" $Script:LDAPContext.LocalIdentity
                    Show-Line "  Identity Mismatch: DETECTED" -Class Hint
                }

                # Show DN and UPN if available
                if ($Script:LDAPContext.AuthenticatedUserDN) {
                    Show-KeyValue "Distinguished Name:" $Script:LDAPContext.AuthenticatedUserDN
                }
                if ($Script:LDAPContext.AuthenticatedUserUPN) {
                    Show-KeyValue "User Principal Name:" $Script:LDAPContext.AuthenticatedUserUPN
                }
            }
            # Fallback if LDAP verification not available
            elseif ($Script:LDAPContext.Credential) {
                Show-KeyValue "Authenticated as:" $Script:LDAPContext.Credential.UserName
            }
            else {
                Show-KeyValue "Authenticated as:" "$env:USERDOMAIN\$env:USERNAME"
            }

            # Authentication Method (Kerberos vs SimpleBind vs Schannel vs NTLM)
            $AuthMethodDisplay = switch ($Script:LDAPContext.AuthMethod) {
                'Kerberos' {
                    # Check if TGT info is available (explicit Kerberos) or detected via SSPI
                    if ($Script:LDAPContext.TGTInfo) {
                        'Kerberos (TGT/TGS)'
                    } else {
                        'Kerberos (SSPI)'
                    }
                }
                'Schannel' { 'Schannel (TLS Client Certificate)' }
                'SimpleBind' { if ($Script:LDAPContext.UseLDAPS) { 'SimpleBind (LDAPS)' } else { 'SimpleBind (LDAP)' } }
                'WindowsSSPI' { 'Windows SSPI (Negotiate)' }
                'WindowsAuth' { 'Windows Authentication (Negotiate)' }
                'NTLM' { if ($Script:LDAPContext.UseLDAPS) { 'NTLM (LDAPS)' } else { 'NTLM (LDAP)' } }
                'NTLM Impersonation' { 'NTLM Impersonation (runas /netonly)' }
                default { 'Unknown' }
            }
            Show-KeyValue "Authentication Method:" $AuthMethodDisplay

            # Show TGT details if Kerberos was used
            if ($Script:LDAPContext.KerberosUsed -and $Script:LDAPContext.TGTInfo) {
                $TGT = $Script:LDAPContext.TGTInfo

                # Encryption type mapping (from original session)
                $ETypeDisplay = switch ($TGT.EncryptionType) {
                    17 { 'AES128-CTS-HMAC-SHA1' }
                    18 { 'AES256-CTS-HMAC-SHA1' }
                    23 { 'RC4-HMAC (NTLM)' }
                    default { "etype $($TGT.EncryptionType)" }
                }
                Show-KeyValue "TGT Encryption:" $ETypeDisplay

                # Show TGT method (how the TGT was obtained)
                if ($TGT.Method) {
                    Show-KeyValue "TGT Method:" $TGT.Method
                }

                # Show TGT realm
                if ($TGT.Domain) {
                    Show-KeyValue "TGT Realm:" $TGT.Domain
                }

                # Show clock skew between local system and KDC
                if ($TGT.ClockSkew -and $TGT.ClockSkew -is [TimeSpan]) {
                    $skewSeconds = [Math]::Round($TGT.ClockSkew.TotalSeconds)
                    $skewAbs = [Math]::Abs($skewSeconds)
                    $skewSign = if ($skewSeconds -ge 0) { "+" } else { "-" }
                    if ($skewAbs -ge 3600) {
                        $skewDisplay = "${skewSign}$([Math]::Floor($skewAbs / 3600))h $([Math]::Floor(($skewAbs % 3600) / 60))m"
                    } elseif ($skewAbs -ge 60) {
                        $skewDisplay = "${skewSign}$([Math]::Floor($skewAbs / 60))m $($skewAbs % 60)s"
                    } else {
                        $skewDisplay = "${skewSign}${skewAbs}s"
                    }
                    if ($skewAbs -gt 300) {
                        # >5 minutes - exceeds Kerberos tolerance
                        Show-KeyValue "Clock Skew:" "$skewDisplay (WARNING: exceeds 5-minute Kerberos limit!)" -Class Finding
                    } elseif ($skewAbs -gt 270) {
                        # 4.5-5 minutes - close to Kerberos tolerance
                        Show-KeyValue "Clock Skew:" "$skewDisplay (WARNING: close to 5-minute Kerberos limit)" -Class Finding
                    } elseif ($skewAbs -gt 60) {
                        Show-KeyValue "Clock Skew:" $skewDisplay -Class Hint
                    } else {
                        Show-KeyValue "Clock Skew:" $skewDisplay
                    }
                }

                # LIVE TGT Status Check via LSA API
                # Use -Force to bypass the 60-second cache and get real-time ticket status
                $LiveTicketStatus = Test-KerberosTGTExists -Detailed -Force

                if ($LiveTicketStatus.Valid) {
                    # Tickets are valid - show live EndTime from LSA
                    $endTimeLocal = $LiveTicketStatus.EndTime.ToLocalTime()
                    $now = Get-Date
                    $timeRemaining = $LiveTicketStatus.EndTime - $now

                    if ($timeRemaining.TotalSeconds -gt 0) {
                        $remainingDisplay = "{0:hh\:mm\:ss}" -f $timeRemaining
                        Show-KeyValue "TGT Valid Until:" "$($endTimeLocal.ToString('yyyy-MM-dd HH:mm:ss')) (in $remainingDisplay)"
                    }
                    else {
                        Show-KeyValue "TGT Valid Until:" "$($endTimeLocal.ToString('yyyy-MM-dd HH:mm:ss'))" -Class Finding
                        Write-Warning "[!] TGT EXPIRED - Re-authentication required!"
                    }

                }
                elseif ($LiveTicketStatus.TicketCount -eq 0) {
                    # Tickets were purged (klist purge)
                    Show-KeyValue "TGT Status:" "NO TICKETS IN CACHE - Re-authenticate with Connect-adPEAS" -Class Finding
                }
                elseif (-not $LiveTicketStatus.TGTPresent) {
                    # Tickets exist but no TGT (only service tickets)
                    Show-KeyValue "TGT Status:" "NO TGT FOUND ($($LiveTicketStatus.TicketCount) service tickets) - Re-authenticate with Connect-adPEAS" -Class Finding
                }
                elseif ($LiveTicketStatus.Expired) {
                    # TGT exists but is expired
                    $expiredTime = if ($LiveTicketStatus.EndTime) {
                        $LiveTicketStatus.EndTime.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')
                    } else { "unknown" }
                    Show-KeyValue "TGT Status:" "EXPIRED at $expiredTime - Re-authenticate with Connect-adPEAS" -Class Finding
                }
                elseif ($LiveTicketStatus.ClientMatch -eq $false) {
                    # TGT exists but for different user
                    $tgtClient = $LiveTicketStatus.ClientName
                    $expectedClient = $Script:LDAPContext.TGTInfo.UserName
                    Show-KeyValue "TGT Status:" "CLIENT MISMATCH (TGT=$tgtClient, Expected=$expectedClient) - Re-authenticate with Connect-adPEAS" -Class Finding
                }
                else {
                    # Unknown issue with tickets
                    Show-KeyValue "TGT Status:" "INVALID - Re-authenticate with Connect-adPEAS" -Class Finding
                }
            }

            # Session Metadata
            Show-EmptyLine
            Show-Line "Session:" -Class Hint
            if ($Script:LDAPContext.SessionStartTime) {
                $sessionDuration = (Get-Date) - $Script:LDAPContext.SessionStartTime
                Show-KeyValue "Session Started:" $Script:LDAPContext.SessionStartTime
                Show-KeyValue "Session Duration:" $sessionDuration.ToString('hh\:mm\:ss')
            }

            # Connection State - check live TGT status for Kerberos sessions
            if ($Script:LDAPContext.KerberosUsed) {
                # Re-use LiveTicketStatus if already queried, otherwise query again with -Force
                if (-not $LiveTicketStatus) {
                    $LiveTicketStatus = Test-KerberosTGTExists -Detailed -Force
                }

                if ($LiveTicketStatus.Valid) {
                    Show-KeyValue "Connection State:" "Connected (Kerberos TGT valid)"
                }
                elseif ($LiveTicketStatus.TicketCount -eq 0) {
                    Show-KeyValue "Connection State:" "DEGRADED (No Kerberos tickets)" -Class Finding
                }
                elseif (-not $LiveTicketStatus.TGTPresent) {
                    Show-KeyValue "Connection State:" "DEGRADED (No TGT, only service tickets)" -Class Finding
                }
                elseif ($LiveTicketStatus.Expired) {
                    Show-KeyValue "Connection State:" "DEGRADED (TGT expired)" -Class Finding
                }
                elseif ($LiveTicketStatus.ClientMatch -eq $false) {
                    Show-KeyValue "Connection State:" "DEGRADED (TGT client mismatch)" -Class Finding
                }
                else {
                    Show-KeyValue "Connection State:" "DEGRADED (TGT invalid)" -Class Finding
                }
            }
            elseif ($Script:LDAPContext.AuthMethod -eq 'Schannel') {
                Show-KeyValue "Connection State:" "Connected (Schannel/TLS)"
            }
            else {
                Show-KeyValue "Connection State:" "Connected"
            }

            # Hints
            Show-EmptyLine
            Show-Line "Help:" -Class Hint
            Show-KeyValue "Get-adPEASSession -TestConnection" "Test connection health"
            Show-KeyValue "Disconnect-adPEAS" "End the session"
            Show-EmptyLine
        }
    }
}
