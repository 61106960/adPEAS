function Invoke-KerberosAuth {
<#
.SYNOPSIS
    Unified Kerberos authentication module supporting multiple authentication methods.

.DESCRIPTION
    This function provides a central entry point for Kerberos authentication using various credential types.
    It supports password-based authentication, hash-based attacks (Overpass-the-Hash, Pass-the-Key), and certificate-based PKINIT.

    Authentication Methods:
    - Password: Standard Kerberos AS-REQ with PA-ENC-TIMESTAMP (AES256 > AES128 > RC4)
    - NT-Hash (RC4-HMAC): Overpass-the-Hash attack
    - AES128 Key: Pass-the-Key with AES128-CTS-HMAC-SHA1-96
    - AES256 Key: Pass-the-Key with AES256-CTS-HMAC-SHA1-96
    - Certificate (PKINIT): Certificate-based Kerberos with Diffie-Hellman

.PARAMETER UserName
    The username to authenticate as (sAMAccountName).

.PARAMETER Domain
    Target domain for authentication (FQDN).

.PARAMETER DomainController
    Specific domain controller to target. If not specified, uses auto-discovery.

.PARAMETER Credential
    PSCredential object for password-based authentication.

.PARAMETER Password
    Plain text password for authentication (converted to key internally).

.PARAMETER NTHash
    NT-Hash (NTLM hash) for RC4-HMAC authentication (Overpass-the-Hash).
    Format: 32 hex characters (e.g., "32ED87BDB5FDC5E9CBA88547376818D4")

.PARAMETER AES256Key
    AES256 key for AES256-CTS-HMAC-SHA1-96 authentication (Pass-the-Key).
    Format: 64 hex characters

.PARAMETER AES128Key
    AES128 key for AES128-CTS-HMAC-SHA1-96 authentication (Pass-the-Key).
    Format: 32 hex characters

.PARAMETER Certificate
    Certificate for PKINIT authentication. Accepts:
    - X509Certificate2 object
    - Path to a PFX certificate file
    - Base64-encoded PFX data
    The function auto-detects the input type.

.PARAMETER CertificatePassword
    Password for the PFX certificate file (optional, empty string if no password).

.PARAMETER PreferredEType
    Preferred encryption type for password-based auth (18=AES256, 17=AES128, 23=RC4).
    Default: 18 (AES256)

.PARAMETER OutputKirbi
    Optional path to save the TGT as a .kirbi file.

.PARAMETER NoPAC
    Request TGT without PAC (Privilege Attribute Certificate).

.PARAMETER OutputTicketOnly
    Returns only the Base64-encoded KRB-CRED (kirbi format) as a single-line string.
    This includes the session key, making it directly usable with:
    - Connect-adPEAS -Kirbi <ticket>
    - Rubeus ptt /ticket:<ticket>
    - Impacket tools

.EXAMPLE
    Invoke-KerberosAuth -UserName "john.doe" -Domain "contoso.com" -Credential (Get-Credential)
    Authenticates using password from PSCredential object.

.EXAMPLE
    Invoke-KerberosAuth -UserName "john.doe" -Domain "contoso.com" -Password "P@ssw0rd123"
    Authenticates using plain text password.

.EXAMPLE
    Invoke-KerberosAuth -UserName "john.doe" -Domain "contoso.com" -NTHash "32ED87BDB5FDC5E9CBA88547376818D4"
    Performs Overpass-the-Hash using the NT-Hash.

.EXAMPLE
    Invoke-KerberosAuth -UserName "john.doe" -Domain "contoso.com" -AES256Key "4a3b2c1d5e6f..."
    Performs Pass-the-Key using the AES256 key.

.EXAMPLE
    Invoke-KerberosAuth -UserName "john.doe" -Domain "contoso.com" -Certificate "user.pfx"
    Authenticates using PKINIT with a certificate file.

.EXAMPLE
    Invoke-KerberosAuth -UserName "john.doe" -Domain "contoso.com" -Certificate "MIIKwgYJKoZI..."
    Authenticates using PKINIT with a Base64-encoded certificate.

.EXAMPLE
    Invoke-KerberosAuth -UserName "john.doe" -Domain "contoso.com" -Certificate $x509Cert
    Authenticates using PKINIT with an X509Certificate2 object.

.EXAMPLE
    Invoke-KerberosAuth -UserName "john.doe" -Domain "contoso.com" -NTHash "32ED87..." -OutputTicketOnly
    Returns only the Base64 ticket string (single line) for easy copy-paste.

.EXAMPLE
    Invoke-KerberosAuth -UserName "john.doe" -Domain "contoso.com" -Password "pass" -OutputTicketOnly | Set-Clipboard
    Gets TGT and copies directly to clipboard.

.OUTPUTS
    PSCustomObject with authentication result including TGT and session key.

.NOTES
    Author: Alexander Sturz (@_61106960_)
    References:
    - RFC 4120: Kerberos V5
    - RFC 3961: Kerberos Cryptographic Framework
    - RFC 3962: AES Encryption for Kerberos 5
    - RFC 4556: PKINIT
    - RFC 4757: RC4-HMAC Kerberos Encryption
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$UserName,

        [Parameter(Mandatory=$true, Position=1)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$DomainController,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [string]$Password,

        [Parameter(Mandatory=$false)]
        [ValidatePattern('^[0-9a-fA-F]{32}$')]
        [string]$NTHash,

        [Parameter(Mandatory=$false)]
        [ValidatePattern('^[0-9a-fA-F]{64}$')]
        [string]$AES256Key,

        [Parameter(Mandatory=$false)]
        [ValidatePattern('^[0-9a-fA-F]{32}$')]
        [string]$AES128Key,

        [Parameter(Mandatory=$false)]
        $Certificate,  # Accepts X509Certificate2, string (file path), or string (Base64)

        [Parameter(Mandatory=$false)]
        [string]$CertificatePassword = "",

        [Parameter(Mandatory=$false)]
        [ValidateSet(18, 17, 23)]
        [int]$PreferredEType = 18,

        [Parameter(Mandatory=$false)]
        [string]$OutputKirbi,

        [Parameter(Mandatory=$false)]
        [switch]$NoPAC,

        [Parameter(Mandatory=$false)]
        [switch]$OutputTicketOnly
    )

    begin {
        Write-Log "[Invoke-KerberosAuth] Starting unified Kerberos authentication..."

        # Use PSBoundParameters to detect if parameter was provided (allows empty string passwords)
        $authMethods = @()
        if ($Credential) { $authMethods += "Credential" }
        if ($PSBoundParameters.ContainsKey('Password')) { $authMethods += "Password" }
        if ($NTHash) { $authMethods += "NTHash" }
        if ($AES256Key) { $authMethods += "AES256Key" }
        if ($AES128Key) { $authMethods += "AES128Key" }
        if ($Certificate) { $authMethods += "Certificate" }

        if ($authMethods.Count -eq 0) {
            throw "You must provide one authentication method: -Credential, -Password, -NTHash, -AES256Key, -AES128Key, or -Certificate"
        }
        if ($authMethods.Count -gt 1) {
            throw "You can only provide one authentication method at a time. Provided: $($authMethods -join ', ')"
        }

        $AuthMethodType = $authMethods[0]

        # Check for custom DNS configuration
        $CustomDnsServer = $null
        if ($Script:LDAPContext -and $Script:LDAPContext['DnsServer']) {
            $CustomDnsServer = $Script:LDAPContext['DnsServer']
            Write-Log "[Invoke-KerberosAuth] Custom DNS server configured: $CustomDnsServer"
        }

        if (-not $DomainController) {
            # Resolve DC using unified resolver
            $dcResult = Resolve-adPEASName -Domain $Domain -DnsServer $CustomDnsServer
            Write-Log "[Invoke-KerberosAuth] DC resolution: Hostname=$($dcResult.Hostname), IP=$($dcResult.IP)"

            # Prefer IP address if available (for custom DNS scenarios)
            if ($dcResult.IP) {
                $DomainController = $dcResult.IP
                Write-Log "[Invoke-KerberosAuth] Using resolved IP: $DomainController"
            }
            elseif ($dcResult.Hostname) {
                $DomainController = $dcResult.Hostname
                Write-Log "[Invoke-KerberosAuth] Using resolved hostname: $DomainController"
            }
            else {
                # Fallback to domain name
                $DomainController = $Domain
                Write-Log "[Invoke-KerberosAuth] Using domain name as fallback: $DomainController"
            }
        }
        else {
            # Explicit DomainController provided - resolve to IP if custom DNS is used
            if ($CustomDnsServer) {
                $ipTest = $null
                if (-not [System.Net.IPAddress]::TryParse($DomainController, [ref]$ipTest)) {
                    # Resolve hostname to IP via custom DNS (use -Name, not -Domain since DC is explicit)
                    $ResolvedIP = Resolve-adPEASName -Name $DomainController -DnsServer $CustomDnsServer
                    if ($ResolvedIP) {
                        Write-Log "[Invoke-KerberosAuth] Resolved explicit DC $DomainController to IP: $ResolvedIP"
                        $DomainController = $ResolvedIP
                    }
                }
            }
        }

        function New-PAEncTimestamp {
            param(
                [byte[]]$Key,
                [int]$EType
            )

            $now = [datetime]::UtcNow
            $pausec = $now.Millisecond * 1000

            $paEncTsEnc = @()
            $paEncTsEnc += New-ASN1ContextTag -Tag 0 -Data (New-ASN1GeneralizedTime -Value $now)
            $paEncTsEnc += New-ASN1ContextTag -Tag 1 -Data (New-ASN1Integer -Value $pausec)
            $paEncTsEncSeq = New-ASN1Sequence -Data $paEncTsEnc

            $keyUsage = 1

            switch ($EType) {
                23 { $encrypted = Encrypt-RC4HMAC -Key $Key -Data $paEncTsEncSeq -KeyUsage $keyUsage }
                17 { $encrypted = Encrypt-AESCTS -Key $Key -Data $paEncTsEncSeq -KeyUsage $keyUsage }
                18 { $encrypted = Encrypt-AESCTS -Key $Key -Data $paEncTsEncSeq -KeyUsage $keyUsage }
                default { throw "Unsupported encryption type: $EType" }
            }

            $encryptedData = New-KerberosEncryptedData -EType $EType -Cipher $encrypted

            return $encryptedData
        }

        function New-KerberosASREQ {
            param(
                [string]$UserName,
                [string]$Realm,
                [byte[]]$Key,
                [int]$EType,
                [switch]$NoPAC,
                [switch]$NoPreAuth  # Send AS-REQ without PA-ENC-TIMESTAMP to get PA-ETYPE-INFO2
            )

            $realmUpper = $Realm.ToUpper()
            $nonce = [uint32](Get-Random -Minimum 1 -Maximum 2147483647)

            # Build padata array
            $padataItems = @()

            # PA-ENC-TIMESTAMP (only if we have a key and not requesting salt)
            if (-not $NoPreAuth -and $Key) {
                $paEncTs = New-PAEncTimestamp -Key $Key -EType $EType
                $paPaEncTs = New-KerberosPAData -PADataType $Script:PA_ENC_TIMESTAMP -PADataValue $paEncTs
                $padataItems += $paPaEncTs
            }

            # PA-PAC-REQUEST
            $pacRequest = if ($NoPAC) {
                New-ASN1Sequence -Data (New-ASN1ContextTag -Tag 0 -Data (New-ASN1Boolean -Value $false))
            } else {
                New-ASN1Sequence -Data (New-ASN1ContextTag -Tag 0 -Data (New-ASN1Boolean -Value $true))
            }
            $paPacReq = New-KerberosPAData -PADataType $Script:PA_PAC_REQUEST -PADataValue $pacRequest
            $padataItems += $paPacReq

            $padata = New-ASN1Sequence -Data $padataItems

            # KDC-OPTIONS
            $kdcOptions = New-KerberosKDCOptions -Forwardable -Renewable -Canonicalize -RenewableOK

            # cname
            $cname = New-KerberosPrincipalName -NameType $Script:NT_PRINCIPAL -NameStrings @($UserName)

            # sname - krbtgt/REALM
            $sname = New-KerberosPrincipalName -NameType $Script:NT_SRV_INST -NameStrings @("krbtgt", $realmUpper)

            # till
            $till = [datetime]::new(2037, 9, 13, 2, 48, 5, [System.DateTimeKind]::Utc)

            # etype - request the same type we're using
            $etypeASN = New-ASN1Integer -Value $EType

            # KDC-REQ-BODY
            $reqBodyContent = @()
            $reqBodyContent += New-ASN1ContextTag -Tag 0 -Data $kdcOptions
            $reqBodyContent += New-ASN1ContextTag -Tag 1 -Data $cname
            $reqBodyContent += New-ASN1ContextTag -Tag 2 -Data (New-ASN1GeneralString -Value $realmUpper)
            $reqBodyContent += New-ASN1ContextTag -Tag 3 -Data $sname
            $reqBodyContent += New-ASN1ContextTag -Tag 5 -Data (New-ASN1GeneralizedTime -Value $till)
            $reqBodyContent += New-ASN1ContextTag -Tag 7 -Data (New-ASN1Integer -Value $nonce)
            $reqBodyContent += New-ASN1ContextTag -Tag 8 -Data (New-ASN1Sequence -Data $etypeASN)

            $reqBody = New-ASN1Sequence -Data $reqBodyContent

            # KDC-REQ
            $kdcReqContent = @()
            $kdcReqContent += New-ASN1ContextTag -Tag 1 -Data (New-ASN1Integer -Value 5)
            $kdcReqContent += New-ASN1ContextTag -Tag 2 -Data (New-ASN1Integer -Value $Script:KRB_AS_REQ)
            $kdcReqContent += New-ASN1ContextTag -Tag 3 -Data $padata
            $kdcReqContent += New-ASN1ContextTag -Tag 4 -Data $reqBody

            $kdcReq = New-ASN1Sequence -Data $kdcReqContent

            # AS-REQ = APPLICATION 10
            $asReq = New-ASN1ApplicationTag -Tag 10 -Data $kdcReq

            return @{
                ASReq = $asReq
                Nonce = $nonce
            }
        }

        function Parse-ASREP {
            param([byte[]]$Data)

            $result = @{
                Success = $false
                Error = $null
                ErrorCode = $null  # KDC error code (integer) for structured error handling
                ServerTime = $null # KDC server time from KRB-ERROR stime field
                Ticket = $null
                EncPart = $null
                EType = $null
                Kvno = $null
                ETypeInfo2 = $null  # PA-ETYPE-INFO2 from e-data (contains salt for AES)
            }

            try {
                $root = Read-ASN1Element -Data $Data -Offset 0
                Write-Debug "[Parse-ASREP] Root tag: $($root.Tag) (masked: $($root.Tag -band 0x1F))"

                if (($root.Tag -band 0x1F) -eq 30) {
                    Write-Debug "[Parse-ASREP] Detected KRB-ERROR response"

                    # KRB-ERROR structure: [APPLICATION 30] SEQUENCE { fields }
                    # The root.Content contains SEQUENCE which wraps the actual fields
                    $sequenceElement = Read-ASN1Element -Data $root.Content -Offset 0
                    Write-Debug "[Parse-ASREP] Inner element tag: $($sequenceElement.Tag) (TagNumber: $($sequenceElement.TagNumber))"

                    # Get the content to parse - if it's a SEQUENCE (0x30), use its content
                    # Otherwise, the APPLICATION tag directly contains the fields
                    $contentToParse = if ($sequenceElement.Tag -eq 0x30) {
                        Write-Debug "[Parse-ASREP] Parsing inner SEQUENCE content"
                        $sequenceElement.Content
                    } else {
                        Write-Debug "[Parse-ASREP] Parsing APPLICATION content directly"
                        $root.Content
                    }

                    $children = Read-ASN1Children -Data $contentToParse
                    $errorCode = $null
                    $errorText = $null
                    $edata = $null
                    $serverTime = $null

                    foreach ($child in $children) {
                        Write-Debug "[Parse-ASREP] Processing child tag: $($child.Tag) (TagNumber: $($child.TagNumber))"
                        if ($child.TagNumber -eq 4) {
                            # stime [4] KerberosTime - server time at error generation
                            try {
                                $stimeStr = Read-ASN1String -Content (Read-ASN1Element -Data $child.Content).Content
                                $serverTime = [DateTime]::ParseExact($stimeStr, "yyyyMMddHHmmssZ", $null, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal)
                                Write-Debug "[Parse-ASREP] Server time (stime): $serverTime"
                            } catch {
                                Write-Debug "[Parse-ASREP] Failed to read stime: $_"
                            }
                        }
                        elseif ($child.TagNumber -eq 6) {
                            # error-code [6] INTEGER
                            try {
                                $innerElement = Read-ASN1Element -Data $child.Content
                                $errorCode = Read-ASN1Integer -Content $innerElement.Content
                                Write-Debug "[Parse-ASREP] Error code: $errorCode"
                            } catch {
                                Write-Debug "[Parse-ASREP] Failed to read error code: $_"
                            }
                        }
                        elseif ($child.TagNumber -eq 11) {
                            # e-text [11] KerberosString OPTIONAL
                            try {
                                $errorText = Read-ASN1String -Content (Read-ASN1Element -Data $child.Content).Content
                                Write-Debug "[Parse-ASREP] Error text: $errorText"
                            } catch { }
                        }
                        elseif ($child.TagNumber -eq 12) {
                            # e-data [12] OCTET STRING OPTIONAL (contains PA-DATA or METHOD-DATA)
                            try {
                                $edata = (Read-ASN1Element -Data $child.Content).Content
                                Write-Debug "[Parse-ASREP] e-data present, length: $($edata.Length)"
                            } catch { }
                        }
                    }

                    # Store error code as separate property for structured error handling
                    $result.ErrorCode = $errorCode
                    $result.ServerTime = $serverTime

                    $result.Error = "KRB-ERROR"
                    if ($null -ne $errorCode) { $result.Error = "KRB-ERROR $errorCode" }
                    if ($errorText) { $result.Error += ": $errorText" }

                    # Use centralized Kerberos error code mapping
                    if ($null -ne $errorCode) {
                        $errorDesc = Get-KerberosErrorMessage -ErrorCode $errorCode
                        $result.Error += " ($errorDesc)"
                    }

                    # For clock skew errors, append DC time and offset
                    if ($errorCode -eq 37 -and $serverTime) {
                        $localTimeUTC = [DateTime]::UtcNow
                        $skew = $serverTime - $localTimeUTC
                        $skewStr = if ($skew.TotalSeconds -ge 0) { "+$($skew.ToString('hh\:mm\:ss'))" } else { "-$(([Math]::Abs($skew.TotalSeconds) -as [TimeSpan]).ToString('hh\:mm\:ss'))" }
                        $result.Error += " | DC time: $($serverTime.ToString('yyyy-MM-dd HH:mm:ss')) UTC, Local: $($localTimeUTC.ToString('yyyy-MM-dd HH:mm:ss')) UTC, Offset: $skewStr"
                    }

                    # Parse PA-ETYPE-INFO2 from edata if present (for preauth required errors)
                    # PA-ETYPE-INFO2 contains the correct salt for AES key derivation
                    if ($edata -and $errorCode -eq 25) {
                        try {
                            # e-data contains METHOD-DATA which is a SEQUENCE of PA-DATA
                            # METHOD-DATA ::= SEQUENCE OF PA-DATA
                            # PA-DATA ::= SEQUENCE {
                            #     padata-type [1] INTEGER,
                            #     padata-value [2] OCTET STRING
                            # }
                            $edataElement = Read-ASN1Element -Data $edata -Offset 0
                            Write-Debug "[Parse-ASREP] e-data element tag: $($edataElement.Tag), content length: $($edataElement.ContentLength)"

                            # Read-ASN1Children returns elements where .Content is the inner data
                            # Each PA-DATA is a SEQUENCE, so the element tag should be 0x30
                            $paDataSeq = Read-ASN1Children -Data $edataElement.Content
                            Write-Debug "[Parse-ASREP] Parsing e-data: $($paDataSeq.Count) PA-DATA entries"

                            foreach ($paItem in $paDataSeq) {
                                Write-Debug "[Parse-ASREP] PA-DATA item tag: $($paItem.Tag)"

                                # paItem is already a parsed element from Read-ASN1Children
                                # paItem.Content contains the inner data of this SEQUENCE
                                # We need to parse the children of this PA-DATA SEQUENCE
                                $paChildren = Read-ASN1Children -Data $paItem.Content

                                $paType = $null
                                $paValue = $null

                                foreach ($paChild in $paChildren) {
                                    Write-Debug "[Parse-ASREP] PA-DATA child tag: $($paChild.Tag), TagNumber: $($paChild.TagNumber)"
                                    if ($paChild.TagNumber -eq 1) {
                                        # padata-type [1] INTEGER - context tag wraps the INTEGER
                                        $paTypeElement = Read-ASN1Element -Data $paChild.Content
                                        $paType = Read-ASN1Integer -Content $paTypeElement.Content
                                        Write-Debug "[Parse-ASREP] PA-DATA type: $paType"
                                    }
                                    elseif ($paChild.TagNumber -eq 2) {
                                        # padata-value [2] OCTET STRING - context tag wraps the OCTET STRING
                                        $paValueElement = Read-ASN1Element -Data $paChild.Content
                                        $paValue = $paValueElement.Content
                                        Write-Debug "[Parse-ASREP] PA-DATA value length: $($paValue.Length)"
                                    }
                                }

                                # PA-ETYPE-INFO2 (type 19) - RFC 4120
                                # ETYPE-INFO2 ::= SEQUENCE OF ETYPE-INFO2-ENTRY
                                # ETYPE-INFO2-ENTRY ::= SEQUENCE {
                                #   etype     [0] Int32,
                                #   salt      [1] KerberosString OPTIONAL,
                                #   s2kparams [2] OCTET STRING OPTIONAL
                                # }
                                if ($paType -eq 19 -and $paValue) {
                                    Write-Debug "[Parse-ASREP] Found PA-ETYPE-INFO2, parsing..."
                                    try {
                                        $etypeInfo2Seq = Read-ASN1Element -Data $paValue -Offset 0
                                        Write-Debug "[Parse-ASREP] ETYPE-INFO2 outer tag: $($etypeInfo2Seq.Tag)"
                                        $etypeInfo2Entries = Read-ASN1Children -Data $etypeInfo2Seq.Content

                                        foreach ($entry in $etypeInfo2Entries) {
                                            Write-Debug "[Parse-ASREP] ETYPE-INFO2-ENTRY tag: $($entry.Tag)"
                                            # entry is a SEQUENCE element, its Content has the fields
                                            $entryChildren = Read-ASN1Children -Data $entry.Content

                                            $entryEType = $null
                                            $entrySalt = $null

                                            foreach ($field in $entryChildren) {
                                                Write-Debug "[Parse-ASREP] ETYPE-INFO2 field tag: $($field.Tag), TagNumber: $($field.TagNumber)"
                                                if ($field.TagNumber -eq 0) {
                                                    # etype [0] Int32
                                                    $etypeElement = Read-ASN1Element -Data $field.Content
                                                    $entryEType = Read-ASN1Integer -Content $etypeElement.Content
                                                    Write-Debug "[Parse-ASREP] Parsed etype: $entryEType"
                                                }
                                                elseif ($field.TagNumber -eq 1) {
                                                    # salt [1] KerberosString
                                                    $saltElement = Read-ASN1Element -Data $field.Content
                                                    $entrySalt = Read-ASN1String -Content $saltElement.Content
                                                    Write-Debug "[Parse-ASREP] Parsed salt: $entrySalt"
                                                }
                                            }

                                            Write-Debug "[Parse-ASREP] ETYPE-INFO2-ENTRY: etype=$entryEType, salt=$entrySalt"

                                            # Store first entry with salt (usually AES256)
                                            if ($entrySalt -and -not $result.ETypeInfo2) {
                                                $result.ETypeInfo2 = @{
                                                    EType = $entryEType
                                                    Salt = $entrySalt
                                                }
                                                Write-Debug "[Parse-ASREP] Using salt from PA-ETYPE-INFO2: $entrySalt"
                                            }
                                        }
                                    } catch {
                                        Write-Debug "[Parse-ASREP] Failed to parse PA-ETYPE-INFO2: $_"
                                    }
                                }
                            }
                        } catch {
                            Write-Debug "[Parse-ASREP] Failed to parse e-data: $_"
                        }
                    }

                    return $result
                }

                if (($root.Tag -band 0x1F) -ne 11) {
                    $result.Error = "Unexpected response type: $($root.Tag)"
                    return $result
                }

                # AS-REP is [APPLICATION 11] which wraps a SEQUENCE
                # The root.Content contains the SEQUENCE, so we need to parse it first
                $innerSeq = Read-ASN1Element -Data $root.Content -Offset 0
                $children = Read-ASN1Children -Data $innerSeq.Content

                foreach ($child in $children) {
                    switch ($child.TagNumber) {
                        5 {
                            $result.Ticket = $child.Content
                        }
                        6 {
                            $encPartSeq = Read-ASN1Element -Data $child.Content
                            $encPartChildren = Read-ASN1Children -Data $encPartSeq.Content

                            foreach ($encChild in $encPartChildren) {
                                if ($encChild.TagNumber -eq 0) {
                                    $result.EType = Read-ASN1Integer -Content (Read-ASN1Element -Data $encChild.Content).Content
                                }
                                elseif ($encChild.TagNumber -eq 1) {
                                    $result.Kvno = Read-ASN1Integer -Content (Read-ASN1Element -Data $encChild.Content).Content
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
                $result.Error = "Failed to parse AS-REP: $_"
            }

            return $result
        }

        function Parse-EncASRepPart {
            param(
                [byte[]]$Data,
                [byte[]]$Key,
                [int]$EType
            )

            $keyUsage = 3

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

                # EncASRepPart is [APPLICATION 25] which contains a SEQUENCE
                # We need to parse the inner SEQUENCE first
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
                                    # keytype [0] INTEGER
                                    $result.SessionKeyType = Read-ASN1Integer -Content (Read-ASN1Element -Data $keyChild.Content).Content
                                }
                                elseif ($keyChild.TagNumber -eq 1) {
                                    # keyvalue [1] OCTET STRING
                                    $result.SessionKey = (Read-ASN1Element -Data $keyChild.Content).Content
                                }
                            }
                        }
                        4 {
                            # flags [4] TicketFlags (BIT STRING, 4 bytes)
                            $flagElement = Read-ASN1Element -Data $child.Content
                            # BIT STRING: first byte is number of unused bits, remaining bytes are the flag data
                            if ($flagElement.Content.Length -ge 5) {
                                # Standard: 1 byte unused-bits + 4 bytes flags
                                $result.TicketFlags = $flagElement.Content[1..4]
                            } elseif ($flagElement.Content.Length -eq 4) {
                                # Some implementations omit unused-bits prefix
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
                            # endtime [7] KerberosTime - MANDATORY, this is when TGT expires
                            $timeElement = Read-ASN1Element -Data $child.Content
                            $timeString = [System.Text.Encoding]::ASCII.GetString($timeElement.Content)
                            $result.EndTime = [DateTime]::ParseExact($timeString, "yyyyMMddHHmmssZ", $null, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal)
                        }
                        8 {
                            # renew-till [8] KerberosTime OPTIONAL - renewable until this time
                            $timeElement = Read-ASN1Element -Data $child.Content
                            $timeString = [System.Text.Encoding]::ASCII.GetString($timeElement.Content)
                            $result.RenewTill = [DateTime]::ParseExact($timeString, "yyyyMMddHHmmssZ", $null, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal)
                        }
                    }
                }
            }
            catch {
                $result.Success = $false
                $result.Error = "Failed to parse EncASRepPart: $_"
            }

            return $result
        }

        # Helper function to build KRB-CRED and return as Base64
        # Centralizes the Build-KRBCred logic to avoid code duplication
        function ConvertTo-KRBCredBase64 {
            param(
                [byte[]]$TicketBytes,
                [byte[]]$SessionKeyBytes,
                [int]$SessionKeyType,
                [string]$Realm,
                [string]$ClientName,
                [byte[]]$TicketFlags,
                $StartTime,
                $EndTime,
                $RenewTill
            )

            # Validate required parameters
            if (-not $TicketBytes -or $TicketBytes.Length -eq 0) {
                Write-Warning "[ConvertTo-KRBCredBase64] TicketBytes is null or empty"
                return $null
            }
            if (-not $SessionKeyBytes -or $SessionKeyBytes.Length -eq 0) {
                Write-Warning "[ConvertTo-KRBCredBase64] SessionKeyBytes is null or empty - cannot create valid KRB-CRED"
                return $null
            }

            $buildParams = @{
                Ticket = $TicketBytes
                SessionKey = $SessionKeyBytes
                SessionKeyType = $SessionKeyType
                Realm = $Realm
                ClientName = $ClientName
                ServerName = "krbtgt"
                ServerInstance = $Realm
                StartTime = $StartTime
                EndTime = $EndTime
                RenewTill = $RenewTill
            }
            if ($TicketFlags) { $buildParams['TicketFlags'] = $TicketFlags }

            $krbCred = Build-KRBCred @buildParams
            return [Convert]::ToBase64String($krbCred)
        }

        # Helper function to add CopyTicket and ShowTicket ScriptMethods to result object
        function Add-TicketHelperMethods {
            param(
                [Parameter(Mandatory=$true)]
                [PSCustomObject]$ResultObject
            )

            $ResultObject | Add-Member -MemberType ScriptMethod -Name "CopyTicket" -Value {
                if ($this.Ticket) {
                    $this.Ticket | Set-Clipboard
                    Write-Host "[+] Ticket copied to clipboard (Base64, single line)" -ForegroundColor Green
                }
            }

            $ResultObject | Add-Member -MemberType ScriptMethod -Name "ShowTicket" -Value {
                if ($this.Ticket) {
                    Write-Host "`n[Ticket Base64 - Single Line]" -ForegroundColor Cyan
                    Write-Host $this.Ticket -ForegroundColor White
                    Write-Host ""
                }
            }

            return $ResultObject
        }
    }

    process {
        try {
            $realmUpper = $Domain.ToUpper()

            # Initialize AuthMethod with fallback value (used in error handler)
            $AuthMethod = "Unknown"

            switch ($AuthMethodType) {
                { $_ -in @("Credential", "Password") } {
                    # Extract plaintext password from source
                    if ($AuthMethodType -eq "Credential") {
                        $PlainPassword = $Credential.GetNetworkCredential().Password
                        $AuthMethod = "Password (from Credential)"
                    } else {
                        $PlainPassword = $Password
                        $AuthMethod = "Password"
                    }

                    # Derive key based on encryption type
                    # Salt format: UPPERCASE(REALM) + username (RFC 3962)
                    # NOTE: The username part is CASE-SENSITIVE! The salt uses the username
                    # exactly as stored in AD (typically with original casing from account creation).
                    # We try the provided username first, which should match what the user knows.
                    $EType = $PreferredEType
                    $Salt = $realmUpper + $UserName

                    switch ($EType) {
                        18 {
                            $KeyBytes = Get-AESKeyFromPassword -PlainPassword $PlainPassword -Salt $Salt -KeyLength 32
                            Write-Log "[Invoke-KerberosAuth] Using AES256 with salt: $Salt"
                        }
                        17 {
                            $KeyBytes = Get-AESKeyFromPassword -PlainPassword $PlainPassword -Salt $Salt -KeyLength 16
                            Write-Log "[Invoke-KerberosAuth] Using AES128 with salt: $Salt"
                        }
                        default {
                            # RC4-HMAC uses NT-Hash (no salt needed)
                            $KeyBytes = Get-NTHashFromPassword -PlainPassword $PlainPassword
                            $ntHashHex = ($KeyBytes | ForEach-Object { $_.ToString('X2') }) -join ''
                            Write-Log "[Invoke-KerberosAuth] Using RC4-HMAC (NT-Hash)"
                            Write-Debug "[Invoke-KerberosAuth] Computed NT-Hash: $ntHashHex (from password: '$PlainPassword')"
                        }
                    }
                }

                "NTHash" {
                    $EType = 23
                    $KeyBytes = [byte[]]@(for ($i = 0; $i -lt 32; $i += 2) { [Convert]::ToByte($NTHash.Substring($i, 2), 16) })
                    $AuthMethod = "Overpass-the-Hash (RC4-HMAC)"
                }

                "AES256Key" {
                    $EType = 18
                    $KeyBytes = [byte[]]@(for ($i = 0; $i -lt 64; $i += 2) { [Convert]::ToByte($AES256Key.Substring($i, 2), 16) })
                    $AuthMethod = "Pass-the-Key (AES256)"
                }

                "AES128Key" {
                    $EType = 17
                    $KeyBytes = [byte[]]@(for ($i = 0; $i -lt 32; $i += 2) { [Convert]::ToByte($AES128Key.Substring($i, 2), 16) })
                    $AuthMethod = "Pass-the-Key (AES128)"
                }

                "Certificate" {
                    # Unified certificate handling - accepts X509Certificate2, file path, or Base64
                    $AuthMethod = "PKINIT (Certificate)"
                    Write-Log "[Invoke-KerberosAuth] Starting PKINIT for $UserName@$realmUpper via $DomainController"

                    $pkInitParams = @{
                        Domain = $Domain
                        DomainController = $DomainController
                        UserName = $UserName
                        NoPAC = $NoPAC
                    }

                    # Handle different certificate input types
                    if ($Certificate -is [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
                        # X509Certificate2 object - pass directly
                        $pkInitParams['Certificate'] = $Certificate
                        $AuthMethod = "PKINIT (Certificate Object)"
                    }
                    elseif ($Certificate -is [string]) {
                        # String input - could be file path or Base64
                        $certResult = ConvertFrom-Base64OrFile -InputValue $Certificate -ExpectedFormat "Certificate" -ParameterName "Certificate"

                        if (-not $certResult.Success) {
                            return [PSCustomObject]@{
                                Success = $false
                                Method = $AuthMethod
                                UserName = $UserName
                                Domain = $realmUpper
                                DomainController = $DomainController
                                Error = "Certificate error: $($certResult.Error)"
                                ErrorCode = $null  # Certificate errors are not KDC errors
                                Message = "Certificate error: $($certResult.Error)"
                            }
                        }

                        Write-Log "[Invoke-KerberosAuth] Certificate loaded from $($certResult.Source): $($certResult.Data.Length) bytes"

                        # Load the certificate from bytes
                        try {
                            $CertObject = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
                                $certResult.Data,
                                $CertificatePassword,
                                [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
                            )
                            $pkInitParams['Certificate'] = $CertObject
                            $AuthMethod = "PKINIT (Certificate from $($certResult.Source))"
                        }
                        catch {
                            return [PSCustomObject]@{
                                Success = $false
                                Method = $AuthMethod
                                UserName = $UserName
                                Domain = $realmUpper
                                DomainController = $DomainController
                                Error = "Failed to load certificate: $_"
                                ErrorCode = $null  # Certificate errors are not KDC errors
                                Message = "Failed to load certificate: $_"
                            }
                        }
                    }
                    else {
                        return [PSCustomObject]@{
                            Success = $false
                            Method = $AuthMethod
                            UserName = $UserName
                            Domain = $realmUpper
                            DomainController = $DomainController
                            Error = "Invalid Certificate parameter type. Expected X509Certificate2, file path, or Base64 string."
                            ErrorCode = $null  # Certificate errors are not KDC errors
                            Message = "Invalid Certificate parameter type"
                        }
                    }

                    if ($OutputKirbi) { $pkInitParams['OutputKirbi'] = $OutputKirbi }

                    $pkInitResult = Invoke-PKINITAuth-Native @pkInitParams

                    # Calculate clock skew for PKINIT
                    $pkInitClockSkew = $null
                    if ($pkInitResult.AuthTime) {
                        $pkInitClockSkew = $pkInitResult.AuthTime - [DateTime]::UtcNow
                    }

                    # Create result object with ScriptMethod for easy ticket copying
                    $resultObj = [PSCustomObject]@{
                        Success = $pkInitResult.Success
                        Method = $AuthMethod
                        UserName = $UserName
                        Domain = $realmUpper
                        DomainController = $DomainController
                        EncryptionType = if ($pkInitResult.EncryptionType) { $pkInitResult.EncryptionType } else { "PKINIT-DH" }
                        Ticket = $pkInitResult.Ticket
                        SessionKey = $pkInitResult.SessionKey
                        SessionKeyBytes = $pkInitResult.SessionKeyBytes
                        TicketBytes = $pkInitResult.TicketBytes
                        TicketFlags = $pkInitResult.TicketFlags
                        ASRepReplyKey = $pkInitResult.ASRepReplyKey  # DH-derived key for UnPAC-the-hash
                        AuthTime = $pkInitResult.AuthTime
                        StartTime = $pkInitResult.StartTime
                        EndTime = $pkInitResult.EndTime
                        RenewTill = $pkInitResult.RenewTill
                        ClockSkew = $pkInitClockSkew
                        Message = if ($pkInitResult.Success) { "PKINIT authentication successful" } else { $pkInitResult.Error }
                        Error = $pkInitResult.Error
                    }

                    # Add helper methods only if authentication was successful
                    if ($pkInitResult.Success -and $pkInitResult.Ticket) {
                        $resultObj = Add-TicketHelperMethods -ResultObject $resultObj
                    }

                    # OutputTicketOnly: Return KRB-CRED as Base64 string (single line, no object)
                    if ($OutputTicketOnly) {
                        if ($pkInitResult.Success -and $pkInitResult.TicketBytes -and $pkInitResult.SessionKeyBytes) {
                            return ConvertTo-KRBCredBase64 -TicketBytes $pkInitResult.TicketBytes `
                                -SessionKeyBytes $pkInitResult.SessionKeyBytes `
                                -SessionKeyType $pkInitResult.EncryptionType `
                                -Realm $realmUpper `
                                -ClientName $UserName `
                                -TicketFlags $pkInitResult.TicketFlags `
                                -StartTime $pkInitResult.StartTime `
                                -EndTime $pkInitResult.EndTime `
                                -RenewTill $pkInitResult.RenewTill
                        } else {
                            Write-Error "PKINIT authentication failed: $($pkInitResult.Error)"
                            return $null
                        }
                    }

                    return $resultObj
                }
            }
            Write-Log "[Invoke-KerberosAuth] $AuthMethod for $UserName@$realmUpper via $DomainController (etype $EType)"

            # For AES password-based authentication, we need the correct salt from the KDC
            # The salt is case-sensitive (RFC 3962) and AD stores usernames with original casing
            # Standard approach: Send AS-REQ without preauth to get PA-ETYPE-INFO2 with correct salt
            $UseKDCSalt = ($AuthMethodType -in @("Credential", "Password")) -and ($EType -in @(17, 18))

            if ($UseKDCSalt) {
                # Step 1: Send AS-REQ without preauth to get PA-ETYPE-INFO2 from KDC
                Write-Log "[Invoke-KerberosAuth] Requesting salt from KDC (AS-REQ without preauth)..."
                $saltReqResult = New-KerberosASREQ -UserName $UserName -Realm $Domain -EType $EType -NoPreAuth
                $saltReqBytes = $saltReqResult.ASReq
                $saltResponseBytes = Send-KerberosRequest -Server $DomainController -Request $saltReqBytes
                $saltResponse = Parse-ASREP -Data $saltResponseBytes

                # We expect KDC_ERR_PREAUTH_REQUIRED (25) with PA-ETYPE-INFO2 in e-data
                if ($saltResponse.ErrorCode -eq 25 -and $saltResponse.ETypeInfo2) {
                    # Extract salt from PA-ETYPE-INFO2
                    $kdcSalt = $saltResponse.ETypeInfo2.Salt
                    # CRITICAL: Use -cne (case-sensitive comparison) because Kerberos salt IS case-sensitive!
                    # PowerShell's -ne is case-insensitive by default, which would miss "Administrator" vs "administrator"
                    if ($kdcSalt -and $kdcSalt -cne $Salt) {
                        Write-Log "[Invoke-KerberosAuth] KDC provided salt: $kdcSalt (differs from default: $Salt)"
                        $Salt = $kdcSalt

                        # Recalculate key with correct salt
                        switch ($EType) {
                            18 { $KeyBytes = Get-AESKeyFromPassword -PlainPassword $PlainPassword -Salt $Salt -KeyLength 32 }
                            17 { $KeyBytes = Get-AESKeyFromPassword -PlainPassword $PlainPassword -Salt $Salt -KeyLength 16 }
                        }
                    } else {
                        Write-Log "[Invoke-KerberosAuth] KDC salt matches default: $Salt"
                    }
                } elseif ($saltResponse.ErrorCode -eq 25) {
                    # PREAUTH_REQUIRED but no PA-ETYPE-INFO2 - use default salt
                    Write-Log "[Invoke-KerberosAuth] KDC requires preauth but no PA-ETYPE-INFO2 provided, using default salt: $Salt"
                } else {
                    # Unexpected response (maybe user doesn't exist, or other error)
                    Write-Log "[Invoke-KerberosAuth] Unexpected response to salt request (error $($saltResponse.ErrorCode)), proceeding with default salt"
                }
            }

            # Build AS-REQ with preauth (using correct salt)
            $asReqResult = New-KerberosASREQ -UserName $UserName -Realm $Domain -Key $KeyBytes -EType $EType -NoPAC:$NoPAC
            $asReqBytes = $asReqResult.ASReq
            Write-Log "[Invoke-KerberosAuth] AS-REQ built ($($asReqBytes.Length) bytes), sending to KDC..."

            # Send to KDC
            $responseBytes = Send-KerberosRequest -Server $DomainController -Request $asReqBytes
            Write-Log "[Invoke-KerberosAuth] Received response ($($responseBytes.Length) bytes)"

            # Parse AS-REP
            $asRep = Parse-ASREP -Data $responseBytes
            if (-not $asRep.Success) {
                # Calculate clock skew from server time if available
                $clockSkew = $null
                if ($asRep.ServerTime) {
                    $clockSkew = $asRep.ServerTime - [DateTime]::UtcNow
                }

                # Return structured error with ErrorCode for upstream handling
                return [PSCustomObject]@{
                    Success = $false
                    Method = $AuthMethod
                    UserName = $UserName
                    Domain = $Domain
                    Error = $asRep.Error
                    ErrorCode = $asRep.ErrorCode  # KDC error code (e.g., 24=KDC_ERR_PREAUTH_FAILED)
                    ClockSkew = $clockSkew  # TimeSpan if server time available
                    Message = "$AuthMethod failed: $($asRep.Error)"
                }
            }
            Write-Log "[Invoke-KerberosAuth] AS-REP received (etype $($asRep.EType), kvno $($asRep.Kvno))"

            # Verify EType matches what we requested
            if ($asRep.EType -ne $EType) {
                Write-Log "[Invoke-KerberosAuth] WARNING: KDC returned etype $($asRep.EType) but we requested etype $EType"
            }

            # Debug: Show key being used for decryption
            $keyHex = ($KeyBytes | ForEach-Object { $_.ToString('X2') }) -join ''
            Write-Log "[Invoke-KerberosAuth] Decrypting with key ($($KeyBytes.Length) bytes): $($keyHex.Substring(0, [Math]::Min(16, $keyHex.Length)))..."
            Write-Log "[Invoke-KerberosAuth] enc-part size: $($asRep.EncPart.Length) bytes"

            # Decrypt enc-part to get session key
            $encRepPart = Parse-EncASRepPart -Data $asRep.EncPart -Key $KeyBytes -EType $asRep.EType
            if (-not $encRepPart.Success) {
                # Decryption failure - but KDC accepted our preauth, so password may be correct!
                # This could happen with very old accounts or edge cases
                Write-Log "[Invoke-KerberosAuth] Decryption failed: $($encRepPart.Error)"

                # Use ErrorCode $null to indicate this is NOT a KDC error - fallback should be attempted
                # The password might still be correct (KDC accepted preauth) but we can't decrypt the response
                return [PSCustomObject]@{
                    Success = $false
                    Method = $AuthMethod
                    UserName = $UserName
                    Domain = $realmUpper
                    DomainController = $DomainController
                    EncryptionType = $asRep.EType
                    Ticket = $null
                    SessionKey = $null
                    SessionKeyBytes = $null
                    TicketBytes = $null
                    Error = "Decryption failed: $($encRepPart.Error)"
                    ErrorCode = $null  # NOT a KDC error - allow fallback to NTLM/SimpleBind
                    Message = "$AuthMethod failed: Cannot decrypt AS-REP (try -ForceSimpleBind)"
                }
            } else {
                $sessionKey = $encRepPart.SessionKey
                Write-Log "[Invoke-KerberosAuth] Session key extracted ($($sessionKey.Length) bytes, type $($encRepPart.SessionKeyType))"
                if ($encRepPart.EndTime) {
                    Write-Log "[Invoke-KerberosAuth] TGT valid until: $($encRepPart.EndTime.ToString('yyyy-MM-dd HH:mm:ss')) UTC"
                }
                if ($encRepPart.RenewTill) {
                    Write-Log "[Invoke-KerberosAuth] Renewable until: $($encRepPart.RenewTill.ToString('yyyy-MM-dd HH:mm:ss')) UTC"
                }
            }

            # Build result
            $ticketB64 = [Convert]::ToBase64String($asRep.Ticket)
            $sessionKeyB64 = if ($sessionKey) { [Convert]::ToBase64String($sessionKey) } else { $null }

            # Optional: Save as .kirbi (KRB-CRED format with session key)
            if ($OutputKirbi) {
                if (-not $sessionKey) {
                    Write-Warning "[Invoke-KerberosAuth] Cannot save kirbi: Session key not available (decryption failed)"
                } else {
                    # Build proper KRB-CRED structure (not just raw ticket!)
                    $krbCredBytes = Build-KRBCred -Ticket $asRep.Ticket `
                        -SessionKey $sessionKey `
                        -SessionKeyType $asRep.EType `
                        -Realm $realmUpper `
                        -ClientName $UserName `
                        -ServerName "krbtgt" `
                        -ServerInstance $realmUpper `
                        -StartTime $encRepPart.StartTime `
                        -EndTime $encRepPart.EndTime `
                        -RenewTill $encRepPart.RenewTill

                    $exportResult = Export-adPEASFile -Path $OutputKirbi -Content $krbCredBytes -Type Binary -Force
                    if ($exportResult.Success) {
                        Write-Log "[Invoke-KerberosAuth] Kirbi (KRB-CRED) saved to: $($exportResult.Path) ($($exportResult.BytesWritten) bytes)"
                    } else {
                        Write-Warning "[Invoke-KerberosAuth] Failed to save kirbi: $($exportResult.Message)"
                    }
                }
            }

            # Calculate clock skew between local system and KDC
            $clockSkew = $null
            if ($encRepPart.AuthTime) {
                $clockSkew = $encRepPart.AuthTime - [DateTime]::UtcNow
            }

            # Create result object with ScriptMethod for easy ticket copying
            $resultObj = [PSCustomObject]@{
                Success = $true
                Method = $AuthMethod
                UserName = $UserName
                Domain = $realmUpper
                DomainController = $DomainController
                EncryptionType = $asRep.EType
                Ticket = $ticketB64
                SessionKey = $sessionKeyB64
                SessionKeyBytes = $sessionKey
                TicketBytes = $asRep.Ticket
                TicketFlags = $encRepPart.TicketFlags
                AuthTime = $encRepPart.AuthTime
                StartTime = $encRepPart.StartTime
                EndTime = $encRepPart.EndTime
                RenewTill = $encRepPart.RenewTill
                ClockSkew = $clockSkew  # TimeSpan: KDC time minus local UTC time
                Error = $null
                ErrorCode = $null  # No error on success
                Message = "$AuthMethod authentication successful"
            }

            # Add helper methods for ticket handling
            $resultObj = Add-TicketHelperMethods -ResultObject $resultObj

            # OutputTicketOnly: Return KRB-CRED as Base64 string (single line, no object)
            if ($OutputTicketOnly) {
                if (-not $sessionKey) {
                    Write-Error "Cannot create KRB-CRED: Session key not available (decryption failed)"
                    return $null
                }
                $krbCredB64 = ConvertTo-KRBCredBase64 -TicketBytes $asRep.Ticket `
                    -SessionKeyBytes $sessionKey `
                    -SessionKeyType $asRep.EType `
                    -Realm $realmUpper `
                    -ClientName $UserName `
                    -TicketFlags $encRepPart.TicketFlags `
                    -StartTime $encRepPart.StartTime `
                    -EndTime $encRepPart.EndTime `
                    -RenewTill $encRepPart.RenewTill
                if (-not $krbCredB64) {
                    Write-Error "Failed to create KRB-CRED"
                    return $null
                }
                return $krbCredB64
            }

            return $resultObj
        }
        catch {
            Write-Log "[Invoke-KerberosAuth] $AuthMethod failed: $_"
            Write-Debug "[Invoke-KerberosAuth] Error details: $($_.Exception.ToString())"

            # Detect network errors (connection refused, host unreachable, etc.)
            # These are NOT authentication errors and should be reported differently
            $IsNetworkError = $false
            $NetworkErrorServer = $null
            $NetworkErrorPort = 88

            # Check for socket/network exceptions
            $innerEx = $_.Exception
            while ($innerEx) {
                if ($innerEx -is [System.Net.Sockets.SocketException] -or
                    $innerEx.Message -match 'No connection could be made|actively refused|target machine|cannot be reached|network is unreachable|host is down|timed out') {
                    $IsNetworkError = $true
                    $NetworkErrorServer = $DomainController
                    break
                }
                $innerEx = $innerEx.InnerException
            }

            # OutputTicketOnly: Return null on error (error message already written)
            if ($OutputTicketOnly) {
                Write-Error "$AuthMethod failed: $_"
                return $null
            }

            return [PSCustomObject]@{
                Success = $false
                Method = $AuthMethod
                UserName = $UserName
                Domain = $Domain
                Error = $_.Exception.Message
                ErrorCode = $null  # Non-KDC errors don't have error codes
                Message = "$AuthMethod failed: $_"
                IsNetworkError = $IsNetworkError
                NetworkErrorServer = $NetworkErrorServer
                NetworkErrorPort = $NetworkErrorPort
            }
        }
    }

    end {
        Write-Log "[Invoke-KerberosAuth] Kerberos authentication completed"
    }
}
