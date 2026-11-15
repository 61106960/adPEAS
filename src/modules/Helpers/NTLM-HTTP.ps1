<#
.SYNOPSIS
    NTLM over HTTP helpers for testing Extended Protection for Authentication (EPA).

.DESCRIPTION
    EPA binds an NTLM logon to the TLS channel it travels on. The client puts a hash of the
    server's certificate - the channel binding, MsvAvChannelBindings - into its NTLMv2
    response, and IIS rejects a logon whose binding is missing or names another channel. A
    relayed logon names the attacker's channel or none at all, so EPA stops the relay.

    Only a logon that succeeds can show whether the binding was checked. IIS answers every
    rejected logon with the same 401: a missing binding and a wrong password alike, with
    byte-identical headers, an empty body and no measurable difference in timing (measured
    against Exchange SE with random credentials and every binding variant, NTLMv1 and an
    anonymous logon). A probe with invalid credentials therefore cannot tell, whatever it
    sends - the probe this module used to run could only ever answer "undetermined".

    The probe logs on with a real identity, up to four times, each over a connection of its
    own (Test-ExtendedProtection, Resolve-EPAProbeVerdict):

    - with the correct binding       the control - if this logon fails, the identity cannot
                                     log on to this endpoint and nothing else is a verdict
    - without a binding              rejected: EPA is required
    - with the binding of another    rejected: EPA is set to Accept; accepted: EPA is off
      channel

    "Without a binding" means without the MsvAvChannelBindings pair at all, and the
    difference matters (measured against IIS in all three modes): a Windows client that
    has no channel to bind sends the pair with 16 zero bytes, and Accept rejects that just
    like a foreign binding - it takes only a logon that carries no pair, the logon of a
    client that implements no channel binding. Accept therefore stops the relay of a
    coerced Windows machine, and only such clients remain relayable through it. SSPI
    always sends the pair, so a logon through SSPI cannot tell Required from Accept.

    Where TLS ends at a proxy in front of IIS, the channel binding cannot be verified, and
    IIS with the Proxy flag and an SPN list checks the service binding instead - the SPN
    the client named (MsvAvTargetName). Any binding that is not zero passes there, so a
    fourth logon names another host: rejected means service binding. Plain HTTP can only
    be protected that way, and is probed with the control and that logon alone.

    The identity is named, never assumed (New-EPAProbeIdentity): a credential, a password or an
    NT hash given to the call, the identity of the adPEAS session (-UseSession, what the checks
    pass), or the current Windows logon through SSPI (-UseWindowsAuth). A password or NT hash
    answers the challenge here, in New-NTLMAuthenticateMessage. An identity that has no password
    or NT hash - AES key, certificate, ticket - cannot answer an NTLM challenge, and its endpoints
    stay undetermined.

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

# Global RNG instance for efficiency (thread-safe, created once)
$Script:NTLM_RNG = $null

function Get-NTLMSecureRNG {
    <#
    .SYNOPSIS
        Returns a shared cryptographically secure RNG instance.
    .DESCRIPTION
        Creates or returns a shared RandomNumberGenerator instance.
        This avoids creating/disposing RNG for each random operation.
    #>
    if ($null -eq $Script:NTLM_RNG) {
        $Script:NTLM_RNG = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    }
    return $Script:NTLM_RNG
}

function Get-NTLMRandomBytes {
    <#
    .SYNOPSIS
        Returns the given number of cryptographically random bytes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$Count
    )

    $bytes = New-Object byte[] $Count
    (Get-NTLMSecureRNG).GetBytes($bytes)
    return ,$bytes
}

# NTLM Message Type Constants
$Script:NTLM_TYPE1 = 1
$Script:NTLM_TYPE2 = 2
$Script:NTLM_TYPE3 = 3

# NTLM Negotiate Flags
# Note: High-bit values (0x80000000) must use "2147483648" decimal notation
# because PowerShell interprets hex literals as Int32 first, causing overflow
$Script:NTLMSSP_NEGOTIATE_UNICODE = [uint32]0x00000001
$Script:NTLMSSP_NEGOTIATE_OEM = [uint32]0x00000002
$Script:NTLMSSP_REQUEST_TARGET = [uint32]0x00000004
$Script:NTLMSSP_NEGOTIATE_SIGN = [uint32]0x00000010
$Script:NTLMSSP_NEGOTIATE_SEAL = [uint32]0x00000020
$Script:NTLMSSP_NEGOTIATE_DATAGRAM = [uint32]0x00000040
$Script:NTLMSSP_NEGOTIATE_LM_KEY = [uint32]0x00000080
$Script:NTLMSSP_NEGOTIATE_NTLM = [uint32]0x00000200
$Script:NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED = [uint32]0x00001000
$Script:NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED = [uint32]0x00002000
$Script:NTLMSSP_NEGOTIATE_ALWAYS_SIGN = [uint32]0x00008000
$Script:NTLMSSP_TARGET_TYPE_DOMAIN = [uint32]0x00010000
$Script:NTLMSSP_TARGET_TYPE_SERVER = [uint32]0x00020000
$Script:NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = [uint32]0x00080000
$Script:NTLMSSP_NEGOTIATE_TARGET_INFO = [uint32]0x00800000
$Script:NTLMSSP_NEGOTIATE_VERSION = [uint32]0x02000000
$Script:NTLMSSP_NEGOTIATE_128 = [uint32]0x20000000
$Script:NTLMSSP_NEGOTIATE_KEY_EXCH = [uint32]0x40000000
$Script:NTLMSSP_NEGOTIATE_56 = [uint32]2147483648  # 0x80000000 - must use decimal for high-bit

<#
.SYNOPSIS
    Creates an NTLM Type1 (Negotiate) message.
.DESCRIPTION
    Builds an NTLM Type1 message that initiates the NTLM handshake.
    The message includes negotiate flags but no domain/workstation info.
.RETURNS
    Base64-encoded NTLM Type1 message.
#>
function New-NTLMType1Message {
    [CmdletBinding()]
    param()

    # NTLMSSP signature
    $signature = [System.Text.Encoding]::ASCII.GetBytes("NTLMSSP`0")

    # Message type (1 = Negotiate)
    $messageType = [BitConverter]::GetBytes([uint32]1)

    # Negotiate flags. Signing and sealing are not requested: the probe sends one request
    # after the logon and needs no session security, so no session key is exchanged either.
    # Note: All flag constants are already [uint32], combine with -bor and ensure result stays [uint32]
    [uint32]$flags = $Script:NTLMSSP_NEGOTIATE_UNICODE -bor
                     $Script:NTLMSSP_REQUEST_TARGET -bor
                     $Script:NTLMSSP_NEGOTIATE_NTLM -bor
                     $Script:NTLMSSP_NEGOTIATE_ALWAYS_SIGN -bor
                     $Script:NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY -bor
                     $Script:NTLMSSP_NEGOTIATE_128 -bor
                     $Script:NTLMSSP_NEGOTIATE_56

    $flagsBytes = [BitConverter]::GetBytes($flags)

    # Domain name fields (empty - offset 0, length 0)
    $domainLen = [BitConverter]::GetBytes([uint16]0)
    $domainMaxLen = [BitConverter]::GetBytes([uint16]0)
    $domainOffset = [BitConverter]::GetBytes([uint32]0)

    # Workstation name fields (empty - offset 0, length 0)
    $workstationLen = [BitConverter]::GetBytes([uint16]0)
    $workstationMaxLen = [BitConverter]::GetBytes([uint16]0)
    $workstationOffset = [BitConverter]::GetBytes([uint32]0)

    # Build the message
    $message = New-Object System.Collections.Generic.List[byte]
    $message.AddRange($signature)           # 0-7:   "NTLMSSP\0"
    $message.AddRange($messageType)         # 8-11:  Type (1)
    $message.AddRange($flagsBytes)          # 12-15: Flags
    $message.AddRange($domainLen)           # 16-17: Domain length
    $message.AddRange($domainMaxLen)        # 18-19: Domain max length
    $message.AddRange($domainOffset)        # 20-23: Domain offset
    $message.AddRange($workstationLen)      # 24-25: Workstation length
    $message.AddRange($workstationMaxLen)   # 26-27: Workstation max length
    $message.AddRange($workstationOffset)   # 28-31: Workstation offset

    return [Convert]::ToBase64String($message.ToArray())
}

# AV_PAIR Type IDs (MS-NLMP 2.2.2.1)
$Script:MsvAvEOL = 0x0000              # End of list
$Script:MsvAvNbComputerName = 0x0001   # NetBIOS computer name
$Script:MsvAvNbDomainName = 0x0002     # NetBIOS domain name
$Script:MsvAvDnsComputerName = 0x0003  # DNS computer name (FQDN)
$Script:MsvAvDnsDomainName = 0x0004    # DNS domain name
$Script:MsvAvDnsTreeName = 0x0005      # DNS forest name
$Script:MsvAvFlags = 0x0006            # Flags, set by the CLIENT in its AUTHENTICATE message
$Script:MsvAvTimestamp = 0x0007        # FILETIME timestamp
$Script:MsvAvSingleHost = 0x0008       # Single host data
$Script:MsvAvTargetName = 0x0009       # SPN target name
$Script:MsvAvChannelBindings = 0x000A  # Channel bindings MD5 hash

<#
.SYNOPSIS
    Parses an NTLM Type2 (Challenge) message with full AV_PAIR extraction.
.DESCRIPTION
    Extracts the server challenge, target info, and all AV_PAIRs from an NTLM Type2 message.
    AV_PAIRs contain valuable internal information:
    - MsvAvNbComputerName (0x0001): NetBIOS hostname
    - MsvAvNbDomainName (0x0002): NetBIOS domain name
    - MsvAvDnsComputerName (0x0003): DNS hostname (FQDN)
    - MsvAvDnsDomainName (0x0004): DNS domain name
    - MsvAvDnsTreeName (0x0005): DNS forest/tree name
    - MsvAvTimestamp (0x0007): Server timestamp (FILETIME)

    Nothing in a Type2 says whether the server enforces EPA. MsvAvFlags is a field of the
    client's AUTHENTICATE message (MS-NLMP 2.2.2.1: 0x02 means the client included a MIC),
    and a Windows server sends none in its challenge. Its bit 0x02 used to be read here as
    "EPA required" - a rule that could never fire against Windows and would have given a
    server sending the flag an unearned "Enabled".
.PARAMETER Type2Base64
    Base64-encoded NTLM Type2 message from server.
.RETURNS
    PSCustomObject with Challenge, TargetName, TargetInfo, Flags, and parsed AV_PAIRs.
#>
function Read-NTLMType2Message {
    [CmdletBinding()]
    param(
        # AllowEmptyString so an empty value reaches the length check below - which
        # already reports it as "too short" through the normal Success=$false result -
        # instead of the parameter binder throwing ahead of the try/catch this function
        # otherwise answers every failure through.
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$Type2Base64
    )

    try {
        $bytes = [Convert]::FromBase64String($Type2Base64)

        # Validate minimum length for Type2 message
        if ($bytes.Length -lt 32) {
            throw "Type2 message too short (minimum 32 bytes, got $($bytes.Length))"
        }

        # Validate signature
        $signature = [System.Text.Encoding]::ASCII.GetString($bytes, 0, 8)
        if ($signature -ne "NTLMSSP`0") {
            throw "Invalid NTLM signature"
        }

        # Validate message type
        $messageType = [BitConverter]::ToUInt32($bytes, 8)
        if ($messageType -ne 2) {
            throw "Not a Type2 message (got type $messageType)"
        }

        # Extract fields
        $targetNameLen = [BitConverter]::ToUInt16($bytes, 12)
        $targetNameOffset = [BitConverter]::ToInt32($bytes, 16)
        # Read flags directly from bytes to avoid Int32/UInt32 conversion issues in PowerShell
        $flags = [uint32]$bytes[20] + ([uint32]$bytes[21] -shl 8) + ([uint32]$bytes[22] -shl 16) + ([uint32]$bytes[23] -shl 24)
        $challenge = [byte[]]$bytes[24..31]

        # Target info (if present)
        $targetInfoLen = 0
        $targetInfoOffset = 0
        $targetInfo = $null
        $avPairs = $null

        if ($bytes.Length -ge 48) {
            $targetInfoLen = [BitConverter]::ToUInt16($bytes, 40)
            $targetInfoOffset = [BitConverter]::ToInt32($bytes, 44)

            # FIX: Allow offset 0 if length is also 0, otherwise validate bounds
            if ($targetInfoLen -gt 0 -and $targetInfoOffset -ge 0 -and ($targetInfoOffset + $targetInfoLen) -le $bytes.Length) {
                $targetInfo = [byte[]]$bytes[$targetInfoOffset..($targetInfoOffset + $targetInfoLen - 1)]

                # Parse AV_PAIRs from TargetInfo
                $avPairs = Read-NTLMAvPairs -TargetInfoBytes $targetInfo
            }
        }

        # Initialize default avPairs if not parsed
        if ($null -eq $avPairs) {
            $avPairs = [PSCustomObject]@{
                NbComputerName = $null
                NbDomainName = $null
                DnsComputerName = $null
                DnsDomainName = $null
                DnsTreeName = $null
                AvFlags = $null
                Timestamp = $null
                TimestampUtc = $null
                TargetSPN = $null
            }
        }

        # Extract target name
        $targetName = ""
        if ($targetNameLen -gt 0 -and $targetNameOffset -ge 0 -and ($targetNameOffset + $targetNameLen) -le $bytes.Length) {
            if (($flags -band $Script:NTLMSSP_NEGOTIATE_UNICODE) -ne 0) {
                $targetName = [System.Text.Encoding]::Unicode.GetString($bytes, $targetNameOffset, $targetNameLen)
            } else {
                $targetName = [System.Text.Encoding]::ASCII.GetString($bytes, $targetNameOffset, $targetNameLen)
            }
        }

        return [PSCustomObject]@{
            Success = $true
            Challenge = $challenge
            ChallengeHex = [BitConverter]::ToString($challenge) -replace '-', ''
            TargetName = $targetName
            TargetInfo = $targetInfo
            Flags = $flags
            # Parsed AV_PAIR values
            NbComputerName = $avPairs.NbComputerName
            NbDomainName = $avPairs.NbDomainName
            DnsComputerName = $avPairs.DnsComputerName
            DnsDomainName = $avPairs.DnsDomainName
            DnsTreeName = $avPairs.DnsTreeName
            Timestamp = $avPairs.Timestamp
            TimestampUtc = $avPairs.TimestampUtc
            AvFlags = $avPairs.AvFlags
            TargetSPN = $avPairs.TargetSPN
        }
    }
    catch {
        return [PSCustomObject]@{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

<#
.SYNOPSIS
    Parses AV_PAIRs from NTLM TargetInfo field.
.DESCRIPTION
    AV_PAIR structure (MS-NLMP 2.2.2.1):
    - AvId (2 bytes): Type identifier
    - AvLen (2 bytes): Length of Value
    - Value (AvLen bytes): The actual data

    The list is terminated by MsvAvEOL (0x0000).
.PARAMETER TargetInfoBytes
    Raw bytes of the TargetInfo field from Type2 message.
.RETURNS
    PSCustomObject with parsed AV_PAIR values.
#>
function Read-NTLMAvPairs {
    [CmdletBinding()]
    param(
        # AllowEmptyCollection so the loop below decides, rather than the parameter
        # binder throwing in front of it - a TargetInfo field of length 0 is a normal,
        # empty AV_PAIR list, not a caller error.
        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        [byte[]]$TargetInfoBytes
    )

    $result = [PSCustomObject]@{
        NbComputerName = $null    # NetBIOS computer name
        NbDomainName = $null      # NetBIOS domain name
        DnsComputerName = $null   # DNS computer name (FQDN)
        DnsDomainName = $null     # DNS domain name
        DnsTreeName = $null       # DNS forest name
        AvFlags = $null           # Raw flags value - carries no EPA statement (Read-NTLMType2Message)
        Timestamp = $null         # Raw FILETIME (Int64)
        TimestampUtc = $null      # Parsed DateTime in UTC
        TargetSPN = $null         # Target SPN (if present)
        RawPairs = @{}            # All pairs for debugging
    }

    $offset = 0
    $length = $TargetInfoBytes.Length

    while ($offset + 4 -le $length) {
        # Read AvId (2 bytes) and AvLen (2 bytes)
        $avId = [BitConverter]::ToUInt16($TargetInfoBytes, $offset)
        $avLen = [BitConverter]::ToUInt16($TargetInfoBytes, $offset + 2)
        $offset += 4

        # End of list?
        if ($avId -eq $Script:MsvAvEOL) {
            break
        }

        # Bounds check for value
        if ($offset + $avLen -gt $length) {
            Write-Log "[Read-NTLMAvPairs] Truncated AV_PAIR at offset $offset"
            break
        }

        # Extract value bytes.
        #
        # Guarded on $avLen -gt 0 rather than sliced unconditionally: PowerShell reads
        # $offset..($offset - 1) as the two-element descending range @($offset, $offset -
        # 1), not an empty array, so a zero-length AV_PAIR - a valid MS-NLMP encoding,
        # e.g. an empty NbDomainName - pulled in one adjacent byte from the buffer on
        # each side instead of nothing. Decoded as UTF-16, those two stray bytes surface
        # as one bogus character rather than an empty string, and at offset 0 the
        # negative index -1 means "last element of the array" in PowerShell, so the
        # corruption could reach into completely unrelated bytes at the end of the blob.
        #
        # The comma in the else branch is load-bearing: an if/else assignment routes each
        # branch's output through the normal success stream, and an empty array written
        # there unrolls to zero objects - so "else { [byte[]]@() }" assigns $null, not an
        # empty array, and every GetString() call below throws ArgumentNullException on
        # the very case this guard exists to make safe.
        $valueBytes = if ($avLen -gt 0) { $TargetInfoBytes[$offset..($offset + $avLen - 1)] } else { ,[byte[]]@() }
        $offset += $avLen

        # Parse based on AvId
        switch ($avId) {
            $Script:MsvAvNbComputerName {
                # Unicode string
                $result.NbComputerName = [System.Text.Encoding]::Unicode.GetString($valueBytes)
                $result.RawPairs['MsvAvNbComputerName'] = $result.NbComputerName
            }
            $Script:MsvAvNbDomainName {
                $result.NbDomainName = [System.Text.Encoding]::Unicode.GetString($valueBytes)
                $result.RawPairs['MsvAvNbDomainName'] = $result.NbDomainName
            }
            $Script:MsvAvDnsComputerName {
                $result.DnsComputerName = [System.Text.Encoding]::Unicode.GetString($valueBytes)
                $result.RawPairs['MsvAvDnsComputerName'] = $result.DnsComputerName
            }
            $Script:MsvAvDnsDomainName {
                $result.DnsDomainName = [System.Text.Encoding]::Unicode.GetString($valueBytes)
                $result.RawPairs['MsvAvDnsDomainName'] = $result.DnsDomainName
            }
            $Script:MsvAvDnsTreeName {
                $result.DnsTreeName = [System.Text.Encoding]::Unicode.GetString($valueBytes)
                $result.RawPairs['MsvAvDnsTreeName'] = $result.DnsTreeName
            }
            $Script:MsvAvFlags {
                # 4-byte flags value - read bytes directly to avoid conversion issues
                if ($avLen -ge 4) {
                    $result.AvFlags = [uint32]$valueBytes[0] + ([uint32]$valueBytes[1] -shl 8) + ([uint32]$valueBytes[2] -shl 16) + ([uint32]$valueBytes[3] -shl 24)
                    $result.RawPairs['MsvAvFlags'] = "0x{0:X8}" -f $result.AvFlags
                }
            }
            $Script:MsvAvTimestamp {
                # 8-byte FILETIME
                if ($avLen -ge 8) {
                    $result.Timestamp = [BitConverter]::ToInt64($valueBytes, 0)
                    try {
                        # Convert FILETIME to DateTime
                        $result.TimestampUtc = [DateTime]::FromFileTimeUtc($result.Timestamp)
                        $result.RawPairs['MsvAvTimestamp'] = (Format-adPEASDate $result.TimestampUtc 'yyyy-MM-dd HH:mm:ss UTC')
                    }
                    catch {
                        $result.RawPairs['MsvAvTimestamp'] = "Invalid FILETIME: $($result.Timestamp)"
                    }
                }
            }
            $Script:MsvAvTargetName {
                $result.TargetSPN = [System.Text.Encoding]::Unicode.GetString($valueBytes)
                $result.RawPairs['MsvAvTargetName'] = $result.TargetSPN
            }
            $Script:MsvAvChannelBindings {
                # 16-byte MD5 hash of channel bindings (for EPA)
                $result.RawPairs['MsvAvChannelBindings'] = [BitConverter]::ToString($valueBytes) -replace '-', ''
            }
            $Script:MsvAvSingleHost {
                # Complex structure, just store hex
                $result.RawPairs['MsvAvSingleHost'] = [BitConverter]::ToString($valueBytes) -replace '-', ''
            }
            default {
                # Unknown AV_PAIR, store as hex
                $result.RawPairs["Unknown_0x{0:X4}" -f $avId] = [BitConverter]::ToString($valueBytes) -replace '-', ''
            }
        }
    }

    return $result
}

<#
.SYNOPSIS
    Computes an NTLMv2 response (MS-NLMP 3.3.2).
.DESCRIPTION
    NTOWFv2      = HMAC_MD5(NT hash, UNICODE(Uppercase(UserName) + Domain))
    temp         = 0x01 0x01 Z(6) Timestamp ClientChallenge Z(4) AvPairs Z(4)
    NTProofStr   = HMAC_MD5(NTOWFv2, ServerChallenge + temp)
    response     = NTProofStr + temp

    The domain goes in as given, in its case: it is the same string the AUTHENTICATE
    message carries, and the domain controller recomputes NTOWFv2 from that string.
.PARAMETER NTHash
    16-byte NT hash of the account's password.
.PARAMETER AvPairs
    The AV_PAIR list the response carries, terminated by MsvAvEOL.
.OUTPUTS
    PSCustomObject with NTOWFv2, NTProofStr and NtChallengeResponse (byte arrays).
#>
function Get-NTLMv2Response {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$NTHash,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$UserName,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Domain,

        [Parameter(Mandatory = $true)]
        [byte[]]$ServerChallenge,

        [Parameter(Mandatory = $true)]
        [byte[]]$ClientChallenge,

        [Parameter(Mandatory = $true)]
        [byte[]]$Timestamp,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$AvPairs
    )

    $identity = [System.Text.Encoding]::Unicode.GetBytes($UserName.ToUpperInvariant() + $Domain)
    $hmac = [System.Security.Cryptography.HMACMD5]::new($NTHash)
    try { $ntowfv2 = $hmac.ComputeHash($identity) } finally { $hmac.Dispose() }

    $temp = New-Object System.Collections.Generic.List[byte]
    $temp.AddRange([byte[]](1, 1, 0, 0, 0, 0, 0, 0))
    $temp.AddRange($Timestamp)
    $temp.AddRange($ClientChallenge)
    $temp.AddRange([byte[]](0, 0, 0, 0))
    $temp.AddRange($AvPairs)
    $temp.AddRange([byte[]](0, 0, 0, 0))
    $tempBytes = $temp.ToArray()

    $proofInput = New-Object byte[] ($ServerChallenge.Length + $tempBytes.Length)
    [Array]::Copy($ServerChallenge, 0, $proofInput, 0, $ServerChallenge.Length)
    [Array]::Copy($tempBytes, 0, $proofInput, $ServerChallenge.Length, $tempBytes.Length)
    $hmac = [System.Security.Cryptography.HMACMD5]::new($ntowfv2)
    try { $ntProofStr = $hmac.ComputeHash($proofInput) } finally { $hmac.Dispose() }

    $response = New-Object byte[] ($ntProofStr.Length + $tempBytes.Length)
    [Array]::Copy($ntProofStr, 0, $response, 0, $ntProofStr.Length)
    [Array]::Copy($tempBytes, 0, $response, $ntProofStr.Length, $tempBytes.Length)

    return [PSCustomObject]@{
        NTOWFv2             = $ntowfv2
        NTProofStr          = $ntProofStr
        NtChallengeResponse = $response
    }
}

<#
.SYNOPSIS
    Computes the MsvAvChannelBindings value for a channel binding.
.DESCRIPTION
    MS-NLMP 2.2.2.1: the MD5 hash of a gss_channel_bindings_struct (RFC 2744). For a TLS
    server end point binding (RFC 5929) the initiator and acceptor addresses are empty, so
    the struct is 16 zero bytes - address type and length of each - followed by the
    length of the application data and the application data itself,
    "tls-server-end-point:" + the hash of the server certificate.
.PARAMETER ApplicationData
    The application data of the binding.
.OUTPUTS
    [byte[]] 16-byte MD5 hash.
#>
function Get-NTLMChannelBindingHash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$ApplicationData
    )

    $struct = New-Object byte[] (20 + $ApplicationData.Length)
    [Array]::Copy([BitConverter]::GetBytes([uint32]$ApplicationData.Length), 0, $struct, 16, 4)
    [Array]::Copy($ApplicationData, 0, $struct, 20, $ApplicationData.Length)

    $md5 = [System.Security.Cryptography.MD5]::Create()
    try { $hash = $md5.ComputeHash($struct) } finally { $md5.Dispose() }
    return ,$hash
}

<#
.SYNOPSIS
    Reads the application data out of a SEC_CHANNEL_BINDINGS structure.
.DESCRIPTION
    SEC_CHANNEL_BINDINGS is eight 32-bit fields - initiator and acceptor address type,
    length and offset, then the length and the offset of the application data - followed
    by the data the offsets point into. Windows hands a TLS channel's binding out in this
    form (SslStream.TransportContext.GetChannelBinding), and SSPI takes it in this form.
.PARAMETER SecChannelBindings
    The structure, as raw bytes.
.OUTPUTS
    [byte[]] the application data.
#>
function Get-ChannelBindingApplicationData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$SecChannelBindings
    )

    if ($SecChannelBindings.Length -lt 32) {
        throw "SEC_CHANNEL_BINDINGS too short ($($SecChannelBindings.Length) bytes)"
    }
    $length = [BitConverter]::ToUInt32($SecChannelBindings, 24)
    $offset = [BitConverter]::ToUInt32($SecChannelBindings, 28)
    if (($offset + $length) -gt $SecChannelBindings.Length) {
        throw "SEC_CHANNEL_BINDINGS application data runs past the structure"
    }

    $data = New-Object byte[] $length
    [Array]::Copy($SecChannelBindings, [int]$offset, $data, 0, [int]$length)
    return ,$data
}

<#
.SYNOPSIS
    Builds a SEC_CHANNEL_BINDINGS structure that carries only application data.
.DESCRIPTION
    The form SSPI takes a channel binding in (Get-ChannelBindingApplicationData). Used to
    hand SSPI the binding of a channel the probe is NOT on.
.PARAMETER ApplicationData
    The application data of the binding.
.OUTPUTS
    [byte[]] the structure.
#>
function New-SecChannelBindings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$ApplicationData
    )

    $struct = New-Object byte[] (32 + $ApplicationData.Length)
    [Array]::Copy([BitConverter]::GetBytes([uint32]$ApplicationData.Length), 0, $struct, 24, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint32]32), 0, $struct, 28, 4)
    [Array]::Copy($ApplicationData, 0, $struct, 32, $ApplicationData.Length)
    return ,$struct
}

<#
.SYNOPSIS
    Creates an NTLMv2 Type3 (Authenticate) message for a real account.
.DESCRIPTION
    Answers the server's challenge with the account's NT hash and puts the given channel
    binding into the response. Without -ChannelBindingHash the binding is 16 zero bytes,
    which is what a Windows client sends when it has no channel to bind. With
    -OmitChannelBindings there is no MsvAvChannelBindings pair at all, the logon of a
    client that implements no channel binding - the one logon IIS in Accept mode takes
    without a binding (Test-ExtendedProtection).

    No session key is exchanged and no MIC is computed: the probe sends one request after
    the logon and needs no session security, and MS-NLMP leaves both to the client.
.PARAMETER Type2Result
    Parsed Type2 message from Read-NTLMType2Message.
.PARAMETER UserName
    Account name, or a UPN with an empty Domain.
.PARAMETER Domain
    Domain of the account, as the AUTHENTICATE message carries it.
.PARAMETER NTHash
    16-byte NT hash of the account's password.
.PARAMETER ChannelBindingHash
    MsvAvChannelBindings value (Get-NTLMChannelBindingHash). Omitted: 16 zero bytes, the
    binding of a Windows client without a channel.
.PARAMETER OmitChannelBindings
    Send no MsvAvChannelBindings pair at all.
.PARAMETER TargetName
    The SPN the client means to reach (MsvAvTargetName), e.g. HTTP/mail.contoso.com.
.PARAMETER ClientChallenge
    8-byte client challenge. Omitted: random. Given only by tests.
.PARAMETER Timestamp
    8-byte FILETIME. Omitted: the server's MsvAvTimestamp, else the current time.
.OUTPUTS
    [byte[]] the Type3 message.
#>
function New-NTLMAuthenticateMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Type2Result,

        [Parameter(Mandatory = $true)]
        [string]$UserName,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Domain,

        [Parameter(Mandatory = $true)]
        [byte[]]$NTHash,

        [Parameter(Mandatory = $false)]
        [byte[]]$ChannelBindingHash,

        [Parameter(Mandatory = $false)]
        [switch]$OmitChannelBindings,

        [Parameter(Mandatory = $false)]
        [string]$TargetName,

        [Parameter(Mandatory = $false)]
        [byte[]]$ClientChallenge,

        [Parameter(Mandatory = $false)]
        [byte[]]$Timestamp
    )

    if (-not $ChannelBindingHash) { $ChannelBindingHash = New-Object byte[] 16 }
    if ($ChannelBindingHash.Length -ne 16) { throw "ChannelBindingHash must be 16 bytes, got $($ChannelBindingHash.Length)" }
    if (-not $ClientChallenge) { $ClientChallenge = Get-NTLMRandomBytes -Count 8 }
    if (-not $Timestamp) {
        if ($null -ne $Type2Result.Timestamp) {
            $Timestamp = [BitConverter]::GetBytes([long]$Type2Result.Timestamp)
        }
        else {
            $Timestamp = [BitConverter]::GetBytes([DateTime]::UtcNow.ToFileTimeUtc())
        }
    }

    # The server's AV_PAIRs, then the client's own. Pairs only a client sets are dropped
    # from the server's list so that none appears twice.
    $avPairs = New-Object System.Collections.Generic.List[byte]
    # Assigned, not taken from an if-expression: that would unroll the byte[] into an
    # object[], which BitConverter does not take.
    [byte[]]$targetInfo = @()
    if ($Type2Result.TargetInfo) { $targetInfo = [byte[]]$Type2Result.TargetInfo }
    $offset = 0
    while ($offset + 4 -le $targetInfo.Length) {
        $avId = [BitConverter]::ToUInt16($targetInfo, $offset)
        $avLen = [BitConverter]::ToUInt16($targetInfo, $offset + 2)
        if ($avId -eq $Script:MsvAvEOL -or ($offset + 4 + $avLen) -gt $targetInfo.Length) { break }
        if ($avId -notin @($Script:MsvAvFlags, $Script:MsvAvTargetName, $Script:MsvAvChannelBindings)) {
            for ($i = 0; $i -lt (4 + $avLen); $i++) { $avPairs.Add($targetInfo[$offset + $i]) }
        }
        $offset += 4 + $avLen
    }
    if ($TargetName) {
        $targetBytes = [System.Text.Encoding]::Unicode.GetBytes($TargetName)
        $avPairs.AddRange([BitConverter]::GetBytes([uint16]$Script:MsvAvTargetName))
        $avPairs.AddRange([BitConverter]::GetBytes([uint16]$targetBytes.Length))
        $avPairs.AddRange($targetBytes)
    }
    if (-not $OmitChannelBindings) {
        $avPairs.AddRange([BitConverter]::GetBytes([uint16]$Script:MsvAvChannelBindings))
        $avPairs.AddRange([BitConverter]::GetBytes([uint16]16))
        $avPairs.AddRange($ChannelBindingHash)
    }
    $avPairs.AddRange([byte[]](0, 0, 0, 0))

    $ntlmv2 = Get-NTLMv2Response -NTHash $NTHash -UserName $UserName -Domain $Domain `
        -ServerChallenge ([byte[]]$Type2Result.Challenge) -ClientChallenge $ClientChallenge `
        -Timestamp $Timestamp -AvPairs $avPairs.ToArray()

    # With a server timestamp the LM response is Z(24) (MS-NLMP 3.1.5.1.2)
    $lmResponse = New-Object byte[] 24
    $ntResponse = $ntlmv2.NtChallengeResponse
    $domainBytes = [System.Text.Encoding]::Unicode.GetBytes($Domain)
    $userBytes = [System.Text.Encoding]::Unicode.GetBytes($UserName)
    $workstationBytes = New-Object byte[] 0

    # The flags the server agreed to, minus key exchange (no session key is sent), plus
    # Unicode and the version field this message carries.
    [uint32]$allowed = $Script:NTLMSSP_NEGOTIATE_UNICODE -bor
                       $Script:NTLMSSP_REQUEST_TARGET -bor
                       $Script:NTLMSSP_NEGOTIATE_NTLM -bor
                       $Script:NTLMSSP_NEGOTIATE_ALWAYS_SIGN -bor
                       $Script:NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY -bor
                       $Script:NTLMSSP_NEGOTIATE_TARGET_INFO -bor
                       $Script:NTLMSSP_NEGOTIATE_128 -bor
                       $Script:NTLMSSP_NEGOTIATE_56
    [uint32]$flags = ([uint32]$Type2Result.Flags -band $allowed) -bor $Script:NTLMSSP_NEGOTIATE_UNICODE -bor $Script:NTLMSSP_NEGOTIATE_VERSION

    # Header: 64 bytes of fields, 8 bytes of version, no MIC (MS-NLMP 2.2.1.3)
    $offset = 72
    $fields = New-Object System.Collections.Generic.List[byte]
    foreach ($payload in @($lmResponse, $ntResponse, $domainBytes, $userBytes, $workstationBytes)) {
        $fields.AddRange([BitConverter]::GetBytes([uint16]$payload.Length))
        $fields.AddRange([BitConverter]::GetBytes([uint16]$payload.Length))
        $fields.AddRange([BitConverter]::GetBytes([uint32]$offset))
        $offset += $payload.Length
    }
    # EncryptedRandomSessionKey: empty
    $fields.AddRange([BitConverter]::GetBytes([uint16]0))
    $fields.AddRange([BitConverter]::GetBytes([uint16]0))
    $fields.AddRange([BitConverter]::GetBytes([uint32]$offset))

    $message = New-Object System.Collections.Generic.List[byte]
    $message.AddRange([System.Text.Encoding]::ASCII.GetBytes("NTLMSSP`0"))
    $message.AddRange([BitConverter]::GetBytes([uint32]3))
    $message.AddRange($fields)
    $message.AddRange([BitConverter]::GetBytes($flags))
    # Version: Windows 10 (10.0.19041), NTLMSSP_REVISION_W2K3
    $message.AddRange([byte[]](0x0A, 0x00, 0x61, 0x4A, 0x00, 0x00, 0x00, 0x0F))
    $message.AddRange($lmResponse)
    $message.AddRange($ntResponse)
    $message.AddRange($domainBytes)
    $message.AddRange($userBytes)
    $message.AddRange($workstationBytes)

    return ,$message.ToArray()
}

# C# client for the current Windows logon: NTLM through SSPI, with the channel binding
# handed in as SECBUFFER_CHANNEL_BINDINGS - or not handed in, which makes SSPI send the
# zero binding of a client that has none. Compiled on first use (Initialize-EPASspiType).
$Script:EPASspiTypeDefinition = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public sealed class adPEASNtlmSspi : IDisposable
{
    [StructLayout(LayoutKind.Sequential)]
    private struct SecHandle { public IntPtr Lower; public IntPtr Upper; }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecBuffer { public int Size; public int Type; public IntPtr Buffer; }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecBufferDesc { public int Version; public int Count; public IntPtr Buffers; }

    [DllImport("secur32.dll", CharSet = CharSet.Unicode)]
    private static extern int AcquireCredentialsHandleW(string principal, string package, int credentialUse,
        IntPtr logonId, IntPtr authData, IntPtr getKeyFn, IntPtr getKeyArgument, ref SecHandle credential, out long expiry);

    [DllImport("secur32.dll", CharSet = CharSet.Unicode, EntryPoint = "InitializeSecurityContextW")]
    private static extern int InitializeFirst(ref SecHandle credential, IntPtr context, string targetName, int contextReq,
        int reserved1, int targetDataRep, IntPtr input, int reserved2, ref SecHandle newContext, ref SecBufferDesc output,
        out int contextAttributes, out long expiry);

    [DllImport("secur32.dll", CharSet = CharSet.Unicode, EntryPoint = "InitializeSecurityContextW")]
    private static extern int InitializeNext(ref SecHandle credential, ref SecHandle context, string targetName, int contextReq,
        int reserved1, int targetDataRep, ref SecBufferDesc input, int reserved2, ref SecHandle newContext, ref SecBufferDesc output,
        out int contextAttributes, out long expiry);

    [DllImport("secur32.dll")] private static extern int FreeCredentialsHandle(ref SecHandle credential);
    [DllImport("secur32.dll")] private static extern int DeleteSecurityContext(ref SecHandle context);

    // SecPkgCredentials_NamesW is a single pointer, so the call writes it straight into namePointer
    [DllImport("secur32.dll", CharSet = CharSet.Unicode)]
    private static extern int QueryCredentialsAttributesW(ref SecHandle credential, int attribute, out IntPtr namePointer);
    [DllImport("secur32.dll")] private static extern int FreeContextBuffer(IntPtr buffer);
    private const int SECPKG_CRED_ATTR_NAMES = 1;

    private const int SECPKG_CRED_OUTBOUND = 2;
    private const int SECBUFFER_TOKEN = 2;
    private const int SECBUFFER_CHANNEL_BINDINGS = 14;
    private const int SECURITY_NATIVE_DREP = 0x10;
    private const int ISC_REQ_CONNECTION = 0x800;

    private SecHandle credential;
    private SecHandle context;
    private bool haveCredential;
    private bool haveContext;
    private readonly string targetName;

    public adPEASNtlmSspi(string targetName)
    {
        this.targetName = targetName;
        long expiry;
        int status = AcquireCredentialsHandleW(null, "NTLM", SECPKG_CRED_OUTBOUND, IntPtr.Zero, IntPtr.Zero,
            IntPtr.Zero, IntPtr.Zero, ref credential, out expiry);
        if (status != 0) { throw new InvalidOperationException("AcquireCredentialsHandle failed: 0x" + status.ToString("X8")); }
        haveCredential = true;
    }

    // The account the credential logs on as - under runas /netonly the network identity,
    // not the user of the process. Null if the package does not say.
    public string CredentialName()
    {
        IntPtr namePointer;
        if (QueryCredentialsAttributesW(ref credential, SECPKG_CRED_ATTR_NAMES, out namePointer) != 0 || namePointer == IntPtr.Zero) { return null; }
        try { return Marshal.PtrToStringUni(namePointer); }
        finally { FreeContextBuffer(namePointer); }
    }

    public byte[] Negotiate() { return Step(null, null); }

    public byte[] Authenticate(byte[] challenge, byte[] channelBindings)
    {
        if (!haveContext) { throw new InvalidOperationException("Negotiate must run first"); }
        return Step(challenge, channelBindings);
    }

    private byte[] Step(byte[] input, byte[] channelBindings)
    {
        int bufferSize = Marshal.SizeOf(typeof(SecBuffer));
        byte[] output = new byte[16384];
        List<GCHandle> pins = new List<GCHandle>();
        IntPtr outputBuffer = Marshal.AllocHGlobal(bufferSize);
        IntPtr inputBuffers = IntPtr.Zero;
        try
        {
            GCHandle outputPin = GCHandle.Alloc(output, GCHandleType.Pinned); pins.Add(outputPin);
            SecBuffer outBuf = new SecBuffer { Size = output.Length, Type = SECBUFFER_TOKEN, Buffer = outputPin.AddrOfPinnedObject() };
            Marshal.StructureToPtr(outBuf, outputBuffer, false);
            SecBufferDesc outputDesc = new SecBufferDesc { Version = 0, Count = 1, Buffers = outputBuffer };

            int attributes; long expiry; int status;
            SecHandle current = context;
            if (input == null)
            {
                status = InitializeFirst(ref credential, IntPtr.Zero, targetName, ISC_REQ_CONNECTION, 0,
                    SECURITY_NATIVE_DREP, IntPtr.Zero, 0, ref current, ref outputDesc, out attributes, out expiry);
            }
            else
            {
                int count = channelBindings == null ? 1 : 2;
                inputBuffers = Marshal.AllocHGlobal(bufferSize * count);
                GCHandle inputPin = GCHandle.Alloc(input, GCHandleType.Pinned); pins.Add(inputPin);
                Marshal.StructureToPtr(new SecBuffer { Size = input.Length, Type = SECBUFFER_TOKEN, Buffer = inputPin.AddrOfPinnedObject() }, inputBuffers, false);
                if (channelBindings != null)
                {
                    GCHandle bindingPin = GCHandle.Alloc(channelBindings, GCHandleType.Pinned); pins.Add(bindingPin);
                    Marshal.StructureToPtr(new SecBuffer { Size = channelBindings.Length, Type = SECBUFFER_CHANNEL_BINDINGS, Buffer = bindingPin.AddrOfPinnedObject() },
                        new IntPtr(inputBuffers.ToInt64() + bufferSize), false);
                }
                SecBufferDesc inputDesc = new SecBufferDesc { Version = 0, Count = count, Buffers = inputBuffers };
                status = InitializeNext(ref credential, ref current, targetName, ISC_REQ_CONNECTION, 0,
                    SECURITY_NATIVE_DREP, ref inputDesc, 0, ref current, ref outputDesc, out attributes, out expiry);
            }
            context = current;
            haveContext = true;
            if (status < 0) { throw new InvalidOperationException("InitializeSecurityContext failed: 0x" + status.ToString("X8")); }

            SecBuffer written = (SecBuffer)Marshal.PtrToStructure(outputBuffer, typeof(SecBuffer));
            byte[] token = new byte[written.Size];
            Array.Copy(output, token, written.Size);
            return token;
        }
        finally
        {
            foreach (GCHandle pin in pins) { pin.Free(); }
            Marshal.FreeHGlobal(outputBuffer);
            if (inputBuffers != IntPtr.Zero) { Marshal.FreeHGlobal(inputBuffers); }
        }
    }

    public void Dispose()
    {
        if (haveContext) { DeleteSecurityContext(ref context); haveContext = false; }
        if (haveCredential) { FreeCredentialsHandle(ref credential); haveCredential = false; }
    }
}
'@

<#
.SYNOPSIS
    Compiles the SSPI client of the current Windows logon, once per process.
#>
function Initialize-EPASspiType {
    [CmdletBinding()]
    param()

    if (([System.Management.Automation.PSTypeName]'adPEASNtlmSspi').Type) { return }
    try {
        Add-Type -TypeDefinition $Script:EPASspiTypeDefinition -ErrorAction Stop
        Write-Log "[Initialize-EPASspiType] adPEASNtlmSspi type compiled"
    }
    catch {
        if (-not ([System.Management.Automation.PSTypeName]'adPEASNtlmSspi').Type) {
            throw "Failed to compile the SSPI client: $($_.Exception.Message)"
        }
    }
}

<#
.SYNOPSIS
    Splits an account name into the user and domain an NTLM logon carries.
.DESCRIPTION
    DOMAIN\user carries both; a UPN goes as the user name with an empty domain (MS-NLMP
    allows that, and the DC resolves the suffix); a bare name takes the default domain.
.PARAMETER Account
    The account as given: DOMAIN\user, user@domain or user.
.PARAMETER DefaultDomain
    Domain for a bare name - the session's.
#>
function Split-EPAProbeAccount {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Account,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$DefaultDomain = ''
    )

    if ($Account -match '^([^\\]+)\\(.+)$') {
        return [PSCustomObject]@{ UserName = $Matches[2]; Domain = $Matches[1] }
    }
    if ($Account -match '@') {
        return [PSCustomObject]@{ UserName = $Account; Domain = '' }
    }
    return [PSCustomObject]@{ UserName = $Account; Domain = $DefaultDomain }
}

<#
.SYNOPSIS
    The current Windows logon as an EPA probe identity, logging on through SSPI.
.DESCRIPTION
    The name comes from the SSPI credential itself: under runas /netonly it is the network
    identity, which the environment does not know; the environment's name is the fallback.
.PARAMETER Source
    How this identity was chosen, for the diagnostic.
#>
function New-EPASspiIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Source = 'current Windows logon'
    )

    $currentUser = if ($env:USERDOMAIN) { "$($env:USERDOMAIN)\$($env:USERNAME)" } else { [string]$env:USERNAME }
    try {
        Initialize-EPASspiType
        $sspi = New-Object adPEASNtlmSspi('HTTP/localhost')
        try {
            $credentialName = $sspi.CredentialName()
            if ($credentialName) { $currentUser = $credentialName }
        }
        finally { $sspi.Dispose() }
    }
    catch {
        Write-Log "[New-EPASspiIdentity] SSPI credential name not available: $($_.Exception.Message)"
    }
    return [PSCustomObject]@{
        Kind     = 'Sspi'
        Name     = $currentUser
        Source   = $Source
        UserName = $null
        Domain   = $null
        NTHash   = $null
        Reason   = $null
    }
}

<#
.SYNOPSIS
    The identity of the adPEAS session, as the EPA probe logs on with it.
.DESCRIPTION
    The session's own, so the probe answers for the account the scan runs as, against
    the systems of the AD the session is in:
    - a password given to Connect-adPEAS (Credential, Username/Password): its NT hash
    - an NT hash given to Connect-adPEAS: that hash
    - an AES key, a certificate or a ticket: none - they have nothing to answer an NTLM
      challenge with, and the endpoints stay undetermined
    - a session as the current Windows user: the current Windows logon, through SSPI
    - no session: none. The current Windows logon is never used without being asked for
      (New-EPAProbeIdentity -UseWindowsAuth): run by hand against a host of another
      organisation, it would hand that host the logon of the tester's own account.

    A session that forced Kerberos for LDAP still has a password and is probed with it
    (decided 2026-11-15) - EPA is a question about NTLM, and only an NTLM logon answers it.
.OUTPUTS
    PSCustomObject with Kind ('Hash', 'Sspi' or 'None'), Name, Source, UserName, Domain,
    NTHash (Kind Hash only) and Reason (Kind None only).
#>
function Resolve-EPAProbeIdentity {
    [CmdletBinding()]
    param()

    $none = {
        param([string]$Reason)
        [PSCustomObject]@{ Kind = 'None'; Name = $null; Source = $null; UserName = $null; Domain = $null; NTHash = $null; Reason = $Reason }
    }

    $context = $Script:LDAPContext
    if (-not $context) {
        return (& $none 'there is no adPEAS session (Connect-adPEAS) to take the identity from')
    }
    $parameterSet = [string]$context['ParameterSet']
    $sessionDomain = [string]$context['Domain']

    $credential = $null
    if ($context['Credential'] -is [System.Management.Automation.PSCredential]) {
        $credential = $context['Credential']
    }
    elseif ($Script:LDAPCredential -is [System.Management.Automation.PSCredential]) {
        $credential = $Script:LDAPCredential
    }

    if ($credential -and -not [string]::IsNullOrEmpty($credential.UserName)) {
        $account = Split-EPAProbeAccount -Account $credential.UserName -DefaultDomain $sessionDomain
        return [PSCustomObject]@{
            Kind     = 'Hash'
            Name     = $credential.UserName
            Source   = 'session password'
            UserName = $account.UserName
            Domain   = $account.Domain
            NTHash   = [byte[]](Get-NTHashFromPassword -PlainPassword $credential.GetNetworkCredential().Password)
            Reason   = $null
        }
    }

    if ($parameterSet -eq 'NTHash') {
        $stored = $Script:LDAPNTHashIdentity
        if ($stored -and $stored.NTHash) {
            $account = Split-EPAProbeAccount -Account $stored.UserName -DefaultDomain ([string]$stored.Domain)
            return [PSCustomObject]@{
                Kind     = 'Hash'
                Name     = $stored.UserName
                Source   = 'session NT hash'
                UserName = $account.UserName
                Domain   = $account.Domain
                NTHash   = [byte[]]$stored.NTHash
                Reason   = $null
            }
        }
        return (& $none 'the NT hash of the session is not available')
    }

    # A password session whose credential is gone must not fall through to the Windows
    # logon below: that is another account, and the verdict would be about it.
    if ($parameterSet -in @('UsernamePassword', 'PSCredential')) {
        return (& $none 'the credential of the session is not available')
    }

    if ($parameterSet -in @('AES256', 'AES128', 'Certificate', 'Kirbi', 'Ccache')) {
        return (& $none "the session authenticated with $parameterSet, which has no password or NT hash to answer an NTLM challenge")
    }

    # A session as the current Windows user: that logon is the session's identity
    return (New-EPASspiIdentity -Source 'session, current Windows logon')
}

<#
.SYNOPSIS
    Builds the EPA probe identity from what the caller named.
.DESCRIPTION
    -TestEPA logs on to every NTLM endpoint of its target, so the caller names the identity,
    exactly one of:
    - -Credential                     a password, as a PSCredential
    - -Username with -Password        a password
    - -Username with -NTHash          an NT hash (32 hex characters)
    - -UseSession                     the identity of the adPEAS session (Resolve-EPAProbeIdentity)
    - -UseWindowsAuth                 the current Windows logon, through SSPI

    Nothing named is an error before any connection is made, and so is more than one
    (decided 2026-11-15). Such a usage mistake throws System.ArgumentException, which
    Invoke-HTTPRequest shows with Show-EPAProbeIdentityError; any other exception is a
    failure and passes through. The current Windows logon is never taken without being named:
    run by hand against a host of another organisation, it would hand that host the logon
    of the tester's own account. AES keys, certificates and tickets are not offered - NTLM
    is answered with a password or an NT hash, nothing else.

    A user name without a domain logs on in the target's own domain, the one its NTLM
    challenge names: the caller gave the credential for that target.
.OUTPUTS
    PSCustomObject as Resolve-EPAProbeIdentity returns it.
#>
function New-EPAProbeIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [string]$Username,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$Password,

        [Parameter(Mandatory = $false)]
        [string]$NTHash,

        [Parameter(Mandatory = $false)]
        [switch]$UseSession,

        [Parameter(Mandatory = $false)]
        [switch]$UseWindowsAuth
    )

    # A usage mistake, told apart from a failure by its type - see the description
    $usageError = { param([string]$Message) throw (New-Object System.ArgumentException -ArgumentList $Message) }

    $forms = @()
    if ($PSBoundParameters.ContainsKey('Credential') -and $Credential) { $forms += 'Credential' }
    if ($PSBoundParameters.ContainsKey('Password')) { $forms += 'Password' }
    if ($PSBoundParameters.ContainsKey('NTHash')) { $forms += 'NTHash' }
    if ($UseSession) { $forms += 'UseSession' }
    if ($UseWindowsAuth) { $forms += 'UseWindowsAuth' }

    if ($forms.Count -eq 0) {
        if ($PSBoundParameters.ContainsKey('Username')) {
            & $usageError '-Username needs -Password or -NTHash'
        }
        & $usageError '-TestEPA needs an identity to log on with'
    }
    if ($forms.Count -gt 1) {
        & $usageError "-TestEPA takes one identity, got -$($forms -join ', -')"
    }
    if ($forms[0] -in @('Password', 'NTHash') -and [string]::IsNullOrWhiteSpace($Username)) {
        & $usageError "-$($forms[0]) needs -Username"
    }
    if ($forms[0] -in @('Credential', 'UseSession', 'UseWindowsAuth') -and $PSBoundParameters.ContainsKey('Username')) {
        & $usageError "-Username goes with -Password or -NTHash, not with -$($forms[0])"
    }

    switch ($forms[0]) {
        'Credential' {
            if ([string]::IsNullOrEmpty($Credential.UserName)) { & $usageError '-Credential carries no user name' }
            $account = Split-EPAProbeAccount -Account $Credential.UserName
            return [PSCustomObject]@{
                Kind     = 'Hash'
                Name     = $Credential.UserName
                Source   = 'given credential'
                UserName = $account.UserName
                Domain   = $account.Domain
                NTHash   = [byte[]](Get-NTHashFromPassword -PlainPassword $Credential.GetNetworkCredential().Password)
                Reason   = $null
            }
        }
        'Password' {
            $account = Split-EPAProbeAccount -Account $Username
            return [PSCustomObject]@{
                Kind     = 'Hash'
                Name     = $Username
                Source   = 'given password'
                UserName = $account.UserName
                Domain   = $account.Domain
                NTHash   = [byte[]](Get-NTHashFromPassword -PlainPassword $Password)
                Reason   = $null
            }
        }
        'NTHash' {
            if ($NTHash -notmatch '^[0-9a-fA-F]{32}$') { & $usageError '-NTHash takes 32 hex characters' }
            $hashBytes = New-Object byte[] 16
            for ($i = 0; $i -lt 16; $i++) { $hashBytes[$i] = [Convert]::ToByte($NTHash.Substring($i * 2, 2), 16) }
            $account = Split-EPAProbeAccount -Account $Username
            return [PSCustomObject]@{
                Kind     = 'Hash'
                Name     = $Username
                Source   = 'given NT hash'
                UserName = $account.UserName
                Domain   = $account.Domain
                NTHash   = $hashBytes
                Reason   = $null
            }
        }
        'UseSession' {
            if (-not $Script:LDAPContext) {
                & $usageError '-UseSession needs an adPEAS session - run Connect-adPEAS first'
            }
            return (Resolve-EPAProbeIdentity)
        }
        'UseWindowsAuth' {
            return (New-EPASspiIdentity -Source 'current Windows logon')
        }
    }
}

<#
.SYNOPSIS
    Shows a mistake in naming the EPA probe identity, with the forms it takes.
.DESCRIPTION
    Invoke-HTTPRequest -TestEPA is run by hand, so a missing or wrong identity is a usage
    mistake: an adPEAS message lists the forms, where a PowerShell exception would point
    at a line inside adPEAS.ps1. -Hint replaces the forms when the mistake is not about
    them. Not collected - a usage message is no finding.
#>
function Show-EPAProbeIdentityError {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [string[]]$Hint
    )

    if ($Hint) {
        Show-Message -Type Error -Title $Message -Hints $Hint -NoCollect
        return
    }
    Show-Message -Type Error -Title $Message -NoCollect `
        -Details @('The EPA probe logs on to every NTLM endpoint of the target, as one of:') `
        -Hints @(
            '-Credential (Get-Credential)'
            "-Username 'DOMAIN\user' -Password '<password>'"
            "-Username 'DOMAIN\user' -NTHash '<32 hex characters>'"
            '-UseSession       the account of the adPEAS session (Connect-adPEAS)'
            '-UseWindowsAuth   the current Windows logon'
        )
}

<#
.SYNOPSIS
    Opens a TLS connection for one EPA probe logon.
.DESCRIPTION
    A connection of its own rather than HttpWebRequest: NTLM authenticates a connection,
    so Type1, Type3 and nothing else have to travel on the same one, and the channel
    binding has to be the binding of exactly that channel. HttpWebRequest decides itself
    which pooled connection a request takes, and it adds the binding on its own. Proxies
    are not used: the binding is the server's certificate, and the probe asks the server.
.OUTPUTS
    PSCustomObject with Client, Stream (SslStream) and ChannelBinding (SEC_CHANNEL_BINDINGS
    bytes of the TLS server end point binding, $null if the channel offered none).
#>
function Open-EPAProbeConnection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostName,

        [Parameter(Mandatory = $true)]
        [int]$Port,

        [Parameter(Mandatory = $true)]
        [int]$TimeoutSeconds,

        # Plain HTTP: no TLS, so no channel binding either
        [Parameter(Mandatory = $false)]
        [switch]$Plain
    )

    $timeoutMs = $TimeoutSeconds * 1000

    if ($Plain) {
        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $connect = $client.BeginConnect($HostName, $Port, $null, $null)
            if (-not $connect.AsyncWaitHandle.WaitOne($timeoutMs)) {
                throw "TCP connection to ${HostName}:$Port timed out"
            }
            $client.EndConnect($connect)
            $client.NoDelay = $true
            $network = $client.GetStream()
            $network.ReadTimeout = $timeoutMs
            $network.WriteTimeout = $timeoutMs
            return [PSCustomObject]@{
                Client         = $client
                Stream         = $network
                ChannelBinding = $null
            }
        }
        catch {
            $failure = $_
            try { $client.Close() }
            catch { Write-Log "[Open-EPAProbeConnection] Closing the failed connection: $($_.Exception.Message)" }
            throw $failure
        }
    }

    # TLS 1.0 to 1.2 first, which every .NET Framework names; the operating system's own
    # choice second, for a server that speaks nothing older than TLS 1.3.
    $protocolChoices = @(
        ([System.Security.Authentication.SslProtocols]::Tls12 -bor [System.Security.Authentication.SslProtocols]::Tls11 -bor [System.Security.Authentication.SslProtocols]::Tls),
        [System.Security.Authentication.SslProtocols]::None
    )

    $lastError = $null
    foreach ($protocols in $protocolChoices) {
        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $connect = $client.BeginConnect($HostName, $Port, $null, $null)
            if (-not $connect.AsyncWaitHandle.WaitOne($timeoutMs)) {
                throw "TCP connection to ${HostName}:$Port timed out"
            }
            $client.EndConnect($connect)
            $client.NoDelay = $true
            $network = $client.GetStream()
            $network.ReadTimeout = $timeoutMs
            $network.WriteTimeout = $timeoutMs

            $tls = New-Object System.Net.Security.SslStream($network, $false, (New-AcceptAnyCertificateCallback))
            $tls.AuthenticateAsClient($HostName, $null, $protocols, $false)

            $bindingBytes = $null
            $binding = $tls.TransportContext.GetChannelBinding([System.Security.Authentication.ExtendedProtection.ChannelBindingKind]::Endpoint)
            if ($binding -and $binding.Size -gt 0) {
                $bindingBytes = New-Object byte[] $binding.Size
                [System.Runtime.InteropServices.Marshal]::Copy($binding.DangerousGetHandle(), $bindingBytes, 0, $binding.Size)
            }

            return [PSCustomObject]@{
                Client         = $client
                Stream         = $tls
                ChannelBinding = $bindingBytes
            }
        }
        catch {
            $lastError = $_.Exception
            try { $client.Close() } catch { }
            # A connection that never came up will not come up with other TLS versions
            if ($lastError.Message -match 'timed out' -or $lastError -is [System.Net.Sockets.SocketException] -or
                $lastError.InnerException -is [System.Net.Sockets.SocketException]) {
                break
            }
        }
    }
    throw $lastError
}

<#
.SYNOPSIS
    Closes a connection from Open-EPAProbeConnection.
#>
function Close-EPAProbeConnection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        $Connection
    )

    if (-not $Connection) { return }
    try { $Connection.Stream.Dispose() } catch { }
    try { $Connection.Client.Close() } catch { }
}

<#
.SYNOPSIS
    Reads one HTTP response off a stream: status, headers, and the body skipped.
.DESCRIPTION
    The body is read only to keep the connection in step for the next request; nothing
    the probe decides depends on it. Content-Length and chunked bodies are read; a
    response with neither carries none (a 401 always has a Content-Length).
.OUTPUTS
    PSCustomObject with StatusCode and Headers (a list of Name/Value objects).
#>
function Read-EPAProbeResponse {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Stream
    )

    # Header block: up to the empty line
    $header = New-Object System.IO.MemoryStream
    $state = 0
    while ($state -lt 4) {
        $b = $Stream.ReadByte()
        if ($b -lt 0) { throw 'the server closed the connection' }
        $header.WriteByte([byte]$b)
        if ($header.Length -gt 65536) { throw 'response header larger than 64 KB' }
        if ($b -eq 13) {
            if ($state -eq 0 -or $state -eq 2) { $state++ } else { $state = 1 }
        }
        elseif ($b -eq 10 -and ($state -eq 1 -or $state -eq 3)) {
            $state++
        }
        else {
            $state = 0
        }
    }

    $lines = [System.Text.Encoding]::ASCII.GetString($header.ToArray()) -split "`r`n"
    if ($lines[0] -notmatch '^HTTP/\d\.\d\s+(\d{3})') { throw "not an HTTP response: '$($lines[0])'" }
    $statusCode = [int]$Matches[1]

    $headers = New-Object System.Collections.Generic.List[object]
    foreach ($line in ($lines | Select-Object -Skip 1)) {
        $colon = $line.IndexOf(':')
        if ($colon -gt 0) {
            $headers.Add([PSCustomObject]@{ Name = $line.Substring(0, $colon).Trim(); Value = $line.Substring($colon + 1).Trim() })
        }
    }

    $contentLength = $headers | Where-Object { $_.Name -eq 'Content-Length' } | Select-Object -First 1
    $transferEncoding = $headers | Where-Object { $_.Name -eq 'Transfer-Encoding' } | Select-Object -First 1
    $skip = New-Object byte[] 8192
    if ($transferEncoding -and $transferEncoding.Value -match 'chunked') {
        while ($true) {
            $sizeLine = Read-EPAProbeLine -Stream $Stream
            $size = [Convert]::ToInt32(($sizeLine -split ';')[0].Trim(), 16)
            if ($size -eq 0) {
                while ((Read-EPAProbeLine -Stream $Stream).Length -gt 0) { }
                break
            }
            Skip-EPAProbeBytes -Stream $Stream -Count $size -Buffer $skip
            [void](Read-EPAProbeLine -Stream $Stream)
        }
    }
    elseif ($contentLength) {
        Skip-EPAProbeBytes -Stream $Stream -Count ([int]$contentLength.Value) -Buffer $skip
    }

    return [PSCustomObject]@{
        StatusCode = $statusCode
        Headers    = $headers
    }
}

function Read-EPAProbeLine {
    <#
    .SYNOPSIS
        Reads one CRLF-terminated line off a stream, without the line break.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] $Stream)

    $line = New-Object System.Text.StringBuilder
    while ($true) {
        $b = $Stream.ReadByte()
        if ($b -lt 0) { throw 'the server closed the connection' }
        if ($b -eq 10) { break }
        if ($b -ne 13) { [void]$line.Append([char]$b) }
    }
    return $line.ToString()
}

function Skip-EPAProbeBytes {
    <#
    .SYNOPSIS
        Reads and discards the given number of bytes off a stream.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $Stream,
        [Parameter(Mandatory = $true)] [int]$Count,
        [Parameter(Mandatory = $true)] [byte[]]$Buffer
    )

    $remaining = $Count
    while ($remaining -gt 0) {
        $read = $Stream.Read($Buffer, 0, [Math]::Min($Buffer.Length, $remaining))
        if ($read -le 0) { throw 'the server closed the connection in the middle of a body' }
        $remaining -= $read
    }
}

<#
.SYNOPSIS
    Sends one GET over a probe connection and reads the answer.
#>
function Send-EPAProbeRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Connection,

        [Parameter(Mandatory = $true)]
        [string]$HostHeader,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Authorization,

        [Parameter(Mandatory = $true)]
        [string]$UserAgent
    )

    $request = "GET $Path HTTP/1.1`r`nHost: $HostHeader`r`nUser-Agent: $UserAgent`r`nAccept: */*`r`nConnection: keep-alive`r`nAuthorization: $Authorization`r`n`r`n"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($request)
    $Connection.Stream.Write($bytes, 0, $bytes.Length)
    $Connection.Stream.Flush()
    return Read-EPAProbeResponse -Stream $Connection.Stream
}

<#
.SYNOPSIS
    Runs one NTLM logon of the EPA probe, over a TLS connection of its own.
.DESCRIPTION
    Type1, the server's challenge, Type3 - with the channel binding the -Binding asks for:
    - Bound         the binding of this connection
    - Unbound       none. The own message leaves the MsvAvChannelBindings pair out
                    (UnboundForm Absent); SSPI cannot, it sends the zero binding of a
                    Windows client without a channel (UnboundForm Zero)
    - Wrong         the binding of a channel the probe is not on
    - ForeignSpn    the binding of Bound, but MsvAvTargetName names another host - the
                    logon only service binding (IIS Proxy flag with an SPN list) rejects
    - ChallengeOnly stop after the challenge; the server facts it carries, no logon
    Over plain HTTP there is no channel: Bound and ForeignSpn carry a random binding that
    is not zero, as a client behind a TLS-terminating proxy does.
.OUTPUTS
    PSCustomObject with Binding, UnboundForm, StatusCode (of the answer to the Type3,
    $null if none came), Type2Result and Error.
#>
function Invoke-EPAProbeHandshake {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Uri]$Uri,

        [Parameter(Mandatory = $true)]
        $Identity,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Bound', 'Unbound', 'Wrong', 'ForeignSpn', 'ChallengeOnly')]
        [string]$Binding,

        [Parameter(Mandatory = $true)]
        [int]$TimeoutSeconds,

        [Parameter(Mandatory = $true)]
        [string]$UserAgent
    )

    $result = [PSCustomObject]@{
        Binding     = $Binding
        UnboundForm = $(if ($Identity.Kind -eq 'Sspi') { 'Zero' } else { 'Absent' })
        StatusCode  = $null
        Type2Result = $null
        Error       = $null
    }

    $connection = $null
    $sspi = $null
    try {
        $plain = ($Uri.Scheme -eq 'http')
        $connection = Open-EPAProbeConnection -HostName $Uri.Host -Port $Uri.Port -TimeoutSeconds $TimeoutSeconds -Plain:$plain
        $hostHeader = if ($Uri.IsDefaultPort) { $Uri.Host } else { "$($Uri.Host):$($Uri.Port)" }
        # The SPN the client means to reach. ForeignSpn names another host - what a logon
        # relayed from a client that authenticated to the attacker carries
        $targetName = "HTTP/$($Uri.Host)"
        if ($Binding -eq 'ForeignSpn') {
            $targetName = 'HTTP/epa-probe-' + ([BitConverter]::ToString((Get-NTLMRandomBytes -Count 4)) -replace '-', '').ToLowerInvariant() + '.invalid'
        }

        # Plain HTTP has no channel. There the control and the foreign-SPN logon carry a
        # binding that is not zero - what a client behind a TLS-terminating proxy sends,
        # the case an IIS with the Proxy flag is built for - and the zero binding of a
        # client without a channel is what the probe tests against it.
        $randomBinding = {
            $applicationData = [byte[]]([System.Text.Encoding]::ASCII.GetBytes('tls-server-end-point:') + (Get-NTLMRandomBytes -Count 32))
            New-SecChannelBindings -ApplicationData $applicationData
        }
        $bindingStruct = $null
        if ($Binding -in @('Bound', 'ForeignSpn')) {
            if ($plain) {
                $bindingStruct = & $randomBinding
            }
            else {
                if (-not $connection.ChannelBinding) { throw 'the TLS channel offered no channel binding' }
                $bindingStruct = $connection.ChannelBinding
            }
        }
        elseif ($Binding -eq 'Wrong') {
            $bindingStruct = & $randomBinding
        }

        $useSspi = ($Identity.Kind -eq 'Sspi') -and ($Binding -ne 'ChallengeOnly')
        if ($useSspi) {
            Initialize-EPASspiType
            $sspi = New-Object adPEASNtlmSspi($targetName)
            # The name the environment gives is the process's user; the credential's is
            # the account that actually logs on (they differ under runas /netonly)
            $credentialName = $sspi.CredentialName()
            if ($credentialName) { $Identity.Name = $credentialName }
            $type1 = [Convert]::ToBase64String($sspi.Negotiate())
        }
        else {
            $type1 = New-NTLMType1Message
        }

        $challengeAnswer = Send-EPAProbeRequest -Connection $connection -HostHeader $hostHeader -Path $Uri.PathAndQuery `
            -Authorization "NTLM $type1" -UserAgent $UserAgent
        if ($challengeAnswer.StatusCode -ne 401) {
            throw "the Type1 was answered with HTTP $($challengeAnswer.StatusCode), not with an NTLM challenge"
        }
        $type2Base64 = $null
        foreach ($headerLine in $challengeAnswer.Headers) {
            if ($headerLine.Name -eq 'WWW-Authenticate' -and $headerLine.Value -match '^NTLM\s+([A-Za-z0-9+/=]+)') {
                $type2Base64 = $Matches[1]
                break
            }
        }
        if (-not $type2Base64) { throw 'the 401 carried no NTLM challenge' }
        $type2 = Read-NTLMType2Message -Type2Base64 $type2Base64
        if (-not $type2.Success) { throw "unreadable NTLM challenge: $($type2.Error)" }
        $result.Type2Result = $type2

        if ($Binding -eq 'ChallengeOnly') { return $result }

        if ($useSspi) {
            $type3 = $sspi.Authenticate([Convert]::FromBase64String($type2Base64), $bindingStruct)
        }
        else {
            $bindingHash = $null
            if ($bindingStruct) {
                $bindingHash = Get-NTLMChannelBindingHash -ApplicationData (Get-ChannelBindingApplicationData -SecChannelBindings $bindingStruct)
            }
            # The domain in the form the server names it, when it is the server's own; a
            # bare user name (not a UPN) logs on in the domain the challenge names - the
            # caller gave the credential for this target
            $domain = $Identity.Domain
            if ($domain -and $type2.NbDomainName -and
                ($domain -ieq $type2.DnsDomainName -or $domain -ieq $type2.NbDomainName)) {
                $domain = $type2.NbDomainName
            }
            elseif (-not $domain -and $Identity.UserName -notmatch '@' -and $type2.NbDomainName) {
                $domain = $type2.NbDomainName
            }
            $authenticateParams = @{
                Type2Result = $type2
                UserName    = $Identity.UserName
                Domain      = [string]$domain
                NTHash      = $Identity.NTHash
                TargetName  = $targetName
            }
            if ($bindingHash) { $authenticateParams['ChannelBindingHash'] = $bindingHash }
            if ($Binding -eq 'Unbound') { $authenticateParams['OmitChannelBindings'] = $true }
            $type3 = New-NTLMAuthenticateMessage @authenticateParams
        }

        $logonAnswer = Send-EPAProbeRequest -Connection $connection -HostHeader $hostHeader -Path $Uri.PathAndQuery `
            -Authorization ("NTLM " + [Convert]::ToBase64String($type3)) -UserAgent $UserAgent
        $result.StatusCode = $logonAnswer.StatusCode
    }
    catch {
        $result.Error = $_.Exception.Message
    }
    finally {
        if ($sspi) { try { $sspi.Dispose() } catch { } }
        Close-EPAProbeConnection -Connection $connection
    }

    return $result
}

<#
.SYNOPSIS
    Reads the logons of the EPA probe as a verdict.
.DESCRIPTION
    A logon counts as accepted when it is answered with anything but 401: a 200, a 403
    or a 500 all come from past the authentication, and which one depends on the
    endpoint and the account, not on EPA. A 502, 503 or 504 counts as no answer.

    What IIS does over HTTPS (measured, Exchange and AD CS web enrollment; "own SPN" is
    MsvAvTargetName naming the server, as every logon but ForeignSpn does):

                         correct      no binding   zero        foreign      correct binding,
                         binding      pair         binding     binding      foreign SPN
        Require          accepted     rejected     rejected    rejected     accepted
        Allow (Accept)   accepted     accepted     rejected    rejected     accepted
        None (Off)       accepted     accepted     accepted    accepted     accepted
        Require + Proxy  accepted     rejected     rejected    accepted     rejected
        Allow + Proxy    accepted     accepted     rejected    accepted     rejected

    The Proxy flag (an SPN list set, TLS ending at a proxy in front of IIS) stops
    verifying the binding and checks the SPN instead - service binding. Over plain HTTP
    only service binding can work: without the Proxy flag IIS takes every logon there,
    with it only one that carries a binding that is not zero and the listed SPN.

    HTTPS, with the pair left out (UnboundForm Absent, the probe's own message):
    - Bound rejected or missing        no verdict - the identity cannot log on here
    - Unbound rejected, Wrong rejected Required
    - Unbound rejected, Wrong accepted Service binding if ForeignSpn is rejected
    - Unbound accepted, Wrong rejected Accept
    - Unbound and Wrong accepted       Service binding if ForeignSpn is rejected, else Off
    With the zero binding (UnboundForm Zero, SSPI, which cannot leave the pair out):
    - Unbound rejected, Wrong rejected enabled - Required or Accept, which SSPI cannot
                                       tell apart
    - Unbound rejected, Wrong accepted Service binding if ForeignSpn is rejected
    - Unbound accepted                 Service binding if ForeignSpn is rejected, else Off
    Plain HTTP (Bound and ForeignSpn carry a binding that is not zero):
    - ForeignSpn rejected              Service binding
    - ForeignSpn accepted              Off
    A logon that did not complete leaves the verdict open where it was needed.
.PARAMETER Bound
    Status code of the control logon, $null if it did not complete.
.PARAMETER Unbound
    Status code of the logon without a binding, $null if not run or not completed.
.PARAMETER Wrong
    Status code of the logon with a foreign binding, $null if not run or not completed.
.PARAMETER ForeignSpn
    Status code of the logon naming another host, $null if not run or not completed.
.PARAMETER UnboundForm
    How the unbound logon went without a binding: Absent (no pair) or Zero (zero binding).
.PARAMETER Transport
    Https or Http.
.PARAMETER IdentityName
    Who logged on, for the diagnostic.
.OUTPUTS
    PSCustomObject with EPAEnabled, Confidence, Mode and DiagnosticInfo. EPAEnabled is
    $true for Required, Accept and Service binding - each rejects the logon a relay of a
    Windows client carries - and $false for Off.
#>
function Resolve-EPAProbeVerdict {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        $Bound,

        [Parameter(Mandatory = $false)]
        $Unbound,

        [Parameter(Mandatory = $false)]
        $Wrong,

        [Parameter(Mandatory = $false)]
        $ForeignSpn,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Absent', 'Zero')]
        [string]$UnboundForm = 'Absent',

        [Parameter(Mandatory = $false)]
        [ValidateSet('Https', 'Http')]
        [string]$Transport = 'Https',

        [Parameter(Mandatory = $false)]
        [string]$IdentityName = 'the probe identity'
    )

    $verdict = [PSCustomObject]@{
        EPAEnabled     = $null
        Confidence     = 'Unknown'
        Mode           = $null
        DiagnosticInfo = $null
    }

    # 502, 503 and 504 say nothing about the logon: a gateway, a load balancer or an
    # application pool that is not up answers them, and three of them would otherwise
    # read as three accepted logons - EPA off - on a server that was merely starting.
    foreach ($name in @('Bound', 'Unbound', 'Wrong', 'ForeignSpn')) {
        $value = Get-Variable -Name $name -ValueOnly
        if ($null -ne $value -and [int]$value -in @(502, 503, 504)) { Set-Variable -Name $name -Value $null }
    }

    $setVerdict = {
        param($Enabled, $Mode, $Text)
        $verdict.EPAEnabled = $Enabled
        $verdict.Confidence = 'High'
        $verdict.Mode = $Mode
        $verdict.DiagnosticInfo = $Text
    }
    $serviceBindingText = "service binding is enforced: the logon naming another host was rejected, and a logon relayed from a client that authenticated to the attacker names the attacker"

    if ($null -eq $Bound) {
        $verdict.DiagnosticInfo = "the control logon of $IdentityName did not complete"
        return $verdict
    }
    if ([int]$Bound -eq 401) {
        $verdict.DiagnosticInfo = "$IdentityName was rejected even in the control logon - it cannot log on to this endpoint (wrong password, NTLM restricted, Protected Users), so a rejection of the other logons would prove nothing"
        return $verdict
    }

    if ($Transport -eq 'Http') {
        if ($null -eq $ForeignSpn) {
            $verdict.DiagnosticInfo = "$IdentityName logged on (HTTP $Bound); the logon naming another host did not complete"
        }
        elseif ([int]$ForeignSpn -eq 401) {
            & $setVerdict $true 'ServiceBinding' "$IdentityName was accepted over plain HTTP naming this server (HTTP $Bound) - $serviceBindingText"
        }
        else {
            & $setVerdict $false 'Off' "$IdentityName was accepted over plain HTTP naming another host (HTTP $ForeignSpn) - neither a channel nor a service binding is checked"
        }
        return $verdict
    }

    if ($null -eq $Unbound) {
        $verdict.DiagnosticInfo = "$IdentityName logged on with the channel binding (HTTP $Bound); the logon without it did not complete"
        return $verdict
    }

    $unboundRejected = ([int]$Unbound -eq 401)
    $wrongAnswered = ($null -ne $Wrong)
    $wrongRejected = ($wrongAnswered -and [int]$Wrong -eq 401)

    # Accepted without a binding: Accept or Off - or, if nothing checks the binding,
    # service binding. Accept rejects a zero binding, so after an accepted zero binding
    # (SSPI) only the SPN can still be checked.
    if (-not $unboundRejected) {
        if ($UnboundForm -eq 'Absent') {
            if (-not $wrongAnswered) {
                $verdict.DiagnosticInfo = "$IdentityName was accepted without a channel binding (HTTP $Unbound) - Extended Protection is not required; the logon with a foreign binding, which tells Accept from Off, did not complete"
                return $verdict
            }
            if ($wrongRejected) {
                & $setVerdict $true 'Accept' "$IdentityName was accepted without a channel binding (HTTP $Unbound) but rejected with a foreign one - Extended Protection is set to Accept: it takes the logon of a client that implements no channel binding and rejects a Windows client, which sends a binding"
                return $verdict
            }
        }
        if ($null -eq $ForeignSpn) {
            $verdict.DiagnosticInfo = "$IdentityName was accepted without a channel binding (HTTP $Unbound); the logon naming another host, which tells service binding from Off, did not complete"
            return $verdict
        }
        if ([int]$ForeignSpn -eq 401) {
            & $setVerdict $true 'ServiceBinding' "$IdentityName was accepted without verifying the channel binding - $serviceBindingText"
            return $verdict
        }
        & $setVerdict $false 'Off' "$IdentityName was accepted without a channel binding (HTTP $Unbound), with a foreign one and naming another host - Extended Protection is off"
        return $verdict
    }

    # Rejected without a binding: channel binding - or the Proxy flag, which rejects a
    # missing binding too but takes any binding that is not zero and checks the SPN
    if (-not $wrongAnswered) {
        & $setVerdict $true $null "$IdentityName was rejected without a channel binding - Extended Protection is enforced; the logon with a foreign binding, which tells channel from service binding, did not complete"
        return $verdict
    }
    if ($wrongRejected) {
        if ($UnboundForm -eq 'Zero') {
            & $setVerdict $true $null "$IdentityName was accepted with the channel binding (HTTP $Bound) and rejected with the zero binding of a Windows client without a channel and with a foreign one - Extended Protection is Required or Accept, which an SSPI logon cannot tell apart"
        }
        else {
            & $setVerdict $true 'Required' "$IdentityName was accepted with the channel binding (HTTP $Bound) and rejected without it and with a foreign one - Extended Protection is required"
        }
        return $verdict
    }
    if ($null -eq $ForeignSpn) {
        $verdict.DiagnosticInfo = "$IdentityName was rejected without a channel binding but accepted with a foreign one (HTTP $Wrong); the logon naming another host did not complete"
        return $verdict
    }
    if ([int]$ForeignSpn -eq 401) {
        & $setVerdict $true 'ServiceBinding' "$IdentityName was accepted with a foreign channel binding (HTTP $Wrong) - the binding is not verified, but $serviceBindingText"
        return $verdict
    }
    $verdict.DiagnosticInfo = "$IdentityName was rejected without a channel binding but accepted with a foreign one and naming another host - a combination no measured IIS mode produces"
    return $verdict
}

<#
.SYNOPSIS
    Names the EPA state of one web endpoint for its "[EPA: ...]" marker.
.DESCRIPTION
    Six states:
    - Enabled: Extended Protection checks the channel binding - required, or, from an SSPI
      logon, required or set to Accept, which such a logon cannot tell apart
    - Accept: Extended Protection rejects a logon that brings a zero or foreign binding,
      as every Windows client does, and takes one that brings no binding at all, as a
      client without channel binding support does
    - Service binding: the binding is not verified (IIS Proxy flag) but the SPN is - a
      logon relayed from a client that authenticated to the attacker names the attacker
    - Disabled: Extended Protection is off
    - Untested: the endpoint was never probed - EPA is probed only where NTLM is offered
    - Undetermined: the endpoint was probed and the probe could not tell - no identity to
      log on with, or the identity could not log on there
    A probed endpoint always carries a confidence and a never-probed one none, which is
    what tells the last two apart. Both used to read "Untested", so an endpoint that had
    been asked and gave no answer looked like one nobody asked.
.PARAMETER EPAEnabled
    The endpoint's verdict: $true, $false or $null.
.PARAMETER EPAConfidence
    The endpoint's confidence, $null when it was never probed.
.PARAMETER EPAMode
    The endpoint's Extended Protection mode, when the probe established it: Required,
    Accept, ServiceBinding or Off.
#>
function Get-EPAStatusLabel {
    [CmdletBinding()]
    param(
        $EPAEnabled,
        $EPAConfidence,
        $EPAMode
    )

    if ($EPAMode -eq 'Accept') { return 'Accept' }
    if ($EPAMode -eq 'ServiceBinding') { return 'Service binding' }
    if ($EPAEnabled -eq $true) { return 'Enabled' }
    if ($EPAEnabled -eq $false) { return 'Disabled' }
    if ($null -eq $EPAConfidence) { return 'Untested' }
    return 'Undetermined'
}

<#
.SYNOPSIS
    Tests whether a web endpoint enforces Extended Protection for Authentication (EPA).
.DESCRIPTION
    Logs on with a real identity several times (Invoke-EPAProbeHandshake) and reads the
    answers as a verdict (Resolve-EPAProbeVerdict). It stops as soon as the verdict is
    reached.

    HTTPS: with the channel binding as the control; without a binding; with the binding
    of another channel; and - only where a foreign binding was taken, or SSPI's zero
    binding was - with the correct binding but naming another host, which only service
    binding rejects.

    Plain HTTP has no channel, so only service binding can protect it: the control
    names this server, the second logon another host, both carrying a binding that is
    not zero.

    A probe with invalid credentials cannot decide any of this - IIS answers every failed
    logon alike - which is why the probe needs an identity that can log on
    (Resolve-EPAProbeIdentity). Without one, the endpoint is undetermined, and the server
    facts of its NTLM challenge are still read.
.PARAMETER Url
    The HTTPS or HTTP URL to test.
.PARAMETER TimeoutSeconds
    Timeout of each connection and read, in seconds (default: 10).
.PARAMETER UserAgent
    HTTP User-Agent header.
.PARAMETER Identity
    The identity to log on with (Resolve-EPAProbeIdentity). Omitted: resolved here.
.RETURNS
    PSCustomObject with:
    - Success: $true if the probe got an answer to its logon, $false if it could not run
    - EPAEnabled: $true (Required, Accept, Service binding), $false (Off), $null (unknown)
    - Confidence: "High" (a verdict), "Unknown" (no verdict)
    - Mode: Required, Accept, ServiceBinding, Off, or $null when the probe could not tell
      (an SSPI logon cannot tell Required from Accept)
    - Identity: who logged on
    - ProbeStatus: status codes of the Bound, Unbound, Wrong and ForeignSpn logons
    - Type2Received, ErrorMessage, DiagnosticInfo
    - Server info from NTLM Type2 AV_PAIRs (NbComputerName, DnsComputerName, etc.)
#>
function Test-ExtendedProtection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Url,

        [Parameter(Mandatory=$false)]
        [int]$TimeoutSeconds = 10,

        [Parameter(Mandatory=$false)]
        [string]$UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",

        [Parameter(Mandatory=$false)]
        $Identity
    )

    $result = [PSCustomObject]@{
        Success = $false           # True if the probe got an answer to its logon (not if EPA is enabled)
        EPAEnabled = $null         # $true = relay of a Windows client rejected, $false = EPA off, $null = unknown
        Confidence = "Unknown"     # "High", "Unknown"
        Mode = $null               # Required, Accept, ServiceBinding, Off
        Identity = $null           # Who logged on
        ProbeStatus = [PSCustomObject]@{ Bound = $null; Unbound = $null; Wrong = $null; ForeignSpn = $null }
        Type2Received = $false
        ErrorMessage = $null
        DiagnosticInfo = $null
        # Server information from NTLM Type2 AV_PAIRs
        NbComputerName = $null     # NetBIOS computer name
        NbDomainName = $null       # NetBIOS domain name
        DnsComputerName = $null    # DNS computer name (FQDN)
        DnsDomainName = $null      # DNS domain name
        DnsTreeName = $null        # DNS forest name
        ServerTimestamp = $null    # Server time (DateTime)
        NTLMChallenge = $null      # NTLM challenge (hex)
    }

    $uri = $null
    try {
        $uri = [System.Uri]$Url
    }
    catch {
        $result.ErrorMessage = "Invalid URL syntax: $Url"
        $result.DiagnosticInfo = $_.Exception.Message
        return $result
    }
    if ($uri.Scheme -notin @('https', 'http')) {
        $result.ErrorMessage = "Not an HTTP or HTTPS URL: $Url"
        return $result
    }
    $transport = if ($uri.Scheme -eq 'http') { 'Http' } else { 'Https' }

    if ($null -eq $Identity) { $Identity = Resolve-EPAProbeIdentity }
    $result.Identity = $Identity.Name

    Write-Log "[Test-ExtendedProtection] Testing EPA for: $Url"

    $handshake = @{ Uri = $uri; Identity = $Identity; TimeoutSeconds = $TimeoutSeconds; UserAgent = $UserAgent }

    if ($Identity.Kind -eq 'None') {
        $challenge = Invoke-EPAProbeHandshake @handshake -Binding 'ChallengeOnly'
        Set-EPAProbeServerFacts -Result $result -Type2Result $challenge.Type2Result
        if ($challenge.Error) {
            $result.ErrorMessage = $challenge.Error
        }
        else {
            $result.Success = $true
        }
        $result.DiagnosticInfo = "no identity to log on with: $($Identity.Reason)"
        Write-Log "[Test-ExtendedProtection] No probe logon - $($result.DiagnosticInfo)"
        return $result
    }

    # Runs one logon and records its status; $null when it got no answer
    $logon = {
        param([string]$Kind, [string]$What)
        Write-Log "[Test-ExtendedProtection] Logging on $What"
        $answer = Invoke-EPAProbeHandshake @handshake -Binding $Kind
        $result.ProbeStatus.$Kind = $answer.StatusCode
        if ($answer.Error) {
            $result.ErrorMessage = "Logon $What failed: $($answer.Error)"
            Write-Log "[Test-ExtendedProtection] $($result.ErrorMessage)"
        }
        $answer
    }
    $accepted = { param($Status) $null -ne $Status -and $Status -ne 401 -and $Status -notin @(502, 503, 504) }
    $rejected = { param($Status) $Status -eq 401 }

    Write-Log "[Test-ExtendedProtection] Logging on as $($Identity.Name) ($($Identity.Source))"
    $bound = & $logon 'Bound' 'naming this server (control)'
    # An SSPI logon names its account only once the credential exists
    $result.Identity = $Identity.Name
    Set-EPAProbeServerFacts -Result $result -Type2Result $bound.Type2Result
    $unboundForm = if ($Identity.Kind -eq 'Sspi') { 'Zero' } else { 'Absent' }

    if (& $accepted $result.ProbeStatus.Bound) {
        if ($transport -eq 'Http') {
            [void](& $logon 'ForeignSpn' 'naming another host')
        }
        else {
            [void](& $logon 'Unbound' 'without a channel binding')
            $unboundStatus = $result.ProbeStatus.Unbound
            # The foreign binding tells Accept from Off after an absent pair, and channel
            # from service binding after a rejection. After an accepted zero binding it
            # has nothing to tell: Accept rejects that binding.
            $runWrong = (& $rejected $unboundStatus) -or ((& $accepted $unboundStatus) -and $unboundForm -eq 'Absent')
            if ($runWrong) {
                [void](& $logon 'Wrong' 'with a foreign channel binding')
            }
            # Naming another host tells service binding from no protection, wherever the
            # binding turned out not to be verified
            $runForeignSpn = (& $accepted $result.ProbeStatus.Wrong) -or ((& $accepted $unboundStatus) -and $unboundForm -eq 'Zero')
            if ($runForeignSpn) {
                [void](& $logon 'ForeignSpn' 'naming another host')
            }
        }
    }

    $verdict = Resolve-EPAProbeVerdict -Bound $result.ProbeStatus.Bound -Unbound $result.ProbeStatus.Unbound `
        -Wrong $result.ProbeStatus.Wrong -ForeignSpn $result.ProbeStatus.ForeignSpn `
        -UnboundForm $unboundForm -Transport $transport -IdentityName $Identity.Name
    $result.Success = ($null -ne $result.ProbeStatus.Bound)
    $result.EPAEnabled = $verdict.EPAEnabled
    $result.Confidence = $verdict.Confidence
    $result.Mode = $verdict.Mode
    $result.DiagnosticInfo = $verdict.DiagnosticInfo
    Write-Log "[Test-ExtendedProtection] $($verdict.DiagnosticInfo)"

    return $result
}

<#
.SYNOPSIS
    Copies the server facts of an NTLM challenge onto a Test-ExtendedProtection result.
#>
function Set-EPAProbeServerFacts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Result,

        [Parameter(Mandatory = $false)]
        $Type2Result
    )

    if (-not $Type2Result) { return }
    $Result.Type2Received = $true
    $Result.NbComputerName = $Type2Result.NbComputerName
    $Result.NbDomainName = $Type2Result.NbDomainName
    $Result.DnsComputerName = $Type2Result.DnsComputerName
    $Result.DnsDomainName = $Type2Result.DnsDomainName
    $Result.DnsTreeName = $Type2Result.DnsTreeName
    $Result.ServerTimestamp = $Type2Result.TimestampUtc
    $Result.NTLMChallenge = $Type2Result.ChallengeHex

    if ($Type2Result.DnsComputerName) {
        Write-Log "[Test-ExtendedProtection] Server: $($Type2Result.DnsComputerName) ($($Type2Result.NbComputerName))"
    }
    if ($Type2Result.DnsDomainName) {
        Write-Log "[Test-ExtendedProtection] Domain: $($Type2Result.DnsDomainName) (Forest: $($Type2Result.DnsTreeName))"
    }
}
