<#
.SYNOPSIS
    NTLM over HTTP authentication helpers for Extended Protection for Authentication (EPA) testing.

.DESCRIPTION
    Implements NTLM Type1/Type2/Type3 message handling over HTTP to test whether Extended Protection
    for Authentication (EPA/Channel Binding) is enabled.

    EPA binds NTLM authentication to the TLS channel, preventing relay attacks.
    This module tests EPA by attempting NTLM auth without a Channel Binding Token (CBT).

    If EPA is enabled:  Auth fails (401) even with valid dummy credentials
    If EPA is disabled: Auth proceeds (may fail for other reasons, but not due to CBT)

    Success Flag Semantics:
    - Success = $true:  EPA test completed (result is in EPAEnabled)
    - Success = $false: EPA test could not be completed (network error, no NTLM, etc.)
    - EPAEnabled = $true:  EPA is active (secure against NTLM relay)
    - EPAEnabled = $false: EPA is NOT active (vulnerable to NTLM relay)
    - EPAEnabled = $null:  EPA status could not be determined or not applicable

    Timeout Semantics:
    - TimeoutSeconds is a per-operation timeout, not a total timeout
    - Each HTTP request (Type1 and Type3) has its own timeout
    - Slow connections with many small packets may exceed TimeoutSeconds total

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

    # Negotiate flags - request extended session security but NOT Channel Binding
    # This is key for EPA testing - we explicitly don't include CBT
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
$Script:MsvAvFlags = 0x0006            # Flags (bit 0x02 = EPA required)
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
    - MsvAvFlags (0x0006): Flags (bit 0x02 indicates EPA required)
    - MsvAvTimestamp (0x0007): Server timestamp (FILETIME)
.PARAMETER Type2Base64
    Base64-encoded NTLM Type2 message from server.
.RETURNS
    PSCustomObject with Challenge, TargetName, TargetInfo, Flags, and parsed AV_PAIRs.
#>
function Read-NTLMType2Message {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
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
        $challenge = $bytes[24..31]

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
                $targetInfo = $bytes[$targetInfoOffset..($targetInfoOffset + $targetInfoLen - 1)]

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
                EPARequired = $false
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
            EPARequired = $avPairs.EPARequired
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
        [Parameter(Mandatory=$true)]
        [byte[]]$TargetInfoBytes
    )

    $result = [PSCustomObject]@{
        NbComputerName = $null    # NetBIOS computer name
        NbDomainName = $null      # NetBIOS domain name
        DnsComputerName = $null   # DNS computer name (FQDN)
        DnsDomainName = $null     # DNS domain name
        DnsTreeName = $null       # DNS forest name
        AvFlags = $null           # Raw flags value
        EPARequired = $false      # True if flag 0x02 is set
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

        # Extract value bytes
        $valueBytes = $TargetInfoBytes[$offset..($offset + $avLen - 1)]
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
                    # Bit 0x02 = MIC present / EPA required
                    $result.EPARequired = ($result.AvFlags -band 0x02) -ne 0
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
                        $result.RawPairs['MsvAvTimestamp'] = $result.TimestampUtc.ToString("yyyy-MM-dd HH:mm:ss UTC")
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
    Generates a random identifier for EPA testing.
.DESCRIPTION
    Creates a random identifier that looks like a typical Windows account name.
    Uses a common prefix followed by random characters to blend in with normal log entries.
    Uses cryptographically secure random number generation.
.PARAMETER Type
    Type of identifier to generate: "Username" or "Workstation".
.RETURNS
    Random identifier string (e.g., "svc.a7k2mq9", "WS-X4P2N8").
#>
function New-RandomEPAIdentifier {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [ValidateSet('Username', 'Workstation')]
        [string]$Type = 'Username'
    )

    # Use shared cryptographically secure random number generator
    $rng = Get-NTLMSecureRNG

    if ($Type -eq 'Workstation') {
        # Workstation prefixes that look like typical enterprise naming
        $prefixes = @('WS', 'PC', 'DT', 'NB', 'VM', 'SRV')
    }
    else {
        # Username prefixes that look like typical service/admin accounts
        $prefixes = @('admin', 'user', 'test', 'svc', 'app', 'sys', 'dev', 'ops')
    }

    # Generate random bytes for prefix selection
    $prefixBytes = New-Object byte[] 1
    $rng.GetBytes($prefixBytes)
    $prefix = $prefixes[$prefixBytes[0] % $prefixes.Count]

    # Generate random suffix length (5-8 chars)
    $lengthBytes = New-Object byte[] 1
    $rng.GetBytes($lengthBytes)
    $suffixLength = 5 + ($lengthBytes[0] % 4)

    # Generate random suffix using CSPRNG
    $chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
    if ($Type -eq 'Workstation') {
        $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    }

    $suffixBytes = New-Object byte[] $suffixLength
    $rng.GetBytes($suffixBytes)
    $suffix = -join ($suffixBytes | ForEach-Object { $chars[$_ % $chars.Length] })

    if ($Type -eq 'Workstation') {
        return "$prefix-$suffix"
    }
    else {
        return "$prefix.$suffix"
    }
}

<#
.SYNOPSIS
    Creates an NTLM Type3 (Authenticate) message WITHOUT Channel Binding Token.
.DESCRIPTION
    Builds an NTLM Type3 message with dummy credentials for EPA testing.
    The message intentionally does NOT include a Channel Binding Token (MsvAvChannelBindings).
    If EPA is enabled, the server will reject this authentication attempt.
.PARAMETER Type2Result
    Parsed Type2 message from Read-NTLMType2Message. Must have Success=$true and contain Flags property.
.PARAMETER Username
    Username for the dummy authentication. If not specified, a random username is generated
    at runtime to avoid predictable patterns in server logs.
.PARAMETER Domain
    Domain for the dummy authentication (default: "WORKGROUP").
.RETURNS
    Base64-encoded NTLM Type3 message, or $null if Type2Result is invalid.
#>
function New-NTLMType3Message {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Type2Result,

        [Parameter(Mandatory=$false)]
        [string]$Username,

        [Parameter(Mandatory=$false)]
        [string]$Domain = "WORKGROUP"
    )

    # Validate Type2Result parameter
    if ($null -eq $Type2Result) {
        Write-Log "[New-NTLMType3Message] Error: Type2Result is null"
        return $null
    }
    if ($Type2Result.PSObject.Properties['Success'] -and -not $Type2Result.Success) {
        Write-Log "[New-NTLMType3Message] Error: Type2Result.Success is false"
        return $null
    }
    if ($null -eq $Type2Result.Flags) {
        Write-Log "[New-NTLMType3Message] Error: Type2Result.Flags is null"
        return $null
    }

    # Generate random username if not provided
    if ([string]::IsNullOrEmpty($Username)) {
        $Username = New-RandomEPAIdentifier -Type 'Username'
    }

    # Generate random workstation name
    $workstationName = New-RandomEPAIdentifier -Type 'Workstation'

    # NTLMSSP signature
    $signature = [System.Text.Encoding]::ASCII.GetBytes("NTLMSSP`0")

    # Message type (3 = Authenticate)
    $messageType = [BitConverter]::GetBytes([uint32]3)

    # Use Unicode encoding
    $domainBytes = [System.Text.Encoding]::Unicode.GetBytes($Domain)
    $usernameBytes = [System.Text.Encoding]::Unicode.GetBytes($Username)
    $workstationBytes = [System.Text.Encoding]::Unicode.GetBytes($workstationName)

    # Generate dummy LM and NT responses using shared CSPRNG (cryptographically secure)
    # For EPA testing, we just need to complete the handshake - the credentials are irrelevant
    $lmResponse = New-Object byte[] 24
    $ntResponse = New-Object byte[] 24
    $rng = Get-NTLMSecureRNG
    $rng.GetBytes($lmResponse)
    $rng.GetBytes($ntResponse)

    # Calculate offsets
    # Type3 header structure (MS-NLMP 2.2.1.3):
    # - Signature: 8 bytes (0-7)
    # - MessageType: 4 bytes (8-11)
    # - LmChallengeResponse: 8 bytes (12-19) - len/maxlen/offset
    # - NtChallengeResponse: 8 bytes (20-27)
    # - DomainName: 8 bytes (28-35)
    # - UserName: 8 bytes (36-43)
    # - Workstation: 8 bytes (44-51)
    # - EncryptedRandomSessionKey: 8 bytes (52-59)
    # - NegotiateFlags: 4 bytes (60-63)
    # Total fixed header: 64 bytes
    # Optional Version: 8 bytes (64-71) - if NTLMSSP_NEGOTIATE_VERSION
    # Optional MIC: 16 bytes (72-87) - if MsvAvFlags indicates MIC required
    # We include Version but no MIC since we don't have valid credentials
    $headerSize = 72  # 64 + 8 for version
    $currentOffset = $headerSize

    $lmResponseOffset = $currentOffset
    $currentOffset += $lmResponse.Length

    $ntResponseOffset = $currentOffset
    $currentOffset += $ntResponse.Length

    $domainOffset = $currentOffset
    $currentOffset += $domainBytes.Length

    $usernameOffset = $currentOffset
    $currentOffset += $usernameBytes.Length

    $workstationOffset = $currentOffset
    $currentOffset += $workstationBytes.Length

    # Negotiate flags - match Type2 response but ensure UNICODE and VERSION
    # Explicitly cast to [uint32] to prevent Int32 overflow issues with high-bit flags
    [uint32]$flags = [uint32]$Type2Result.Flags -bor $Script:NTLMSSP_NEGOTIATE_UNICODE -bor $Script:NTLMSSP_NEGOTIATE_VERSION

    # Build the message
    $message = New-Object System.Collections.Generic.List[byte]

    # Header
    $message.AddRange($signature)                                           # 0-7:   Signature
    $message.AddRange($messageType)                                         # 8-11:  Type (3)

    # LM Response
    $message.AddRange([BitConverter]::GetBytes([uint16]$lmResponse.Length)) # 12-13: LM length
    $message.AddRange([BitConverter]::GetBytes([uint16]$lmResponse.Length)) # 14-15: LM max length
    $message.AddRange([BitConverter]::GetBytes([uint32]$lmResponseOffset))  # 16-19: LM offset

    # NT Response
    $message.AddRange([BitConverter]::GetBytes([uint16]$ntResponse.Length)) # 20-21: NT length
    $message.AddRange([BitConverter]::GetBytes([uint16]$ntResponse.Length)) # 22-23: NT max length
    $message.AddRange([BitConverter]::GetBytes([uint32]$ntResponseOffset))  # 24-27: NT offset

    # Domain
    $message.AddRange([BitConverter]::GetBytes([uint16]$domainBytes.Length))  # 28-29: Domain length
    $message.AddRange([BitConverter]::GetBytes([uint16]$domainBytes.Length))  # 30-31: Domain max length
    $message.AddRange([BitConverter]::GetBytes([uint32]$domainOffset))        # 32-35: Domain offset

    # Username
    $message.AddRange([BitConverter]::GetBytes([uint16]$usernameBytes.Length))  # 36-37: User length
    $message.AddRange([BitConverter]::GetBytes([uint16]$usernameBytes.Length))  # 38-39: User max length
    $message.AddRange([BitConverter]::GetBytes([uint32]$usernameOffset))        # 40-43: User offset

    # Workstation
    $message.AddRange([BitConverter]::GetBytes([uint16]$workstationBytes.Length))  # 44-45: WS length
    $message.AddRange([BitConverter]::GetBytes([uint16]$workstationBytes.Length))  # 46-47: WS max length
    $message.AddRange([BitConverter]::GetBytes([uint32]$workstationOffset))        # 48-51: WS offset

    # Encrypted random session key (empty for EPA test)
    $message.AddRange([BitConverter]::GetBytes([uint16]0))                  # 52-53: Session key length
    $message.AddRange([BitConverter]::GetBytes([uint16]0))                  # 54-55: Session key max length
    $message.AddRange([BitConverter]::GetBytes([uint32]0))                  # 56-59: Session key offset

    # Flags
    $message.AddRange([BitConverter]::GetBytes([uint32]$flags))             # 60-63: Flags

    # Version (8 bytes) - Windows 10 version info
    # ProductMajorVersion: 10 (0x0A)
    # ProductMinorVersion: 0 (0x00)
    # ProductBuild: 19041 (0x4A61)
    # Reserved: 0x000000
    # NTLMRevisionCurrent: 15 (0x0F) = NTLMSSP_REVISION_W2K3
    $version = [byte[]]@(0x0A, 0x00, 0x61, 0x4A, 0x00, 0x00, 0x00, 0x0F)
    $message.AddRange($version)                                             # 64-71: Version

    # Payload
    $message.AddRange($lmResponse)
    $message.AddRange($ntResponse)
    $message.AddRange($domainBytes)
    $message.AddRange($usernameBytes)
    $message.AddRange($workstationBytes)

    return [Convert]::ToBase64String($message.ToArray())
}

<#
.SYNOPSIS
    Tests whether Extended Protection for Authentication (EPA) is enabled on an HTTPS endpoint.
.DESCRIPTION
    Performs a full NTLM handshake over HTTPS without a Channel Binding Token (CBT).
    If EPA is enabled, the server will reject the Type3 message due to missing CBT.

    This function maintains proper NTLM connection state by using a single ServicePoint
    and limiting connections to ensure Type1->Type2->Type3 flow over the same TCP connection.

    EPA Detection Logic (in priority order):
    1. MsvAvFlags in Type2 with bit 0x02 set = EPA ENABLED (definitive, High confidence)
    2. Type3 response has "NTLM <blob>" (new Type2) = EPA ENABLED (High confidence)
    3. Type3 response has bare "NTLM" (no Negotiate prefix) = EPA ENABLED (High confidence)
    4. Type3 response has "Negotiate" or "Negotiate,NTLM" = EPA DISABLED (Medium confidence)
       Note: "Negotiate,NTLM" ends with NTLM but is a normal auth-failure challenge, NOT a restart
    5. Type3 accepted (200/302) = EPA DISABLED (High confidence)
    6. Connection reset after Type3 = EPA ENABLED (Medium confidence)

.PARAMETER Url
    The HTTPS URL to test (must be HTTPS for EPA to be relevant).
.PARAMETER TimeoutSeconds
    HTTP request timeout in seconds (default: 10).
.PARAMETER UserAgent
    HTTP User-Agent header (default: "Mozilla/5.0").
.RETURNS
    PSCustomObject with:
    - Success: $true if EPA test completed, $false if test could not run
    - EPAEnabled: $true (EPA active/secure), $false (EPA inactive/vulnerable), $null (unknown/N/A)
    - Confidence: "High", "Medium", "Low", "Unknown", "N/A"
    - Type2Received, Type3Response, Type3StatusCode, ErrorMessage, DiagnosticInfo
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
        [string]$UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    )

    $result = [PSCustomObject]@{
        Success = $false           # True if EPA test completed (not if EPA is enabled)
        EPAEnabled = $null         # $true = EPA active (secure), $false = EPA not active (vulnerable), $null = unknown/N/A
        Confidence = "Unknown"     # "High", "Medium", "Low", "Unknown", "N/A"
        Type2Received = $false
        Type3Response = $null
        Type3StatusCode = $null
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

    # FIX: Validate URL syntax before processing
    $uri = $null
    try {
        $uri = [System.Uri]$Url
    }
    catch {
        $result.ErrorMessage = "Invalid URL syntax: $Url"
        $result.DiagnosticInfo = $_.Exception.Message
        return $result
    }

    # Validate URL is HTTPS (EPA only applies to TLS connections)
    # FIX: For HTTP, EPA is not applicable, so EPAEnabled should be $null (not $false)
    if ($uri.Scheme -ne 'https') {
        $result.Success = $true    # Test completed (we know the answer)
        $result.EPAEnabled = $null # Not applicable (not "disabled")
        $result.Confidence = "N/A"
        $result.ErrorMessage = "EPA only applies to HTTPS connections. HTTP does not use Channel Binding."
        $result.DiagnosticInfo = "HTTP has no TLS channel to bind to - NTLM relay is always possible over HTTP regardless of EPA settings"
        return $result
    }

    Write-Log "[Test-ExtendedProtection] Testing EPA for: $Url"

    # Save original TLS settings to restore later
    $originalSecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol
    $originalCertCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback

    # Track ServicePoint and its original connection limit for cleanup
    $servicePoint = $null
    $originalConnectionLimit = $null

    try {
        # Configure TLS - enable all versions and ignore certificate errors
        try {
            $protocols = [System.Net.SecurityProtocolType]::Tls12
            try { $protocols = $protocols -bor [System.Net.SecurityProtocolType]::Tls11 } catch { }
            try { $protocols = $protocols -bor [System.Net.SecurityProtocolType]::Tls } catch { }
            try {
                $protocols = $protocols -bor [System.Net.SecurityProtocolType]::Tls13
            }
            catch {
                # TLS 1.3 not available on this .NET version - this is expected on older systems
                Write-Log "[Test-ExtendedProtection] TLS 1.3 not available: $($_.Exception.Message)"
            }
            [System.Net.ServicePointManager]::SecurityProtocol = $protocols
        }
        catch {
            Write-Log "[Test-ExtendedProtection] Failed to configure TLS: $($_.Exception.Message)"
        }

        # Ignore SSL certificate errors (self-signed, expired, etc.)
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

        # FIX: NTLM is connection-oriented - we need Type1->Type2->Type3 on SAME TCP connection
        # Limit connections to 1 for this ServicePoint to ensure connection reuse
        $servicePoint = [System.Net.ServicePointManager]::FindServicePoint($uri)
        if ($servicePoint) {
            $originalConnectionLimit = $servicePoint.ConnectionLimit
            $servicePoint.ConnectionLimit = 1
        }

        # Step 1: Send Type1 to get Type2 challenge
        Write-Log "[Test-ExtendedProtection] Step 1: Sending Type1 to initiate NTLM handshake"

        $type1Message = New-NTLMType1Message
        $type2Base64 = $null
        $type2Result = $null

        try {
            $request1 = [System.Net.HttpWebRequest]::Create($Url)
            $request1.Method = 'GET'
            $request1.Timeout = $TimeoutSeconds * 1000
            $request1.ReadWriteTimeout = $TimeoutSeconds * 1000
            $request1.UserAgent = $UserAgent
            $request1.KeepAlive = $true
            $request1.Headers.Add("Authorization", "NTLM $type1Message")
            # Ensure we don't use pre-authenticated connections
            $request1.PreAuthenticate = $false
            $request1.UnsafeAuthenticatedConnectionSharing = $true

            $response1 = $request1.GetResponse()
            # If we got 200 OK with just Type1, endpoint allows anonymous access or doesn't require NTLM
            $result.Success = $true
            $result.EPAEnabled = $null
            $result.Confidence = "N/A"
            $result.DiagnosticInfo = "Endpoint returned 200 OK - anonymous access allowed or no NTLM auth required. EPA test not applicable."
            $response1.Close()
            $response1.Dispose()
            return $result
        }
        catch [System.Net.WebException] {
            $webEx = $_.Exception
            if ($webEx.Response) {
                $statusCode = [int]$webEx.Response.StatusCode

                if ($statusCode -eq 401) {
                    # Expected - look for Type2 in WWW-Authenticate header
                    $wwwAuth = $webEx.Response.Headers['WWW-Authenticate']

                    if ($wwwAuth -match 'NTLM\s+([A-Za-z0-9+/=]+)') {
                        $type2Base64 = $Matches[1]
                        $result.Type2Received = $true
                        Write-Log "[Test-ExtendedProtection] Step 2: Received Type2 challenge"
                    }
                    else {
                        $result.ErrorMessage = "Server returned 401 but no NTLM Type2 challenge in WWW-Authenticate header"
                        $result.DiagnosticInfo = "WWW-Authenticate: $wwwAuth"
                    }
                }
                else {
                    $result.ErrorMessage = "Unexpected status code: $statusCode"
                }

                # FIX: DO NOT close the response here - closing can terminate the TCP connection
                # which breaks NTLM's connection-oriented state machine.
                # The response will be garbage collected and the connection pool manages lifecycle.
                # Only close on the outer exception handler if we're returning early.
            }
            else {
                $result.ErrorMessage = "Connection failed: $($webEx.Message)"
            }
        }

        if (-not $result.Type2Received) {
            Write-Log "[Test-ExtendedProtection] Failed to receive Type2 challenge"
            return $result
        }

        # Step 2: Parse Type2 message
        $type2Result = Read-NTLMType2Message -Type2Base64 $type2Base64
        if (-not $type2Result.Success) {
            $result.ErrorMessage = "Failed to parse Type2: $($type2Result.Error)"
            return $result
        }

        # Copy AV_PAIR values to result
        $result.NbComputerName = $type2Result.NbComputerName
        $result.NbDomainName = $type2Result.NbDomainName
        $result.DnsComputerName = $type2Result.DnsComputerName
        $result.DnsDomainName = $type2Result.DnsDomainName
        $result.DnsTreeName = $type2Result.DnsTreeName
        $result.ServerTimestamp = $type2Result.TimestampUtc
        $result.NTLMChallenge = $type2Result.ChallengeHex

        Write-Log "[Test-ExtendedProtection] Type2 parsed - Target: $($type2Result.TargetName), Challenge: $($type2Result.ChallengeHex)"
        if ($type2Result.DnsComputerName) {
            Write-Log "[Test-ExtendedProtection] Server: $($type2Result.DnsComputerName) ($($type2Result.NbComputerName))"
        }
        if ($type2Result.DnsDomainName) {
            Write-Log "[Test-ExtendedProtection] Domain: $($type2Result.DnsDomainName) (Forest: $($type2Result.DnsTreeName))"
        }

        # FIX: Check MsvAvFlags for EPA requirement BEFORE sending Type3
        # This is the most reliable indicator - the server explicitly tells us EPA is required
        if ($type2Result.EPARequired) {
            Write-Log "[Test-ExtendedProtection] MsvAvFlags indicates EPA required (bit 0x02 set) - DEFINITIVE EPA ENABLED"
            $result.Success = $true
            $result.EPAEnabled = $true
            $result.Confidence = "High"
            $result.DiagnosticInfo = "MsvAvFlags in Type2 contains bit 0x02 (MIC/EPA required) - server definitively requires Channel Binding"
            return $result
        }

        # Step 3: Create Type3 message WITHOUT Channel Binding Token
        $type3Message = New-NTLMType3Message -Type2Result $type2Result
        if ($null -eq $type3Message) {
            $result.ErrorMessage = "Failed to create Type3 message"
            return $result
        }
        Write-Log "[Test-ExtendedProtection] Step 3: Sending Type3 (without CBT) to test EPA"

        # Step 4: Send Type3 and analyze response
        try {
            $request2 = [System.Net.HttpWebRequest]::Create($Url)
            $request2.Method = 'GET'
            $request2.Timeout = $TimeoutSeconds * 1000
            $request2.ReadWriteTimeout = $TimeoutSeconds * 1000
            $request2.UserAgent = $UserAgent
            $request2.KeepAlive = $true
            $request2.Headers.Add("Authorization", "NTLM $type3Message")
            $request2.PreAuthenticate = $false
            $request2.UnsafeAuthenticatedConnectionSharing = $true

            $response2 = $request2.GetResponse()
            $result.Type3StatusCode = [int]$response2.StatusCode

            # If we got 200 OK or redirect, EPA is NOT active (our dummy creds "worked" past the channel binding check)
            # Note: The auth itself may succeed or fail based on server config, but EPA would have rejected BEFORE this
            $result.EPAEnabled = $false
            $result.Confidence = "High"
            $result.Type3Response = "Success ($($response2.StatusCode))"
            $result.DiagnosticInfo = "Type3 accepted (HTTP $($result.Type3StatusCode)) - EPA is NOT blocking missing CBT"
            $result.Success = $true

            Write-Log "[Test-ExtendedProtection] Type3 accepted - EPA NOT enabled"

            $response2.Close()
            $response2.Dispose()
        }
        catch [System.Net.WebException] {
            $webEx = $_.Exception
            if ($webEx.Response) {
                $statusCode = [int]$webEx.Response.StatusCode
                $result.Type3StatusCode = $statusCode

                if ($statusCode -eq 401) {
                    # 401 on Type3 - need to analyze WHY
                    $wwwAuth = $webEx.Response.Headers['WWW-Authenticate']
                    $result.Type3Response = "401 Unauthorized"

                    # EPA Detection after Type3 (priority order):
                    #
                    # 1. "NTLM <base64blob>" — server sent a new Type2 challenge = NTLM restart.
                    #    EPA rejects the Type3 (SEC_E_INVALID_TOKEN) and restarts negotiation.
                    #    Only NTLM without Negotiate prefix: IIS uses pure NTLM channel for the restart.
                    #    → EPA ENABLED (High confidence)
                    #
                    # 2. "NTLM" bare (no Negotiate prefix, no blob) — NTLM-only offer = restart signal.
                    #    Same meaning as above but without a blob attached.
                    #    → EPA ENABLED (High confidence)
                    #
                    # 3. "Negotiate,NTLM" or "Negotiate" (with or without blob) — blanke new Auth-Challenge.
                    #    This is the normal IIS response when authentication FAILS (invalid credentials).
                    #    Both EPA=enabled and EPA=disabled can produce this, BUT:
                    #    - When EPA=disabled: dummy Type3 passes the CBT check, fails on credentials → 401 Negotiate,NTLM
                    #    - When EPA=enabled:  dummy Type3 fails the CBT check first → typically NTLM restart (case 1/2)
                    #    If we reach this branch, CBT check passed (EPA not enforced) and only creds failed.
                    #    → EPA DISABLED (Medium confidence)
                    #
                    # NOTE: The old pattern "NTLM\s*$" incorrectly matched "Negotiate,NTLM" because NTLM
                    # appears at the end of the string. Fixed by requiring NTLM NOT be preceded by "Negotiate,".
                    if ($wwwAuth -match 'NTLM\s+([A-Za-z0-9+/=]{20,})') {
                        # Case 1: Server sent a new NTLM Type2 blob — genuine NTLM restart after EPA rejection
                        $result.EPAEnabled = $true
                        $result.Confidence = "High"
                        $result.DiagnosticInfo = "Server sent new NTLM Type2 challenge after Type3 - EPA rejected the request due to missing Channel Binding Token"
                        Write-Log "[Test-ExtendedProtection] EPA ENABLED - Server restarted NTLM with new Type2 (CBT missing)"
                    }
                    elseif ($wwwAuth -match '(?<![,\s])NTLM\s*$' -or $wwwAuth -match '^NTLM\s*$') {
                        # Case 2: Bare "NTLM" without Negotiate prefix — NTLM-only restart signal
                        # Exclude "Negotiate,NTLM" which ends with NTLM but means normal auth failure
                        $result.EPAEnabled = $true
                        $result.Confidence = "High"
                        $result.DiagnosticInfo = "Server offered bare NTLM after Type3 - NTLM restart indicates EPA rejected missing Channel Binding Token"
                        Write-Log "[Test-ExtendedProtection] EPA ENABLED - Bare NTLM offer after Type3 (CBT missing)"
                    }
                    elseif ($wwwAuth -match 'Negotiate\s+([A-Za-z0-9+/=]{20,})') {
                        # Case 3a: Negotiate blob — Kerberos token or NTLM-via-Negotiate; auth failed on credentials
                        $result.EPAEnabled = $false
                        $result.Confidence = "Medium"
                        $result.DiagnosticInfo = "Server returned 401 with Negotiate blob after Type3 - credentials rejected (CBT check passed, EPA not enforced)"
                        Write-Log "[Test-ExtendedProtection] EPA NOT enabled - auth failure with Negotiate blob (normal credential rejection)"
                    }
                    elseif ($wwwAuth -match 'Negotiate') {
                        # Case 3b: "Negotiate" or "Negotiate,NTLM" — blanke new Auth-Challenge after credential failure
                        # This is the standard IIS response when NTLM auth fails with invalid credentials
                        # and EPA is not blocking (EPA=disabled: CBT check passed, credential check failed)
                        $result.EPAEnabled = $false
                        $result.Confidence = "Medium"
                        $result.DiagnosticInfo = "Server returned 401 with Negotiate,NTLM after Type3 - credentials rejected (CBT check passed, EPA not enforced)"
                        Write-Log "[Test-ExtendedProtection] EPA NOT enabled - auth failure with Negotiate,NTLM (normal credential rejection)"
                    }
                    else {
                        # Generic 401 without recognizable auth header
                        $result.EPAEnabled = $null
                        $result.Confidence = "Low"
                        $result.DiagnosticInfo = "401 received after Type3 but WWW-Authenticate header is unrecognized. Cannot determine EPA status. Header: $wwwAuth"
                        Write-Log "[Test-ExtendedProtection] Inconclusive - 401 with unrecognized WWW-Authenticate: $wwwAuth"
                    }

                    $result.Success = $true
                }
                else {
                    $result.Type3Response = "HTTP $statusCode"
                    $result.ErrorMessage = "Unexpected status code on Type3: $statusCode"
                }

                try { $webEx.Response.Close() } catch {}
            }
            else {
                # Connection error during Type3 - might indicate EPA terminating connection
                $result.ErrorMessage = "Connection failed on Type3: $($webEx.Message)"

                if ($webEx.Message -match 'connection.*closed|reset|aborted' -or $webEx.Status -eq 'ConnectionClosed') {
                    $result.EPAEnabled = $true
                    $result.Confidence = "Medium"
                    $result.DiagnosticInfo = "Connection terminated after Type3 - may indicate EPA rejection"
                    $result.Success = $true
                }
            }
        }
    }
    catch {
        $result.ErrorMessage = "Unexpected error: $($_.Exception.Message)"
        Write-Log "[Test-ExtendedProtection] Error: $($_.Exception.Message)"
    }
    finally {
        # FIX: Proper null check for originalConnectionLimit
        # $originalConnectionLimit could be 0 (though unlikely), so check for $null explicitly
        if ($servicePoint -and $null -ne $originalConnectionLimit) {
            try { $servicePoint.ConnectionLimit = $originalConnectionLimit } catch { }
        }

        # Restore original TLS settings
        try {
            [System.Net.ServicePointManager]::SecurityProtocol = $originalSecurityProtocol
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $originalCertCallback
        } catch { }
    }

    return $result
}
