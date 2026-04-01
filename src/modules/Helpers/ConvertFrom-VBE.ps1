<#
.SYNOPSIS
    Decodes VBScript Encoded (.vbe) files.

.DESCRIPTION
    VBScript.Encode (screnc.exe) creates "encoded" scripts that are obfuscated but NOT encrypted.
    This function reverses the encoding using the known character substitution table and escape sequence handling.

    VBE encoding is a simple obfuscation technique used to hide VBScript source code.
    The algorithm was reverse-engineered and published by multiple security researchers.

    VBE Format: #@~^XXXXXX==<encoded_data>YYYYYY==^#~@
    Where XXXXXX and YYYYYY are 6-character checksums

    Escape Sequences (processed during decoding):
    - @& → newline (chr(10))
    - @# → carriage return (chr(13))
    - @* → >
    - @! → <
    - @$ → @

.PARAMETER EncodedScript
    The content of a .vbe file (VBScript Encoded).

.EXAMPLE
    $vbeContent = Get-Content "script.vbe" -Raw
    ConvertFrom-VBE -EncodedScript $vbeContent

.EXAMPLE
    ConvertFrom-VBE -EncodedScript '#@~^DgAAAA==\ko$K6,JCV^GJqAQAAA==^#~@'
    # Returns: MsgBox "Hello"

.OUTPUTS
    String - Decoded VBScript source code

.NOTES
    Author: Alexander Sturz (@_61106960_)
    Algorithm based on Didier Stevens' decode-vbe.py
    Reference: https://blog.didierstevens.com/2016/03/29/decoding-vbe/
#>

function ConvertFrom-VBE {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$EncodedScript
    )

    begin {
        Write-Log "[ConvertFrom-VBE] Starting VBE decoding"

        # VBE decode table - 128 entries indexed DIRECTLY by byte value
        # Each entry contains 3 chars, selected by VBECombination[index % 64]
        $script:VBEDecodings = @(
            [char[]]@(0x00, 0x00, 0x00),  # 0
            [char[]]@(0x01, 0x01, 0x01),  # 1
            [char[]]@(0x02, 0x02, 0x02),  # 2
            [char[]]@(0x03, 0x03, 0x03),  # 3
            [char[]]@(0x04, 0x04, 0x04),  # 4
            [char[]]@(0x05, 0x05, 0x05),  # 5
            [char[]]@(0x06, 0x06, 0x06),  # 6
            [char[]]@(0x07, 0x07, 0x07),  # 7
            [char[]]@(0x08, 0x08, 0x08),  # 8
            [char[]]@(0x57, 0x6E, 0x7B),  # 9  (TAB)
            [char[]]@(0x4A, 0x4C, 0x41),  # 10 (LF)
            [char[]]@(0x0B, 0x0B, 0x0B),  # 11
            [char[]]@(0x0C, 0x0C, 0x0C),  # 12
            [char[]]@(0x4A, 0x4C, 0x41),  # 13 (CR)
            [char[]]@(0x0E, 0x0E, 0x0E),  # 14
            [char[]]@(0x0F, 0x0F, 0x0F),  # 15
            [char[]]@(0x10, 0x10, 0x10),  # 16
            [char[]]@(0x11, 0x11, 0x11),  # 17
            [char[]]@(0x12, 0x12, 0x12),  # 18
            [char[]]@(0x13, 0x13, 0x13),  # 19
            [char[]]@(0x14, 0x14, 0x14),  # 20
            [char[]]@(0x15, 0x15, 0x15),  # 21
            [char[]]@(0x16, 0x16, 0x16),  # 22
            [char[]]@(0x17, 0x17, 0x17),  # 23
            [char[]]@(0x18, 0x18, 0x18),  # 24
            [char[]]@(0x19, 0x19, 0x19),  # 25
            [char[]]@(0x1A, 0x1A, 0x1A),  # 26
            [char[]]@(0x1B, 0x1B, 0x1B),  # 27
            [char[]]@(0x1C, 0x1C, 0x1C),  # 28
            [char[]]@(0x1D, 0x1D, 0x1D),  # 29
            [char[]]@(0x1E, 0x1E, 0x1E),  # 30
            [char[]]@(0x1F, 0x1F, 0x1F),  # 31
            [char[]]@(0x2E, 0x2D, 0x32),  # 32 (space)
            [char[]]@(0x47, 0x75, 0x30),  # 33 !
            [char[]]@(0x7A, 0x52, 0x21),  # 34 "
            [char[]]@(0x56, 0x60, 0x29),  # 35 #
            [char[]]@(0x42, 0x71, 0x5B),  # 36 $
            [char[]]@(0x6A, 0x5E, 0x38),  # 37 %
            [char[]]@(0x2F, 0x49, 0x33),  # 38 &
            [char[]]@(0x26, 0x5C, 0x3D),  # 39 '
            [char[]]@(0x49, 0x62, 0x58),  # 40 (
            [char[]]@(0x41, 0x7D, 0x3A),  # 41 )
            [char[]]@(0x34, 0x29, 0x35),  # 42 *
            [char[]]@(0x32, 0x36, 0x65),  # 43 +
            [char[]]@(0x5B, 0x20, 0x39),  # 44 ,
            [char[]]@(0x76, 0x7C, 0x5C),  # 45 -
            [char[]]@(0x72, 0x7A, 0x56),  # 46 .
            [char[]]@(0x43, 0x7F, 0x73),  # 47 /
            [char[]]@(0x38, 0x6B, 0x66),  # 48 0
            [char[]]@(0x39, 0x63, 0x4E),  # 49 1
            [char[]]@(0x70, 0x33, 0x45),  # 50 2
            [char[]]@(0x45, 0x2B, 0x6B),  # 51 3
            [char[]]@(0x68, 0x68, 0x62),  # 52 4
            [char[]]@(0x71, 0x51, 0x59),  # 53 5
            [char[]]@(0x4F, 0x66, 0x78),  # 54 6
            [char[]]@(0x09, 0x76, 0x5E),  # 55 7
            [char[]]@(0x62, 0x31, 0x7D),  # 56 8
            [char[]]@(0x44, 0x64, 0x4A),  # 57 9
            [char[]]@(0x23, 0x54, 0x6D),  # 58 :
            [char[]]@(0x75, 0x43, 0x71),  # 59 ;
            [char[]]@(0x4A, 0x4C, 0x41),  # 60 < (special)
            [char[]]@(0x7E, 0x3A, 0x60),  # 61 =
            [char[]]@(0x4A, 0x4C, 0x41),  # 62 > (special)
            [char[]]@(0x5E, 0x7E, 0x53),  # 63 ?
            [char[]]@(0x40, 0x4C, 0x40),  # 64 @ (special)
            [char[]]@(0x77, 0x45, 0x42),  # 65 A
            [char[]]@(0x4A, 0x2C, 0x27),  # 66 B
            [char[]]@(0x61, 0x2A, 0x48),  # 67 C
            [char[]]@(0x5D, 0x74, 0x72),  # 68 D
            [char[]]@(0x22, 0x27, 0x75),  # 69 E
            [char[]]@(0x4B, 0x37, 0x31),  # 70 F
            [char[]]@(0x6F, 0x44, 0x37),  # 71 G
            [char[]]@(0x4E, 0x79, 0x4D),  # 72 H
            [char[]]@(0x3B, 0x59, 0x52),  # 73 I
            [char[]]@(0x4C, 0x2F, 0x22),  # 74 J
            [char[]]@(0x50, 0x6F, 0x54),  # 75 K
            [char[]]@(0x67, 0x26, 0x6A),  # 76 L
            [char[]]@(0x2A, 0x72, 0x47),  # 77 M
            [char[]]@(0x7D, 0x6A, 0x64),  # 78 N
            [char[]]@(0x74, 0x39, 0x2D),  # 79 O
            [char[]]@(0x54, 0x7B, 0x20),  # 80 P
            [char[]]@(0x2B, 0x3F, 0x7F),  # 81 Q
            [char[]]@(0x2D, 0x38, 0x2E),  # 82 R
            [char[]]@(0x2C, 0x77, 0x4C),  # 83 S
            [char[]]@(0x30, 0x67, 0x5D),  # 84 T
            [char[]]@(0x6E, 0x53, 0x7E),  # 85 U
            [char[]]@(0x6B, 0x47, 0x6C),  # 86 V
            [char[]]@(0x66, 0x34, 0x6F),  # 87 W
            [char[]]@(0x35, 0x78, 0x79),  # 88 X
            [char[]]@(0x25, 0x5D, 0x74),  # 89 Y
            [char[]]@(0x21, 0x30, 0x43),  # 90 Z
            [char[]]@(0x64, 0x23, 0x26),  # 91 [
            [char[]]@(0x4D, 0x5A, 0x76),  # 92 \
            [char[]]@(0x52, 0x5B, 0x25),  # 93 ]
            [char[]]@(0x63, 0x6C, 0x24),  # 94 ^
            [char[]]@(0x3F, 0x48, 0x2B),  # 95 _
            [char[]]@(0x7B, 0x55, 0x28),  # 96 `
            [char[]]@(0x78, 0x70, 0x23),  # 97 a
            [char[]]@(0x29, 0x69, 0x41),  # 98 b
            [char[]]@(0x28, 0x2E, 0x34),  # 99 c
            [char[]]@(0x73, 0x4C, 0x09),  # 100 d
            [char[]]@(0x59, 0x21, 0x2A),  # 101 e
            [char[]]@(0x33, 0x24, 0x44),  # 102 f
            [char[]]@(0x7F, 0x4E, 0x3F),  # 103 g
            [char[]]@(0x6D, 0x50, 0x77),  # 104 h
            [char[]]@(0x55, 0x09, 0x3B),  # 105 i
            [char[]]@(0x53, 0x56, 0x55),  # 106 j
            [char[]]@(0x7C, 0x73, 0x69),  # 107 k
            [char[]]@(0x3A, 0x35, 0x61),  # 108 l
            [char[]]@(0x5F, 0x61, 0x63),  # 109 m
            [char[]]@(0x65, 0x4B, 0x50),  # 110 n
            [char[]]@(0x46, 0x58, 0x67),  # 111 o
            [char[]]@(0x58, 0x3B, 0x51),  # 112 p
            [char[]]@(0x31, 0x57, 0x49),  # 113 q
            [char[]]@(0x69, 0x22, 0x4F),  # 114 r
            [char[]]@(0x6C, 0x6D, 0x46),  # 115 s
            [char[]]@(0x5A, 0x4D, 0x68),  # 116 t
            [char[]]@(0x48, 0x25, 0x7C),  # 117 u
            [char[]]@(0x27, 0x28, 0x36),  # 118 v
            [char[]]@(0x5C, 0x46, 0x70),  # 119 w
            [char[]]@(0x3D, 0x4A, 0x6E),  # 120 x
            [char[]]@(0x24, 0x32, 0x7A),  # 121 y
            [char[]]@(0x79, 0x41, 0x2F),  # 122 z
            [char[]]@(0x37, 0x3D, 0x5F),  # 123 {
            [char[]]@(0x60, 0x5F, 0x4B),  # 124 |
            [char[]]@(0x51, 0x4F, 0x5A),  # 125 }
            [char[]]@(0x20, 0x42, 0x2C),  # 126 ~
            [char[]]@(0x36, 0x65, 0x57)   # 127
        )

        # Combination table - determines which of the 3 decoded chars to use
        # Index into this table is (position % 64)
        $script:VBECombination = @(
            0, 1, 2, 0, 1, 2, 1, 2, 2, 1, 2, 1, 0, 2, 1, 2,
            0, 2, 1, 2, 0, 0, 1, 2, 2, 1, 0, 2, 1, 2, 2, 1,
            0, 0, 2, 1, 2, 1, 2, 0, 2, 0, 0, 1, 2, 0, 2, 1,
            0, 2, 1, 2, 0, 0, 1, 2, 2, 0, 0, 1, 2, 0, 2, 1
        )

        # Bad bytes that should not be decoded (passed through as-is)
        $script:VBEBadBytes = @(60, 62, 64)  # < > @
    }

    process {
        try {
            # Check for VBE marker format
            # Format: #@~^XXXXXX==<encoded_data>YYYYYY==^#~@
            # Where XXXXXX and YYYYYY are 6-character checksums (any characters)
            if ($EncodedScript -match '#@~\^.{6}==(.+).{6}==\^#~@') {
                $encodedData = $Matches[1]

                Write-Log "[ConvertFrom-VBE] Found VBE block, encoded data length: $($encodedData.Length)"

                if ([string]::IsNullOrEmpty($encodedData)) {
                    Write-Log "[ConvertFrom-VBE] Empty encoded data"
                    return ""
                }

                # Process escape sequences first (like Python version does inline)
                $processedData = $encodedData
                $processedData = $processedData -replace '@&', "`n"    # Line feed (chr(10))
                $processedData = $processedData -replace '@#', "`r"    # Carriage return (chr(13))
                $processedData = $processedData -replace '@\*', '>'    # Greater than
                $processedData = $processedData -replace '@!', '<'     # Less than
                $processedData = $processedData -replace '@\$', '@'    # At sign

                Write-Log "[ConvertFrom-VBE] After escape processing: $($processedData.Length) characters"

                # Decode using substitution table with combination cycling
                $decoded = New-Object System.Text.StringBuilder
                $index = -1

                foreach ($char in $processedData.ToCharArray()) {
                    $byteValue = [int][char]$char

                    # Only increment index for bytes < 128 (VBE_PERM_TRIPLET_SIZE)
                    if ($byteValue -lt 128) {
                        $index++
                    }

                    # Check if this byte should be decoded:
                    # (byte == 9 or (byte > 31 and byte < 128)) and byte not in bad_bytes
                    if (($byteValue -eq 9 -or ($byteValue -gt 31 -and $byteValue -lt 128)) -and
                        $byteValue -notin $script:VBEBadBytes) {

                        # Direct index into table (no offset subtraction)
                        # Table has 128 entries, index = byte value
                        if ($byteValue -lt $script:VBEDecodings.Count) {
                            $triplet = $script:VBEDecodings[$byteValue]
                            $combinationIndex = $script:VBECombination[$index % 64]
                            $decodedChar = $triplet[$combinationIndex]
                            [void]$decoded.Append($decodedChar)
                        } else {
                            # Out of range - pass through
                            [void]$decoded.Append($char)
                        }
                    } else {
                        # Special characters (< > @) or control chars - pass through
                        [void]$decoded.Append($char)
                    }
                }

                $decodedScript = $decoded.ToString()
                Write-Log "[ConvertFrom-VBE] Decoding successful, decoded length: $($decodedScript.Length) characters"

                return $decodedScript

            } else {
                Write-Log "[ConvertFrom-VBE] Not a valid VBE encoded script (missing #@~^ markers)"
                # Not VBE encoded - return as-is (might be plain VBS in .vbe extension)
                return $EncodedScript
            }

        } catch {
            Write-Log "[ConvertFrom-VBE] Decoding failed: $_"
            return "[VBE Decoding Failed: $_]"
        }
    }

    end {
        Write-Log "[ConvertFrom-VBE] VBE decoding completed"
    }
}
