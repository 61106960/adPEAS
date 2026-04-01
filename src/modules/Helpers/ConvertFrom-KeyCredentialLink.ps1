<#
.SYNOPSIS
    Parses msDS-KeyCredentialLink binary blob to extract Shadow Credential metadata.

.DESCRIPTION
    Decodes the KEYCREDENTIALLINK_BLOB structure (LTV format) to extract human-readable
    information such as DeviceID, KeyCreationTime, KeyUsage, and KeySource.

    The structure is:
    - Version (4 bytes): 0x00000200 for version 2
    - Entries: LTV format (Length 2 bytes, Type 2 bytes, Value variable)

    Entry Types:
    - 0x0001: KeyID (SHA256 hash of public key)
    - 0x0002: KeyHash (SHA256 of entries 3-9)
    - 0x0003: KeyMaterial (BCRYPT_RSAKEY_BLOB)
    - 0x0004: KeyUsage (1=NGC, 2=FIDO, 7=FEK)
    - 0x0005: KeySource (0=AD, 1=AzureAD)
    - 0x0006: DeviceId (GUID)
    - 0x0007: CustomKeyInformation
    - 0x0008: KeyApproximateLastLogonTimeStamp (FILETIME)
    - 0x0009: KeyCreationTime (FILETIME)

.PARAMETER KeyCredentialBytes
    The raw binary bytes of the KeyCredentialLink blob.

.PARAMETER DNWithBinary
    The DNWithBinary string format: B:Length:HexData:DN

.PARAMETER Raw
    If specified, returns the full parsed object with all fields.
    Default: Returns a compact display string.

.EXAMPLE
    ConvertFrom-KeyCredentialLink -KeyCredentialBytes $bytes
    Returns: "DeviceID: a1b2c3d4-... | Created: 2024-01-15 10:30:00 | Source: AD"

.EXAMPLE
    ConvertFrom-KeyCredentialLink -DNWithBinary "B:880:0002000001..." -Raw
    Returns the full PSCustomObject with all parsed fields.

.OUTPUTS
    String or PSCustomObject depending on -Raw switch.

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

function ConvertFrom-KeyCredentialLink {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false, ValueFromPipeline=$true)]
        [byte[]]$KeyCredentialBytes,

        [Parameter(Mandatory=$false)]
        [string]$DNWithBinary,

        [Parameter(Mandatory=$false)]
        [switch]$Raw
    )

    process {
        try {
            # Handle DNWithBinary format: B:Length:HexData:DN
            if ($DNWithBinary) {
                if ($DNWithBinary -match '^B:(\d+):([0-9A-Fa-f]+)(?::(.+))?$') {
                    $HexData = $Matches[2]
                    # Convert hex string to bytes
                    $KeyCredentialBytes = [byte[]]::new($HexData.Length / 2)
                    for ($i = 0; $i -lt $HexData.Length; $i += 2) {
                        $KeyCredentialBytes[$i / 2] = [Convert]::ToByte($HexData.Substring($i, 2), 16)
                    }
                } else {
                    if ($Raw) {
                        return [PSCustomObject]@{
                            Success = $false
                            Error = "Invalid DNWithBinary format"
                        }
                    }
                    return "[Invalid format]"
                }
            }

            if (-not $KeyCredentialBytes -or $KeyCredentialBytes.Length -lt 8) {
                if ($Raw) {
                    return [PSCustomObject]@{
                        Success = $false
                        Error = "Invalid or empty KeyCredentialLink data"
                    }
                }
                return "[Invalid data]"
            }

            # Parse Version (4 bytes, little-endian)
            $Version = [BitConverter]::ToUInt32($KeyCredentialBytes, 0)
            if ($Version -ne 0x00000200) {
                if ($Raw) {
                    return [PSCustomObject]@{
                        Success = $false
                        Error = "Unknown version: 0x$($Version.ToString('X8'))"
                        Version = $Version
                    }
                }
                return "[Unknown version: 0x$($Version.ToString('X8'))]"
            }

            # Initialize result object
            $Result = [PSCustomObject]@{
                Success = $true
                Version = 2
                KeyID = $null
                KeyIDHex = $null
                DeviceID = $null
                KeyCreationTime = $null
                KeyLastLogonTime = $null
                KeyUsage = $null
                KeyUsageText = $null
                KeySource = $null
                KeySourceText = $null
                KeyMaterialLength = 0
                CustomKeyInfo = $null
                RawBytes = $KeyCredentialBytes
                ByteLength = $KeyCredentialBytes.Length
            }

            # Parse LTV entries starting at offset 4
            # MS-ADTS 2.2.19: Each entry is Length (2 bytes) + Identifier (1 byte) + Data (variable)
            $Offset = 4
            while ($Offset + 3 -le $KeyCredentialBytes.Length) {
                # Length (2 bytes, little-endian) - length of Data field only
                $EntryLength = [BitConverter]::ToUInt16($KeyCredentialBytes, $Offset)
                $Offset += 2

                # Identifier/Type (1 byte)
                $EntryType = $KeyCredentialBytes[$Offset]
                $Offset += 1

                # Check bounds
                if ($Offset + $EntryLength -gt $KeyCredentialBytes.Length) {
                    break
                }

                # Extract entry data
                $EntryData = if ($EntryLength -gt 0) { $KeyCredentialBytes[$Offset..($Offset + $EntryLength - 1)] } else { @() }
                $Offset += $EntryLength

                # Parse based on entry type (1 byte identifier per MS-ADTS 2.2.19)
                switch ($EntryType) {
                    0x01 {  # KeyID (SHA256 hash of public key)
                        if ($EntryData.Length -ge 16) {
                            $Result.KeyIDHex = [BitConverter]::ToString($EntryData).Replace('-', '').ToLower()
                            $Result.KeyID = $Result.KeyIDHex.Substring(0, 16) + "..."
                        }
                    }
                    0x02 {  # KeyHash (SHA256 of entries 3-9)
                        # Not displayed, but parsed for completeness
                    }
                    0x03 {  # KeyMaterial (BCRYPT_RSAKEY_BLOB)
                        $Result.KeyMaterialLength = $EntryLength
                    }
                    0x04 {  # KeyUsage
                        if ($EntryData.Length -ge 1) {
                            $Result.KeyUsage = $EntryData[0]
                            $Result.KeyUsageText = switch ($EntryData[0]) {
                                0x01 { "NGC" }
                                0x02 { "FIDO" }
                                0x07 { "FEK" }
                                default { "0x$($EntryData[0].ToString('X2'))" }
                            }
                        }
                    }
                    0x05 {  # KeySource
                        if ($EntryData.Length -ge 1) {
                            $Result.KeySource = $EntryData[0]
                            $Result.KeySourceText = switch ($EntryData[0]) {
                                0x00 { "AD" }
                                0x01 { "AzureAD" }
                                default { "0x$($EntryData[0].ToString('X2'))" }
                            }
                        }
                    }
                    0x06 {  # DeviceId (GUID)
                        if ($EntryData.Length -eq 16) {
                            try {
                                # Must use New-Object constructor syntax for byte array to GUID conversion
                                # [GUID]$EntryData does NOT work - it silently fails
                                $Result.DeviceID = (New-Object GUID(,$EntryData)).ToString()
                            } catch {
                                $Result.DeviceID = [BitConverter]::ToString($EntryData).Replace('-', '').ToLower()
                            }
                        }
                    }
                    0x07 {  # CustomKeyInformation
                        $Result.CustomKeyInfo = [BitConverter]::ToString($EntryData).Replace('-', '').ToLower()
                    }
                    0x08 {  # KeyApproximateLastLogonTimeStamp (FILETIME)
                        if ($EntryData.Length -eq 8) {
                            try {
                                $FileTime = [BitConverter]::ToInt64($EntryData, 0)
                                if ($FileTime -gt 0) {
                                    $Result.KeyLastLogonTime = [DateTime]::FromFileTimeUtc($FileTime)
                                }
                            } catch { }
                        }
                    }
                    0x09 {  # KeyCreationTime (FILETIME)
                        if ($EntryData.Length -eq 8) {
                            try {
                                $FileTime = [BitConverter]::ToInt64($EntryData, 0)
                                if ($FileTime -gt 0) {
                                    $Result.KeyCreationTime = [DateTime]::FromFileTimeUtc($FileTime)
                                }
                            } catch { }
                        }
                    }
                }
            }

            # Return based on mode
            if ($Raw) {
                return $Result
            }

            # Build compact display string: Full DeviceID + CreationTime
            # Source (AD) and Usage (NGC) are omitted as they're almost always the same for Shadow Credentials
            $Parts = @()

            if ($Result.DeviceID) {
                # Show FULL DeviceID (needed for -RemoveDeviceID parameter)
                $Parts += "DeviceID: $($Result.DeviceID)"
            }

            if ($Result.KeyCreationTime) {
                $Parts += "Created: $($Result.KeyCreationTime.ToString('yyyy-MM-dd HH:mm'))"
            }

            if ($Parts.Count -gt 0) {
                return $Parts -join " | "
            }

            return "KeyCredential ($($KeyCredentialBytes.Length) bytes)"

        } catch {
            if ($Raw) {
                return [PSCustomObject]@{
                    Success = $false
                    Error = $_.Exception.Message
                }
            }
            return "[Parse error: $($_.Exception.Message)]"
        }
    }
}
