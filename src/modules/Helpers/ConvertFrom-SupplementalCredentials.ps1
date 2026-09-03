<#
.SYNOPSIS
    Parses USER_PROPERTIES structure from supplementalCredentials attribute.

.DESCRIPTION
    Parses the supplementalCredentials attribute (Layer 3 decryption after DRSUAPI + RID-DES).
    Extracts Kerberos keys (AES256/AES128/DES), cleartext password, and WDigest hashes.

    Structure (from MS-SAMR):
    USER_PROPERTIES:
      Reserved1     : 4 bytes (0x00000000)
      Length        : 4 bytes
      Reserved2     : 2 bytes
      Reserved3     : 2 bytes
      Reserved4     : 96 bytes
      PropertySignature : 2 bytes (0x0050 = 'P')
      PropertyCount : 2 bytes
      UserProperties: variable (array of USER_PROPERTY)

    USER_PROPERTY:
      NameLength    : 2 bytes
      ValueLength   : 2 bytes
      Reserved      : 2 bytes
      PropertyName  : NameLength bytes (UTF-16LE)
      PropertyValue : ValueLength bytes (hex-encoded ASCII!)

.PARAMETER Data
    Raw supplementalCredentials bytes (after DRSUAPI + RID-DES decryption).

.OUTPUTS
    PSCustomObject with properties:
    - AES256Key (string, hex)
    - AES128Key (string, hex)
    - DESKey (string, hex)
    - KerberosSalt (string)
    - CleartextPassword (string, if available)
    - WDigestHashes (array of strings)

.EXAMPLE
    $suppCreds = ConvertFrom-SupplementalCredentials -Data $userData.SupplementalCredentials
    Write-Host "AES256: $($suppCreds.AES256Key)"

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

function ConvertFrom-SupplementalCredentials {
    [CmdletBinding()]
    param(
        # AllowNull/AllowEmptyCollection because the guard below is meant to answer for
        # both. Without them the parameter binder throws first, so a caller handed an
        # empty supplementalCredentials value gets a terminating error where the rest of
        # this function's contract is to return $null.
        [Parameter(Mandatory=$true)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [byte[]]$Data
    )

    process {
        try {
            if (-not $Data -or $Data.Length -lt 110) {
                Write-Log "[ConvertFrom-SupplementalCredentials] Data too small or empty"
                return $null
            }

            # Read USER_PROPERTIES header
            $offset = 0

            # Reserved1 (4 bytes) - skip
            $offset += 4

            # Length (4 bytes)
            $length = [BitConverter]::ToUInt32($Data, $offset)
            $offset += 4

            # Reserved2 + Reserved3 + Reserved4 (2 + 2 + 96 = 100 bytes) - skip
            $offset += 100

            # PropertySignature (2 bytes) - should be 0x0050 ('P')
            $signature = [BitConverter]::ToUInt16($Data, $offset)
            $offset += 2

            if ($signature -ne 0x0050) {
                Write-Log "[ConvertFrom-SupplementalCredentials] Invalid PropertySignature: 0x$($signature.ToString('X4')) (expected 0x0050)"
                return $null
            }

            # PropertyCount (2 bytes)
            # A blob can end right after the signature - MS-SAMR notes that PropertyCount
            # is absent when there are no properties. Without this test the read below
            # throws and the caller is told the whole attribute failed to parse.
            if ($offset + 2 -gt $Data.Length) {
                Write-Log "[ConvertFrom-SupplementalCredentials] No PropertyCount present - structure carries no properties"
                return $null
            }

            $propertyCount = [BitConverter]::ToUInt16($Data, $offset)
            $offset += 2

            Write-Log "[ConvertFrom-SupplementalCredentials] PropertyCount: $propertyCount"

            # Parse USER_PROPERTY entries
            $properties = @{}

            for ($i = 0; $i -lt $propertyCount; $i++) {
                if ($offset + 6 -gt $Data.Length) {
                    Write-Log "[ConvertFrom-SupplementalCredentials] Incomplete property header at offset $offset"
                    break
                }

                # NameLength (2 bytes)
                $nameLength = [BitConverter]::ToUInt16($Data, $offset)
                $offset += 2

                # ValueLength (2 bytes)
                $valueLength = [BitConverter]::ToUInt16($Data, $offset)
                $offset += 2

                # Reserved (2 bytes) - skip
                $offset += 2

                # PropertyName (UTF-16LE)
                if ($offset + $nameLength -gt $Data.Length) {
                    Write-Log "[ConvertFrom-SupplementalCredentials] Incomplete property name at offset $offset"
                    break
                }

                $propertyName = [System.Text.Encoding]::Unicode.GetString($Data, $offset, $nameLength)
                $offset += $nameLength

                # PropertyValue (hex-encoded ASCII!)
                if ($offset + $valueLength -gt $Data.Length) {
                    Write-Log "[ConvertFrom-SupplementalCredentials] Incomplete property value at offset $offset"
                    break
                }

                $propertyValueHex = [System.Text.Encoding]::ASCII.GetString($Data, $offset, $valueLength)
                $offset += $valueLength

                # Convert hex string to bytes
                # Validate hex string length is even
                if ($propertyValueHex.Length % 2 -ne 0) {
                    Write-Log "[ConvertFrom-SupplementalCredentials] Invalid hex string length for '$propertyName' (must be even): $($propertyValueHex.Length)"
                    continue
                }

                # Typed array rather than the output of a for loop. The loop form yields
                # nothing at all for a zero-length value, so the property was stored as
                # $null - and the consumers below then threw on it, which the outer catch
                # turned into "the whole attribute failed to parse". One empty property
                # was enough to throw away the Kerberos keys next to it.
                try {
                    $propertyValueBytes = New-Object byte[] ($propertyValueHex.Length / 2)
                    for ($j = 0; $j -lt $propertyValueHex.Length; $j += 2) {
                        $propertyValueBytes[$j / 2] = [Convert]::ToByte($propertyValueHex.Substring($j, 2), 16)
                    }
                }
                catch {
                    Write-Log "[ConvertFrom-SupplementalCredentials] Failed to parse property value for '$propertyName': $($_.Exception.Message)"
                    continue
                }

                $properties[$propertyName] = $propertyValueBytes
                Write-Log "[ConvertFrom-SupplementalCredentials] Property: $propertyName (ValueLength: $valueLength bytes)"
            }

            # Extract Kerberos keys from Primary:Kerberos-Newer-Keys
            $aes256Key = $null
            $aes128Key = $null
            $desKey = $null
            $kerberosSalt = $null

            if ($properties.ContainsKey('Primary:Kerberos-Newer-Keys')) {
                $kerberosData = $properties['Primary:Kerberos-Newer-Keys']
                Write-Log "[ConvertFrom-SupplementalCredentials] Parsing Primary:Kerberos-Newer-Keys ($($kerberosData.Length) bytes)"
                $result = Parse-KerberosNewerKeys -Data $kerberosData
                if ($result) {
                    $aes256Key = $result.AES256Key
                    $aes128Key = $result.AES128Key
                    if ($result.DESKey) { $desKey = $result.DESKey }
                    $kerberosSalt = $result.Salt
                    Write-Log "[ConvertFrom-SupplementalCredentials] Extracted AES256: $($null -ne $aes256Key), AES128: $($null -ne $aes128Key), DES: $($null -ne $desKey), Salt: $kerberosSalt"
                } else {
                    Write-Log "[ConvertFrom-SupplementalCredentials] Parse-KerberosNewerKeys returned null"
                }
            }

            # Extract DES key from Primary:Kerberos (old format) - fallback if not in Newer-Keys
            if (-not $desKey -and $properties.ContainsKey('Primary:Kerberos')) {
                $kerberosData = $properties['Primary:Kerberos']
                $desKeyFromOld = Parse-KerberosKeys -Data $kerberosData
                if ($desKeyFromOld) { $desKey = $desKeyFromOld }
            }

            # Extract cleartext password
            $cleartextPassword = $null
            if ($properties.ContainsKey('Primary:CLEARTEXT')) {
                $cleartextData = [byte[]]$properties['Primary:CLEARTEXT']
                if ($cleartextData.Length -gt 0) {
                    $cleartextPassword = [System.Text.Encoding]::Unicode.GetString($cleartextData)
                }
            }

            # Extract WDigest hashes
            # @(...) around the call because Parse-WDigestHashes returns a bare string
            # when exactly one hash is set and nothing at all when none is - the
            # documented output is an array, and indexing a string yields characters.
            $wdigestHashes = @()
            if ($properties.ContainsKey('Primary:WDigest')) {
                $wdigestData = $properties['Primary:WDigest']
                $wdigestHashes = @(Parse-WDigestHashes -Data $wdigestData)
            }

            # Return parsed credentials
            return [PSCustomObject]@{
                AES256Key = $aes256Key
                AES128Key = $aes128Key
                DESKey = $desKey
                KerberosSalt = $kerberosSalt
                CleartextPassword = $cleartextPassword
                WDigestHashes = $wdigestHashes
            }
        }
        catch {
            Write-Log "[ConvertFrom-SupplementalCredentials] Failed to parse supplementalCredentials: $($_.Exception.Message)"
            return $null
        }
    }
}

<#
.SYNOPSIS
Reads KeyLength bytes at KeyOffset out of a KERB_STORED_CREDENTIAL blob.

.DESCRIPTION
Internal helper. Both key parsers used to slice with $Data[$keyOffset..($keyOffset +
$keyLength - 1)], which has two problems.

A range index returns Object[] rather than byte[], and a KeyLength of 0 makes the range
count backwards: PowerShell reads 5..4 as @(5, 4), so a key that is declared empty came
back as two bytes in reverse order and was reported as a real key. The bounds check in
front of it does not catch that, because offset + 0 is always within the blob.

Returns an empty byte[] when the entry does not describe a readable key, which is what
the callers test for.
#>
function Get-KeyBytesAt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Data,

        [Parameter(Mandatory = $true)]
        [uint32]$KeyOffset,

        [Parameter(Mandatory = $true)]
        [uint32]$KeyLength
    )

    $empty = New-Object byte[] 0

    if ($KeyLength -eq 0) { return ,$empty }
    if ($KeyOffset -ge $Data.Length) { return ,$empty }
    if (([long]$KeyOffset + [long]$KeyLength) -gt $Data.Length) { return ,$empty }

    $keyBytes = New-Object byte[] $KeyLength
    [Array]::Copy($Data, $KeyOffset, $keyBytes, 0, $KeyLength)
    return ,$keyBytes
}

# Helper function to parse KERB_STORED_CREDENTIAL_NEW
function Parse-KerberosNewerKeys {
    [CmdletBinding()]
    param([byte[]]$Data)

    try {
        if ($Data.Length -lt 20) { return $null }

        $offset = 0

        # Revision (2 bytes) - should be 3 or 4
        $revision = [BitConverter]::ToUInt16($Data, $offset)
        $offset += 2

        # Flags (2 bytes)
        $flags = [BitConverter]::ToUInt16($Data, $offset)
        $offset += 2

        # CredentialCount (2 bytes)
        $credentialCount = [BitConverter]::ToUInt16($Data, $offset)
        $offset += 2

        # ServiceCredentialCount (2 bytes)
        $serviceCredentialCount = [BitConverter]::ToUInt16($Data, $offset)
        $offset += 2

        # OldCredentialCount (2 bytes)
        $oldCredentialCount = [BitConverter]::ToUInt16($Data, $offset)
        $offset += 2

        # OlderCredentialCount (2 bytes)
        $olderCredentialCount = [BitConverter]::ToUInt16($Data, $offset)
        $offset += 2

        # DefaultSaltLength (2 bytes)
        $defaultSaltLength = [BitConverter]::ToUInt16($Data, $offset)
        $offset += 2

        # DefaultSaltMaximumLength (2 bytes) - skip
        $offset += 2

        # DefaultSaltOffset (4 bytes)
        $defaultSaltOffset = [BitConverter]::ToUInt32($Data, $offset)
        $offset += 4

        # Extract salt
        $salt = $null
        if ($defaultSaltLength -gt 0 -and $defaultSaltOffset -lt $Data.Length -and ($defaultSaltOffset + $defaultSaltLength) -le $Data.Length) {
            $salt = [System.Text.Encoding]::Unicode.GetString($Data, $defaultSaltOffset, $defaultSaltLength)
        }

        # Parse KERB_KEY_DATA_NEW entries
        $aes256Key = $null
        $aes128Key = $null
        $desKey = $null

        Write-Verbose "[Parse-KerberosNewerKeys] Parsing $credentialCount credential entries starting at offset $offset"

        for ($i = 0; $i -lt $credentialCount; $i++) {

            # First entry is 28 bytes (with extra Reserved4), subsequent entries are 24 bytes
            $entrySize = if ($i -eq 0) { 28 } else { 24 }

            if ($offset + $entrySize -gt $Data.Length) {
                Write-Verbose "[Parse-KerberosNewerKeys] Entry ${i}: Insufficient data at offset $offset"
                break
            }

            # KERB_KEY_DATA_NEW structure
            # Reserved1 (2 bytes)
            $offset += 2
            # Reserved2 (2 bytes)
            $offset += 2
            # Reserved3 (4 bytes)
            $offset += 4

            # Reserved4 (4 bytes) - ONLY in first entry for Revision 4
            if ($i -eq 0) {
                $offset += 4
            }

            # IterationCount (4 bytes) - PBKDF2 iterations
            $offset += 4
            # KeyType (4 bytes) - Encryption type (17=AES128, 18=AES256, 3=DES)
            $keyType = [BitConverter]::ToUInt32($Data, $offset)
            $offset += 4
            # KeyLength (4 bytes) - Key size in bytes
            $keyLength = [BitConverter]::ToUInt32($Data, $offset)
            $offset += 4
            # KeyOffset (4 bytes) - Offset from start of KERB_STORED_CREDENTIAL_NEW
            $keyOffset = [BitConverter]::ToUInt32($Data, $offset)
            $offset += 4

            Write-Verbose "[Parse-KerberosNewerKeys] Entry ${i}: KeyType=${keyType}, KeyLength=${keyLength}, KeyOffset=${keyOffset}"

            # Extract key
            $keyBytes = Get-KeyBytesAt -Data $Data -KeyOffset $keyOffset -KeyLength $keyLength
            if ($keyBytes.Length -gt 0) {
                $keyHex = ($keyBytes | ForEach-Object { $_.ToString('x2') }) -join ''

                # Map KeyType to encryption type
                switch ($keyType) {
                    18 {
                        $aes256Key = $keyHex
                        $keySize = $keyHex.Length / 2
                        Write-Verbose "[Parse-KerberosNewerKeys] Entry ${i}: Extracted AES256 key ($keySize bytes)"
                    }
                    17 {
                        $aes128Key = $keyHex
                        $keySize = $keyHex.Length / 2
                        Write-Verbose "[Parse-KerberosNewerKeys] Entry ${i}: Extracted AES128 key ($keySize bytes)"
                    }
                    3 {
                        $desKey = $keyHex
                        $keySize = $keyHex.Length / 2
                        Write-Verbose "[Parse-KerberosNewerKeys] Entry ${i}: Extracted DES key ($keySize bytes)"
                    }
                    default {
                        Write-Verbose "[Parse-KerberosNewerKeys] Entry ${i}: Skipped KeyType $keyType"
                    }
                }
            } else {
                Write-Verbose "[Parse-KerberosNewerKeys] Entry ${i}: no usable key (offset=${keyOffset}, length=${keyLength}, dataSize=$($Data.Length))"
            }
        }

        return [PSCustomObject]@{
            AES256Key = $aes256Key
            AES128Key = $aes128Key
            DESKey = $desKey
            Salt = $salt
        }
    }
    catch {
        Write-Log "[Parse-KerberosNewerKeys] Failed: $($_.Exception.Message)"
        return $null
    }
}

# Helper function to parse Primary:Kerberos (DES key)
function Parse-KerberosKeys {
    [CmdletBinding()]
    param([byte[]]$Data)

    try {
        # Primary:Kerberos is KERB_STORED_CREDENTIAL (MS-SAMR 2.2.10.5), which is NOT the
        # structure Primary:Kerberos-Newer-Keys uses. This function used to read it with
        # the new format's layout and therefore never returned a key at all.
        #
        # KERB_STORED_CREDENTIAL header, 16 bytes:
        #   Revision (2) Flags (2) CredentialCount (2) OldCredentialCount (2)
        #   DefaultSaltLength (2) DefaultSaltMaximumLength (2) DefaultSaltOffset (4)
        # The new format has ServiceCredentialCount, OlderCredentialCount and
        # DefaultIterationCount on top of that - 24 bytes.
        #
        # KERB_KEY_DATA entry (MS-SAMR 2.2.10.4), 20 bytes:
        #   Reserved1 (2) Reserved2 (2) Reserved3 (4) KeyType (4) KeyLength (4) KeyOffset (4)
        # The new format's entry carries an IterationCount before KeyType - 24 bytes.
        #
        # Reading a 16-byte header as 20 and a 20-byte entry as 24 put every field eight
        # bytes past where it lives: KeyType landed on KeyLength, so the KeyType 3 test
        # never matched and the DES fallback silently produced nothing.
        $headerLength = 16
        $entryLength = 20

        if ($Data.Length -lt $headerLength) { return $null }

        $offset = 0
        $offset += 2  # Revision
        $offset += 2  # Flags
        $credentialCount = [BitConverter]::ToUInt16($Data, $offset)
        $offset += 2
        $offset += 2  # OldCredentialCount
        $offset += 2  # DefaultSaltLength
        $offset += 2  # DefaultSaltMaximumLength
        $offset += 4  # DefaultSaltOffset

        for ($i = 0; $i -lt $credentialCount; $i++) {
            if ($offset + $entryLength -gt $Data.Length) { break }

            $offset += 8  # Reserved1 + Reserved2 + Reserved3
            $keyType = [BitConverter]::ToUInt32($Data, $offset)
            $offset += 4
            $keyLength = [BitConverter]::ToUInt32($Data, $offset)
            $offset += 4
            $keyOffset = [BitConverter]::ToUInt32($Data, $offset)
            $offset += 4

            if ($keyType -eq 3) {  # DES-CBC-MD5
                $keyBytes = Get-KeyBytesAt -Data $Data -KeyOffset $keyOffset -KeyLength $keyLength
                if ($keyBytes.Length -gt 0) {
                    return ($keyBytes | ForEach-Object { $_.ToString('x2') }) -join ''
                }
            }
        }

        return $null
    }
    catch {
        Write-Log "[Parse-KerberosKeys] Failed: $($_.Exception.Message)"
        return $null
    }
}

# Helper function to parse WDigest hashes
function Parse-WDigestHashes {
    [CmdletBinding()]
    param([byte[]]$Data)

    try {
        # WDigest structure:
        # Offset 0-3:   Reserved1(1) + Reserved2(1) + Version(1) + NumberOfHashes(1)
        # Offset 4-15:  Reserved3 (12 bytes)
        # Offset 16+:   29 x MD5 hashes (16 bytes each)

        if ($Data.Length -lt (16 + 29 * 16)) {
            Write-Log "[Parse-WDigestHashes] Data too small: $($Data.Length) bytes"
            return @()
        }

        $hashes = @()
        $offset = 16  # Skip 16-byte header (not 8!)

        for ($i = 1; $i -le 29; $i++) {
            if ($offset + 16 -gt $Data.Length) { break }

            $hashBytes = $Data[$offset..($offset + 15)]
            $hashHex = ($hashBytes | ForEach-Object { $_.ToString('x2') }) -join ''

            # Only include non-zero hashes
            if ($hashHex -ne '00000000000000000000000000000000') {
                $hashes += "${i}: $hashHex"
            }

            $offset += 16
        }

        return $hashes
    }
    catch {
        Write-Log "[Parse-WDigestHashes] Failed: $($_.Exception.Message)"
        return @()
    }
}
