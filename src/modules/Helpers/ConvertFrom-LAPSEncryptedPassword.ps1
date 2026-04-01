function ConvertFrom-LAPSEncryptedPassword {
    <#
    .SYNOPSIS
    Parses and optionally decrypts the msLAPS-EncryptedPassword attribute from Windows LAPS v2.

    .DESCRIPTION
    Decodes the LAPS encrypted password structure which uses DPAPI-NG (CNG DPAPI) protection.

    The function can:
    1. Parse metadata (always works):
       - Password update timestamp (from header)
       - Encryption algorithm info
       - Target SID (who is authorized to decrypt)

    2. Decrypt the password (only if authorized):
       - Calls NCryptUnprotectSecret Windows API
       - DC validates if caller is member of authorized group
       - Returns cleartext password and account name

    The encrypted blob structure:
    - 16-byte header: Timestamp (8) + EncryptedSize (4) + Flags (4)
    - Body: CMS EnvelopedData (DPAPI-NG protected)
    - JSON format after decryption: {"n":"AccountName","t":"HexTimestamp","p":"Password"}

    .PARAMETER Blob
    The raw byte array from the msLAPS-EncryptedPassword attribute.

    .PARAMETER Decrypt
    If specified, attempts to decrypt the password using the Windows CNG API.
    This requires the caller to be a member of an authorized group.

    .EXAMPLE
    # Parse metadata only (no decryption)
    $computer = Get-DomainComputer -Identity "WS001" -Properties msLAPS-EncryptedPassword
    $lapsInfo = ConvertFrom-LAPSEncryptedPassword -Blob $computer.'msLAPS-EncryptedPassword'
    $lapsInfo.UpdateTimestamp
    $lapsInfo.TargetSID

    .EXAMPLE
    # Decrypt password (requires authorization)
    $computer = Get-DomainComputer -Identity "WS001" -Properties msLAPS-EncryptedPassword
    $lapsInfo = ConvertFrom-LAPSEncryptedPassword -Blob $computer.'msLAPS-EncryptedPassword' -Decrypt
    $lapsInfo.Password
    $lapsInfo.Account

    .NOTES
    Author: Alexander Sturz (@_61106960_)
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [byte[]]$Blob,

        [Parameter(Mandatory = $false)]
        [switch]$Decrypt
    )

    begin {
        # LAPS v2 Encrypted Password blob structure (Windows LAPS):
        # The blob has a 16-byte header followed by CMS EnvelopedData
        #
        # Header (16 bytes):
        #   - Bytes 0-7:  Timestamp (FILETIME, Little-Endian) - Password update time
        #   - Bytes 8-11: Encrypted data length (DWORD, Little-Endian)
        #   - Bytes 12-15: Flags/Reserved (DWORD)
        #
        # Body: CMS EnvelopedData (DPAPI-NG protected)
        # JSON format after decryption: {"n":"AccountName","t":"HexTimestamp","p":"Password"}

        $HeaderSize = 16
    }

    process {
        try {
            # Validate input
            if ($null -eq $Blob) {
                Write-Log "[ConvertFrom-LAPSEncryptedPassword] Blob is null"
                return $null
            }

            if ($Blob.Length -lt 20) {
                Write-Log "[ConvertFrom-LAPSEncryptedPassword] Blob too short (min 20 bytes, got $($Blob.Length))"
                return $null
            }

            Write-Log "[ConvertFrom-LAPSEncryptedPassword] Blob size: $($Blob.Length) bytes, first bytes: $($Blob[0..15] -join ',')"

            # Check if blob starts with ASN.1 SEQUENCE (0x30) - no header
            # Or if it has a 16-byte header before CMS data
            $encryptedData = $null
            $updateTimestamp = $null

            if ($Blob[0] -eq 0x30) {
                # Raw CMS EnvelopedData without header
                Write-Log "[ConvertFrom-LAPSEncryptedPassword] Blob starts with ASN.1 SEQUENCE - no header"
                $encryptedData = $Blob
            } else {
                # Has 16-byte header - parse it
                Write-Log "[ConvertFrom-LAPSEncryptedPassword] Parsing 16-byte header"

                # Extract timestamp from header (bytes 0-7)
                # LAPS v2 uses Big-Endian format for FILETIME:
                #   Bytes 0-3: High DWORD (Big-Endian stored as Little-Endian DWORD)
                #   Bytes 4-7: Low DWORD (Big-Endian stored as Little-Endian DWORD)
                # Reconstruct: (HighDWORD << 32) | LowDWORD
                try {
                    $highDword = [BitConverter]::ToUInt32($Blob, 0)
                    $lowDword = [BitConverter]::ToUInt32($Blob, 4)
                    $fileTime = ([Int64]$highDword -shl 32) -bor [Int64]$lowDword

                    # Validate FILETIME is reasonable (between year 2000 and 2100)
                    $minFileTime = 125911584000000000  # 2000-01-01
                    $maxFileTime = 157766880000000000  # 2100-01-01

                    if ($fileTime -gt $minFileTime -and $fileTime -lt $maxFileTime) {
                        $updateTimestamp = [DateTime]::FromFileTimeUtc($fileTime)
                        Write-Log "[ConvertFrom-LAPSEncryptedPassword] Header timestamp: $updateTimestamp"
                    } else {
                        Write-Log "[ConvertFrom-LAPSEncryptedPassword] Header timestamp out of valid range: $fileTime (raw bytes: $($Blob[0..7] -join ','))"
                    }
                } catch {
                    Write-Log "[ConvertFrom-LAPSEncryptedPassword] Failed to parse header timestamp: $_"
                }

                # Extract encrypted size from header (bytes 8-11)
                $encryptedSize = [BitConverter]::ToUInt32($Blob, 8)
                Write-Log "[ConvertFrom-LAPSEncryptedPassword] Header encrypted size: $encryptedSize"

                # Extract flags (bytes 12-15)
                $flags = [BitConverter]::ToUInt32($Blob, 12)
                Write-Log "[ConvertFrom-LAPSEncryptedPassword] Header flags: 0x$($flags.ToString('X8'))"

                # Extract CMS data after header
                if ($Blob.Length -ge $HeaderSize + $encryptedSize) {
                    $encryptedData = New-Object byte[] $encryptedSize
                    [Array]::Copy($Blob, $HeaderSize, $encryptedData, 0, $encryptedSize)
                    Write-Log "[ConvertFrom-LAPSEncryptedPassword] Extracted CMS data: $($encryptedData.Length) bytes, starts with: 0x$($encryptedData[0].ToString('X2'))"
                } else {
                    # Encrypted size doesn't match - try using remaining bytes
                    $remainingSize = $Blob.Length - $HeaderSize
                    Write-Log "[ConvertFrom-LAPSEncryptedPassword] Size mismatch (header says $encryptedSize, have $remainingSize), using remaining bytes"
                    $encryptedData = New-Object byte[] $remainingSize
                    [Array]::Copy($Blob, $HeaderSize, $encryptedData, 0, $remainingSize)
                }
            }

            # Parse CMS structure to extract metadata (Target SID, algorithms)
            $targetSID = $null
            $contentEncryptionAlgorithm = $null
            $keyEncryptionAlgorithm = $null

            try {
                $cmsInfo = Parse-CMSEnvelopedData -Data $encryptedData
                if ($cmsInfo) {
                    $targetSID = $cmsInfo.TargetSID
                    $contentEncryptionAlgorithm = $cmsInfo.ContentEncryptionAlgorithm
                    $keyEncryptionAlgorithm = $cmsInfo.KeyEncryptionAlgorithm
                }
            } catch {
                Write-Log "[ConvertFrom-LAPSEncryptedPassword] Failed to parse CMS structure: $_"
            }

            # Resolve Target SID to name
            $targetSIDName = $null
            if ($targetSID) {
                try {
                    $targetSIDName = ConvertFrom-SID -SID $targetSID
                } catch {
                    $targetSIDName = $targetSID
                }
            }

            # Build result object with metadata
            $result = [PSCustomObject]@{
                UpdateTimestamp            = $updateTimestamp
                EncryptedSize              = if ($encryptedData) { $encryptedData.Length } else { $Blob.Length }
                TargetSID                  = $targetSID
                TargetSIDName              = $targetSIDName
                ContentEncryptionAlgorithm = $contentEncryptionAlgorithm
                KeyEncryptionAlgorithm     = $keyEncryptionAlgorithm
                Password                   = $null
                Account                    = $null
                DecryptionSucceeded        = $false
                DecryptionError            = $null
            }

            # Attempt decryption if requested
            if ($Decrypt) {
                Write-Log "[ConvertFrom-LAPSEncryptedPassword] Attempting decryption via NCryptUnprotectSecret"

                try {
                    # LAPS v2 encrypted blob should be passed directly to NCryptUnprotectSecret
                    # The API handles the DPAPI-NG/CMS format internally
                    # Try full blob first (most common), then CMS-only as fallback
                    $decryptedData = $null

                    try {
                        Write-Log "[ConvertFrom-LAPSEncryptedPassword] Trying full blob ($($Blob.Length) bytes)"
                        $decryptedData = Invoke-NCryptUnprotectSecret -ProtectedBlob $Blob
                    } catch {
                        $fullError = $_.Exception.Message
                        Write-Log "[ConvertFrom-LAPSEncryptedPassword] Full blob failed: $fullError"

                        # If full blob fails, try CMS-only (without header)
                        if ($encryptedData -and $encryptedData.Length -ne $Blob.Length) {
                            try {
                                Write-Log "[ConvertFrom-LAPSEncryptedPassword] Trying CMS-only ($($encryptedData.Length) bytes)"
                                $decryptedData = Invoke-NCryptUnprotectSecret -ProtectedBlob $encryptedData
                            } catch {
                                # Both failed - rethrow the original error
                                throw $fullError
                            }
                        } else {
                            throw
                        }
                    }

                    if ($decryptedData -and $decryptedData.Length -gt 0) {
                        # Parse the decrypted LAPS password structure (JSON format in UTF-16LE)
                        $jsonString = [System.Text.Encoding]::Unicode.GetString($decryptedData)

                        # Remove null terminator if present
                        $jsonString = $jsonString.TrimEnd([char]0)

                        Write-Log "[ConvertFrom-LAPSEncryptedPassword] Decrypted data length: $($decryptedData.Length), JSON length: $($jsonString.Length)"

                        if ($jsonString.StartsWith('{')) {
                            try {
                                $lapsData = $jsonString | ConvertFrom-Json

                                # Validate expected JSON properties exist
                                if ($null -ne $lapsData.p) {
                                    $result.Password = $lapsData.p
                                    $result.Account = $lapsData.n
                                    $result.DecryptionSucceeded = $true

                                    # Parse timestamp from JSON "t" property (hex FILETIME string)
                                    if ($lapsData.t) {
                                        try {
                                            $fileTime = [Convert]::ToInt64($lapsData.t, 16)
                                            $result.UpdateTimestamp = [DateTime]::FromFileTimeUtc($fileTime)
                                        } catch {
                                            Write-Log "[ConvertFrom-LAPSEncryptedPassword] Failed to parse timestamp: $($lapsData.t)"
                                        }
                                    }

                                    Write-Log "[ConvertFrom-LAPSEncryptedPassword] Successfully decrypted password for account: $($lapsData.n)"
                                } else {
                                    Write-Log "[ConvertFrom-LAPSEncryptedPassword] JSON missing 'p' (password) property"
                                    $result.DecryptionError = "JSON structure invalid - missing 'p' property"
                                }
                            } catch {
                                Write-Log "[ConvertFrom-LAPSEncryptedPassword] Failed to parse JSON: $_"
                                $result.DecryptionError = "JSON parse error: $_"
                            }
                        } else {
                            # Might be plain password without JSON wrapper
                            $result.Password = $jsonString
                            $result.DecryptionSucceeded = $true
                        }
                    } else {
                        $result.DecryptionError = "NCryptUnprotectSecret returned empty data"
                    }
                } catch {
                    $errorMessage = $_.Exception.Message
                    Write-Log "[ConvertFrom-LAPSEncryptedPassword] Decryption failed: $errorMessage"
                    $result.DecryptionError = $errorMessage

                    # Check for common error codes and provide meaningful messages
                    if ($errorMessage -match "0x8009310B") {
                        # NTE_NOT_SUPPORTED - typically means non-domain-joined system
                        $result.DecryptionError = "DPAPI-NG not supported - requires domain-joined system for LAPS v2 encrypted password decryption"
                    } elseif ($errorMessage -match "0x8009002C") {
                        # NTE_INTERNAL_ERROR - CMS format issue
                        $result.DecryptionError = "CMS format error - encrypted blob may be corrupted or incompatible"
                    } elseif ($errorMessage -match "0x80090034" -or $errorMessage -match "NTE_DECRYPTION_FAILURE") {
                        $result.DecryptionError = "Access denied - current user is not authorized to decrypt this password"
                    } elseif ($errorMessage -match "0x80070005" -or $errorMessage -match "ACCESS_DENIED") {
                        $result.DecryptionError = "Access denied - not a member of authorized group ($targetSIDName)"
                    }
                }
            }

            return $result

        } catch {
            Write-Log "[ConvertFrom-LAPSEncryptedPassword] Error: $_"
            return $null
        }
    }
}


function Parse-CMSEnvelopedData {
    <#
    .SYNOPSIS
    Parses a CMS EnvelopedData structure to extract DPAPI-NG metadata.
    Internal helper function.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Data
    )

    # This is a simplified ASN.1 parser for CMS EnvelopedData
    # Full parsing would require a proper ASN.1 library

    $result = @{
        TargetSID = $null
        ContentEncryptionAlgorithm = $null
        KeyEncryptionAlgorithm = $null
    }

    try {
        # Look for SID pattern in the data (S-1-5-21-...)
        # SIDs in DPAPI-NG are stored in binary format
        # Domain SIDs have format: S-1-5-21-<DomainID1>-<DomainID2>-<DomainID3>-<RID>
        # That's 4 sub-authorities after the "21" (which is the first sub-authority)

        # Search for SID header: 0x01 (revision) followed by sub-authority count
        for ($i = 0; $i -lt $Data.Length - 8; $i++) {
            # Check for SID revision 1 and reasonable sub-authority count (4-5 for domain SIDs)
            # Domain SID without RID = 4, with RID = 5
            if ($Data[$i] -eq 0x01 -and $Data[$i + 1] -ge 4 -and $Data[$i + 1] -le 6) {
                $subAuthCount = $Data[$i + 1]

                # Check bounds before accessing authority bytes
                if ($i + 8 + ($subAuthCount * 4) -gt $Data.Length) {
                    continue
                }

                # Check for NT Authority (0x00 0x00 0x00 0x00 0x00 0x05) at offset +2
                if ($Data[$i + 2] -eq 0 -and $Data[$i + 3] -eq 0 -and
                    $Data[$i + 4] -eq 0 -and $Data[$i + 5] -eq 0 -and
                    $Data[$i + 6] -eq 0 -and $Data[$i + 7] -eq 5) {

                    # Extract sub-authorities (each is 4 bytes, Little-Endian)
                    $subAuths = @()
                    for ($j = 0; $j -lt $subAuthCount; $j++) {
                        $offset = $i + 8 + ($j * 4)
                        $subAuth = [BitConverter]::ToUInt32($Data, $offset)
                        $subAuths += $subAuth
                    }

                    # Build SID string
                    $sidString = "S-1-5-" + ($subAuths -join '-')

                    # Validate it looks like a domain SID (S-1-5-21-<3 domain parts>[-RID])
                    # Domain SIDs: S-1-5-21-xxxxxxx-xxxxxxx-xxxxxxx or S-1-5-21-xxxxxxx-xxxxxxx-xxxxxxx-RID
                    if ($sidString -match '^S-1-5-21-\d+-\d+-\d+(-\d+)?$') {
                        $result.TargetSID = $sidString
                        Write-Log "[Parse-CMSEnvelopedData] Found Target SID: $sidString"
                        break
                    }
                }
            }
        }

        # Look for OID patterns for algorithm identification
        # AES-256-GCM OID: 2.16.840.1.101.3.4.1.46
        $aes256GcmOid = @(0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2E)
        if (Find-BytePattern -Data $Data -Pattern $aes256GcmOid) {
            $result.ContentEncryptionAlgorithm = "AES-256-GCM (2.16.840.1.101.3.4.1.46)"
        }

    } catch {
        Write-Log "[Parse-CMSEnvelopedData] Error parsing CMS: $_"
    }

    return $result
}


function Find-BytePattern {
    <#
    .SYNOPSIS
    Searches for a byte pattern in a byte array.
    Internal helper function.
    #>
    [CmdletBinding()]
    param(
        [byte[]]$Data,
        [byte[]]$Pattern
    )

    # Validate inputs
    if ($null -eq $Data -or $null -eq $Pattern -or $Data.Length -lt $Pattern.Length) {
        return $false
    }

    for ($i = 0; $i -le $Data.Length - $Pattern.Length; $i++) {
        $match = $true
        for ($j = 0; $j -lt $Pattern.Length; $j++) {
            if ($Data[$i + $j] -ne $Pattern[$j]) {
                $match = $false
                break
            }
        }
        if ($match) {
            return $true
        }
    }

    return $false
}


function Invoke-NCryptUnprotectSecret {
    <#
    .SYNOPSIS
    Calls the Windows NCryptUnprotectSecret API to decrypt DPAPI-NG protected data.

    .DESCRIPTION
    This function uses P/Invoke to call the native NCryptUnprotectSecret function
    from ncrypt.dll. The API contacts the Domain Controller which validates
    if the caller is authorized to decrypt the data.

    .PARAMETER ProtectedBlob
    The DPAPI-NG protected data blob.

    .OUTPUTS
    Byte array containing the decrypted data, or throws an exception on failure.

    .NOTES
    Requires Windows 8 / Server 2012 or later.
    The calling process must be able to contact a Domain Controller.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$ProtectedBlob
    )

    # Define P/Invoke signatures
    $ncryptSignatures = @"
using System;
using System.Runtime.InteropServices;

public class NCryptInterop
{
    // NCryptUnprotectSecret flags
    public const int NCRYPT_UNPROTECT_NO_DECRYPT = 0x00000001;
    public const int NCRYPT_SILENT_FLAG = 0x00000040;

    // SECURITY_STATUS values
    public const int ERROR_SUCCESS = 0;
    public const int NTE_DECRYPTION_FAILURE = unchecked((int)0x80090034);

    [StructLayout(LayoutKind.Sequential)]
    public struct NCryptDescriptor
    {
        public IntPtr pDescriptorString;
    }

    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int NCryptUnprotectSecret(
        IntPtr phDescriptor,           // Optional output descriptor handle
        int dwFlags,                   // Flags
        [In] byte[] pbProtectedBlob,   // Protected data
        int cbProtectedBlob,           // Size of protected data
        IntPtr pMemPara,               // Memory allocation (NULL = LocalAlloc)
        IntPtr hWnd,                   // Window handle for UI (NULL for silent)
        out IntPtr ppbData,            // Output: decrypted data
        out int pcbData                // Output: size of decrypted data
    );

    [DllImport("kernel32.dll")]
    public static extern IntPtr LocalFree(IntPtr hMem);
}
"@

    # Add the type if not already added
    if (-not ([System.Management.Automation.PSTypeName]'NCryptInterop').Type) {
        try {
            Add-Type -TypeDefinition $ncryptSignatures -Language CSharp -ErrorAction Stop
        } catch {
            if ($_.Exception.Message -notmatch "already exists") {
                throw $_
            }
        }
    }

    $ppbData = [IntPtr]::Zero
    $pcbData = 0

    try {
        # Call NCryptUnprotectSecret
        # Using NCRYPT_SILENT_FLAG to prevent UI prompts
        $result = [NCryptInterop]::NCryptUnprotectSecret(
            [IntPtr]::Zero,                      # No descriptor output needed
            [NCryptInterop]::NCRYPT_SILENT_FLAG, # Silent mode
            $ProtectedBlob,                      # Protected data
            $ProtectedBlob.Length,               # Size
            [IntPtr]::Zero,                      # Default memory allocation
            [IntPtr]::Zero,                      # No UI window
            [ref]$ppbData,                       # Output pointer
            [ref]$pcbData                        # Output size
        )

        if ($result -ne 0) {
            $errorHex = "0x{0:X8}" -f $result
            throw "NCryptUnprotectSecret failed with error code $errorHex"
        }

        if ($ppbData -eq [IntPtr]::Zero -or $pcbData -eq 0) {
            throw "NCryptUnprotectSecret returned empty data"
        }

        # Copy decrypted data to managed array
        $decryptedData = New-Object byte[] $pcbData
        [System.Runtime.InteropServices.Marshal]::Copy($ppbData, $decryptedData, 0, $pcbData)

        return $decryptedData

    } finally {
        # Free allocated memory
        if ($ppbData -ne [IntPtr]::Zero) {
            [void][NCryptInterop]::LocalFree($ppbData)
        }
    }
}
