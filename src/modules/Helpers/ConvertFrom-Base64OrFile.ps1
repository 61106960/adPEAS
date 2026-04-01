<#
.SYNOPSIS
    Converts a Base64 string or reads a file path to byte array.

.DESCRIPTION
    This helper function handles input that can be either:
    1. A Base64-encoded string (standard or URL-safe)
    2. A file path to read

    Logic:
    1. First attempts to decode as Base64 (both standard and URL-safe)
    2. Validates decoded bytes match expected format (optional)
    3. If Base64 decoding fails or produces invalid format, treats input as file path

.PARAMETER InputValue
    The input string - either Base64-encoded data or a file path.

.PARAMETER ExpectedFormat
    Optional. The expected format of the decoded data:
    - "Kirbi" - KRB-CRED format (starts with 0x76) or raw Ticket (0x61)
    - "Ccache" - MIT Kerberos ccache format (starts with 0x0501-0x0504)
    - "Certificate" - PFX/PKCS12 format (starts with 0x30) or PEM (starts with "-----")
    - "Any" - Accept any valid Base64 (default)

.PARAMETER ParameterName
    Optional. The name of the parameter for error messages.

.OUTPUTS
    PSCustomObject with:
    - Success: Boolean indicating success
    - Data: Byte array of the decoded/read data
    - Source: "Base64" or "File"
    - Format: Detected format
    - Error: Error message if failed

.EXAMPLE
    $result = ConvertFrom-Base64OrFile -InputValue "YII..." -ExpectedFormat "Kirbi"
    if ($result.Success) {
        $ticketBytes = $result.Data
    }

.EXAMPLE
    $result = ConvertFrom-Base64OrFile -InputValue "C:\tickets\admin.kirbi" -ExpectedFormat "Kirbi"
    if ($result.Success) {
        $ticketBytes = $result.Data
    }

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

function ConvertFrom-Base64OrFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$InputValue,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Kirbi", "Ccache", "Certificate", "Any")]
        [string]$ExpectedFormat = "Any",

        [Parameter(Mandatory = $false)]
        [string]$ParameterName = "Input"
    )

    process {
        $result = [PSCustomObject]@{
            Success = $false
            Data    = $null
            Source  = $null
            Format  = $null
            Error   = $null
        }

        # Empty or null check
        if ([string]::IsNullOrWhiteSpace($InputValue)) {
            $result.Error = "$ParameterName cannot be empty"
            return $result
        }

        Write-Log "[ConvertFrom-Base64OrFile] Processing $ParameterName (length: $($InputValue.Length) chars)"

        #Try Base64 decoding first
        $decodedBytes = $null
        $isValidBase64 = $false

        try {
            # Normalize the input - handle URL-safe Base64
            $base64String = $InputValue.Trim()

            # Replace URL-safe characters with standard Base64 characters
            $base64String = $base64String -replace '-', '+' -replace '_', '/'

            # Add padding if necessary
            $paddingNeeded = $base64String.Length % 4
            if ($paddingNeeded -gt 0) {
                $base64String += ('=' * (4 - $paddingNeeded))
            }

            # Check if it looks like Base64 (only valid Base64 characters), also reject strings that look like file paths
            $isPathLike = $base64String -match '^[A-Za-z]:\\' -or        # Windows absolute path
                          $base64String -match '^\\\\' -or                 # UNC path
                          $base64String -match '^\.\.?[/\\]' -or           # Relative path
                          $base64String -match '^[/~]' -or                 # Unix path
                          $base64String -match '\.[a-zA-Z0-9]{2,5}$' -and  # File extension
                          $base64String.Length -lt 100                      # Short string with extension

            if ($isPathLike) {
                Write-Log "[ConvertFrom-Base64OrFile] Input looks like a file path, skipping Base64 decoding"
            }
            else {
                # Check for valid Base64 characters
                $base64Pattern = '^[A-Za-z0-9+/=]+$'
                if ($base64String -match $base64Pattern -and $base64String.Length -ge 4) {

                    # Try to decode
                    $decodedBytes = [Convert]::FromBase64String($base64String)

                    if ($decodedBytes.Length -gt 0) {
                        Write-Log "[ConvertFrom-Base64OrFile] Base64 decoded to $($decodedBytes.Length) bytes"

                        # Validate against expected format
                        $formatValid = $false
                        $detectedFormat = "Unknown"

                        switch ($ExpectedFormat) {
                            "Kirbi" {
                                # KRB-CRED starts with APPLICATION 22 (0x76)
                                # Raw Ticket starts with APPLICATION 1 (0x61)
                                if ($decodedBytes[0] -eq 0x76) {
                                    $formatValid = $true
                                    $detectedFormat = "KRB-CRED"
                                }
                                elseif ($decodedBytes[0] -eq 0x61) {
                                    $formatValid = $true
                                    $detectedFormat = "RawTicket"
                                }
                                else {
                                    Write-Log "[ConvertFrom-Base64OrFile] Kirbi format check failed: first byte is 0x$($decodedBytes[0].ToString('X2')), expected 0x76 or 0x61"
                                }
                            }
                            "Ccache" {
                                # Ccache starts with version bytes (0x0501, 0x0502, 0x0503, 0x0504)
                                if ($decodedBytes.Length -ge 2) {
                                    $version = ([uint16]$decodedBytes[0] -shl 8) -bor $decodedBytes[1]
                                    if ($version -ge 0x0501 -and $version -le 0x0504) {
                                        $formatValid = $true
                                        $detectedFormat = "Ccache-v$($version -band 0xFF)"
                                    }
                                    else {
                                        Write-Log "[ConvertFrom-Base64OrFile] Ccache format check failed: version is 0x$($version.ToString('X4')), expected 0x0501-0x0504"
                                    }
                                }
                            }
                            "Certificate" {
                                # PFX/PKCS12 starts with SEQUENCE (0x30)
                                # PEM starts with "-----BEGIN" (but that would be in InputValue, not decoded)
                                if ($decodedBytes[0] -eq 0x30) {
                                    # Additional check: valid ASN.1 length byte
                                    if ($decodedBytes.Length -ge 2) {
                                        $formatValid = $true
                                        $detectedFormat = "PFX/PKCS12"
                                    }
                                }
                                else {
                                    Write-Log "[ConvertFrom-Base64OrFile] Certificate format check failed: first byte is 0x$($decodedBytes[0].ToString('X2')), expected 0x30 (SEQUENCE)"
                                }
                            }
                            "Any" {
                                # Accept any valid decoded bytes
                                $formatValid = $true

                                # Try to detect format
                                if ($decodedBytes[0] -eq 0x76) { $detectedFormat = "KRB-CRED" }
                                elseif ($decodedBytes[0] -eq 0x61) { $detectedFormat = "RawTicket" }
                                elseif ($decodedBytes.Length -ge 2 -and (([uint16]$decodedBytes[0] -shl 8) -bor $decodedBytes[1]) -ge 0x0501 -and (([uint16]$decodedBytes[0] -shl 8) -bor $decodedBytes[1]) -le 0x0504) { $detectedFormat = "Ccache" }
                                elseif ($decodedBytes[0] -eq 0x30) { $detectedFormat = "ASN.1" }
                                else { $detectedFormat = "Binary" }
                            }
                        }

                        if ($formatValid) {
                            $isValidBase64 = $true
                            Write-Log "[ConvertFrom-Base64OrFile] Valid $ExpectedFormat format detected: $detectedFormat"

                            $result.Success = $true
                            $result.Data = $decodedBytes
                            $result.Source = "Base64"
                            $result.Format = $detectedFormat
                            return $result
                        }
                        else {
                            Write-Log "[ConvertFrom-Base64OrFile] Base64 decoded but format doesn't match expected: $ExpectedFormat"
                            # Clear decoded bytes - will try as file path
                            $decodedBytes = $null
                        }
                    }
                }
                else {
                    Write-Log "[ConvertFrom-Base64OrFile] Input doesn't look like Base64"
                }
            }
        }
        catch {
            Write-Log "[ConvertFrom-Base64OrFile] Base64 decoding failed: $_"
            $decodedBytes = $null
        }

        # Try as file path

        Write-Log "[ConvertFrom-Base64OrFile] Trying as file path: $InputValue"

        # Check if file exists
        if (Test-Path -Path $InputValue -PathType Leaf) {
            try {
                $fileBytes = [System.IO.File]::ReadAllBytes($InputValue)

                if ($fileBytes.Length -eq 0) {
                    $result.Error = "File is empty: $InputValue"
                    return $result
                }

                Write-Log "[ConvertFrom-Base64OrFile] Read $($fileBytes.Length) bytes from file"

                # Validate format for files too
                $detectedFormat = "Unknown"
                $formatValid = $false

                switch ($ExpectedFormat) {
                    "Kirbi" {
                        if ($fileBytes[0] -eq 0x76) {
                            $formatValid = $true
                            $detectedFormat = "KRB-CRED"
                        }
                        elseif ($fileBytes[0] -eq 0x61) {
                            $formatValid = $true
                            $detectedFormat = "RawTicket"
                        }
                        else {
                            $result.Error = "Invalid Kirbi file format. Expected KRB-CRED (0x76) or Ticket (0x61), got 0x$($fileBytes[0].ToString('X2'))"
                            return $result
                        }
                    }
                    "Ccache" {
                        if ($fileBytes.Length -ge 2) {
                            $version = ([uint16]$fileBytes[0] -shl 8) -bor $fileBytes[1]
                            if ($version -ge 0x0501 -and $version -le 0x0504) {
                                $formatValid = $true
                                $detectedFormat = "Ccache-v$($version -band 0xFF)"
                            }
                            else {
                                $result.Error = "Invalid Ccache file format. Expected version 0x0501-0x0504, got 0x$($version.ToString('X4'))"
                                return $result
                            }
                        }
                        else {
                            $result.Error = "Ccache file too small"
                            return $result
                        }
                    }
                    "Certificate" {
                        if ($fileBytes[0] -eq 0x30) {
                            $formatValid = $true
                            $detectedFormat = "PFX/PKCS12"
                        }
                        elseif ($fileBytes.Length -ge 10) {
                            $header = [System.Text.Encoding]::ASCII.GetString($fileBytes, 0, [Math]::Min(11, $fileBytes.Length))
                            if ($header.StartsWith("-----BEGIN")) {
                                $formatValid = $true
                                $detectedFormat = "PEM"
                            }
                        }

                        if (-not $formatValid) {
                            $result.Error = "Invalid certificate file format. Expected PFX/PKCS12 (0x30) or PEM"
                            return $result
                        }
                    }
                    "Any" {
                        $formatValid = $true
                        # Try to detect format
                        if ($fileBytes[0] -eq 0x76) { $detectedFormat = "KRB-CRED" }
                        elseif ($fileBytes[0] -eq 0x61) { $detectedFormat = "RawTicket" }
                        elseif ($fileBytes.Length -ge 2 -and (([uint16]$fileBytes[0] -shl 8) -bor $fileBytes[1]) -ge 0x0501 -and (([uint16]$fileBytes[0] -shl 8) -bor $fileBytes[1]) -le 0x0504) { $detectedFormat = "Ccache" }
                        elseif ($fileBytes[0] -eq 0x30) { $detectedFormat = "ASN.1" }
                        else { $detectedFormat = "Binary" }
                    }
                }

                $result.Success = $true
                $result.Data = $fileBytes
                $result.Source = "File"
                $result.Format = $detectedFormat
                return $result
            }
            catch {
                $result.Error = "Failed to read file '$InputValue': $_"
                return $result
            }
        }
        else {
            if ($isValidBase64 -eq $false -and $null -eq $decodedBytes) {
                $result.Error = "Input is neither a valid Base64 string nor an existing file path: $InputValue"
            }
            else {
                $result.Error = "File not found: $InputValue"
            }
            return $result
        }
    }
}
