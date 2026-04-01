<#
.SYNOPSIS
    Validates an adPEAS license file using RSA-SHA256 signature verification.

.DESCRIPTION
    Verifies the RSA-SHA256 signature of a license JSON string and checks the expiry date.
    The public key is embedded in this module and must match the private key used for signing.

    Returns a result object with validation status, licensee info, and display message.

.PARAMETER LicenseJson
    The license input - accepts either:
    - A file path to a .json license file
    - A raw JSON string
    Expected JSON format: {"Licensee":"...","ValidUntil":"yyyy-MM-dd","Signature":"base64..."}

.EXAMPLE
    Test-adPEASLicense -LicenseJson .\license.json
    Validates the license file at the given path.

.EXAMPLE
    $json = Get-Content .\license.json -Raw
    $result = Test-adPEASLicense -LicenseJson $json
    if ($result.IsValid -and -not $result.Expired) {
        Write-Host $result.Message
    }

.OUTPUTS
    PSCustomObject with properties:
    - IsValid    [bool]     : Signature verification passed
    - Licensee   [string]   : Licensee name (null if invalid)
    - ValidUntil [string]   : Expiry date as yyyy-MM-dd (null if invalid)
    - Expired    [bool]     : Whether license has expired (null if invalid)
    - Message    [string]   : Display text for disclaimer

.NOTES
    Author: Alexander Sturz (@_61106960_)
    The public key below is embedded at build time and used for signature verification.
#>

# RSA public key for license verification (XML format, embedded at build time)
$Script:adPEASPublicKey = @"
<RSAKeyValue><Modulus>psPrGFENqXqua+i/cUiPyXEkqbtBtAyRaorioa1WflemUEMyD7zIm96rPOUcPIUu7e1qZj3dt3trXfBnt2gRloRSx/gujZSw8xep7PB1AtU0t87Qfb1RMiBuwmc/68ziRhicYEjwD2bGtQ12lf4NE32vMUee9AZbsMgEoR/zEJEybb8sl8e0kz5FAAhzvyzeXpNHZFTTYBVqvbTZXXlhUb7l1QQ8TGtWalo0Wna7NxG3iN/xT7UeCssAy2Vm4f18SnF43kfTGWj+a+47piIxqJH47jvQNkVdWSpstTf2ZtnPZ1xavXy1779T3MZApuQ+NOXHKB87dTyoRThSjv9hyQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>
"@

function Test-adPEASLicense {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$LicenseJson
    )

    process {
        try {
            # If input looks like a file path, read the file content
            if ($LicenseJson -notmatch '^\s*\{' -and (Test-Path $LicenseJson -ErrorAction SilentlyContinue)) {
                $LicenseJson = Get-Content $LicenseJson -Raw -Encoding UTF8
            }

            # Parse JSON
            $license = $LicenseJson | ConvertFrom-Json

            # Validate required fields
            if (-not $license.Licensee -or -not $license.ValidUntil -or -not $license.Signature) {
                return [PSCustomObject]@{
                    IsValid    = $false
                    Licensee   = $null
                    ValidUntil = $null
                    Expired    = $null
                    Message    = "Invalid license format"
                }
            }

            # Check if public key is configured
            if ($Script:adPEASPublicKey -match 'PLACEHOLDER') {
                return [PSCustomObject]@{
                    IsValid    = $false
                    Licensee   = $null
                    ValidUntil = $null
                    Expired    = $null
                    Message    = "License validation not configured"
                }
            }

            # Verify RSA-SHA256 signature
            $rsa = $null
            try {
                $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
                $rsa.FromXmlString($Script:adPEASPublicKey)

                # Reconstruct signed payload: "Licensee|ValidUntil"
                $payload = "$($license.Licensee)|$($license.ValidUntil)"
                $payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
                $signatureBytes = [Convert]::FromBase64String($license.Signature)

                # Use .NET Framework compatible API (PowerShell 5.1)
                # RSACryptoServiceProvider.VerifyData(byte[] data, object halg, byte[] signature)
                $isValidSignature = $rsa.VerifyData($payloadBytes, "SHA256", $signatureBytes)

                if (-not $isValidSignature) {
                    return [PSCustomObject]@{
                        IsValid    = $false
                        Licensee   = $null
                        ValidUntil = $null
                        Expired    = $null
                        Message    = "Invalid license signature"
                    }
                }
            }
            finally {
                if ($rsa) { $rsa.Dispose() }
            }

            # Parse and check expiry date
            $validUntilDate = [datetime]::ParseExact(
                $license.ValidUntil,
                "yyyy-MM-dd",
                [System.Globalization.CultureInfo]::InvariantCulture
            )
            $isExpired = (Get-Date).Date -gt $validUntilDate

            # Build display message
            $displayMessage = if ($isExpired) {
                "License expired on $($license.ValidUntil) (Licensee: $($license.Licensee))"
            }
            else {
                "Licensed to $($license.Licensee) - Valid until $($license.ValidUntil)"
            }

            return [PSCustomObject]@{
                IsValid    = $true
                Licensee   = $license.Licensee
                ValidUntil = $license.ValidUntil
                Expired    = $isExpired
                Message    = $displayMessage
            }
        }
        catch {
            return [PSCustomObject]@{
                IsValid    = $false
                Licensee   = $null
                ValidUntil = $null
                Expired    = $null
                Message    = "License validation error: $($_.Exception.Message)"
            }
        }
    }
}
