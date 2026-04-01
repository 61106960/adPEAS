function Get-CertificateInfo {
<#
.SYNOPSIS
    Displays detailed information about a certificate file (PFX/P12/CER/PEM).

.DESCRIPTION
    Parses a certificate file and displays all relevant information on the console
    without importing it into the Windows Certificate Store. Supports PFX/P12 (with
    private key), CER/DER (public only), and PEM formats.

    Shows: Subject, Issuer, Serial Number, Thumbprint, Validity, Key Information,
    Extended Key Usage, Subject Alternative Name, Template, and PKINIT assessment
    with Connect-adPEAS usage hints.

.PARAMETER Certificate
    Path to the certificate file or Base64-encoded certificate data.

.PARAMETER CertificatePassword
    Password for PFX/P12 files. Accepts String or SecureString. Default: empty string.

.PARAMETER PassThru
    Return a PSCustomObject with all parsed certificate properties instead of console output.

.EXAMPLE
    Get-CertificateInfo -Certificate ".\admin.pfx" -CertificatePassword "pass"
    Displays all certificate information for a password-protected PFX file.

.EXAMPLE
    Get-CertificateInfo -Certificate ".\server.cer"
    Displays certificate information for a DER/CER public certificate (no password needed).

.EXAMPLE
    $info = Get-CertificateInfo -Certificate ".\admin.pfx" -PassThru
    $info.Subject
    $info.PKINITCapable
    Returns a PSCustomObject with all parsed certificate properties for programmatic use.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Certificate,

        [Parameter(Mandatory=$false)]
        $CertificatePassword = "",

        [Parameter(Mandatory=$false)]
        [switch]$PassThru
    )

    process {
        $FunctionPrefix = "[Get-CertificateInfo]"
        $cert = $null

        try {
            # --- Password handling (SecureString / String) ---
            if ($CertificatePassword -is [System.Security.SecureString]) {
                $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($CertificatePassword)
                try {
                    $PlainCertPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
                }
                finally {
                    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
                }
            }
            elseif ($CertificatePassword -is [string]) {
                $PlainCertPassword = $CertificatePassword
            }
            else {
                Write-Warning "[!] CertificatePassword must be either String or SecureString."
                return $null
            }

            # --- Load certificate via ConvertFrom-Base64OrFile ---
            Write-Log "$FunctionPrefix Loading certificate: $Certificate"
            $certResult = ConvertFrom-Base64OrFile -InputValue $Certificate -ExpectedFormat "Certificate" -ParameterName "Certificate"

            if (-not $certResult.Success) {
                Write-Warning "[!] Failed to load certificate: $($certResult.Error)"
                return $null
            }

            Write-Log "$FunctionPrefix Certificate loaded from $($certResult.Source): $($certResult.Data.Length) bytes ($($certResult.Format))"

            # --- Create X509Certificate2 ---
            # Note: Must use -ArgumentList with explicit [byte[]] cast to prevent PowerShell
            # from unwrapping the byte array into individual constructor arguments
            $certBytes = [byte[]]$certResult.Data

            # Strategy: Try passwordless first for CER/DER (no private key), then with password for PFX
            $certLoaded = $false

            # Try passwordless loading first (works for CER/DER/PEM public certs)
            if ([string]::IsNullOrEmpty($PlainCertPassword)) {
                try {
                    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,$certBytes)
                    $certLoaded = $true
                }
                catch {
                    Write-Log "$FunctionPrefix Passwordless load failed, trying with empty password as PFX..."
                }
            }

            # Try with password (for PFX/P12 files)
            if (-not $certLoaded) {
                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(
                    $certBytes,
                    $PlainCertPassword,
                    [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
                )
            }
        }
        catch {
            # HResult-based error classification (same pattern as Connect-adPEAS)
            $errorHResult = $_.Exception.HResult
            $errorMsg = $_.Exception.Message

            Write-Log "$FunctionPrefix Certificate load error - HResult: 0x$($errorHResult.ToString('X8')), Message: $errorMsg"

            switch ($errorHResult) {
                0x80070056 {  # ERROR_INVALID_PASSWORD
                    Write-Warning "[!] Incorrect certificate password."
                }
                { $_ -in @(0x80092009, 0x8009310B) } {  # CRYPT_E_NO_MATCH, CRYPT_E_ASN1_BADTAG
                    Write-Warning "[!] Invalid certificate format (not a valid PFX/P12 file)."
                }
                0x80092002 {  # CRYPT_E_BAD_ENCODE
                    Write-Warning "[!] Invalid certificate encoding - ensure the file is PFX/P12 format (not DER, PEM or CER)."
                }
                0x80090016 {  # NTE_BAD_KEYSET
                    Write-Warning "[!] Keyset does not exist - the PFX private key could not be imported."
                }
                { $_ -in @(0x80070002, 0x80070003) } {  # FILE_NOT_FOUND, PATH_NOT_FOUND
                    Write-Warning "[!] Certificate file not found."
                }
                default {
                    if ($errorMsg -match "network password is not correct") {
                        Write-Warning "[!] Incorrect certificate password."
                    } elseif ($errorMsg -match "Cannot find the requested object") {
                        Write-Warning "[!] Certificate file not found or invalid format."
                    } elseif ($errorMsg -match "ASN1 bad tag value") {
                        Write-Warning "[!] Invalid certificate format (not a valid PFX/P12 file)."
                    } else {
                        Write-Warning "[!] Failed to load certificate: $errorMsg"
                    }
                }
            }
            return $null
        }

        try {
            # === Parse all certificate data ===

            # --- Key Algorithm ---
            $keyAlgo = "Unknown"
            try {
                $pubKey = $cert.PublicKey.Key
                if ($pubKey -is [System.Security.Cryptography.RSACryptoServiceProvider] -or $pubKey -is [System.Security.Cryptography.RSACng]) {
                    $keyAlgo = "RSA ($($pubKey.KeySize) bit)"
                }
                elseif ($pubKey -is [System.Security.Cryptography.ECDsaCng] -or $pubKey -is [System.Security.Cryptography.ECDsa]) {
                    $keyAlgo = "ECDSA ($($pubKey.KeySize) bit)"
                }
                else {
                    $keyAlgo = "$($cert.PublicKey.Oid.FriendlyName) ($($pubKey.KeySize) bit)"
                }
            }
            catch {
                $keyAlgo = $cert.PublicKey.Oid.FriendlyName
                if (-not $keyAlgo) { $keyAlgo = "Unknown" }
            }

            # --- Validity Status ---
            $now = [DateTime]::Now
            if ($cert.NotBefore -gt $now) {
                $daysUntilValid = [math]::Ceiling(($cert.NotBefore - $now).TotalDays)
                $validityStatus = "Not yet valid (starts in $daysUntilValid days)"
                $validityClass = "Hint"
            }
            elseif ($cert.NotAfter -lt $now) {
                $daysExpired = [math]::Ceiling(($now - $cert.NotAfter).TotalDays)
                $validityStatus = "EXPIRED ($daysExpired days ago)"
                $validityClass = "Finding"
            }
            else {
                $daysRemaining = [math]::Ceiling(($cert.NotAfter - $now).TotalDays)
                $validityStatus = "Valid (expires in $daysRemaining days)"
                $validityClass = "Note"
            }

            # --- Extended Key Usage ---
            $ekuExt = $cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' }
            $ekuNames = @()
            if ($ekuExt) {
                $ekuTyped = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]$ekuExt
                foreach ($eku in $ekuTyped.EnhancedKeyUsages) {
                    $ekuNames += ConvertFrom-OID -OID $eku.Value -IncludeOID
                }
            }

            # --- Subject Alternative Name ---
            $sanExt = $cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' }
            $sanEntries = @()
            if ($sanExt) {
                $sanFormatted = $sanExt.Format($true)
                foreach ($sanLine in ($sanFormatted -split "`r`n|`n" | Where-Object { $_.Trim() })) {
                    $sanEntries += $sanLine.Trim()
                }
            }

            # --- Certificate Template ---
            $templateNameExt = $cert.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.4.1.311.20.2' }
            $templateInfoExt = $cert.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.4.1.311.21.7' }
            $templateName = if ($templateNameExt) { $templateNameExt.Format($false) } else { $null }
            $templateInfo = if ($templateInfoExt) { $templateInfoExt.Format($false) } else { $null }

            # V2-only templates: extract OID from TemplateInfo as fallback for TemplateName
            if (-not $templateName -and $templateInfo -match "Template=([0-9.]+)") {
                $templateName = $Matches[1]
            }

            # --- PKINIT Assessment ---
            $isPKINITCapable = $false
            $pkInitEKUs = @()
            $identities = @()

            if ($ekuExt) {
                $isPKINITCapable = Test-CertificatePKINITCapable -Certificate $cert
                if ($isPKINITCapable) {
                    $pkInitEKUs = @(Get-PKINITCapableEKUNames -Certificate $cert)

                    # Extract identities from SAN (same logic as Connect-adPEAS)
                    if ($sanExt) {
                        $san = $sanExt.Format($false)

                        # Collect UPNs
                        $upnMatches = [regex]::Matches($san, "Principal Name[=:]([^,\r\n]+)")
                        foreach ($m in $upnMatches) {
                            $upnValue = $m.Groups[1].Value.Trim()
                            if ($upnValue -match "^([^@]+)@") {
                                $identities += [PSCustomObject]@{ Type = "UPN"; Value = $upnValue; CName = $Matches[1] }
                            }
                        }

                        # Collect DNS names
                        $dnsMatches = [regex]::Matches($san, "DNS Name=([^,\r\n]+)")
                        foreach ($m in $dnsMatches) {
                            $dnsValue = $m.Groups[1].Value.Trim()
                            $hostPart = ($dnsValue -split '\.')[0]
                            $identities += [PSCustomObject]@{ Type = "DNS"; Value = $dnsValue; CName = "$hostPart`$" }
                        }

                        # CN fallback if no SAN identities
                        if ($identities.Count -eq 0 -and $cert.Subject -match "CN=([^,]+)") {
                            $cnValue = $Matches[1]
                            if ($cnValue -match "^([^.]+)\.(.+\..+)$") {
                                $identities += [PSCustomObject]@{ Type = "CN"; Value = $cnValue; CName = "$($Matches[1])`$" }
                            } else {
                                $identities += [PSCustomObject]@{ Type = "CN"; Value = $cnValue; CName = $cnValue }
                            }
                        }
                    }
                }
            }

            # === PassThru: return PSCustomObject ===
            if ($PassThru) {
                return [PSCustomObject]@{
                    Subject            = $cert.Subject
                    Issuer             = $cert.Issuer
                    SerialNumber       = $cert.SerialNumber
                    Thumbprint         = $cert.Thumbprint
                    NotBefore          = $cert.NotBefore
                    NotAfter           = $cert.NotAfter
                    Status             = $validityStatus
                    HasPrivateKey      = $cert.HasPrivateKey
                    KeyAlgorithm       = $keyAlgo
                    SignatureAlgorithm = $cert.SignatureAlgorithm.FriendlyName
                    EKU                = $ekuNames
                    SAN                = $sanEntries
                    TemplateName       = $templateName
                    TemplateInfo       = $templateInfo
                    PKINITCapable      = $isPKINITCapable
                    PKINITEKUs         = $pkInitEKUs
                    Identities         = $identities
                }
            }

            # === Console Output ===
            Show-SubHeader "Certificate Information"

            # --- General ---
            Show-Line "General:" -Class Hint
            Show-KeyValue "Subject:" $cert.Subject
            Show-KeyValue "Issuer:" $cert.Issuer
            Show-KeyValue "Serial Number:" $cert.SerialNumber
            Show-KeyValue "Thumbprint:" $cert.Thumbprint
            Show-EmptyLine

            # --- Validity ---
            Show-Line "Validity:" -Class Hint
            Show-KeyValue "Not Before:" $cert.NotBefore.ToString("yyyy-MM-dd HH:mm:ss")
            Show-KeyValue "Not After:" $cert.NotAfter.ToString("yyyy-MM-dd HH:mm:ss")
            Show-KeyValue "Status:" $validityStatus -Class $validityClass
            Show-EmptyLine

            # --- Key Information ---
            Show-Line "Key Information:" -Class Hint
            Show-KeyValue "Has Private Key:" $cert.HasPrivateKey.ToString()
            Show-KeyValue "Key Algorithm:" $keyAlgo
            Show-KeyValue "Signature Algorithm:" $cert.SignatureAlgorithm.FriendlyName
            Show-EmptyLine

            # --- Extended Key Usage ---
            if ($ekuNames.Count -gt 0) {
                Show-Line "Extended Key Usage:" -Class Hint
                $idx = 1
                foreach ($ekuName in $ekuNames) {
                    Show-KeyValue "[$idx]:" $ekuName
                    $idx++
                }
                Show-EmptyLine
            }

            # --- Subject Alternative Name ---
            if ($sanEntries.Count -gt 0) {
                Show-Line "Subject Alternative Name:" -Class Hint
                $idx = 1
                foreach ($entry in $sanEntries) {
                    Show-KeyValue "[$idx]:" $entry
                    $idx++
                }
                Show-EmptyLine
            }

            # --- Certificate Template ---
            if ($templateName -or $templateInfo) {
                Show-Line "Certificate Template:" -Class Hint
                if ($templateName) {
                    Show-KeyValue "Template Name:" $templateName
                }
                if ($templateInfo) {
                    Show-KeyValue "Template Info:" $templateInfo
                }
                Show-EmptyLine
            }

            # --- PKINIT Assessment ---
            if ($ekuExt) {
                Show-Line "PKINIT Assessment:" -Class Hint

                if ($isPKINITCapable) {
                    Show-KeyValue "PKINIT Capable:" "True" -Class Note
                    if ($pkInitEKUs.Count -gt 0) {
                        Show-KeyValue "PKINIT EKUs:" ($pkInitEKUs -join ", ")
                    }
                }
                else {
                    Show-KeyValue "PKINIT Capable:" "False" -Class Hint
                    Show-KeyValue "Reason:" "No PKINIT-capable EKU (Client Authentication, Smartcard Logon, or PKINIT Client Auth)"
                }

                if ($identities.Count -gt 0) {
                    Show-EmptyLine
                    Show-Line "Identities:" -Class Hint
                    $idx = 1
                    foreach ($id in $identities) {
                        Show-KeyValue "[$idx] $($id.Type):" $id.Value
                        $idx++
                    }

                    # Usage hints
                    Show-EmptyLine
                    Show-Line "Usage:" -Class Hint

                    $certPathHint = $Certificate
                    if ($certPathHint.Length -gt 60) {
                        $certPathHint = "cert.pfx"
                    }

                    if ($identities.Count -eq 1) {
                        Show-Line "Connect-adPEAS -Domain <domain> -Certificate '$certPathHint'"
                    }
                    else {
                        Show-Line "Connect-adPEAS -Domain <domain> -Certificate '$certPathHint'"
                        for ($i = 1; $i -lt $identities.Count; $i++) {
                            $id = $identities[$i]
                            $usernameHint = if ($id.Type -eq "UPN") { ($id.Value -split '@')[0] } else { ($id.Value -split '\.')[0] }
                            Show-Line "Connect-adPEAS -Domain <domain> -Certificate '$certPathHint' -Username $usernameHint"
                        }
                    }
                }
                Show-EmptyLine
            }
        }
        finally {
            if ($cert) {
                $cert.Dispose()
            }
        }
    }
}
