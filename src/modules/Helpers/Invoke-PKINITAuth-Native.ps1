<#
.SYNOPSIS
    Native PowerShell PKINIT authentication using raw Kerberos protocol.

.DESCRIPTION
    This function performs PKINIT (Public Key Cryptography for Initial Authentication in Kerberos) using a pure PowerShell implementation of the Kerberos protocol. No external tools required.

    Features:
    - Pure PowerShell implementation (no Rubeus, no Python tools)
    - Diffie-Hellman key exchange for session key derivation
    - CMS/PKCS#7 signed AuthPack
    - TGT extraction and optional cache import

.PARAMETER Certificate
    Certificate for authentication. Accepts:
    - X509Certificate2 object (already loaded certificate)
    - Path to a PFX/P12 certificate file
    - Base64-encoded PFX data
    The function auto-detects the input type.

.PARAMETER CertificatePassword
    Password for the PFX/P12 certificate file (if using file path or Base64).

.PARAMETER Domain
    Target domain for authentication. If not specified, uses current domain.

.PARAMETER DomainController
    Specific domain controller to target. If not specified, uses auto-discovery.

.PARAMETER UserName
    Username to authenticate as. If not specified, derived from certificate.

.PARAMETER OutputKirbi
    Optional path to save the TGT as a .kirbi file.

.PARAMETER NoPAC
    Request TGT without PAC (Privilege Attribute Certificate).

.EXAMPLE
    Invoke-PKINITAuth-Native -Certificate "C:\cert\user.pfx" -CertificatePassword "P@ssw0rd!"
    Performs PKINIT authentication using a certificate file.

.EXAMPLE
    Invoke-PKINITAuth-Native -Certificate $x509Cert
    Performs PKINIT authentication using an already-loaded X509Certificate2 object.

.EXAMPLE
    Invoke-PKINITAuth-Native -Certificate "MIIKwgYJKoZI..." -CertificatePassword "pass"
    Performs PKINIT authentication using Base64-encoded PFX data.

.EXAMPLE
    Invoke-PKINITAuth-Native -Certificate "C:\cert\admin.pfx" -CertificatePassword "pass" -OutputKirbi "C:\tickets\admin.kirbi"
    Performs PKINIT and saves the TGT to a kirbi file for later use.

.OUTPUTS
    PSCustomObject with authentication result including TGT and session key.

.NOTES
    Author: Alexander Sturz (@_61106960_)
    References:
    - https://github.com/dirkjanm/PKINITtools (Python reference implementation)
    - https://github.com/skelsec/minikerberos (Python Kerberos library)
#>

function Invoke-PKINITAuth-Native {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        $Certificate,  # Accepts X509Certificate2, file path, or Base64

        [Parameter(Mandatory=$false, Position=1)]
        [string]$CertificatePassword = "",

        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$DomainController,

        [Parameter(Mandatory=$false)]
        [string]$UserName,

        [Parameter(Mandatory=$false)]
        [string]$OutputKirbi,

        [Parameter(Mandatory=$false)]
        [switch]$NoPAC
    )

    begin {
        Write-Log "[Invoke-PKINITAuth-Native] Starting native PKINIT authentication..."

        # Track if we created the certificate (so we know whether to dispose it)
        $CertCreatedByUs = $false

        # Load certificate based on input type
        try {
            if ($Certificate -is [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
                # Already an X509Certificate2 object - don't dispose it, caller owns it
                $Cert = $Certificate
                $CertCreatedByUs = $false
                Write-Log "[Invoke-PKINITAuth-Native] Using provided X509Certificate2 object"
            }
            elseif ($Certificate -is [string]) {
                # String input - could be file path or Base64
                $certResult = ConvertFrom-Base64OrFile -InputValue $Certificate -ExpectedFormat "Certificate" -ParameterName "Certificate"

                if (-not $certResult.Success) {
                    throw $certResult.Error
                }

                Write-Log "[Invoke-PKINITAuth-Native] Certificate loaded from $($certResult.Source): $($certResult.Data.Length) bytes"

                # Load the certificate from bytes - we created it, so we must dispose it
                $Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
                    $certResult.Data,
                    $CertificatePassword,
                    [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
                )
                $CertCreatedByUs = $true
            }
            else {
                throw "Invalid Certificate parameter type. Expected X509Certificate2, file path, or Base64 string."
            }

            Write-Log "[Invoke-PKINITAuth-Native] Certificate loaded: $($Cert.Subject)"

            # Show certificate EKUs for diagnostics (using central OID mapping from adPEAS-OIDs.ps1)
            $ekuExt = $Cert.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.37" }
            if ($ekuExt) {
                try {
                    # Use X509EnhancedKeyUsageExtension for proper OID extraction
                    if ($ekuExt -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
                        $ekuOids = @()
                        foreach ($eku in $ekuExt.EnhancedKeyUsages) {
                            $ekuOids += $eku.Value
                        }
                        # Convert OIDs to names using central mapping
                        $ekuNames = Convert-OIDsToNames -OIDs $ekuOids
                        Write-Log "[Invoke-PKINITAuth-Native] Certificate EKUs: $($ekuNames -join ', ')"

                        # Check for PKINIT-capable EKUs using central function
                        $hasPKINITEku = Test-CertificatePKINITCapable -EKUOIDs $ekuOids
                        if (-not $hasPKINITEku) {
                            Write-Log "[Invoke-PKINITAuth-Native] WARNING: Certificate may not have PKINIT-capable EKU!"
                        }
                    }
                    else {
                        # Fallback: Parse formatted string output
                        $ekuOids = $ekuExt.Format($false) -split ', '
                        $ekuNames = Convert-OIDsToNames -OIDs $ekuOids
                        Write-Log "[Invoke-PKINITAuth-Native] Certificate EKUs: $($ekuNames -join ', ')"
                    }
                } catch {
                    Write-Log "[Invoke-PKINITAuth-Native] Could not parse EKUs: $_"
                }
            } else {
                Write-Log "[Invoke-PKINITAuth-Native] No Extended Key Usage extension found in certificate"
            }

            if (-not $Cert.HasPrivateKey) {
                throw "Certificate does not have a private key"
            }
        } catch {
            throw "Failed to load certificate: $_"
        }

        # Determine domain if not specified
        if (-not $Domain) {
            try {
                $CurrentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
                $Domain = $CurrentDomain.Name
                Write-Log "[Invoke-PKINITAuth-Native] Auto-detected domain: $Domain"
            } catch {
                throw "Could not detect domain. Please specify -Domain parameter."
            }
        }

        # Resolve Domain Controller using unified resolver
        # If -DomainController is explicit, just resolve that hostname to IP (skip DC discovery)
        # If -DomainController is not set, use domain-based DC discovery via SRV records
        if ($DomainController) {
            $ResolvedIP = Resolve-adPEASName -Name $DomainController
            $DCResolution = [PSCustomObject]@{ Hostname = $DomainController; IP = $ResolvedIP }
        } else {
            $DCResolution = Resolve-adPEASName -Domain $Domain
        }
        Write-Log "[Invoke-PKINITAuth-Native] DC Resolution: Hostname=$($DCResolution.Hostname), IP=$($DCResolution.IP)"

        # Use resolved IP for KDC connection if available (required for custom DNS scenarios)
        # Otherwise fall back to hostname/domain
        if ($DCResolution.IP) {
            $DomainController = $DCResolution.IP
            Write-Log "[Invoke-PKINITAuth-Native] Using resolved IP for KDC: $DomainController"
        }
        elseif ($DCResolution.Hostname) {
            $DomainController = $DCResolution.Hostname
            Write-Log "[Invoke-PKINITAuth-Native] Using resolved hostname for KDC: $DomainController"
        }
        else {
            # Fallback to domain name
            $DomainController = $Domain
            Write-Log "[Invoke-PKINITAuth-Native] Fallback: Using domain name for KDC: $DomainController"
        }

        # Determine username if not specified
        if (-not $UserName) {
            # Try to extract from certificate SAN or Subject
            $UserName = $null

            # Check Subject Alternative Name for UPN
            foreach ($ext in $Cert.Extensions) {
                if ($ext.Oid.Value -eq "2.5.29.17") {  # SAN OID
                    # Try to find UPN in raw data
                    $sanData = $ext.Format($false)
                    if ($sanData -match 'Principal Name=([^,\r\n]+)') {
                        $UserName = $Matches[1]
                        break
                    }
                }
            }

            if (-not $UserName) {
                # Fall back to CN from Subject
                $SubjectCN = ($Cert.Subject -split ',')[0] -replace 'CN=', ''
                $UserName = $SubjectCN.TrimEnd('$')
            }

            Write-Log "[Invoke-PKINITAuth-Native] Using username: $UserName"
        }

        # Diffie-Hellman Parameters (RFC 2409 MODP Group 2 - 1024 bit)
        # These are the "well-known" DH parameters used by Windows PKINIT
        # Note: Using local scope (not Script:) since these are only used within this function
        $DH_P_HEX = @"
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
"@.Trim()
        $DH_G = 2

        # Kerberos Encryption Types (RFC 3961, RFC 3962, RFC 4757)
        $ETYPE_AES128_CTS = 17
        $ETYPE_AES256_CTS = 18
        $ETYPE_RC4_HMAC = 23

        # Convert hex string to BigInteger
        $DH_P = [System.Numerics.BigInteger]::Parse(
            "00" + $DH_P_HEX,
            [System.Globalization.NumberStyles]::HexNumber
        )
        function Get-RandomBigInteger {
            param([int]$BitLength)

            $byteLength = [math]::Ceiling($BitLength / 8)
            $bytes = New-Object byte[] $byteLength

            $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
            $rng.GetBytes($bytes)
            $rng.Dispose()

            # Ensure positive by setting high bit to 0
            $bytes[$byteLength - 1] = $bytes[$byteLength - 1] -band 0x7F

            # Convert to BigInteger (little-endian)
            return [System.Numerics.BigInteger]::new($bytes)
        }

        function ConvertTo-BigEndianBytes {
            [OutputType([byte[]])]
            param([System.Numerics.BigInteger]$Value, [int]$Length = 0)

            [byte[]]$bytes = $Value.ToByteArray()
            [Array]::Reverse($bytes)

            # Remove leading zeros
            $startIndex = 0
            while ($startIndex -lt $bytes.Length - 1 -and $bytes[$startIndex] -eq 0) {
                $startIndex++
            }

            if ($startIndex -gt 0) {
                # Create new byte array without leading zeros
                $newLength = $bytes.Length - $startIndex
                [byte[]]$trimmed = New-Object byte[] $newLength
                [Array]::Copy($bytes, $startIndex, $trimmed, 0, $newLength)
                $bytes = $trimmed
            }

            # Pad to specified length if needed
            if ($Length -gt 0 -and $bytes.Length -lt $Length) {
                [byte[]]$padded = New-Object byte[] $Length
                [Array]::Copy($bytes, 0, $padded, $Length - $bytes.Length, $bytes.Length)
                $bytes = $padded
            }

            # Use comma operator to prevent PowerShell from unrolling the byte array
            return ,$bytes
        }

        function New-DHKeyPair {
            # Generate private key (random number less than p-1)
            $privateKey = Get-RandomBigInteger -BitLength 256

            # Calculate public key: g^x mod p
            $publicKey = [System.Numerics.BigInteger]::ModPow(
                [System.Numerics.BigInteger]$DH_G,
                $privateKey,
                $DH_P
            )

            return @{
                PrivateKey = $privateKey
                PublicKey = $publicKey
            }
        }

        function Get-DHSharedSecret {
            param(
                [System.Numerics.BigInteger]$TheirPublicKey,
                [System.Numerics.BigInteger]$MyPrivateKey
            )

            # shared_secret = their_public ^ my_private mod p
            return [System.Numerics.BigInteger]::ModPow($TheirPublicKey, $MyPrivateKey, $DH_P)
        }

        function New-PKINITDHNonce {
            $nonce = New-Object byte[] 32
            $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
            $rng.GetBytes($nonce)
            $rng.Dispose()
            return $nonce
        }

        function Get-SHA1Hash {
            param([byte[]]$Data)
            $sha1 = [System.Security.Cryptography.SHA1]::Create()
            $hash = $sha1.ComputeHash($Data)
            $sha1.Dispose()
            return $hash
        }

        function Get-SHA256Hash {
            param([byte[]]$Data)
            $sha256 = [System.Security.Cryptography.SHA256]::Create()
            $hash = $sha256.ComputeHash($Data)
            $sha256.Dispose()
            return $hash
        }

        #region AS-REQ Building

        function New-PKAuthenticator {
            param(
                [int]$CuSec,
                [datetime]$CTime,
                [uint32]$Nonce,
                [byte[]]$PaChecksum,   # SHA1 of KDC-REQ-BODY (RFC 4556)
                [byte[]]$PaChecksum2   # SHA256 of KDC-REQ-BODY (MS-PKCA for Windows Server 2022+)
            )

            # PKAuthenticator ::= SEQUENCE {
            #     cusec          [0] INTEGER,
            #     ctime          [1] KerberosTime,
            #     nonce          [2] INTEGER,
            #     paChecksum     [3] OCTET STRING OPTIONAL,       -- SHA-1 (RFC 4556)
            #     ...,
            #     freshnessToken [4] OCTET STRING OPTIONAL,       -- RFC 8070 (not used here)
            #     paChecksum2    [5] PAChecksum2 OPTIONAL         -- MS-PKCA (Windows Server 2022+)
            # }
            #
            # PAChecksum2 ::= SEQUENCE {
            #     checksum            [0] OCTET STRING,           -- SHA-256 hash
            #     algorithmIdentifier [1] AlgorithmIdentifier     -- OID 2.16.840.1.101.3.4.2.1 (sha256)
            # }

            $data = @()

            # cusec [0] INTEGER
            $data += New-ASN1ContextTag -Tag 0 -Data (New-ASN1Integer -Value $CuSec)

            # ctime [1] KerberosTime (GeneralizedTime)
            $data += New-ASN1ContextTag -Tag 1 -Data (New-ASN1GeneralizedTime -Value $CTime)

            # nonce [2] INTEGER
            $data += New-ASN1ContextTag -Tag 2 -Data (New-ASN1Integer -Value $Nonce)

            # paChecksum [3] OCTET STRING (SHA-1)
            if ($PaChecksum) {
                $data += New-ASN1ContextTag -Tag 3 -Data (New-ASN1OctetString -Value $PaChecksum)
            }

            # freshnessToken [4] - not used, skip

            # paChecksum2 [5] PAChecksum2 (SHA-256 for Windows Server 2022+)
            if ($PaChecksum2) {
                # Build PAChecksum2 structure
                # PAChecksum2 ::= SEQUENCE {
                #     checksum            [0] OCTET STRING,
                #     algorithmIdentifier [1] AlgorithmIdentifier
                # }

                # AlgorithmIdentifier for SHA-256: OID 2.16.840.1.101.3.4.2.1
                $sha256Oid = New-ASN1ObjectIdentifier -OID "2.16.840.1.101.3.4.2.1"
                # AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPTIONAL }
                # For SHA-256, parameters is typically NULL or absent
                $algorithmId = New-ASN1Sequence -Data ($sha256Oid + (New-ASN1Null))

                $paChecksum2Content = @()
                # checksum [0] OCTET STRING
                $paChecksum2Content += New-ASN1ContextTag -Tag 0 -Data (New-ASN1OctetString -Value $PaChecksum2)
                # algorithmIdentifier [1] AlgorithmIdentifier
                $paChecksum2Content += New-ASN1ContextTag -Tag 1 -Data $algorithmId

                $paChecksum2Seq = New-ASN1Sequence -Data ([byte[]]$paChecksum2Content)

                # Wrap in context tag [5]
                $data += New-ASN1ContextTag -Tag 5 -Data $paChecksum2Seq
            }

            return New-ASN1Sequence -Data ([byte[]]$data)
        }

        function New-SubjectPublicKeyInfo {
            param(
                [System.Numerics.BigInteger]$DHPublicKey
            )

            # SubjectPublicKeyInfo ::= SEQUENCE {
            #     algorithm AlgorithmIdentifier,
            #     subjectPublicKey BIT STRING
            # }

            # AlgorithmIdentifier for DH
            # OID 1.2.840.10046.2.1 = dhpublicnumber
            $dhOid = New-ASN1ObjectIdentifier -OID "1.2.840.10046.2.1"

            # DomainParameters (p, g, q)
            # ValidationParms ::= SEQUENCE {
            #     seed        BIT STRING,
            #     pgenCounter INTEGER
            # }
            # DomainParameters ::= SEQUENCE {
            #     p INTEGER,
            #     g INTEGER,
            #     q INTEGER OPTIONAL
            # }

            $pBytes = ConvertTo-BigEndianBytes -Value $DH_P
            $pASN = New-ASN1Integer -Value $pBytes

            $gASN = New-ASN1Integer -Value $DH_G

            # q is (p-1)/2 for safe primes
            $q = ($DH_P - 1) / 2
            $qBytes = ConvertTo-BigEndianBytes -Value $q
            $qASN = New-ASN1Integer -Value $qBytes

            $domainParams = New-ASN1Sequence -Data ($pASN + $gASN + $qASN)

            $algorithmId = New-ASN1Sequence -Data ($dhOid + $domainParams)

            # Public key as INTEGER wrapped in BIT STRING
            $pubKeyBytes = ConvertTo-BigEndianBytes -Value $DHPublicKey
            $pubKeyASN = New-ASN1Integer -Value $pubKeyBytes
            $pubKeyBitString = New-ASN1BitString -Value $pubKeyASN -UnusedBits 0

            return New-ASN1Sequence -Data ($algorithmId + $pubKeyBitString)
        }

        function New-AuthPack {
            param(
                [byte[]]$PKAuthenticator,
                [byte[]]$ClientPublicValue,
                [byte[]]$ClientDHNonce
            )

            # AuthPack ::= SEQUENCE {
            #     pkAuthenticator     [0] PKAuthenticator,
            #     clientPublicValue   [1] SubjectPublicKeyInfo OPTIONAL,
            #     supportedCMSTypes   [2] SEQUENCE OF AlgorithmIdentifier OPTIONAL,
            #     clientDHNonce       [3] OCTET STRING OPTIONAL
            # }

            $data = @()

            # pkAuthenticator [0]
            $data += New-ASN1ContextTag -Tag 0 -Data $PKAuthenticator

            # clientPublicValue [1]
            if ($ClientPublicValue) {
                $data += New-ASN1ContextTag -Tag 1 -Data $ClientPublicValue
            }

            # supportedCMSTypes [2] - we'll skip this for simplicity

            # clientDHNonce [3]
            if ($ClientDHNonce) {
                $data += New-ASN1ContextTag -Tag 3 -Data (New-ASN1OctetString -Value $ClientDHNonce)
            }

            return New-ASN1Sequence -Data ([byte[]]$data)
        }

        function New-CMSSignedData {
            param(
                [byte[]]$ContentToSign,
                [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
            )

            # Use .NET SignedCms class for CMS/PKCS#7 signing
            Add-Type -AssemblyName System.Security

            # Note: Content MUST be valid DER-encoded ASN.1 for this OID to work
            $pkInitOid = New-Object System.Security.Cryptography.Oid("1.3.6.1.5.2.3.1")  # id-pkinit-authData
            $contentInfo = New-Object System.Security.Cryptography.Pkcs.ContentInfo(
                $pkInitOid,
                $ContentToSign
            )

            $signedCms = New-Object System.Security.Cryptography.Pkcs.SignedCms($contentInfo, $false)

            $signer = New-Object System.Security.Cryptography.Pkcs.CmsSigner($Certificate)
            $signer.IncludeOption = [System.Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
            $signer.DigestAlgorithm = New-Object System.Security.Cryptography.Oid("2.16.840.1.101.3.4.2.1")  # SHA256

            $signedCms.ComputeSignature($signer)

            return $signedCms.Encode()
        }

        function New-PA_PK_AS_REQ {
            param(
                [byte[]]$SignedAuthPack
            )

            if (-not $SignedAuthPack -or $SignedAuthPack.Length -eq 0) {
                throw "SignedAuthPack is empty - cannot build PA-PK-AS-REQ"
            }

            # PA-PK-AS-REQ ::= SEQUENCE {
            #     signedAuthPack    [0] IMPLICIT OCTET STRING,
            #     trustedCertifiers [1] SEQUENCE OF ExternalPrincipalIdentifier OPTIONAL,  -- not used
            #     kdcPkId           [2] IMPLICIT OCTET STRING OPTIONAL                     -- not used
            # }

            # signedAuthPack [0] IMPLICIT OCTET STRING
            # Note: IMPLICIT means we use the context tag directly without wrapping in OCTET STRING tag
            $implicitTag = New-ASN1ContextTag -Tag 0 -Data $SignedAuthPack -Implicit

            return New-ASN1Sequence -Data ([byte[]]$implicitTag)
        }

        function New-KerberosASREQ {
            param(
                [string]$UserName,
                [string]$Realm,
                [byte[]]$PAData,
                [uint32]$Nonce,
                [switch]$NoPAC
            )

            # AS-REQ ::= [APPLICATION 10] KDC-REQ
            # KDC-REQ ::= SEQUENCE {
            #     pvno      [1] INTEGER (5),
            #     msg-type  [2] INTEGER (10 = AS-REQ),
            #     padata    [3] SEQUENCE OF PA-DATA OPTIONAL,
            #     req-body  [4] KDC-REQ-BODY
            # }

            $realmUpper = $Realm.ToUpper()

            # Build KDC-REQ-BODY first (needed for checksum)
            $kdcOptions = New-KerberosKDCOptions -Forwardable -Renewable -Canonicalize -RenewableOK

            # cname - client principal name
            $cname = New-KerberosPrincipalName -NameType $Script:NT_PRINCIPAL -NameStrings @($UserName)

            # sname - krbtgt/REALM
            $sname = New-KerberosPrincipalName -NameType $Script:NT_SRV_INST -NameStrings @("krbtgt", $realmUpper)

            # till - far future
            $till = [datetime]::new(2037, 9, 13, 2, 48, 5, [System.DateTimeKind]::Utc)

            # etype - supported encryption types (prefer AES)
            # Build etypes as concatenated byte array (not array of arrays)
            $etypesBytes = @()
            $etypesBytes += New-ASN1Integer -Value $Script:ETYPE_AES256_CTS_HMAC_SHA1
            $etypesBytes += New-ASN1Integer -Value $Script:ETYPE_AES128_CTS_HMAC_SHA1
            $etypesBytes += New-ASN1Integer -Value $Script:ETYPE_RC4_HMAC

            # KDC-REQ-BODY
            $reqBodyContent = @()

            # kdc-options [0]
            $reqBodyContent += New-ASN1ContextTag -Tag 0 -Data $kdcOptions

            # cname [1]
            $reqBodyContent += New-ASN1ContextTag -Tag 1 -Data $cname

            # realm [2]
            $reqBodyContent += New-ASN1ContextTag -Tag 2 -Data (New-ASN1GeneralString -Value $realmUpper)

            # sname [3]
            $reqBodyContent += New-ASN1ContextTag -Tag 3 -Data $sname

            # till [5]
            $reqBodyContent += New-ASN1ContextTag -Tag 5 -Data (New-ASN1GeneralizedTime -Value $till)

            # nonce [7]
            $reqBodyContent += New-ASN1ContextTag -Tag 7 -Data (New-ASN1Integer -Value $Nonce)

            # etype [8]
            $reqBodyContent += New-ASN1ContextTag -Tag 8 -Data (New-ASN1Sequence -Data ([byte[]]$etypesBytes))

            $reqBody = New-ASN1Sequence -Data ([byte[]]$reqBodyContent)

            # Build padata array
            $padataArray = @()

            # PA-PK-AS-REQ (only if PAData is provided - first call is just for checksum)
            if ($PAData -and $PAData.Length -gt 0) {
                $paPkAsReq = New-KerberosPAData -PADataType $Script:PA_PK_AS_REQ -PADataValue $PAData
                $padataArray += $paPkAsReq
            }

            # PA-PAC-REQUEST (include or exclude PAC)
            $pacRequest = if ($NoPAC) {
                New-ASN1Sequence -Data (New-ASN1ContextTag -Tag 0 -Data (New-ASN1Boolean -Value $false))
            } else {
                New-ASN1Sequence -Data (New-ASN1ContextTag -Tag 0 -Data (New-ASN1Boolean -Value $true))
            }
            $paPacReq = New-KerberosPAData -PADataType $Script:PA_PAC_REQUEST -PADataValue $pacRequest
            $padataArray += $paPacReq

            $padata = New-ASN1Sequence -Data ([byte[]]$padataArray)

            # Build KDC-REQ
            $kdcReqContent = @()

            # pvno [1]
            $kdcReqContent += New-ASN1ContextTag -Tag 1 -Data (New-ASN1Integer -Value 5)

            # msg-type [2]
            $kdcReqContent += New-ASN1ContextTag -Tag 2 -Data (New-ASN1Integer -Value $Script:KRB_AS_REQ)

            # padata [3]
            $kdcReqContent += New-ASN1ContextTag -Tag 3 -Data $padata

            # req-body [4]
            $kdcReqContent += New-ASN1ContextTag -Tag 4 -Data $reqBody

            $kdcReq = New-ASN1Sequence -Data ([byte[]]$kdcReqContent)

            # Wrap in APPLICATION 10 tag
            $asReq = New-ASN1ApplicationTag -Tag 10 -Data $kdcReq

            return @{
                ASReq = $asReq
                ReqBody = $reqBody
            }
        }

        #endregion

        #region AS-REP Parsing

        function ConvertFrom-ASREP {
            param([byte[]]$Data)

            $result = @{
                Success = $false
                Error = $null
                Ticket = $null
                EncPart = $null
                PAData = @()
                EType = $null
            }

            try {
                # Read APPLICATION tag
                $root = Read-ASN1Element -Data $Data -Offset 0

                # Check for KRB-ERROR (APPLICATION 30)
                if (($root.Tag -band 0x1F) -eq 30) {
                    $result.Error = "KRB-ERROR received"
                    # Parse error details - try to extract error code
                    # KRB-ERROR structure: APPLICATION 30 -> SEQUENCE -> children
                    try {
                        # First child should be SEQUENCE containing all fields
                        $seqElement = Read-ASN1Element -Data $root.Content -Offset 0

                        # Parse children of the SEQUENCE
                        $children = Read-ASN1Children -Data $seqElement.Content
                        foreach ($child in $children) {
                            # CONTEXT tags have high bit set: [0]=0xA0, [6]=0xA6
                            $contextTag = $child.Tag -band 0x1F
                            if ($contextTag -eq 6) {  # error-code [6] INTEGER
                                try {
                                    $innerElem = Read-ASN1Element -Data $child.Content
                                    if ($innerElem.Content -and $innerElem.Content.Length -gt 0) {
                                        $errorCode = 0
                                        foreach ($b in $innerElem.Content) {
                                            $errorCode = ($errorCode -shl 8) -bor $b
                                        }
                                        # Use centralized Kerberos error code mapping
                                        $errorDesc = Get-KerberosErrorMessage -ErrorCode $errorCode
                                        $result.Error = "KRB-ERROR $errorCode`: $errorDesc"
                                    }
                                } catch {
                                    Write-Log "[ConvertFrom-ASREP] Failed to parse error code: $_"
                                }
                            }
                            elseif ($contextTag -eq 12) {  # e-text [12] GeneralString
                                try {
                                    $innerElem = Read-ASN1Element -Data $child.Content
                                    if ($innerElem.Content) {
                                        $etext = [System.Text.Encoding]::UTF8.GetString($innerElem.Content)
                                        # Clean e-text: remove non-printable characters
                                        $etext = $etext -replace '[^\x20-\x7E]', ''
                                        $etext = $etext.Trim()
                                        # Only append if e-text contains meaningful content (more than just single chars/digits)
                                        if ($etext -and $etext.Length -gt 2) {
                                            $result.Error += " - $etext"
                                        }
                                    }
                                } catch {
                                    Write-Log "[ConvertFrom-ASREP] Failed to parse e-text: $_"
                                }
                            }
                        }
                    } catch {
                        Write-Log "[ConvertFrom-ASREP] Failed to parse KRB-ERROR details: $_"
                    }
                    return $result
                }

                # Check for AS-REP (APPLICATION 11)
                if (($root.Tag -band 0x1F) -ne 11) {
                    $result.Error = "Unexpected response type: $($root.Tag)"
                    return $result
                }

                # Parse KDC-REP structure
                # AS-REP: [APPLICATION 11] -> SEQUENCE -> context-tagged fields
                # The root.Content starts with SEQUENCE, we need to parse inside it
                $innerSeq = Read-ASN1Element -Data $root.Content -Offset 0

                $childrenData = if ($innerSeq.Tag -eq 0x30) {
                    # Inner is a SEQUENCE - parse its children
                    $innerSeq.Content
                } else {
                    # No inner SEQUENCE (shouldn't happen), try root content directly
                    $root.Content
                }

                $children = Read-ASN1Children -Data $childrenData

                foreach ($child in $children) {
                    switch ($child.TagNumber) {
                        # RFC 4120 AS-REP structure:
                        # [0] pvno INTEGER
                        # [1] msg-type INTEGER
                        # [2] padata SEQUENCE OF PA-DATA OPTIONAL
                        # [3] crealm Realm (GeneralString)
                        # [4] cname PrincipalName
                        # [5] ticket Ticket
                        # [6] enc-part EncryptedData
                        0 {  # pvno [0]
                            $pvnoElement = Read-ASN1Element -Data $child.Content
                            $pvno = Read-ASN1Integer -Content $pvnoElement.Content
                        }
                        1 {  # msg-type [1]
                            $msgTypeElement = Read-ASN1Element -Data $child.Content
                            $msgType = Read-ASN1Integer -Content $msgTypeElement.Content
                        }
                        2 {  # padata [2] SEQUENCE OF PA-DATA
                            try {
                                $padataSeq = Read-ASN1Element -Data $child.Content
                                $padataChildren = Read-ASN1Children -Data $padataSeq.Content

                                foreach ($pa in $padataChildren) {
                                    # Each PA-DATA is a SEQUENCE with padata-type [1] and padata-value [2]
                                    $paSeq = Read-ASN1Element -Data $pa.Content
                                    if ($paSeq.Tag -eq 0x30) {
                                        $paChildren = Read-ASN1Children -Data $paSeq.Content
                                    } else {
                                        $paChildren = Read-ASN1Children -Data $pa.Content
                                    }
                                    $paType = $null
                                    $paValue = $null

                                    foreach ($paChild in $paChildren) {
                                        if ($paChild.TagNumber -eq 1) {
                                            $paTypeElement = Read-ASN1Element -Data $paChild.Content
                                            $paType = Read-ASN1Integer -Content $paTypeElement.Content
                                        }
                                        elseif ($paChild.TagNumber -eq 2) {
                                            $paValueElement = Read-ASN1Element -Data $paChild.Content
                                            $paValue = $paValueElement.Content
                                        }
                                    }

                                    if ($null -ne $paType) {
                                        $result.PAData += @{
                                            Type = $paType
                                            Value = $paValue
                                        }
                                    }
                                }
                            } catch {
                                Write-Log "[ConvertFrom-ASREP] Error parsing padata: $_"
                            }
                        }
                        3 {  # crealm [3] Realm (GeneralString)
                            $crealmElement = Read-ASN1Element -Data $child.Content
                            $result.Realm = [System.Text.Encoding]::ASCII.GetString($crealmElement.Content)
                        }
                        4 {  # cname [4] PrincipalName - skip
                        }
                        5 {  # ticket [5]
                            $result.Ticket = $child.Content
                        }
                        6 {  # enc-part [6]
                            $encPartSeq = Read-ASN1Element -Data $child.Content
                            $encPartChildren = Read-ASN1Children -Data $encPartSeq.Content

                            foreach ($encChild in $encPartChildren) {
                                if ($encChild.TagNumber -eq 0) {  # etype
                                    $result.EType = Read-ASN1Integer -Content (Read-ASN1Element -Data $encChild.Content).Content
                                }
                                elseif ($encChild.TagNumber -eq 2) {  # cipher
                                    $result.EncPart = (Read-ASN1Element -Data $encChild.Content).Content
                                }
                            }
                        }
                    }
                }

                $result.Success = $true
            }
            catch {
                $result.Error = "Failed to parse AS-REP: $_"
            }

            return $result
        }

        function ConvertFrom-PaPkAsRep {
            param([byte[]]$Data)

            $result = @{
                Success = $false
                DHKeyInfo = $null
                ServerDHNonce = $null
            }

            try {
                # PA-PK-AS-REP ::= CHOICE {
                #     dhInfo        [0] DHRepInfo,
                #     encKeyPack    [1] IMPLICIT OCTET STRING
                # }

                $root = Read-ASN1Element -Data $Data -Offset 0

                if ($root.TagNumber -eq 0) {
                    # DHRepInfo - this is what we expect
                    # DHRepInfo ::= SEQUENCE {
                    #     dhSignedData    [0] IMPLICIT OCTET STRING,
                    #     serverDHNonce   [1] OCTET STRING OPTIONAL
                    # }

                    # The root content is the DHRepInfo SEQUENCE
                    $dhRepInfo = Read-ASN1Element -Data $root.Content
                    $dhChildren = Read-ASN1Children -Data $dhRepInfo.Content

                    foreach ($child in $dhChildren) {
                        if ($child.TagNumber -eq 0) {
                            # dhSignedData [0] IMPLICIT OCTET STRING
                            # IMPLICIT means the [0] tag REPLACES the OCTET STRING tag
                            # So the content IS the CMS SignedData directly
                            $result.DHSignedData = $child.Content
                        }
                        elseif ($child.TagNumber -eq 1) {
                            # serverDHNonce [1] OCTET STRING
                            $nonceElement = Read-ASN1Element -Data $child.Content
                            $result.ServerDHNonce = $nonceElement.Content
                        }
                    }

                    # Parse the CMS SignedData to get KDCDHKeyInfo
                    if ($result.DHSignedData) {
                        $result.DHKeyInfo = ConvertFrom-KDCDHKeyInfo -SignedData $result.DHSignedData
                    }

                    $result.Success = $true
                }
                elseif ($root.TagNumber -eq 1) {
                    # encKeyPack - RSA mode, not implemented
                    $result.Error = "RSA key encapsulation mode not supported"
                }
            }
            catch {
                $result.Error = "Failed to parse PA-PK-AS-REP: $_"
            }

            return $result
        }

        function ConvertFrom-KDCDHKeyInfo {
            param([byte[]]$SignedData)

            # Parse CMS SignedData to extract encapsulated content
            Add-Type -AssemblyName System.Security

            try {
                $signedCms = New-Object System.Security.Cryptography.Pkcs.SignedCms
                $signedCms.Decode($SignedData)

                # Get the content (KDCDHKeyInfo)
                $content = $signedCms.ContentInfo.Content

                # KDCDHKeyInfo ::= SEQUENCE {
                #     subjectPublicKey    [0] BIT STRING,
                #     nonce               [1] INTEGER,
                #     dhKeyExpiration     [2] KerberosTime OPTIONAL
                # }

                $keyInfo = Read-ASN1Element -Data $content
                $keyInfoChildren = Read-ASN1Children -Data $keyInfo.Content

                $result = @{
                    ServerPublicKey = $null
                    Nonce = $null
                }

                foreach ($child in $keyInfoChildren) {
                    if ($child.TagNumber -eq 0) {
                        # subjectPublicKey [0] - context tag wrapping BIT STRING
                        $bitStringElement = Read-ASN1Element -Data $child.Content

                        if ($bitStringElement.Tag -eq 0x03) {
                            # Proper BIT STRING - first byte is unused bits count
                            $bitStringData = $bitStringElement.Content[1..($bitStringElement.Content.Length - 1)]

                            # The BIT STRING contains an INTEGER (the DH public key)
                            $pubKeyInt = Read-ASN1Element -Data $bitStringData

                            # The content is the DH public key as INTEGER
                            $pubKeyBytes = $pubKeyInt.Content
                            # Remove leading zero if present (for positive numbers)
                            if ($pubKeyBytes[0] -eq 0x00 -and $pubKeyBytes.Length -gt 1) {
                                $pubKeyBytes = $pubKeyBytes[1..($pubKeyBytes.Length - 1)]
                            }

                            # Convert to BigInteger (big-endian input, so reverse for little-endian)
                            $pubKeyBytesLE = [byte[]]::new($pubKeyBytes.Length)
                            [Array]::Copy($pubKeyBytes, $pubKeyBytesLE, $pubKeyBytes.Length)
                            [Array]::Reverse($pubKeyBytesLE)
                            # Add zero byte if needed to ensure positive interpretation
                            if ($pubKeyBytesLE.Length -gt 0 -and ($pubKeyBytesLE[$pubKeyBytesLE.Length - 1] -band 0x80)) {
                                $pubKeyBytesLE = [byte[]]($pubKeyBytesLE + @([byte]0x00))
                            }
                            $result.ServerPublicKey = [System.Numerics.BigInteger]::new($pubKeyBytesLE)
                        }
                    }
                    elseif ($child.TagNumber -eq 1) {
                        # nonce [1]
                        $nonceElement = Read-ASN1Element -Data $child.Content
                        $result.Nonce = Read-ASN1Integer -Content $nonceElement.Content
                    }
                }

                return $result
            }
            catch {
                Write-Log "[ConvertFrom-KDCDHKeyInfo] Error parsing CMS: $_"
                return $null
            }
        }

        #endregion

        #region Key Derivation

        function Get-PKINITSessionKey {
            param(
                [byte[]]$SharedSecret,
                [byte[]]$ClientDHNonce,
                [byte[]]$ServerDHNonce,
                [int]$EType
            )

            # Key derivation as per RFC 4556 Section 3.2.3.1
            # octetstring2key(x) == random-to-key(K-truncate(
            #     SHA1(0x00 | x) | SHA1(0x01 | x) | SHA1(0x02 | x) | ...
            # ))
            # Where x = DHSharedSecret || n_c || n_k
            # n_c = clientDHNonce, n_k = serverDHNonce (when DH nonces are used)
            #
            # The counter (0x00, 0x01, etc.) is a single byte PREPENDED to x
            # NO "pkinit" constant - that was wrong!

            $keyMaterial = [byte[]]$SharedSecret + [byte[]]$ClientDHNonce + [byte[]]$ServerDHNonce

            $keyLength = switch ($EType) {
                $ETYPE_AES128_CTS { 16 }  # AES128
                $ETYPE_AES256_CTS { 32 }  # AES256
                $ETYPE_RC4_HMAC { 16 }    # RC4
                default { 16 }
            }

            $derivedKey = [System.Collections.Generic.List[byte]]::new()
            $counter = 0

            while ($derivedKey.Count -lt $keyLength) {
                # RFC 4556: SHA1(counter_byte | x) where counter starts at 0x00
                $toHash = [byte[]]@([byte]$counter) + $keyMaterial
                $hash = Get-SHA1Hash -Data $toHash
                foreach ($b in $hash) {
                    $derivedKey.Add($b)
                }
                $counter++
            }

            return [byte[]]$derivedKey.GetRange(0, $keyLength).ToArray()
        }

        function Unprotect-KerberosData {
            param(
                [byte[]]$CipherText,
                [byte[]]$Key,
                [int]$EType,
                [int]$KeyUsage
            )

            switch ($EType) {
                $ETYPE_RC4_HMAC {
                    # RC4-HMAC - use centralized function from Kerberos-Crypto.ps1
                    return Decrypt-RC4HMAC -Key $Key -CipherText $CipherText -KeyUsage $KeyUsage
                }
                $ETYPE_AES128_CTS {
                    # AES128-CTS-HMAC-SHA1-96 - use centralized function from Kerberos-Crypto.ps1
                    return Decrypt-AESCTS -Key $Key -CipherText $CipherText -KeyUsage $KeyUsage
                }
                $ETYPE_AES256_CTS {
                    # AES256-CTS-HMAC-SHA1-96 - use centralized function from Kerberos-Crypto.ps1
                    return Decrypt-AESCTS -Key $Key -CipherText $CipherText -KeyUsage $KeyUsage
                }
                default {
                    throw "Unsupported encryption type: $EType"
                }
            }
        }

        #endregion
    }

    process {
        try {
            # Step 1: Generate DH key pair
            $dhKeyPair = New-DHKeyPair

            # Step 2: Generate nonces
            $clientDHNonce = New-PKINITDHNonce
            $krbNonce = [uint32](Get-Random -Minimum 1 -Maximum 2147483647)

            # Step 3: Build AS-REQ body first (for checksum)

            # Temporary AS-REQ to get req-body for checksum
            $tempASReq = New-KerberosASREQ -UserName $UserName -Realm $Domain -PAData @() -Nonce $krbNonce -NoPAC:$NoPAC

            # Calculate both SHA-1 (RFC 4556) and SHA-256 (MS-PKCA for Windows Server 2022+) checksums
            $reqBodyChecksum = Get-SHA1Hash -Data $tempASReq.ReqBody
            $reqBodyChecksum256 = Get-SHA256Hash -Data $tempASReq.ReqBody

            # Step 4: Build PKAuthenticator with both paChecksum (SHA-1) and paChecksum2 (SHA-256)
            # paChecksum2 is required for Windows Server 2022+ to avoid KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED (error 79)
            $now = [datetime]::UtcNow
            $cusec = $now.Millisecond * 1000
            $pkAuthenticator = New-PKAuthenticator -CuSec $cusec -CTime $now -Nonce $krbNonce -PaChecksum $reqBodyChecksum -PaChecksum2 $reqBodyChecksum256

            Write-Log "[Invoke-PKINITAuth-Native] PKAuthenticator built with paChecksum (SHA-1) and paChecksum2 (SHA-256)"

            # Step 5: Build SubjectPublicKeyInfo for DH
            $clientPublicKeyInfo = New-SubjectPublicKeyInfo -DHPublicKey $dhKeyPair.PublicKey

            # Step 6: Build AuthPack
            $authPack = New-AuthPack -PKAuthenticator $pkAuthenticator -ClientPublicValue $clientPublicKeyInfo -ClientDHNonce $clientDHNonce

            # Step 7: Sign AuthPack with certificate (CMS SignedData)
            if (-not $authPack -or $authPack.Length -eq 0) {
                throw "AuthPack is empty - cannot sign"
            }
            $signedAuthPack = New-CMSSignedData -ContentToSign $authPack -Certificate $Cert

            # Step 8: Build PA-PK-AS-REQ
            $paPkAsReq = New-PA_PK_AS_REQ -SignedAuthPack $signedAuthPack

            # Step 9: Build final AS-REQ with PA-DATA
            $asReqResult = New-KerberosASREQ -UserName $UserName -Realm $Domain -PAData $paPkAsReq -Nonce $krbNonce -NoPAC:$NoPAC
            $asReqBytes = $asReqResult.ASReq

            # Step 10: Send AS-REQ to KDC
            Write-Log "[Invoke-PKINITAuth-Native] Sending AS-REQ to $DomainController`:88..."

            $tcpClient = $null
            $stream = $null
            $responseBytes = $null

            try {
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $tcpClient.Connect($DomainController, 88)
                $stream = $tcpClient.GetStream()
                $stream.ReadTimeout = 30000
                $stream.WriteTimeout = 30000

                # Kerberos TCP format: 4-byte big-endian length prefix
                $lengthBytes = [System.BitConverter]::GetBytes([uint32]$asReqBytes.Length)
                [Array]::Reverse($lengthBytes)
                $stream.Write($lengthBytes, 0, 4)
                $stream.Write($asReqBytes, 0, $asReqBytes.Length)
                $stream.Flush()

                # Read response
                $responseLengthBytes = New-Object byte[] 4
                $stream.Read($responseLengthBytes, 0, 4) | Out-Null
                [Array]::Reverse($responseLengthBytes)
                $responseLength = [System.BitConverter]::ToUInt32($responseLengthBytes, 0)

                $responseBytes = New-Object byte[] $responseLength
                $bytesRead = 0
                while ($bytesRead -lt $responseLength) {
                    $bytesRead += $stream.Read($responseBytes, $bytesRead, $responseLength - $bytesRead)
                }

            }
            finally {
                # Ensure TCP resources are always cleaned up
                if ($stream) { try { $stream.Close() } catch { } }
                if ($tcpClient) { try { $tcpClient.Close() } catch { } }
            }

            # Step 11: Parse AS-REP
            $asRep = ConvertFrom-ASREP -Data $responseBytes

            if (-not $asRep.Success) {
                # Distinguish between KRB-ERROR and parsing failures
                if ($asRep.Error -match "^KRB-ERROR") {
                    throw $asRep.Error
                } else {
                    throw "Failed to parse KDC response: $($asRep.Error)"
                }
            }

            # Step 12: Find and parse PA-PK-AS-REP
            # Debug: Show all PA-DATA types received
            if ($asRep.PAData -and $asRep.PAData.Count -gt 0) {
                $paTypes = $asRep.PAData | ForEach-Object {
                    $paTypeName = switch ($_.Type) {
                        2   { "PA-ENC-TIMESTAMP" }
                        11  { "PA-ETYPE-INFO" }
                        16  { "PA-PK-AS-REQ" }
                        17  { "PA-PK-AS-REP" }
                        19  { "PA-ETYPE-INFO2" }
                        128 { "PA-PAC-REQUEST" }
                        133 { "PA-FX-COOKIE" }
                        134 { "PA-AUTHENTICATION-SET" }
                        135 { "PA-AUTH-SET-SELECTED" }
                        136 { "PA-FX-FAST" }
                        137 { "PA-FX-ERROR" }
                        165 { "PA-SUPPORTED-ENCTYPES" }
                        default { "Unknown-$($_.Type)" }
                    }
                    "$paTypeName ($($_.Type))"
                }
                Write-Log "[Invoke-PKINITAuth-Native] PA-DATA types in response: $($paTypes -join ', ')"
            } else {
                Write-Log "[Invoke-PKINITAuth-Native] No PA-DATA in response"
            }

            $paPkAsRep = $asRep.PAData | Where-Object { $_.Type -eq $Script:PA_PK_AS_REP } | Select-Object -First 1

            if (-not $paPkAsRep) {
                # Provide more helpful error message based on what was received
                $errorMsg = "PA-PK-AS-REP (type 17) not found in KDC response"
                if ($asRep.PAData -and $asRep.PAData.Count -gt 0) {
                    $hasEtypeInfo2 = $asRep.PAData | Where-Object { $_.Type -eq 19 }
                    if ($hasEtypeInfo2) {
                        $errorMsg += ". KDC responded with PA-ETYPE-INFO2 indicating it expects password-based auth instead of certificate. "
                        $errorMsg += "Check: 1) Certificate has Smart Card Logon EKU (1.3.6.1.4.1.311.20.2.2) or Client Authentication EKU (1.3.6.1.5.5.7.3.2), "
                        $errorMsg += "2) CA is in AD NTAuth store, 3) UPN in certificate matches AD user"
                    }
                }
                throw $errorMsg
            }

            $dhRepInfo = ConvertFrom-PaPkAsRep -Data $paPkAsRep.Value

            if (-not $dhRepInfo.Success) {
                throw "Failed to parse PA-PK-AS-REP: $($dhRepInfo.Error)"
            }

            if (-not $dhRepInfo.DHKeyInfo -or -not $dhRepInfo.DHKeyInfo.ServerPublicKey) {
                throw "Server DH public key not found in response"
            }

            # Step 13: Calculate shared secret
            $sharedSecret = Get-DHSharedSecret -TheirPublicKey $dhRepInfo.DHKeyInfo.ServerPublicKey -MyPrivateKey $dhKeyPair.PrivateKey
            $sharedSecretBytes = ConvertTo-BigEndianBytes -Value $sharedSecret

            # Step 14: Derive session key
            $serverDHNonce = if ($dhRepInfo.ServerDHNonce) { $dhRepInfo.ServerDHNonce } else { @() }
            $sessionKey = Get-PKINITSessionKey -SharedSecret $sharedSecretBytes -ClientDHNonce $clientDHNonce -ServerDHNonce $serverDHNonce -EType $asRep.EType

            # Save the DH-derived key as AS-REP Reply Key (needed for UnPAC-the-hash PAC_CREDENTIAL_INFO decryption, KeyUsage=16)
            $asRepReplyKey = [byte[]]$sessionKey.Clone()

            # Step 15: Decrypt enc-part to get EncASRepPart

            $authTime = $null
            $startTime = $null
            $endTime = $null
            $renewTill = $null
            $ticketFlags = $null  # Raw flags from EncKDCRepPart
            $encPartSessionKey = $null  # Session key from EncKDCRepPart (should match DH-derived)

            try {
                $decryptedEncPart = Unprotect-KerberosData -CipherText $asRep.EncPart -Key $sessionKey -EType $asRep.EType -KeyUsage 3  # 3 = AS-REP encrypted part

                # Parse EncKDCRepPart to extract session key, flags, and time fields
                # EncKDCRepPart ::= SEQUENCE {
                #     key             [0] EncryptionKey,
                #     last-req        [1] LastReq,
                #     nonce           [2] UInt32,
                #     key-expiration  [3] KerberosTime OPTIONAL,
                #     flags           [4] TicketFlags,
                #     authtime        [5] KerberosTime,
                #     starttime       [6] KerberosTime OPTIONAL,
                #     endtime         [7] KerberosTime,
                #     renew-till      [8] KerberosTime OPTIONAL,
                #     srealm          [9] Realm,
                #     sname           [10] PrincipalName,
                #     caddr           [11] HostAddresses OPTIONAL
                # }
                try {
                    $root = Read-ASN1Element -Data $decryptedEncPart
                    $contentToParse = $root.Content
                    if ($root.Tag -ne 0x30) {
                        $innerSeq = Read-ASN1Element -Data $root.Content -Offset 0
                        $contentToParse = $innerSeq.Content
                    }
                    $children = Read-ASN1Children -Data $contentToParse

                    foreach ($child in $children) {
                        switch ($child.TagNumber) {
                            0 {
                                # key [0] EncryptionKey
                                # EncryptionKey ::= SEQUENCE { keytype [0] INT32, keyvalue [1] OCTET STRING }
                                try {
                                    $keySeq = Read-ASN1Element -Data $child.Content
                                    $keyChildren = Read-ASN1Children -Data $keySeq.Content
                                    foreach ($keyChild in $keyChildren) {
                                        if ($keyChild.TagNumber -eq 1) {
                                            # keyvalue [1] OCTET STRING
                                            $keyValueElement = Read-ASN1Element -Data $keyChild.Content
                                            $encPartSessionKey = $keyValueElement.Content
                                        }
                                    }
                                }
                                catch { }
                            }
                            4 {
                                # flags [4] TicketFlags (BIT STRING)
                                try {
                                    $flagsElement = Read-ASN1Element -Data $child.Content
                                    # BIT STRING: first byte is unused bits count, rest is the flags
                                    if ($flagsElement.Content.Length -ge 5) {
                                        # Skip unused bits byte, take 4 bytes of flags
                                        $ticketFlags = [byte[]]$flagsElement.Content[1..4]
                                    }
                                }
                                catch { }
                            }
                            5 {
                                # authtime [5] KerberosTime
                                $timeElement = Read-ASN1Element -Data $child.Content
                                $timeString = [System.Text.Encoding]::ASCII.GetString($timeElement.Content)
                                $authTime = [DateTime]::ParseExact($timeString, "yyyyMMddHHmmssZ", $null, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal)
                            }
                            6 {
                                # starttime [6] KerberosTime OPTIONAL
                                $timeElement = Read-ASN1Element -Data $child.Content
                                $timeString = [System.Text.Encoding]::ASCII.GetString($timeElement.Content)
                                $startTime = [DateTime]::ParseExact($timeString, "yyyyMMddHHmmssZ", $null, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal)
                            }
                            7 {
                                # endtime [7] KerberosTime
                                $timeElement = Read-ASN1Element -Data $child.Content
                                $timeString = [System.Text.Encoding]::ASCII.GetString($timeElement.Content)
                                $endTime = [DateTime]::ParseExact($timeString, "yyyyMMddHHmmssZ", $null, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal)
                            }
                            8 {
                                # renew-till [8] KerberosTime OPTIONAL
                                $timeElement = Read-ASN1Element -Data $child.Content
                                $timeString = [System.Text.Encoding]::ASCII.GetString($timeElement.Content)
                                $renewTill = [DateTime]::ParseExact($timeString, "yyyyMMddHHmmssZ", $null, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal)
                            }
                        }
                    }

                    # Verify session key matches (for debugging)
                    if ($encPartSessionKey) {
                        $keysMatch = $true
                        if ($encPartSessionKey.Length -ne $sessionKey.Length) {
                            $keysMatch = $false
                        } else {
                            for ($i = 0; $i -lt $sessionKey.Length; $i++) {
                                if ($sessionKey[$i] -ne $encPartSessionKey[$i]) {
                                    $keysMatch = $false
                                    break
                                }
                            }
                        }
                        if (-not $keysMatch) {
                            # This is normal behavior - the EncKDCRepPart contains the authoritative session key
                            # The DH-derived key was only used to decrypt the EncKDCRepPart
                            $sessionKey = $encPartSessionKey
                        }
                    }

                }
                catch { }
            }
            catch {
                Write-Warning "[!] Failed to decrypt AS-REP enc-part: $_"
                Write-Warning "[!] This may be a key derivation issue. Continuing with ticket..."
            }

            # Step 16: Build result
            $ticketB64 = [Convert]::ToBase64String($asRep.Ticket)
            $sessionKeyB64 = [Convert]::ToBase64String($sessionKey)

            # Optional: Save as .kirbi (KRB-CRED format with session key)
            if ($OutputKirbi) {
                if (-not $sessionKey -or $sessionKey.Length -eq 0) {
                    Write-Warning "[Invoke-PKINITAuth-Native] Cannot save kirbi: Session key not available"
                } else {
                    $krbCredBytes = Build-KRBCred -Ticket $asRep.Ticket `
                        -SessionKey $sessionKey `
                        -SessionKeyType $asRep.EType `
                        -Realm $Domain.ToUpper() `
                        -ClientName $UserName `
                        -ServerName "krbtgt" `
                        -ServerInstance $Domain.ToUpper() `
                        -StartTime $startTime `
                        -EndTime $endTime `
                        -RenewTill $renewTill

                    $exportResult = Export-adPEASFile -Path $OutputKirbi -Content $krbCredBytes -Type Binary -Force
                    if ($exportResult.Success) {
                        Write-Log "[Invoke-PKINITAuth-Native] Kirbi (KRB-CRED) saved to: $($exportResult.Path) ($($exportResult.BytesWritten) bytes)"
                    } else {
                        Write-Warning "[Invoke-PKINITAuth-Native] Failed to save kirbi: $($exportResult.Message)"
                    }
                }
            }

            return [PSCustomObject]@{
                Success = $true
                Method = "PKINIT-DH"
                UserName = $UserName
                Domain = $Domain.ToUpper()
                DomainController = $DomainController
                EncryptionType = $asRep.EType
                Ticket = $ticketB64
                SessionKey = $sessionKeyB64
                SessionKeyBytes = $sessionKey
                TicketBytes = $asRep.Ticket
                AuthTime = $authTime
                StartTime = $startTime
                EndTime = $endTime
                RenewTill = $renewTill
                TicketFlags = $ticketFlags  # Raw 4-byte flags from EncKDCRepPart
                ASRepReplyKey = $asRepReplyKey  # DH-derived key for UnPAC-the-hash (PAC_CREDENTIAL_INFO decryption)
                Message = "PKINIT authentication successful"
            }
        }
        catch {
            return [PSCustomObject]@{
                Success = $false
                Method = "PKINIT-DH"
                UserName = $UserName
                Domain = $Domain
                Error = $_.Exception.Message
                Message = "PKINIT authentication failed: $_"
            }
        }
        finally {
            # Cleanup - only dispose certificate if we created it (not if passed by caller)
            if ($CertCreatedByUs -and $Cert) {
                $Cert.Dispose()
            }
        }
    }

    end { }
}
