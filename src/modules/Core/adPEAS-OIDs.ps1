<#
.SYNOPSIS
    Central OID mapping for adPEAS - Extended Key Usage (EKU) and Certificate Extension OIDs.

.DESCRIPTION
    This module provides a centralized, comprehensive mapping of OIDs (Object Identifiers)
    used throughout adPEAS for certificate analysis, PKINIT authentication, and ADCS checks.

    All modules should use these central definitions instead of maintaining their own mappings.

.NOTES
    Author: Alexander Sturz (@_61106960_)
    Part of adPEAS v2 - Active Directory Privilege Escalation Awesome Scripts
#>

# =============================================================================
# CENTRAL OID MAPPING
# =============================================================================

# Well-known OIDs mapping (EKU + Critical Extensions)
# This is the single source of truth for OID-to-name mappings in adPEAS
$Script:OIDMap = @{
    # =========================================================================
    # Extended Key Usage (EKU) OIDs - Standard (RFC 5280)
    # =========================================================================
    "1.3.6.1.5.5.7.3.1"         = "Server Authentication"
    "1.3.6.1.5.5.7.3.2"         = "Client Authentication"
    "1.3.6.1.5.5.7.3.3"         = "Code Signing"
    "1.3.6.1.5.5.7.3.4"         = "Email Protection"
    "1.3.6.1.5.5.7.3.5"         = "IPSec End System"
    "1.3.6.1.5.5.7.3.6"         = "IPSec Tunnel"
    "1.3.6.1.5.5.7.3.7"         = "IPSec User"
    "1.3.6.1.5.5.7.3.8"         = "Time Stamping"
    "1.3.6.1.5.5.7.3.9"         = "OCSP Signing"

    # =========================================================================
    # Extended Key Usage (EKU) OIDs - Microsoft Specific
    # =========================================================================
    "1.3.6.1.4.1.311.10.3.1"    = "Certificate Trust List (CTL) Signing"
    "1.3.6.1.4.1.311.10.3.2"    = "Time Stamp Signing"
    "1.3.6.1.4.1.311.10.3.3"    = "Server Gated Crypto (SGC)"
    "1.3.6.1.4.1.311.10.3.4"    = "Encrypted File System (EFS)"
    "1.3.6.1.4.1.311.10.3.4.1"  = "EFS Recovery"
    "1.3.6.1.4.1.311.10.3.5"    = "Windows Hardware Driver Verification"
    "1.3.6.1.4.1.311.10.3.6"    = "Windows System Component Verification"
    "1.3.6.1.4.1.311.10.3.7"    = "OEM Windows System Component Verification"
    "1.3.6.1.4.1.311.10.3.8"    = "Embedded Windows System Component Verification"
    "1.3.6.1.4.1.311.10.3.9"    = "Root List Signer"
    "1.3.6.1.4.1.311.10.3.10"   = "Qualified Subordination"
    "1.3.6.1.4.1.311.10.3.11"   = "Key Recovery"
    "1.3.6.1.4.1.311.10.3.12"   = "Document Signing"
    "1.3.6.1.4.1.311.10.3.13"   = "Lifetime Signing"
    "1.3.6.1.4.1.311.10.5.1"    = "Digital Rights"
    "1.3.6.1.4.1.311.10.6.1"    = "Key Pack Licenses"
    "1.3.6.1.4.1.311.10.6.2"    = "License Server Verification"
    "1.3.6.1.4.1.311.20.2.1"    = "Certificate Request Agent (Enrollment Agent)"
    "1.3.6.1.4.1.311.20.2.2"    = "Smartcard Logon"
    "1.3.6.1.4.1.311.21.5"      = "Certificate Authority (CA) Encryption Certificate"
    "1.3.6.1.4.1.311.21.6"      = "Key Recovery Agent"
    "1.3.6.1.4.1.311.21.19"     = "Directory Service Email Replication"
    "1.3.6.1.4.1.311.54.1.2"    = "Remote Desktop Authentication"

    # =========================================================================
    # Windows Code Signing / Driver EKUs (Pentesting-relevant)
    # =========================================================================
    "1.3.6.1.4.1.311.61.1.1"    = "Kernel Mode Code Signing"
    "1.3.6.1.4.1.311.61.4.1"    = "Early Launch Antimalware Driver"
    "1.3.6.1.4.1.311.61.5.1"    = "HAL Extension"
    "1.3.6.1.4.1.311.76.3.1"    = "Windows TCB Component"
    "1.3.6.1.4.1.311.76.5.1"    = "Windows Store"
    "1.3.6.1.4.1.311.76.6.1"    = "Windows Software Extension Verification"
    "1.3.6.1.4.1.311.76.8.1"    = "System Health Authentication"

    # =========================================================================
    # Kerberos / PKINIT Specific EKUs
    # =========================================================================
    "1.3.6.1.5.2.3.4"           = "PKINIT Client Authentication"
    "1.3.6.1.5.2.3.5"           = "KDC Authentication"

    # =========================================================================
    # Special EKU Values
    # =========================================================================
    "2.5.29.37.0"               = "Any Purpose"
    "2.5.29.32.0"               = "All Issuance Policies"

    # =========================================================================
    # Legacy / Netscape EKUs
    # =========================================================================
    "2.16.840.1.113730.4.1"     = "Netscape SGC"

    # =========================================================================
    # Certificate Extension OIDs (X.509v3 Standard)
    # =========================================================================
    "2.5.29.9"                  = "Subject Directory Attributes"
    "2.5.29.14"                 = "Subject Key Identifier"
    "2.5.29.15"                 = "Key Usage"
    "2.5.29.17"                 = "Subject Alternative Name"
    "2.5.29.18"                 = "Issuer Alternative Name"
    "2.5.29.19"                 = "Basic Constraints"
    "2.5.29.30"                 = "Name Constraints"
    "2.5.29.31"                 = "CRL Distribution Points"
    "2.5.29.32"                 = "Certificate Policies"
    "2.5.29.33"                 = "Policy Mappings"
    "2.5.29.35"                 = "Authority Key Identifier"
    "2.5.29.36"                 = "Policy Constraints"
    "2.5.29.37"                 = "Extended Key Usage"
    "2.5.29.46"                 = "Freshest CRL (Delta CRL)"
    "2.5.29.54"                 = "Inhibit Any Policy"

    # =========================================================================
    # Authority Information Access (AIA) and related
    # =========================================================================
    "1.3.6.1.5.5.7.1.1"         = "Authority Information Access (AIA)"
    "1.3.6.1.5.5.7.48.1"        = "OCSP"
    "1.3.6.1.5.5.7.48.2"        = "CA Issuers"

    # =========================================================================
    # Microsoft Certificate Template Extensions (ADCS-critical)
    # =========================================================================
    "1.3.6.1.4.1.311.20.2"      = "Certificate Template Name (szOID_ENROLL_CERTTYPE_EXTENSION)"
    "1.3.6.1.4.1.311.21.7"      = "Certificate Template Information"
    "1.3.6.1.4.1.311.21.10"     = "Application Policies"

    # =========================================================================
    # Microsoft ADCS Security Extensions (Critical for ESC vulnerabilities)
    # =========================================================================
    "1.3.6.1.4.1.311.25.2"      = "NTDS CA Security Extension (szOID_NTDS_CA_SECURITY_EXT)"

    # =========================================================================
    # Microsoft Enrollment Extensions
    # =========================================================================
    "1.3.6.1.4.1.311.21.1"      = "CA Version"
    "1.3.6.1.4.1.311.21.2"      = "Previous CA Certificate Hash"
    "1.3.6.1.4.1.311.21.3"      = "Virtual Base CRL"
    "1.3.6.1.4.1.311.21.4"      = "Next CRL Publish"
    "1.3.6.1.4.1.311.21.8"      = "Application Certificate Policies"
    "1.3.6.1.4.1.311.21.9"      = "Cross Certificate Distribution Points"
    "1.3.6.1.4.1.311.21.11"     = "Key Attributes"
    "1.3.6.1.4.1.311.21.14"     = "Issued Certificate Hash"
    "1.3.6.1.4.1.311.21.20"     = "Request Client Information"
    "1.3.6.1.4.1.311.21.21"     = "Encrypted Key Hash"
    "1.3.6.1.4.1.311.21.22"     = "Subject Info Access"

    # =========================================================================
    # Issuance Policy OIDs (for Certificate Policies extension)
    # =========================================================================
    "1.3.6.1.4.1.311.21.8.1"    = "Low Assurance"
    "1.3.6.1.4.1.311.21.8.2"    = "Medium Assurance"
    "1.3.6.1.4.1.311.21.8.3"    = "High Assurance"

    # =========================================================================
    # Smart Card / PIV OIDs
    # =========================================================================
    "2.16.840.1.101.3.6.6"      = "PIV Authentication"
    "2.16.840.1.101.3.6.7"      = "PIV Card Authentication"
    "2.16.840.1.101.3.6.8"      = "PIV Content Signing"
}

# =============================================================================
# PKINIT-CAPABLE EKU OIDs
# These EKUs allow a certificate to be used for Kerberos PKINIT authentication
# =============================================================================
$Script:PKINITCapableEKUs = @(
    "1.3.6.1.4.1.311.20.2.2"    # Smartcard Logon
    "1.3.6.1.5.5.7.3.2"         # Client Authentication
    "1.3.6.1.5.2.3.4"           # PKINIT Client Authentication
    "2.5.29.37.0"               # Any Purpose
)

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

<#
.SYNOPSIS
    Converts an OID to its friendly name.

.DESCRIPTION
    Looks up the OID in the central $Script:OIDMap and returns the friendly name.
    If the OID is not found, returns the original OID string.

.PARAMETER OID
    The OID string to convert.

.PARAMETER IncludeOID
    If specified, includes the OID in parentheses after the name.

.EXAMPLE
    ConvertFrom-OID -OID "1.3.6.1.5.5.7.3.2"
    # Returns: "Client Authentication"

.EXAMPLE
    ConvertFrom-OID -OID "1.3.6.1.5.5.7.3.2" -IncludeOID
    # Returns: "Client Authentication (1.3.6.1.5.5.7.3.2)"
#>
function ConvertFrom-OID {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$OID,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeOID
    )

    process {
        $cleanOID = $OID.Trim()

        if ($Script:OIDMap.ContainsKey($cleanOID)) {
            if ($IncludeOID) {
                return "$($Script:OIDMap[$cleanOID]) ($cleanOID)"
            }
            return $Script:OIDMap[$cleanOID]
        }

        # OID not found - return as-is
        return $cleanOID
    }
}

<#
.SYNOPSIS
    Converts an array of OIDs to their friendly names.

.DESCRIPTION
    Batch conversion of multiple OIDs using the central mapping.

.PARAMETER OIDs
    Array of OID strings to convert.

.PARAMETER IncludeOID
    If specified, includes the OID in parentheses after each name.

.EXAMPLE
    Convert-OIDsToNames -OIDs @("1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2")
    # Returns: @("Server Authentication", "Client Authentication")
#>
function Convert-OIDsToNames {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$OIDs,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeOID
    )

    $result = @()
    foreach ($oid in $OIDs) {
        $result += ConvertFrom-OID -OID $oid -IncludeOID:$IncludeOID
    }
    return ,$result
}

<#
.SYNOPSIS
    Tests if an EKU OID is capable of PKINIT authentication.

.DESCRIPTION
    Checks if the given EKU OID allows the certificate to be used for
    Kerberos PKINIT (certificate-based) authentication.

.PARAMETER OID
    The EKU OID to test.

.EXAMPLE
    Test-PKINITCapableEKU -OID "1.3.6.1.4.1.311.20.2.2"
    # Returns: $true (Smartcard Logon)

.EXAMPLE
    Test-PKINITCapableEKU -OID "1.3.6.1.5.5.7.3.3"
    # Returns: $false (Code Signing - not PKINIT capable)
#>
function Test-PKINITCapableEKU {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$OID
    )

    return $Script:PKINITCapableEKUs -contains $OID.Trim()
}

# Private helper: Extract EKU OIDs from a certificate object or a raw OID array
function Get-EKUOIDsFromInput {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [string[]]$EKUOIDs
    )

    if ($Certificate) {
        $ekuExt = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.37" }
        if ($ekuExt -and $ekuExt -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
            $result = @()
            foreach ($eku in $ekuExt.EnhancedKeyUsages) {
                $result += $eku.Value
            }
            return $result
        }
        return @()
    }
    elseif ($EKUOIDs) {
        return $EKUOIDs
    }

    return @()
}

<#
.SYNOPSIS
    Tests if a certificate has PKINIT-capable EKUs.

.DESCRIPTION
    Examines a certificate's Extended Key Usage extension and determines
    if any of the EKUs allow PKINIT authentication.

.PARAMETER Certificate
    The X509Certificate2 object to examine.

.PARAMETER EKUOIDs
    Alternative: Array of EKU OID strings to check.

.EXAMPLE
    Test-CertificatePKINITCapable -Certificate $cert
    # Returns: $true if certificate can be used for PKINIT
#>
function Test-CertificatePKINITCapable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory=$false)]
        [string[]]$EKUOIDs
    )

    $oidsToCheck = Get-EKUOIDsFromInput -Certificate $Certificate -EKUOIDs $EKUOIDs
    if ($oidsToCheck.Count -eq 0) { return $false }

    # Check if any EKU is PKINIT-capable
    foreach ($oid in $oidsToCheck) {
        if (Test-PKINITCapableEKU -OID $oid) {
            return $true
        }
    }

    return $false
}

<#
.SYNOPSIS
    Gets the friendly names of PKINIT-capable EKUs from a certificate or OID list.

.DESCRIPTION
    Returns the friendly names of EKUs that allow PKINIT authentication.

.PARAMETER Certificate
    The X509Certificate2 object to examine.

.PARAMETER EKUOIDs
    Alternative: Array of EKU OID strings to filter.

.EXAMPLE
    Get-PKINITCapableEKUNames -Certificate $cert
    # Returns: @("Smartcard Logon", "Client Authentication")
#>
function Get-PKINITCapableEKUNames {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory=$false)]
        [string[]]$EKUOIDs
    )

    $oidsToCheck = Get-EKUOIDsFromInput -Certificate $Certificate -EKUOIDs $EKUOIDs

    $pkInitEKUs = @()
    foreach ($oid in $oidsToCheck) {
        if (Test-PKINITCapableEKU -OID $oid) {
            $pkInitEKUs += ConvertFrom-OID -OID $oid
        }
    }

    return $pkInitEKUs
}
