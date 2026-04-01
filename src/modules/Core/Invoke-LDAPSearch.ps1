<#
.SYNOPSIS
    Performs LDAP searches using System.DirectoryServices.Protocols.LdapConnection.

.DESCRIPTION
    Central search function for all LDAP queries.
    Uses LdapConnection for efficient AD queries (works for both LDAP and LDAPS).

    Features:
    - Server-side LDAP filters
    - Paging for large result sets
    - Attribute selection for performance
    - Scope control (Base, OneLevel, Subtree)

.PARAMETER Filter
    LDAP filter string (e.g. "(&(objectClass=user)(adminCount=1))")

.PARAMETER SearchBase
    Distinguished Name as search base.
    Optional - Default: Domain DN from $Script:LDAPContext

.PARAMETER Properties
    Array of attribute names to load.
    Optional - Default: All attributes

.PARAMETER Scope
    Search scope: Base, OneLevel, Subtree
    Default: Subtree

.PARAMETER PageSize
    Page size for paging (performance for large result sets)
    Default: 1000

.PARAMETER SizeLimit
    Maximum number of results (0 = unlimited)
    Default: 0

.PARAMETER Raw
    Switch to return raw LDAP values without any conversions.
    When specified, all attribute conversions are skipped:
    - objectSid remains as byte array (not converted to string)
    - userAccountControl remains as Int32 (not converted to flag array)
    - DateTime attributes remain as Int64 (not converted to DateTime)
    - etc.
    Use this for performance when programmatically processing results.

.PARAMETER CountOnly
    Switch to return only the count of matching objects without collecting or converting them.
    Significantly reduces memory usage and processing time for large result sets
    where only the total number of matches is needed.
    Returns an integer instead of an array of PSCustomObjects.

.EXAMPLE
    Invoke-LDAPSearch -Filter "(&(objectClass=user)(adminCount=1))"
    Searches all users with adminCount=1

.EXAMPLE
    Invoke-LDAPSearch -Filter "(objectClass=group)" -Properties "sAMAccountName","member"
    Searches groups and loads only specific attributes

.EXAMPLE
    Invoke-LDAPSearch -Filter "(objectClass=user)" -Raw
    Searches users and returns raw LDAP values without conversions (faster for programmatic use)

.EXAMPLE
    Invoke-LDAPSearch -Filter "(&(objectClass=computer)(servicePrincipalName=CmRcService/*))" -CountOnly
    Returns only the count of matching computers without loading any object data

.OUTPUTS
    Array of PSCustomObjects with found AD objects

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

function Invoke-LDAPSearch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Filter,

        [Parameter(Mandatory=$false)]
        [string]$SearchBase,

        [Parameter(Mandatory=$false)]
        [string[]]$Properties,

        [Parameter(Mandatory=$false)]
        [string[]]$AdditionalProperties,

        [Parameter(Mandatory=$false)]
        [ValidateSet("Base", "OneLevel", "Subtree")]
        [string]$Scope = "Subtree",

        [Parameter(Mandatory=$false)]
        [int]$PageSize = 1000,

        [Parameter(Mandatory=$false)]
        [int]$SizeLimit = 0,

        [Parameter(Mandatory=$false)]
        [switch]$Raw,

        [Parameter(Mandatory=$false)]
        [switch]$CountOnly,

        [Parameter(Mandatory=$false)]
        [System.DirectoryServices.Protocols.LdapConnection]$LdapConnection
    )

    begin {
        Write-Log "[Invoke-LDAPSearch] Filter: $Filter"

        # Use provided connection or fall back to script-scope connection
        $ActiveConnection = if ($LdapConnection) { $LdapConnection } else { $Script:LdapConnection }

        if (-not $ActiveConnection) {
            throw "No LDAP connection available. Please run Connect-adPEAS first."
        }

        Write-Log "[Invoke-LDAPSearch] Using System.DirectoryServices.Protocols.LdapConnection"
    }

    process {
        # Helper: Convert X.509 certificate bytes to structured object
        function Convert-CertificateToInfo {
            param([byte[]]$CertBytes)
            try {
                $Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,$CertBytes)

                # Extract Subject CN
                $SubjectCN = if ($Cert.Subject -match 'CN=([^,]+)') { $Matches[1] } else { $Cert.Subject }

                # Extract Issuer CN
                $IssuerCN = if ($Cert.Issuer -match 'CN=([^,]+)') { $Matches[1] } else { $Cert.Issuer }

                # Determine certificate status
                $Status = if ((Get-Date) -gt $Cert.NotAfter) { "EXPIRED" }
                          elseif ((Get-Date) -lt $Cert.NotBefore) { "Not yet valid" }
                          else { "Valid" }

                # Extract Subject Alternative Name (SAN) - OID 2.5.29.17
                $SAN = $null
                $SANExtension = $Cert.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.17" }
                if ($SANExtension) {
                    # Format the SAN for display
                    $SANFormatted = $SANExtension.Format($false)
                    if ($SANFormatted) {
                        $SAN = $SANFormatted
                    }
                }

                # Extract Enhanced Key Usage (EKU)
                $EKU = $null
                $EKUExtension = $Cert.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] }
                if ($EKUExtension) {
                    $EKUList = @()
                    foreach ($oid in $EKUExtension.EnhancedKeyUsages) {
                        $EKUList += "$($oid.FriendlyName) ($($oid.Value))"
                    }
                    $EKU = $EKUList -join ", "
                }

                # Signature Algorithm (e.g., sha256RSA, sha1RSA)
                $SigAlgo = $Cert.SignatureAlgorithm.FriendlyName

                # Public Key Length
                $KeyLength = 0
                try {
                    if ($Cert.PublicKey -and $Cert.PublicKey.Key) {
                        $KeyLength = $Cert.PublicKey.Key.KeySize
                    }
                } catch {
                    # Some key types may not expose KeySize
                }

                # Basic Constraints (OID 2.5.29.19) - CA flag and path length
                $HasBasicConstraints = $false
                $BasicConstraintsPathLength = 0
                $bcExt = $Cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' }
                if ($bcExt) {
                    $HasBasicConstraints = $true
                    try {
                        $bcTyped = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]$bcExt
                        if ($bcTyped.HasPathLengthConstraint) {
                            $BasicConstraintsPathLength = $bcTyped.PathLengthConstraint
                        }
                    } catch { }
                }

                # CRL Distribution Points (OID 2.5.29.31)
                $CRLDistributionPoints = @()
                $crlExt = $Cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.31' }
                if ($crlExt) {
                    try {
                        # Format() returns a multi-line string like:
                        # "Distribution Point\r\n  Full Name:\r\n    URL=http://..."
                        $crlFormatted = $crlExt.Format($false)
                        # Extract http(s):// and ldap:// URLs
                        $CRLDistributionPoints = @([regex]::Matches($crlFormatted, 'https?://[^\s,]+|ldap://[^\s,]+') | ForEach-Object { $_.Value })
                    } catch { }
                }

                # Authority Information Access (OID 1.3.6.1.5.5.7.1.1) - OCSP and CA Issuer URLs
                $OCSPURLs = @()
                $AIAURLs = @()
                $aiaExt = $Cert.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.5.5.7.1.1' }
                if ($aiaExt) {
                    try {
                        # Format() returns a string like:
                        # "Access Method=On-line Certificate Status Protocol (1.3.6.1.5.5.7.48.1)\r\nAlternative Name:\r\n  URL=http://ocsp...."
                        # "Access Method=Certification Authority Issuer (1.3.6.1.5.5.7.48.2)\r\nAlternative Name:\r\n  URL=http://..."
                        $aiaFormatted = $aiaExt.Format($false)
                        # Split into per-entry blocks by splitting on Access Method lines
                        # Process each URL with its preceding context
                        $lines = $aiaFormatted -split '\r?\n'
                        $currentIsOCSP = $false
                        $currentIsCAIssuer = $false
                        foreach ($line in $lines) {
                            if ($line -match '1\.3\.6\.1\.5\.5\.7\.48\.1') { $currentIsOCSP = $true; $currentIsCAIssuer = $false }
                            elseif ($line -match '1\.3\.6\.1\.5\.5\.7\.48\.2') { $currentIsOCSP = $false; $currentIsCAIssuer = $true }
                            elseif ($line -match '^\s*URL=(https?://[^\s]+|ldap://[^\s]+)') {
                                $url = $Matches[1]
                                if ($currentIsOCSP) { $OCSPURLs += $url }
                                elseif ($currentIsCAIssuer) { $AIAURLs += $url }
                            }
                        }
                    } catch { }
                }

                $CertInfo = [PSCustomObject]@{
                    Subject      = $SubjectCN
                    SubjectFull  = $Cert.Subject
                    Issuer       = $IssuerCN
                    IssuerFull   = $Cert.Issuer
                    SerialNumber = $Cert.SerialNumber
                    NotBefore    = $Cert.NotBefore
                    NotAfter     = $Cert.NotAfter
                    Status       = $Status
                    Thumbprint   = $Cert.Thumbprint
                    SAN          = $SAN
                    EKU          = $EKU
                    SignatureAlgorithm      = $SigAlgo
                    PublicKeyLength         = $KeyLength
                    HasBasicConstraints     = $HasBasicConstraints
                    BasicConstraintsPathLength = $BasicConstraintsPathLength
                    CRLDistributionPoints   = $CRLDistributionPoints
                    OCSPURLs                = $OCSPURLs
                    AIAURLs                 = $AIAURLs
                }

                $Cert.Dispose()
                return $CertInfo
            } catch {
                # Return error object if certificate parsing fails
                return [PSCustomObject]@{
                    Subject      = "[Invalid Certificate]"
                    SubjectFull  = $null
                    Issuer       = $null
                    IssuerFull   = $null
                    SerialNumber = $null
                    NotBefore    = $null
                    NotAfter     = $null
                    Status       = "Parse Error"
                    Thumbprint   = $null
                    SAN          = $null
                    EKU          = $null
                    SignatureAlgorithm      = $null
                    PublicKeyLength         = 0
                    HasBasicConstraints     = $false
                    BasicConstraintsPathLength = 0
                    CRLDistributionPoints   = @()
                    OCSPURLs                = @()
                    AIAURLs                 = @()
                    ErrorInfo    = if ($CertBytes.Length -gt 0) { "$($CertBytes.Length) bytes" } else { "Empty" }
                }
            }
        }

        # Helper: Convert KeyCredentialLink to readable info
        # msDS-KeyCredentialLink is a DNWithBinary attribute: B:Length:HexData:DN
        # Uses ConvertFrom-KeyCredentialLink helper for full LTV parsing
        function Convert-KeyCredentialToInfo {
            param($KeyCredValue)

            try {
                # Handle string format (DNWithBinary)
                if ($KeyCredValue -is [string]) {
                    # Format: B:Length:HexData:DN
                    if ($KeyCredValue -match '^B:(\d+):([0-9A-Fa-f]+)(?::(.+))?$') {
                        # Use the full parser to extract DeviceID, CreationTime, etc.
                        return ConvertFrom-KeyCredentialLink -DNWithBinary $KeyCredValue
                    }
                    # Return as-is if not matching DNWithBinary format
                    return $KeyCredValue
                }

                # Handle byte array (raw binary)
                if ($KeyCredValue -is [byte[]]) {
                    return ConvertFrom-KeyCredentialLink -KeyCredentialBytes $KeyCredValue
                }

                # Handle COM objects (IADsDNWithBinary) from DirectoryServices
                # COM interop requires using GetType().InvokeMember() for property access
                if ($KeyCredValue -and $KeyCredValue.GetType().IsCOMObject) {
                    try {
                        # Use COM Reflection to access BinaryValue property
                        $binaryValue = $KeyCredValue.GetType().InvokeMember(
                            'BinaryValue',
                            [System.Reflection.BindingFlags]::GetProperty,
                            $null,
                            $KeyCredValue,
                            $null
                        )
                        if ($binaryValue -is [byte[]]) {
                            return ConvertFrom-KeyCredentialLink -KeyCredentialBytes $binaryValue
                        }
                    } catch {
                        # COM reflection failed, try direct access
                    }
                }

                # Method 2: Try direct property access (works for some COM wrappers)
                if ($KeyCredValue.PSObject.Properties['DNString'] -and $KeyCredValue.PSObject.Properties['BinaryValue']) {
                    $binaryValue = $KeyCredValue.BinaryValue
                    if ($binaryValue -is [byte[]]) {
                        return ConvertFrom-KeyCredentialLink -KeyCredentialBytes $binaryValue
                    }
                }

                # Try converting to string and parsing as DNWithBinary
                $strValue = $KeyCredValue.ToString()
                if ($strValue -match '^B:(\d+):([0-9A-Fa-f]+)(?::(.+))?$') {
                    return ConvertFrom-KeyCredentialLink -DNWithBinary $strValue
                }

                return "KeyCredential (unknown format)"
            } catch {
                return "[KeyCredential - parse error: $($_.Exception.Message)]"
            }
        }

        # Helper: Convert SID byte array to string
        function Convert-SIDToString {
            param([byte[]]$SIDBytes)
            try {
                return (New-Object System.Security.Principal.SecurityIdentifier($SIDBytes, 0)).Value
            } catch {
                return $null
            }
        }

        try {
            # Determine SearchBase
            if ([string]::IsNullOrEmpty($SearchBase)) {
                if ($LdapConnection) {
                    # External connection (e.g. GC): use empty SearchBase for forest-wide search (default)
                    $SearchBase = ""
                    Write-Log "[Invoke-LDAPSearch] Using empty SearchBase for external connection (forest-wide)"
                } else {
                    $SearchBase = $Script:LDAPContext.DomainDN
                    Write-Log "[Invoke-LDAPSearch] Using domain DN as SearchBase: $SearchBase"
                }
            } else {
                # SearchBase was explicitly provided - use it
                Write-Log "[Invoke-LDAPSearch] Using explicit SearchBase: $SearchBase"
            }

            # Convert results to PSCustomObjects
            $OutputObjects = [System.Collections.ArrayList]@()

            Write-Log "[Invoke-LDAPSearch] Using LdapConnection for search"

            # Map scope
            $ProtocolScope = switch ($Scope) {
                "Base"     { [System.DirectoryServices.Protocols.SearchScope]::Base }
                "OneLevel" { [System.DirectoryServices.Protocols.SearchScope]::OneLevel }
                "Subtree"  { [System.DirectoryServices.Protocols.SearchScope]::Subtree }
                default    { [System.DirectoryServices.Protocols.SearchScope]::Subtree }
            }

            # Build attribute list
            # CRITICAL: Pass $null (not @("*")) to SearchRequest when Properties is null
            # On Global Catalog (port 3268), @("*") behaves differently than $null:
            # - $null → Returns all PAS attributes (correct for GC)
            # - @("*") → May return DN-only for cross-partition objects (S.DS.P GC quirk)
            $AttributeList = $null

            # CountOnly: force "1.1" (no attributes) to minimize network traffic
            if ($CountOnly) {
                $AttributeList = [string[]]@("1.1")
                Write-Log "[Invoke-LDAPSearch] CountOnly mode: requesting no attributes (1.1)"
            } elseif ($Properties -and $Properties.Count -gt 0) {
                $AttributeList = [string[]]$Properties
                if ($AdditionalProperties) {
                    $AttributeList = [string[]]($Properties + $AdditionalProperties | Select-Object -Unique)
                }
                Write-Log "[Invoke-LDAPSearch] Requesting attributes: $($AttributeList -join ', ')"
            } else {
                # Request all attributes by passing $null (NOT @("*"))
                # $null works correctly on both port 389 and GC port 3268
                $AttributeList = $null
                Write-Log "[Invoke-LDAPSearch] Requesting ALL attributes (null list for GC compatibility)"
            }

            # Create search request
            $SearchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest($SearchBase,$Filter,$ProtocolScope,$AttributeList)

            # Add paging control
            $PageControl = New-Object System.DirectoryServices.Protocols.PageResultRequestControl($PageSize)
            $SearchRequest.Controls.Add($PageControl) | Out-Null

            # Add DomainScope control to prevent phantom results from other domain partitions
            # When the DC is also a Global Catalog, subtree searches can return objects from
            # child domains (phantom objects) even with ReferralChasing=None on the session.
            # SearchOptionsControl with DomainScope tells the DC to only return objects from
            # the domain partition specified by the SearchBase.
            # CRITICAL: Only apply DomainScope to main connection, NOT to external GC connections
            # (GC connections NEED forest-wide results)
            if (-not $LdapConnection) {
                $DomainScopeControl = New-Object System.DirectoryServices.Protocols.SearchOptionsControl(
                    [System.DirectoryServices.Protocols.SearchOption]::DomainScope
                )
                $SearchRequest.Controls.Add($DomainScopeControl) | Out-Null
            }

            # Add SecurityDescriptor control if nTSecurityDescriptor is requested
            $AllRequestedProps = @()
            if ($Properties) { $AllRequestedProps += $Properties }
            if ($AdditionalProperties) { $AllRequestedProps += $AdditionalProperties }

            if ($AllRequestedProps -contains "nTSecurityDescriptor" -or $AttributeList -contains "*") {
                # SecurityDescriptorFlagControl: Owner (1) + Group (2) + DACL (4) = 7
                $SDControl = New-Object System.DirectoryServices.Protocols.SecurityDescriptorFlagControl(
                    [System.DirectoryServices.Protocols.SecurityMasks]::Dacl -bor
                    [System.DirectoryServices.Protocols.SecurityMasks]::Owner -bor
                    [System.DirectoryServices.Protocols.SecurityMasks]::Group
                )
                $SearchRequest.Controls.Add($SDControl) | Out-Null
                Write-Log "[Invoke-LDAPSearch] Added SecurityDescriptorFlagControl for nTSecurityDescriptor"
            }

            # Known binary attributes that need byte[] extraction (defined once, used per-attribute)
            $BinaryAttributeSet = [System.Collections.Generic.HashSet[string]]::new(
                [System.StringComparer]::OrdinalIgnoreCase
            )
            foreach ($ba in @(
                'objectsid', 'objectguid', 'ntsecuritydescriptor', 'sidhistory',
                'msexchmailboxguid', 'msexchmailboxsecuritydescriptor', 'msexchblockedsendershash',
                'msexchsafesendershash', 'msexchmasteraccountsid', 'ms-ds-creatorsid',
                'msds-generationid', 'msds-groupmsamembership', 'msds-managedpasswordid',
                'msds-managedpasswordpreviousid', 'ms-ds-consistencyguid', 'logonhours',
                'msds-allowedtoactonbehalfofotheridentity', 'mslaps-encryptedpassword',
                'mslaps-encryptedpasswordhistory', 'mslaps-encrypteddsconfigurationdata',
                'thumbnailphoto', 'jpegphoto', 'usercertificate', 'cacertificate',
                'msds-keyversionnumber', 'repluptodatevector', 'replpropertymeta',
                'pkiexpirationperiod', 'pkioverlapperiod', 'pkikeyusage',
                'extensiondata',
                'msmqdigests', 'msmqsigncertificates'
            )) { [void]$BinaryAttributeSet.Add($ba) }

            # CountOnly mode: only count matching objects without collecting or converting them
            if ($CountOnly) {
                $TotalCount = 0
                do {
                    $SearchResponse = $ActiveConnection.SendRequest($SearchRequest)

                    # Statistics tracking (CountOnly path)
                    if ($Script:LDAPStatistics) {
                        $Script:LDAPStatistics.TotalQueries++
                        # Base overhead per request/response (~search filter + controls + response header)
                        $Script:LDAPStatistics.TotalEstimatedBytes += 200
                        if ($SearchResponse.Entries) {
                            $Script:LDAPStatistics.TotalResults += $SearchResponse.Entries.Count
                            # CountOnly still returns DNs — estimate ~120 bytes per entry (DN + envelope)
                            $Script:LDAPStatistics.TotalEstimatedBytes += $SearchResponse.Entries.Count * 120
                        }
                    }

                    if ($SearchResponse.Entries) {
                        $TotalCount += $SearchResponse.Entries.Count
                    }

                    # Check for paging response control
                    $PageResponseControl = $null
                    foreach ($ctrl in $SearchResponse.Controls) {
                        if ($ctrl -is [System.DirectoryServices.Protocols.PageResultResponseControl]) {
                            $PageResponseControl = $ctrl
                            break
                        }
                    }

                    if ($PageResponseControl -and $PageResponseControl.Cookie.Length -gt 0) {
                        $PageControl.Cookie = $PageResponseControl.Cookie
                    } else {
                        break
                    }
                } while ($true)

                Write-Log "[Invoke-LDAPSearch] CountOnly: $TotalCount objects matched"
                return $TotalCount
            }

            # Execute paged search
            $AllEntries = [System.Collections.ArrayList]@()
            do {
                $SearchResponse = $ActiveConnection.SendRequest($SearchRequest)

                # Statistics tracking (full search path)
                if ($Script:LDAPStatistics) {
                    $Script:LDAPStatistics.TotalQueries++
                    # Base overhead per request/response (~search filter + controls + response header)
                    $Script:LDAPStatistics.TotalEstimatedBytes += 200
                    if ($SearchResponse.Entries) {
                        $Script:LDAPStatistics.TotalResults += $SearchResponse.Entries.Count
                    }
                }

                if ($SearchResponse.Entries) {
                    [void]$AllEntries.AddRange($SearchResponse.Entries)
                }

                # Check for paging response control
                $PageResponseControl = $null
                foreach ($ctrl in $SearchResponse.Controls) {
                    if ($ctrl -is [System.DirectoryServices.Protocols.PageResultResponseControl]) {
                        $PageResponseControl = $ctrl
                        break
                    }
                }

                if ($PageResponseControl -and $PageResponseControl.Cookie.Length -gt 0) {
                    $PageControl.Cookie = $PageResponseControl.Cookie
                } else {
                    break
                }

                # Check SizeLimit
                if ($SizeLimit -gt 0 -and $AllEntries.Count -ge $SizeLimit) {
                    break
                }

            } while ($true)

            Write-Log "[Invoke-LDAPSearch] Found: $($AllEntries.Count) objects via LdapConnection"

            # Convert LdapConnection results to PSCustomObjects with full attribute conversion
            foreach ($Entry in $AllEntries) {
                $Obj = [PSCustomObject]@{}

                # Add distinguishedName first (use -Force in case it's also in Attributes)
                $Obj | Add-Member -Force -NotePropertyName "distinguishedName" -NotePropertyValue $Entry.DistinguishedName

                # Statistics: count DN bytes per entry (~DN string + LDAP envelope overhead)
                if ($Script:LDAPStatistics -and $Entry.DistinguishedName) {
                    $Script:LDAPStatistics.TotalEstimatedBytes += $Entry.DistinguishedName.Length * 2 + 40
                }

                # Process each attribute with full conversion logic
                foreach ($PropName in $Entry.Attributes.AttributeNames) {
                    $AttrValues = $Entry.Attributes[$PropName]

                    # Statistics: estimate bytes for this attribute
                    if ($Script:LDAPStatistics) {
                        for ($si = 0; $si -lt $AttrValues.Count; $si++) {
                            try {
                                $statVal = $AttrValues[$si]
                                if ($statVal -is [byte[]]) {
                                    $Script:LDAPStatistics.TotalEstimatedBytes += $statVal.Length
                                } elseif ($statVal -is [string]) {
                                    $Script:LDAPStatistics.TotalEstimatedBytes += $statVal.Length * 2  # UTF-16
                                } else {
                                    $Script:LDAPStatistics.TotalEstimatedBytes += 8  # fixed-size estimate
                                }
                            } catch {
                                $Script:LDAPStatistics.TotalEstimatedBytes += 8
                            }
                        }
                        # Add attribute name overhead (~DN length + attribute name)
                        $Script:LDAPStatistics.TotalEstimatedBytes += $PropName.Length + 20
                    }

                    # Build PropValue array from LdapConnection attribute values
                    # NOTE: DirectoryAttribute indexer returns strings by default.
                    # For binary attributes, we need to use GetValues([byte[]]) to get raw bytes.
                    $PropValue = @()
                    $PropNameLower = $PropName.ToLower()

                    if ($BinaryAttributeSet.Contains($PropNameLower)) {
                        # Binary attribute - extract as byte arrays
                        try {
                            $ByteValues = $AttrValues.GetValues([byte[]])
                            foreach ($bv in $ByteValues) {
                                $PropValue += ,$bv  # Use comma to prevent array flattening
                            }
                        } catch {
                            # Fallback to string extraction if byte[] fails
                            for ($i = 0; $i -lt $AttrValues.Count; $i++) {
                                $PropValue += $AttrValues[$i]
                            }
                        }
                    } else {
                        # Non-binary attribute - use default string extraction
                        for ($i = 0; $i -lt $AttrValues.Count; $i++) {
                            $PropValue += $AttrValues[$i]
                        }
                    }

                    # If -Raw is specified, skip all conversions and return raw values
                    if ($Raw) {
                        # Raw mode - no conversions, just add property as-is
                        if ($PropValue.Count -eq 1) {
                            $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                        } else {
                            $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value @($PropValue)
                        }
                        continue
                    }

                    # =====================================================================
                    # Handle multi-value attributes that need special processing
                    # These are processed BEFORE single-value check
                    # =====================================================================

                    # sIDHistory - Multi-valued SID attribute (critical for SID History Injection detection)
                    if ($PropName -ieq "sIDHistory") {
                        $sidStrings = @()
                        foreach ($sidBytes in $PropValue) {
                            if ($sidBytes -is [byte[]]) {
                                $sidString = Convert-SIDToString -SIDBytes $sidBytes
                                if ($sidString) {
                                    $sidStrings += $sidString
                                }
                            } elseif ($sidBytes -is [string]) {
                                $sidStrings += $sidBytes
                            }
                        }
                        if ($sidStrings.Count -eq 1) {
                            $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $sidStrings[0]
                        } elseif ($sidStrings.Count -gt 1) {
                            $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $sidStrings
                        }
                        continue
                    }

                    # userCertificate / cACertificate - Multi-valued X.509 certificates
                    if ($PropName -ieq "userCertificate" -or $PropName -ieq "cACertificate") {
                        $certInfos = @()
                        foreach ($certBytes in $PropValue) {
                            if ($certBytes -is [byte[]]) {
                                $certInfo = Convert-CertificateToInfo -CertBytes $certBytes
                                $certInfos += $certInfo
                            }
                        }
                        if ($certInfos.Count -eq 1) {
                            $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $certInfos[0]
                        } elseif ($certInfos.Count -gt 1) {
                            $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $certInfos
                        }
                        continue
                    }

                    # msDS-KeyCredentialLink - Multi-valued DNWithBinary (Windows Hello for Business, etc.)
                    if ($PropName -ieq "msDS-KeyCredentialLink") {
                        $keyInfos = @()
                        foreach ($keyValue in $PropValue) {
                            $keyInfo = Convert-KeyCredentialToInfo -KeyCredValue $keyValue
                            if ($keyInfo) {
                                $keyInfos += $keyInfo
                            }
                        }
                        if ($keyInfos.Count -gt 0) {
                            $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $keyInfos
                        }
                        continue
                    }

                    # msLAPS-EncryptedPasswordHistory - Multi-valued (array of encrypted blobs)
                    if ($PropName -ieq "msLAPS-EncryptedPasswordHistory") {
                        # LAPS v2 Encrypted Password History - Array of encrypted password blobs
                        try {
                            $historyEntries = @()
                            $entryIndex = 0

                            foreach ($historyBlob in $PropValue) {
                                $entryIndex++
                                try {
                                    $historyInfo = ConvertFrom-LAPSEncryptedPassword -Blob $historyBlob
                                    if ($historyInfo -and $historyInfo.UpdateTimestamp) {
                                        $historyEntries += "[$entryIndex] $($historyInfo.UpdateTimestamp.ToString('yyyy-MM-dd HH:mm:ss'))"
                                    } else {
                                        $historyEntries += "[$entryIndex] [Encrypted - $($historyBlob.Length) bytes]"
                                    }
                                } catch {
                                    $historyEntries += "[$entryIndex] [Encrypted - $($historyBlob.Length) bytes]"
                                }
                            }

                            if ($historyEntries.Count -gt 0) {
                                $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $historyEntries
                            }
                        } catch {
                            $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value "[History: $($PropValue.Count) entries]"
                        }
                        continue
                    }

                    # pKIExtendedKeyUsage - Multi-valued OID array (convert to friendly names)
                    if ($PropName -ieq "pKIExtendedKeyUsage") {
                        # Convert EKU OIDs to friendly names using central OID mapping
                        $ekuNames = Convert-OIDsToNames -OIDs $PropValue -IncludeOID
                        if ($ekuNames.Count -eq 1) {
                            $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $ekuNames[0]
                        } elseif ($ekuNames.Count -gt 1) {
                            $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $ekuNames
                        } else {
                            $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value @("Any Purpose")
                        }
                        continue
                    }

                    # msPKI-Certificate-Application-Policy - Multi-valued OID array (convert to friendly names)
                    if ($PropName -ieq "msPKI-Certificate-Application-Policy") {
                        # Convert Application Policy OIDs to friendly names using central OID mapping
                        $policyNames = Convert-OIDsToNames -OIDs $PropValue -IncludeOID
                        if ($policyNames.Count -eq 1) {
                            $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $policyNames[0]
                        } elseif ($policyNames.Count -gt 1) {
                            $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $policyNames
                        }
                        continue
                    }

                    # pKICriticalExtensions - Multi-valued OID array (convert to friendly names)
                    if ($PropName -ieq "pKICriticalExtensions") {
                        # Convert Critical Extensions OIDs to friendly names using central OID mapping
                        $critExtNames = Convert-OIDsToNames -OIDs $PropValue -IncludeOID
                        if ($critExtNames.Count -eq 1) {
                            $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $critExtNames[0]
                        } elseif ($critExtNames.Count -gt 1) {
                            $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $critExtNames
                        }
                        continue
                    }

                    # thumbnailPhoto / jpegPhoto - Image data (JPEG/PNG)
                    # Store as object with metadata for console and Base64 for HTML rendering
                    if ($PropName -iin @("thumbnailPhoto", "jpegPhoto")) {
                        if ($PropValue.Count -ge 1 -and $PropValue[0] -is [byte[]]) {
                            $imageBytes = $PropValue[0]
                            $imageSizeKB = [math]::Round($imageBytes.Length / 1024, 1)

                            # Detect image type from magic bytes
                            $imageType = "unknown"
                            $mimeType = "application/octet-stream"
                            if ($imageBytes.Length -ge 3) {
                                # JPEG: FF D8 FF
                                if ($imageBytes[0] -eq 0xFF -and $imageBytes[1] -eq 0xD8 -and $imageBytes[2] -eq 0xFF) {
                                    $imageType = "JPEG"
                                    $mimeType = "image/jpeg"
                                }
                                # PNG: 89 50 4E 47
                                elseif ($imageBytes[0] -eq 0x89 -and $imageBytes[1] -eq 0x50 -and $imageBytes[2] -eq 0x4E -and $imageBytes.Length -ge 4 -and $imageBytes[3] -eq 0x47) {
                                    $imageType = "PNG"
                                    $mimeType = "image/png"
                                }
                                # GIF: 47 49 46
                                elseif ($imageBytes[0] -eq 0x47 -and $imageBytes[1] -eq 0x49 -and $imageBytes[2] -eq 0x46) {
                                    $imageType = "GIF"
                                    $mimeType = "image/gif"
                                }
                                # BMP: 42 4D
                                elseif ($imageBytes[0] -eq 0x42 -and $imageBytes[1] -eq 0x4D) {
                                    $imageType = "BMP"
                                    $mimeType = "image/bmp"
                                }
                            }

                            # Create structured object with image data
                            $imageObj = [PSCustomObject]@{
                                PSTypeName = 'adPEAS.ImageData'
                                ImageType = $imageType
                                MimeType = $mimeType
                                SizeBytes = $imageBytes.Length
                                SizeKB = $imageSizeKB
                                Base64 = [Convert]::ToBase64String($imageBytes)
                                DisplayText = "[$imageType image, $imageSizeKB KB]"
                            }

                            $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $imageObj
                        }
                        continue
                    }

                    # mSMQDigests - Multi-valued binary (MD5 message digests, 16 bytes each)
                    if ($PropName -ieq "mSMQDigests") {
                        $digestValues = @()
                        foreach ($bytes in $PropValue) {
                            if ($bytes -is [byte[]] -and $bytes.Length -eq 16) {
                                # MD5 digest - display as hex string
                                $hexStr = ($bytes | ForEach-Object { $_.ToString('X2') }) -join ''
                                $digestValues += $hexStr
                            } elseif ($bytes -is [byte[]]) {
                                # Non-standard length - show with byte count
                                $hexStr = ($bytes | ForEach-Object { $_.ToString('X2') }) -join ''
                                $digestValues += "$hexStr ($($bytes.Length) bytes)"
                            } else {
                                $digestValues += [string]$bytes
                            }
                        }
                        if ($digestValues.Count -eq 1) {
                            $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $digestValues[0]
                        } elseif ($digestValues.Count -gt 1) {
                            $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $digestValues
                        }
                        continue
                    }

                    # mSMQSignCertificates - Multi-valued binary (X.509 certificates)
                    if ($PropName -ieq "mSMQSignCertificates") {
                        $certValues = @()
                        foreach ($bytes in $PropValue) {
                            if ($bytes -is [byte[]]) {
                                try {
                                    # Try to parse as X.509 certificate
                                    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,$bytes)
                                    $subject = $cert.Subject
                                    $thumbprint = $cert.Thumbprint
                                    $notAfter = $cert.NotAfter.ToString('yyyy-MM-dd')
                                    $certValues += "$subject (Thumbprint: $thumbprint, Expires: $notAfter)"
                                    $cert.Dispose()
                                } catch {
                                    # Not a valid certificate - show as binary info
                                    $certValues += "[Certificate: $($bytes.Length) bytes]"
                                }
                            } else {
                                $certValues += [string]$bytes
                            }
                        }
                        if ($certValues.Count -eq 1) {
                            $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $certValues[0]
                        } elseif ($certValues.Count -gt 1) {
                            $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $certValues
                        }
                        continue
                    }

                    # extensionData - Multi-valued binary blob (Exchange mailbox data, etc.)
                    # Format: UTF-16LE header string + null terminator + binary data
                    if ($PropName -ieq "extensionData") {
                        $decodedValues = @()
                        foreach ($bytes in $PropValue) {
                            if ($bytes -is [byte[]]) {
                                $result = $null

                                # Exchange extensionData format: UTF-16LE header followed by binary data
                                # Examples: "MBXEXTDATA", "MBXEXTCTIDATA", "DVPROPERTYSTREAMID", etc.
                                # Pattern: Look for UTF-16LE header (alternating nulls) terminated by double-null

                                # Check for UTF-16LE pattern (alternating nulls in first 20+ bytes)
                                $hasAlternatingNulls = $false
                                if ($bytes.Length -ge 4) {
                                    $nullCount = 0
                                    for ($i = 1; $i -lt [Math]::Min($bytes.Length, 40); $i += 2) {
                                        if ($bytes[$i] -eq 0) { $nullCount++ }
                                    }
                                    $hasAlternatingNulls = ($nullCount -ge 3)
                                }

                                if ($hasAlternatingNulls) {
                                    # Find the null terminator (00 00) that ends the UTF-16LE string
                                    $headerEndIndex = -1
                                    for ($i = 0; $i -lt $bytes.Length - 1; $i += 2) {
                                        if ($bytes[$i] -eq 0 -and $bytes[$i + 1] -eq 0) {
                                            $headerEndIndex = $i
                                            break
                                        }
                                    }

                                    if ($headerEndIndex -gt 0) {
                                        # Extract and decode just the header portion
                                        $headerBytes = $bytes[0..($headerEndIndex - 1)]
                                        $header = [System.Text.Encoding]::Unicode.GetString($headerBytes)

                                        # Check if header is printable text
                                        if ($header -match '^[\x20-\x7E\xA0-\xFF]+$') {
                                            $dataLength = $bytes.Length - $headerEndIndex - 2
                                            $result = "$header ($dataLength bytes binary data)"
                                        }
                                    }

                                    # If no header found, try full decode (for pure text values)
                                    if (-not $result) {
                                        $decoded = [System.Text.Encoding]::Unicode.GetString($bytes)
                                        $decoded = $decoded.TrimEnd([char]0)
                                        if ($decoded -match '^[\x20-\x7E\xA0-\xFF]+$') {
                                            $result = $decoded
                                        }
                                    }
                                }

                                # Try UTF-8 for non-UTF16LE data
                                if (-not $result) {
                                    try {
                                        $decoded = [System.Text.Encoding]::UTF8.GetString($bytes)
                                        $decoded = $decoded.TrimEnd([char]0)
                                        # Check if mostly printable
                                        $printable = ($decoded -replace '[^\x20-\x7E\xA0-\xFF]', '').Length
                                        if ($decoded.Length -gt 0 -and $printable -ge ($decoded.Length * 0.8)) {
                                            $result = $decoded -replace '[^\x20-\x7E\xA0-\xFF]', '?'
                                        }
                                    } catch { }
                                }

                                # Try ASCII
                                if (-not $result) {
                                    $decoded = [System.Text.Encoding]::ASCII.GetString($bytes)
                                    $decoded = $decoded.TrimEnd([char]0)
                                    $printable = ($decoded -replace '[^\x20-\x7E]', '').Length
                                    if ($decoded.Length -gt 0 -and $printable -ge ($decoded.Length * 0.7)) {
                                        $result = $decoded -replace '[^\x20-\x7E]', '?'
                                    }
                                }

                                # Fallback: Show as hex string if not decodable
                                if (-not $result -or $result.Length -eq 0) {
                                    $hexStr = ($bytes | ForEach-Object { $_.ToString('X2') }) -join ' '
                                    if ($hexStr.Length -gt 100) {
                                        $result = "[Binary: $($hexStr.Substring(0, 100))... ($($bytes.Length) bytes)]"
                                    } else {
                                        $result = "[Binary: $hexStr]"
                                    }
                                }

                                $decodedValues += $result
                            } else {
                                $decodedValues += [string]$bytes
                            }
                        }

                        if ($decodedValues.Count -eq 1) {
                            $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $decodedValues[0]
                        } elseif ($decodedValues.Count -gt 1) {
                            $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $decodedValues
                        }
                        continue
                    }

                    # If single value, process with full conversion
                    if ($PropValue.Count -eq 1) {
                        # Convert byte arrays (e.g., objectSid, objectGUID, LAPS)
                        # NOTE: Use -ieq for case-insensitive comparison because LdapConnection returns lowercase attribute names
                        if ($PropValue[0] -is [byte[]]) {
                            if ($PropName -ieq "objectSid") {
                                try {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value (New-Object System.Security.Principal.SecurityIdentifier($PropValue[0], 0)).Value
                                } catch {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                }
                            } elseif ($PropName -ieq "ms-DS-CreatorSID") {
                                try {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value (New-Object System.Security.Principal.SecurityIdentifier($PropValue[0], 0)).Value
                                } catch {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                }
                            } elseif ($PropName -ieq "objectGUID" -or $PropName -ieq "msExchMailboxGuid") {
                                try {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value ([System.Guid]$PropValue[0]).ToString()
                                } catch {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                }
                            } elseif ($PropName -ieq "msDS-GenerationId") {
                                try {
                                    $GenIdBytes = $PropValue[0]
                                    if ($GenIdBytes.Length -eq 16) {
                                        $GenIdGuid = [System.Guid]::new($GenIdBytes)
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $GenIdGuid.ToString()
                                    } elseif ($GenIdBytes.Length -eq 8) {
                                        $HexString = ($GenIdBytes | ForEach-Object { $_.ToString('X2') }) -join '-'
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $HexString
                                    } else {
                                        $HexString = ($GenIdBytes | ForEach-Object { $_.ToString('X2') }) -join ''
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value "0x$HexString"
                                    }
                                } catch {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                }
                            } elseif ($PropName -ieq "msExchMasterAccountSid") {
                                try {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value (New-Object System.Security.Principal.SecurityIdentifier($PropValue[0], 0)).Value
                                } catch {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                }
                            } elseif ($PropName -ieq "msDS-GroupMSAMembership") {
                                try {
                                    # gMSA membership uses same unified structure as nTSecurityDescriptor
                                    $SDResult = ConvertFrom-SecurityDescriptor -SecurityDescriptorBytes $PropValue[0]
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $SDResult
                                } catch {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                }
                            } elseif ($PropName -ieq "msDS-ManagedPasswordId" -or $PropName -ieq "msDS-ManagedPasswordPreviousId") {
                                try {
                                    $PasswordIdBytes = $PropValue[0]
                                    if ($PasswordIdBytes -is [byte[]]) {
                                        $HexString = ($PasswordIdBytes[0..15] | ForEach-Object { $_.ToString('X2') }) -join '-'
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $HexString
                                    } else {
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                    }
                                } catch {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                }
                            } elseif ($PropName -ieq "ms-DS-ConsistencyGuid") {
                                try {
                                    $GuidBytes = $PropValue[0]
                                    if ($GuidBytes -is [byte[]] -and $GuidBytes.Length -eq 16) {
                                        $ByteArray = [byte[]]$GuidBytes
                                        $GuidObj = [System.Guid]::new($ByteArray)
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $GuidObj.ToString()
                                    } else {
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                    }
                                } catch {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                }
                            } elseif ($PropName -ieq "nTSecurityDescriptor") {
                                try {
                                    $SDResult = ConvertFrom-SecurityDescriptor -SecurityDescriptorBytes $PropValue[0]
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $SDResult
                                } catch {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                }
                            } elseif ($PropName -ieq "msExchMailboxSecurityDescriptor") {
                                try {
                                    $SDResult = ConvertFrom-SecurityDescriptor -SecurityDescriptorBytes $PropValue[0]
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $SDResult
                                } catch {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                }
                            } elseif ($PropName -ieq "msDS-AllowedToActOnBehalfOfOtherIdentity") {
                                # RBCD: extract principal names from the security descriptor who are allowed to delegate
                                try {
                                    $SD = New-Object System.DirectoryServices.ActiveDirectorySecurity
                                    $SD.SetSecurityDescriptorBinaryForm($PropValue[0])

                                    # Extract only Allow ACEs - these are the principals allowed to delegate
                                    $rbcdPrincipals = @()
                                    foreach ($ACE in $SD.Access) {
                                        if ($ACE.AccessControlType -eq 'Allow') {
                                            $Principal = $ACE.IdentityReference.Value
                                            # Resolve SID to name if needed
                                            if ($Principal -match '^S-1-') {
                                                $PrincipalName = ConvertFrom-SID -SID $Principal
                                            } else {
                                                $PrincipalName = $Principal
                                            }
                                            $rbcdPrincipals += $PrincipalName
                                        }
                                    }

                                    if ($rbcdPrincipals.Count -eq 1) {
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $rbcdPrincipals[0]
                                    } elseif ($rbcdPrincipals.Count -gt 1) {
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $rbcdPrincipals
                                    } else {
                                        # SD parsed but no Allow ACEs found — attribute is set but SD has no delegates.
                                        # Still set the property so it appears in display (attribute is present in AD).
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value "[SD present, no Allow ACEs]"
                                    }
                                } catch {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                }
                            } elseif ($PropName -ieq "msExchSafeSendersHash" -or $PropName -ieq "msExchBlockedSendersHash") {
                                # Exchange Safe/Blocked Senders Hash - MD5 hash of sender list
                                # Display as compact hex string (these are hashes, not text)
                                try {
                                    $bytes = $PropValue[0]
                                    $hexStr = ($bytes | ForEach-Object { $_.ToString('X2') }) -join ''
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $hexStr
                                } catch {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value "[Hash: $($PropValue[0].Length) bytes]"
                                }
                            } elseif ($PropName -ieq "msLAPS-EncryptedPassword") {
                                # LAPS v2 Encrypted Password (single value) - binary blob
                                try {
                                    $encryptedInfo = ConvertFrom-LAPSEncryptedPassword -Blob $PropValue[0]
                                    if ($encryptedInfo -and $encryptedInfo.UpdateTimestamp) {
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value "[Encrypted - Updated: $($encryptedInfo.UpdateTimestamp.ToString('yyyy-MM-dd HH:mm:ss'))]"
                                    } else {
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value "[Encrypted - $($PropValue[0].Length) bytes]"
                                    }
                                } catch {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value "[Encrypted - $($PropValue[0].Length) bytes]"
                                }
                            } elseif ($PropName -ieq "logonHours") {
                                # logonHours is a 21-byte array (168 bits = 24 hours * 7 days)
                                # Each bit represents one hour, starting Sunday 00:00 UTC
                                try {
                                    $bytes = $PropValue[0]
                                    if ($bytes -is [byte[]] -and $bytes.Length -eq 21) {
                                        # Check if all hours are allowed (all bits set = 0xFF for all bytes)
                                        $allAllowed = $true
                                        foreach ($b in $bytes) {
                                            if ($b -ne 0xFF) { $allAllowed = $false; break }
                                        }

                                        if ($allAllowed) {
                                            $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value "All hours (no restriction)"
                                        } else {
                                            # Check if all hours are denied (all bits clear)
                                            $allDenied = $true
                                            foreach ($b in $bytes) {
                                                if ($b -ne 0x00) { $allDenied = $false; break }
                                            }

                                            if ($allDenied) {
                                                $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value "No hours allowed (logon blocked)"
                                            } else {
                                                # Parse restricted hours - show summary per day
                                                $days = @('Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat')
                                                $restrictions = @()

                                                for ($day = 0; $day -lt 7; $day++) {
                                                    $dayStart = $day * 24
                                                    $allowedHours = @()

                                                    for ($hour = 0; $hour -lt 24; $hour++) {
                                                        $bitIndex = $dayStart + $hour
                                                        $byteIndex = [Math]::Floor($bitIndex / 8)
                                                        $bitPosition = $bitIndex % 8
                                                        $isAllowed = ($bytes[$byteIndex] -band (1 -shl $bitPosition)) -ne 0

                                                        if ($isAllowed) {
                                                            $allowedHours += $hour
                                                        }
                                                    }

                                                    if ($allowedHours.Count -eq 0) {
                                                        $restrictions += "$($days[$day]): Blocked"
                                                    } elseif ($allowedHours.Count -eq 24) {
                                                        $restrictions += "$($days[$day]): All day"
                                                    } else {
                                                        # Find contiguous ranges
                                                        $ranges = @()
                                                        $rangeStart = $allowedHours[0]
                                                        $rangeEnd = $rangeStart

                                                        for ($i = 1; $i -lt $allowedHours.Count; $i++) {
                                                            if ($allowedHours[$i] -eq $rangeEnd + 1) {
                                                                $rangeEnd = $allowedHours[$i]
                                                            } else {
                                                                $ranges += "{0:D2}:00-{1:D2}:00" -f $rangeStart, ($rangeEnd + 1)
                                                                $rangeStart = $allowedHours[$i]
                                                                $rangeEnd = $rangeStart
                                                            }
                                                        }
                                                        $ranges += "{0:D2}:00-{1:D2}:00" -f $rangeStart, (($rangeEnd + 1) % 24)
                                                        $restrictions += "$($days[$day]): $($ranges -join ', ')"
                                                    }
                                                }

                                                $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $restrictions
                                            }
                                        }
                                    } else {
                                        # Unexpected format - show as hex
                                        $hexStr = ($bytes | ForEach-Object { $_.ToString('X2') }) -join ''
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value "[LogonHours: $hexStr]"
                                    }
                                } catch {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                }
                            } elseif ($PropName -ieq "pKIExpirationPeriod" -or $PropName -ieq "pKIOverlapPeriod") {
                                # Convert PKI time period byte arrays to readable duration
                                try {
                                    $Bytes = $PropValue[0]
                                    if ($Bytes.Length -eq 8) {
                                        $Int64Value = [BitConverter]::ToInt64($Bytes, 0)
                                        $Seconds = [Math]::Abs($Int64Value) / 10000000

                                        if ($Seconds -ge 31536000) {
                                            $Years = [Math]::Floor($Seconds / 31536000)
                                            $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value "$Years year(s)"
                                        } elseif ($Seconds -ge 86400) {
                                            $Days = [Math]::Floor($Seconds / 86400)
                                            $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value "$Days day(s)"
                                        } elseif ($Seconds -ge 3600) {
                                            $Hours = [Math]::Floor($Seconds / 3600)
                                            $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value "$Hours hour(s)"
                                        } else {
                                            $Minutes = [Math]::Floor($Seconds / 60)
                                            $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value "$Minutes minute(s)"
                                        }
                                    } else {
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                    }
                                } catch {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                }
                            } elseif ($PropName -ieq "pKIKeyUsage") {
                                # Convert PKI Key Usage byte array to readable flags
                                try {
                                    $Bytes = $PropValue[0]
                                    if ($Bytes.Length -ge 2) {
                                        $KeyUsage = [int]$Bytes[0] + ([int]$Bytes[1] -shl 8)
                                        $KeyUsageList = @()

                                        if ($KeyUsage -band 0x0080) { $KeyUsageList += "Digital Signature" }
                                        if ($KeyUsage -band 0x0040) { $KeyUsageList += "Non Repudiation" }
                                        if ($KeyUsage -band 0x0020) { $KeyUsageList += "Key Encipherment" }
                                        if ($KeyUsage -band 0x0010) { $KeyUsageList += "Data Encipherment" }
                                        if ($KeyUsage -band 0x0008) { $KeyUsageList += "Key Agreement" }
                                        if ($KeyUsage -band 0x0004) { $KeyUsageList += "Key Cert Sign" }
                                        if ($KeyUsage -band 0x0002) { $KeyUsageList += "CRL Sign" }
                                        if ($KeyUsage -band 0x0001) { $KeyUsageList += "Encipher Only" }
                                        if ($KeyUsage -band 0x8000) { $KeyUsageList += "Decipher Only" }

                                        if ($KeyUsageList.Count -gt 0) {
                                            $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $KeyUsageList
                                        } else {
                                            $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value @("NONE")
                                        }
                                    } else {
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                    }
                                } catch {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                }
                            } else {
                                # Generic byte array handling
                                $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                            }
                        } else {
                            # Non-byte array single values - apply type conversions

                            # FileTime attributes (Windows FILETIME - 100-nanosecond intervals since 1601-01-01)
                            $FileTimeAttributes = @(
                                'lastlogon', 'lastlogontimestamp', 'pwdlastset', 'badpasswordtime',
                                'lockouttime', 'accountexpires', 'lastlogoff', 'maxpwdage', 'minpwdage',
                                'forcelogoff', 'lockoutduration', 'lockoutobservationwindow',
                                'creationtime', 'lastsettime'
                            )

                            # Generalized Time attributes (ISO 8601 format: YYYYMMDDHHmmss.0Z)
                            $GeneralizedTimeAttributes = @('whenchanged', 'whencreated', 'msexchwhenmailboxcreated')

                            if ($FileTimeAttributes -contains $PropNameLower) {
                                # Convert FileTime to DateTime
                                try {
                                    $ftValue = [long]$PropValue[0]
                                    # Handle special values: 0 = never, 9223372036854775807 = never expires
                                    if ($ftValue -eq 0 -or $ftValue -eq 9223372036854775807) {
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                    } else {
                                        $dateTime = [DateTime]::FromFileTime($ftValue)
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $dateTime
                                    }
                                } catch {
                                    # Fallback to raw value if conversion fails
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                }
                            } elseif ($GeneralizedTimeAttributes -contains $PropNameLower) {
                                # Convert Generalized Time (YYYYMMDDHHmmss.0Z) to DateTime
                                try {
                                    $gtValue = [string]$PropValue[0]
                                    # Parse format: 20260105135347.0Z
                                    if ($gtValue -match '^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})') {
                                        $dateTime = [DateTime]::new(
                                            [int]$Matches[1],  # Year
                                            [int]$Matches[2],  # Month
                                            [int]$Matches[3],  # Day
                                            [int]$Matches[4],  # Hour
                                            [int]$Matches[5],  # Minute
                                            [int]$Matches[6],  # Second
                                            [DateTimeKind]::Utc
                                        )
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $dateTime
                                    } else {
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                    }
                                } catch {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                }
                            } elseif ($PropNameLower -eq 'userparameters') {
                                # userParameters contains Terminal Services settings - skip conversion, show as placeholder
                                # The raw data is binary/encoded and not useful for display
                                $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value "[Terminal Services Settings]"
                            } elseif ($PropNameLower -eq 'useraccountcontrol') {
                                # Convert userAccountControl to readable flags
                                try {
                                    $UACValue = [Int32]$PropValue[0]
                                    $UACFlags = @()

                                    # Define UAC flags (MS-ADTS 2.2.16)
                                    $FlagMap = @{
                                        1 = "SCRIPT"
                                        2 = "ACCOUNTDISABLE"
                                        8 = "HOMEDIR_REQUIRED"
                                        16 = "LOCKOUT"
                                        32 = "PASSWD_NOTREQD"
                                        64 = "PASSWD_CANT_CHANGE"
                                        128 = "ENCRYPTED_TEXT_PWD_ALLOWED"
                                        256 = "TEMP_DUPLICATE_ACCOUNT"
                                        512 = "NORMAL_ACCOUNT"
                                        2048 = "INTERDOMAIN_TRUST_ACCOUNT"
                                        4096 = "WORKSTATION_TRUST_ACCOUNT"
                                        8192 = "SERVER_TRUST_ACCOUNT"
                                        65536 = "DONT_EXPIRE_PASSWORD"
                                        131072 = "MNS_LOGON_ACCOUNT"
                                        262144 = "SMARTCARD_REQUIRED"
                                        524288 = "TRUSTED_FOR_DELEGATION"
                                        1048576 = "NOT_DELEGATED"
                                        2097152 = "USE_DES_KEY_ONLY"
                                        4194304 = "DONT_REQ_PREAUTH"
                                        8388608 = "PASSWORD_EXPIRED"
                                        16777216 = "TRUSTED_TO_AUTH_FOR_DELEGATION"
                                        33554432 = "NO_AUTH_DATA_REQUIRED"
                                        67108864 = "PARTIAL_SECRETS_ACCOUNT"
                                    }

                                    foreach ($Flag in $FlagMap.Keys) {
                                        if ($UACValue -band $Flag) {
                                            $UACFlags += $FlagMap[$Flag]
                                        }
                                    }

                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $UACFlags
                                } catch {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                }
                            } elseif ($PropNameLower -eq 'msds-supportedencryptiontypes') {
                                # Convert supported encryption types to readable flags
                                try {
                                    $EncTypes = [Int32]$PropValue[0]
                                    $EncTypeFlags = @()

                                    # Encryption types (MS-KILE 2.2.7)
                                    if ($EncTypes -band 1) { $EncTypeFlags += "DES-CBC-CRC" }
                                    if ($EncTypes -band 2) { $EncTypeFlags += "DES-CBC-MD5" }
                                    if ($EncTypes -band 4) { $EncTypeFlags += "RC4-HMAC" }
                                    if ($EncTypes -band 8) { $EncTypeFlags += "AES128-CTS-HMAC-SHA1-96" }
                                    if ($EncTypes -band 16) { $EncTypeFlags += "AES256-CTS-HMAC-SHA1-96" }
                                    if ($EncTypes -band 32) { $EncTypeFlags += "AES256-CTS-HMAC-SHA1-96-SK" }
                                    # Kerberos feature flags
                                    if ($EncTypes -band 64) { $EncTypeFlags += "FAST-Supported" }
                                    if ($EncTypes -band 128) { $EncTypeFlags += "Compound-Identity-Supported" }
                                    if ($EncTypes -band 256) { $EncTypeFlags += "Claims-Supported" }
                                    if ($EncTypes -band 512) { $EncTypeFlags += "Resource-SID-Compression-Disabled" }

                                    if ($EncTypeFlags.Count -gt 0) {
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $EncTypeFlags
                                    } else {
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value @("Not configured")
                                    }
                                } catch {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                }
                            } elseif ($PropNameLower -eq 'samaccounttype') {
                                # Convert sAMAccountType to readable value
                                try {
                                    $SamType = [Int32]$PropValue[0]
                                    $SamTypeName = switch ($SamType) {
                                        268435456 { "GROUP_OBJECT" }
                                        268435457 { "NON_SECURITY_GROUP_OBJECT" }
                                        536870912 { "ALIAS_OBJECT" }
                                        536870913 { "NON_SECURITY_ALIAS_OBJECT" }
                                        805306368 { "USER_OBJECT" }
                                        805306369 { "MACHINE_ACCOUNT" }
                                        805306370 { "TRUST_ACCOUNT" }
                                        1073741824 { "APP_BASIC_GROUP" }
                                        1073741825 { "APP_QUERY_GROUP" }
                                        default { "UNKNOWN ($SamType)" }
                                    }
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $SamTypeName
                                } catch {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                }
                            } elseif ($PropNameLower -eq 'grouptype') {
                                # Convert groupType to readable flags
                                try {
                                    $GroupType = [Int32]$PropValue[0]
                                    $GroupScope = if ($GroupType -band 2) { "Global" }
                                                  elseif ($GroupType -band 4) { "Domain Local" }
                                                  elseif ($GroupType -band 8) { "Universal" }
                                                  elseif ($GroupType -band 1) { "Builtin Local" }
                                                  else { "Unknown Scope" }

                                    $GroupTypeName = if ($GroupType -band [int]0x80000000) {
                                        "$GroupScope Security Group"
                                    } else {
                                        "$GroupScope Distribution Group"
                                    }

                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $GroupTypeName
                                } catch {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                }
                            } elseif ($PropNameLower -eq 'instancetype') {
                                # Convert instanceType to readable value
                                try {
                                    $InstType = [Int32]$PropValue[0]
                                    if ($InstType -eq 4) {
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value "Writable"
                                    } else {
                                        $InstTypeFlags = @()
                                        if ($InstType -band 0x01) { $InstTypeFlags += "NC_HEAD" }
                                        if ($InstType -band 0x02) { $InstTypeFlags += "NC_REPLICA" }
                                        if ($InstType -band 0x04) { $InstTypeFlags += "NC_WRITABLE" }
                                        if ($InstType -band 0x08) { $InstTypeFlags += "NC_ABOVE" }
                                        if ($InstType -band 0x10) { $InstTypeFlags += "NC_BEING_CONSTRUCTED" }
                                        if ($InstType -band 0x20) { $InstTypeFlags += "NC_BEING_REMOVED" }
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value ($InstTypeFlags -join ", ")
                                    }
                                } catch {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                }
                            } elseif ($PropNameLower -eq 'systemflags') {
                                # Convert systemFlags to readable flags
                                try {
                                    $SysFlags = [Int32]$PropValue[0]
                                    $SysFlagsArray = @()

                                    $SysFlagsMap = @{
                                        0x00000001 = "FLAG_DISALLOW_DELETE"
                                        0x00000002 = "FLAG_CONFIG_ALLOW_RENAME"
                                        0x00000004 = "FLAG_CONFIG_ALLOW_MOVE"
                                        0x00000010 = "FLAG_ATTR_NOT_REPLICATED"
                                        0x04000000 = "FLAG_ATTR_IS_CONSTRUCTED"
                                        0x10000000 = "FLAG_DOMAIN_DISALLOW_RENAME"
                                        0x20000000 = "FLAG_DOMAIN_DISALLOW_MOVE"
                                        0x40000000 = "FLAG_CR_NTDS_NC"
                                        0x80000000 = "FLAG_CR_NTDS_DOMAIN"
                                    }

                                    foreach ($Flag in $SysFlagsMap.Keys) {
                                        if ($SysFlags -band $Flag) {
                                            $SysFlagsArray += $SysFlagsMap[$Flag]
                                        }
                                    }

                                    if ($SysFlagsArray.Count -gt 0) {
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $SysFlagsArray
                                    } else {
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value @("NONE")
                                    }
                                } catch {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                }
                            } elseif ($PropNameLower -eq 'trustdirection') {
                                # Convert trust direction to readable value (MS-ADTS 6.1.6.7.9)
                                try {
                                    $TrustDir = [Int32]$PropValue[0]
                                    $TrustDirName = switch ($TrustDir) {
                                        0 { "Disabled" }
                                        1 { "Inbound" }
                                        2 { "Outbound" }
                                        3 { "Bidirectional" }
                                        default { "Unknown ($TrustDir)" }
                                    }
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $TrustDirName
                                } catch {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                }
                            } elseif ($PropNameLower -eq 'trusttype') {
                                # Convert trust type to readable value (MS-ADTS 6.1.6.7.15)
                                try {
                                    $TrustTypeVal = [Int32]$PropValue[0]
                                    $TrustTypeName = switch ($TrustTypeVal) {
                                        1 { "Windows NT (Downlevel)" }
                                        2 { "Active Directory (Uplevel)" }
                                        3 { "MIT Kerberos Realm" }
                                        4 { "DCE" }
                                        default { "Unknown ($TrustTypeVal)" }
                                    }
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $TrustTypeName
                                } catch {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                }
                            } elseif ($PropNameLower -eq 'trustattributes') {
                                # Convert trust attributes to readable flags (MS-ADTS 6.1.6.7.9)
                                try {
                                    $TrustAttr = [Int32]$PropValue[0]
                                    $TrustAttrFlags = @()

                                    if ($TrustAttr -band 0x00000001) { $TrustAttrFlags += "NON_TRANSITIVE" }
                                    if ($TrustAttr -band 0x00000002) { $TrustAttrFlags += "UPLEVEL_ONLY" }
                                    if ($TrustAttr -band 0x00000004) { $TrustAttrFlags += "QUARANTINED_DOMAIN" }
                                    if ($TrustAttr -band 0x00000008) { $TrustAttrFlags += "FOREST_TRANSITIVE" }
                                    if ($TrustAttr -band 0x00000010) { $TrustAttrFlags += "CROSS_ORGANIZATION" }
                                    if ($TrustAttr -band 0x00000020) { $TrustAttrFlags += "WITHIN_FOREST" }
                                    if ($TrustAttr -band 0x00000040) { $TrustAttrFlags += "TREAT_AS_EXTERNAL" }
                                    if ($TrustAttr -band 0x00000080) { $TrustAttrFlags += "USES_RC4_ENCRYPTION" }
                                    if ($TrustAttr -band 0x00000200) { $TrustAttrFlags += "CROSS_ORGANIZATION_NO_TGT_DELEGATION" }
                                    if ($TrustAttr -band 0x00000400) { $TrustAttrFlags += "PIM_TRUST" }

                                    if ($TrustAttrFlags.Count -gt 0) {
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $TrustAttrFlags
                                    } else {
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value @("NONE")
                                    }
                                } catch {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                }
                            } elseif ($PropNameLower -eq 'pwdproperties') {
                                # Convert password properties to readable flags (MS-ADTS 6.1.6.1)
                                try {
                                    $PwdProps = [Int32]$PropValue[0]
                                    $PwdPropsFlags = @()

                                    if ($PwdProps -band 1) { $PwdPropsFlags += "DOMAIN_PASSWORD_COMPLEX" }
                                    if ($PwdProps -band 2) { $PwdPropsFlags += "DOMAIN_PASSWORD_NO_ANON_CHANGE" }
                                    if ($PwdProps -band 4) { $PwdPropsFlags += "DOMAIN_PASSWORD_NO_CLEAR_CHANGE" }
                                    if ($PwdProps -band 8) { $PwdPropsFlags += "DOMAIN_LOCKOUT_ADMINS" }
                                    if ($PwdProps -band 16) { $PwdPropsFlags += "DOMAIN_PASSWORD_STORE_CLEARTEXT" }
                                    if ($PwdProps -band 32) { $PwdPropsFlags += "DOMAIN_REFUSE_PASSWORD_CHANGE" }

                                    if ($PwdPropsFlags.Count -gt 0) {
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PwdPropsFlags
                                    } else {
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value @("NONE")
                                    }
                                } catch {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                }
                            } elseif ($PropNameLower -eq 'maxpwdage' -or $PropNameLower -eq 'minpwdage' -or $PropNameLower -eq 'lockoutduration' -or $PropNameLower -eq 'lockoutobservationwindow' -or $PropNameLower -eq 'forcelogoff') {
                                # Domain policy attributes (negative 100-nanosecond intervals)
                                try {
                                    $Ticks = [Int64]$PropValue[0]

                                    if ($Ticks -eq 0) {
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value "Not set"
                                    } elseif ($Ticks -eq -9223372036854775808) {
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value "Never"
                                    } else {
                                        $Seconds = [Math]::Abs($Ticks) / 10000000

                                        if ($PropNameLower -eq 'maxpwdage' -or $PropNameLower -eq 'minpwdage') {
                                            $Days = [Math]::Floor($Seconds / 86400)
                                            $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value "$Days days"
                                        } else {
                                            $Minutes = [Math]::Floor($Seconds / 60)
                                            $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value "$Minutes minutes"
                                        }
                                    }
                                } catch {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                }
                            } elseif ($PropNameLower -eq 'ms-mcs-admpwdexpirationtime' -or $PropNameLower -eq 'mslaps-passwordexpirationtime') {
                                # LAPS Expiration Times
                                try {
                                    $ExpirationInt64 = [Int64]$PropValue[0]
                                    $ExpirationDateTime = [DateTime]::FromFileTime($ExpirationInt64)
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $ExpirationDateTime
                                } catch {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                }
                            } elseif ($PropNameLower -eq 'mslaps-password') {
                                # LAPS Native Password as string - Parse JSON
                                try {
                                    $LAPSObj = $PropValue[0] | ConvertFrom-Json
                                    if ($LAPSObj.p) {
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $LAPSObj.p
                                    } else {
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                    }
                                } catch {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                }
                            } elseif ($PropNameLower -eq 'msexchrecipientdisplaytype') {
                                # Convert Exchange Recipient Display Type
                                try {
                                    $DisplayType = [Int64]$PropValue[0]
                                    $DisplayTypeName = switch ($DisplayType) {
                                        0 { "MailboxUser" }
                                        1 { "DistributionGroup" }
                                        2 { "PublicFolder" }
                                        3 { "DynamicDistributionGroup" }
                                        4 { "Organization" }
                                        5 { "PrivateDistributionList" }
                                        6 { "RemoteMailUser" }
                                        7 { "ConferenceRoomMailbox" }
                                        8 { "EquipmentMailbox" }
                                        10 { "ArbitrationMailbox" }
                                        11 { "MailboxPlan" }
                                        12 { "LinkedUser" }
                                        15 { "RoomList" }
                                        1073741824 { "ACLableMailboxUser" }
                                        1073741830 { "ACLableRemoteMailUser" }
                                        -2147483642 { "SyncedMailboxUser" }
                                        -2147483391 { "SyncedUDGasUDG" }
                                        -2147483386 { "SyncedUDGasContact" }
                                        -2147483130 { "SyncedPublicFolder" }
                                        -2147482874 { "SyncedDynamicDistributionGroup" }
                                        -2147482106 { "SyncedRemoteMailUser" }
                                        -2147481850 { "SyncedConferenceRoomMailbox" }
                                        -2147481594 { "SyncedEquipmentMailbox" }
                                        -2147481343 { "SyncedUSGasUDG" }
                                        -2147481338 { "SyncedUSGasContact" }
                                        -1073741818 { "ACLableSyncedMailboxUser" }
                                        -1073740282 { "ACLableSyncedRemoteMailUser" }
                                        -1073739514 { "ACLableSyncedUSGasContact" }
                                        -1073739511 { "SyncedUSGasUSG" }
                                        -1073741824 { "SecurityDistributionGroup" }
                                        default { "Type $DisplayType" }
                                    }
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $DisplayTypeName
                                } catch {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                }
                            } elseif ($PropNameLower -eq 'msexchrecipienttypedetails') {
                                # Convert Exchange Recipient Type Details
                                try {
                                    $TypeDetails = [Int64]$PropValue[0]
                                    $TypeName = switch ($TypeDetails) {
                                        1 { "UserMailbox" }
                                        2 { "LinkedMailbox" }
                                        4 { "SharedMailbox" }
                                        8 { "LegacyMailbox" }
                                        16 { "RoomMailbox" }
                                        32 { "EquipmentMailbox" }
                                        64 { "MailContact" }
                                        128 { "MailUser" }
                                        256 { "MailUniversalDistributionGroup" }
                                        512 { "MailNonUniversalGroup" }
                                        1024 { "MailUniversalSecurityGroup" }
                                        2048 { "DynamicDistributionGroup" }
                                        4096 { "PublicFolder" }
                                        8192 { "SystemAttendantMailbox" }
                                        16384 { "SystemMailbox" }
                                        32768 { "MailForestContact" }
                                        65536 { "User" }
                                        131072 { "Contact" }
                                        262144 { "UniversalDistributionGroup" }
                                        524288 { "UniversalSecurityGroup" }
                                        1048576 { "NonUniversalGroup" }
                                        2097152 { "DisabledUser" }
                                        4194304 { "MicrosoftExchange" }
                                        8388608 { "ArbitrationMailbox" }
                                        16777216 { "MailboxPlan" }
                                        33554432 { "LinkedUser" }
                                        268435456 { "RoomList" }
                                        536870912 { "DiscoveryMailbox" }
                                        1073741824 { "RoleGroup" }
                                        2147483648 { "RemoteUserMailbox" }
                                        4294967296 { "Computer" }
                                        8589934592 { "RemoteRoomMailbox" }
                                        17179869184 { "RemoteEquipmentMailbox" }
                                        34359738368 { "RemoteSharedMailbox" }
                                        68719476736 { "PublicFolderMailbox" }
                                        137438953472 { "TeamMailbox" }
                                        549755813888 { "MonitoringMailbox" }
                                        1099511627776 { "GroupMailbox" }
                                        2199023255552 { "LinkedRoomMailbox" }
                                        4398046511104 { "AuditLogMailbox" }
                                        17592186044416 { "SchedulingMailbox" }
                                        35184372088832 { "GuestMailUser" }
                                        default { "Type $TypeDetails" }
                                    }
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $TypeName
                                } catch {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                }
                            } elseif ($PropNameLower -eq 'mspki-certificate-name-flag') {
                                # Convert Certificate Name Flag to readable flags (ADCS ESC1)
                                try {
                                    $CertNameFlag = [Int32]$PropValue[0]
                                    $CertNameFlags = @()

                                    # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT (0x00000001) - ESC1 indicator
                                    if ($CertNameFlag -band 0x00000001) { $CertNameFlags += "ENROLLEE_SUPPLIES_SUBJECT" }
                                    # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME (0x00010000)
                                    if ($CertNameFlag -band 0x00010000) { $CertNameFlags += "ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME" }
                                    # CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS (0x00400000)
                                    if ($CertNameFlag -band 0x00400000) { $CertNameFlags += "SUBJECT_ALT_REQUIRE_DOMAIN_DNS" }
                                    # CT_FLAG_SUBJECT_ALT_REQUIRE_SPN (0x00800000)
                                    if ($CertNameFlag -band 0x00800000) { $CertNameFlags += "SUBJECT_ALT_REQUIRE_SPN" }
                                    # CT_FLAG_SUBJECT_ALT_REQUIRE_DIRECTORY_GUID (0x01000000)
                                    if ($CertNameFlag -band 0x01000000) { $CertNameFlags += "SUBJECT_ALT_REQUIRE_DIRECTORY_GUID" }
                                    # CT_FLAG_SUBJECT_ALT_REQUIRE_UPN (0x02000000)
                                    if ($CertNameFlag -band 0x02000000) { $CertNameFlags += "SUBJECT_ALT_REQUIRE_UPN" }
                                    # CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL (0x04000000)
                                    if ($CertNameFlag -band 0x04000000) { $CertNameFlags += "SUBJECT_ALT_REQUIRE_EMAIL" }
                                    # CT_FLAG_SUBJECT_ALT_REQUIRE_DNS (0x08000000)
                                    if ($CertNameFlag -band 0x08000000) { $CertNameFlags += "SUBJECT_ALT_REQUIRE_DNS" }
                                    # CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN (0x10000000)
                                    if ($CertNameFlag -band 0x10000000) { $CertNameFlags += "SUBJECT_REQUIRE_DNS_AS_CN" }
                                    # CT_FLAG_SUBJECT_REQUIRE_EMAIL (0x20000000)
                                    if ($CertNameFlag -band 0x20000000) { $CertNameFlags += "SUBJECT_REQUIRE_EMAIL" }
                                    # CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME (0x40000000)
                                    if ($CertNameFlag -band 0x40000000) { $CertNameFlags += "SUBJECT_REQUIRE_COMMON_NAME" }
                                    # CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH (0x80000000)
                                    if ($CertNameFlag -band 0x80000000) { $CertNameFlags += "SUBJECT_REQUIRE_DIRECTORY_PATH" }
                                    # CT_FLAG_OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME (0x00000008)
                                    if ($CertNameFlag -band 0x00000008) { $CertNameFlags += "OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME" }

                                    if ($CertNameFlags.Count -gt 0) {
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $CertNameFlags
                                    } else {
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value @("NONE")
                                    }
                                } catch {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                }
                            } elseif ($PropNameLower -eq 'mspki-enrollment-flag') {
                                # Convert Enrollment Flag to readable flags (ADCS ESC2/ESC9)
                                try {
                                    $EnrollFlag = [Int32]$PropValue[0]
                                    $EnrollFlags = @()

                                    # CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS (0x00000001)
                                    if ($EnrollFlag -band 0x00000001) { $EnrollFlags += "INCLUDE_SYMMETRIC_ALGORITHMS" }
                                    # CT_FLAG_PEND_ALL_REQUESTS (0x00000002) - Manager approval required
                                    if ($EnrollFlag -band 0x00000002) { $EnrollFlags += "PEND_ALL_REQUESTS" }
                                    # CT_FLAG_PUBLISH_TO_KRA_CONTAINER (0x00000004)
                                    if ($EnrollFlag -band 0x00000004) { $EnrollFlags += "PUBLISH_TO_KRA_CONTAINER" }
                                    # CT_FLAG_PUBLISH_TO_DS (0x00000008)
                                    if ($EnrollFlag -band 0x00000008) { $EnrollFlags += "PUBLISH_TO_DS" }
                                    # CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE (0x00000010)
                                    if ($EnrollFlag -band 0x00000010) { $EnrollFlags += "AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE" }
                                    # CT_FLAG_AUTO_ENROLLMENT (0x00000020)
                                    if ($EnrollFlag -band 0x00000020) { $EnrollFlags += "AUTO_ENROLLMENT" }
                                    # CT_FLAG_PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT (0x00000040)
                                    if ($EnrollFlag -band 0x00000040) { $EnrollFlags += "PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT" }
                                    # CT_FLAG_USER_INTERACTION_REQUIRED (0x00000100)
                                    if ($EnrollFlag -band 0x00000100) { $EnrollFlags += "USER_INTERACTION_REQUIRED" }
                                    # CT_FLAG_REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE (0x00000400)
                                    if ($EnrollFlag -band 0x00000400) { $EnrollFlags += "REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE" }
                                    # CT_FLAG_ALLOW_ENROLL_ON_BEHALF_OF (0x00000800)
                                    if ($EnrollFlag -band 0x00000800) { $EnrollFlags += "ALLOW_ENROLL_ON_BEHALF_OF" }
                                    # CT_FLAG_ADD_OCSP_NOCHECK (0x00001000)
                                    if ($EnrollFlag -band 0x00001000) { $EnrollFlags += "ADD_OCSP_NOCHECK" }
                                    # CT_FLAG_ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL (0x00002000)
                                    if ($EnrollFlag -band 0x00002000) { $EnrollFlags += "ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL" }
                                    # CT_FLAG_NOREVOCATIONINFOINISSUEDCERTS (0x00004000)
                                    if ($EnrollFlag -band 0x00004000) { $EnrollFlags += "NOREVOCATIONINFOINISSUEDCERTS" }
                                    # CT_FLAG_INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS (0x00008000)
                                    if ($EnrollFlag -band 0x00008000) { $EnrollFlags += "INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS" }
                                    # CT_FLAG_ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT (0x00010000)
                                    if ($EnrollFlag -band 0x00010000) { $EnrollFlags += "ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT" }
                                    # CT_FLAG_ISSUANCE_POLICIES_FROM_REQUEST (0x00020000)
                                    if ($EnrollFlag -band 0x00020000) { $EnrollFlags += "ISSUANCE_POLICIES_FROM_REQUEST" }
                                    # CT_FLAG_SKIP_AUTO_RENEWAL (0x00040000)
                                    if ($EnrollFlag -band 0x00040000) { $EnrollFlags += "SKIP_AUTO_RENEWAL" }
                                    # CT_FLAG_NO_SECURITY_EXTENSION (0x00080000) - ESC9 indicator
                                    if ($EnrollFlag -band 0x00080000) { $EnrollFlags += "NO_SECURITY_EXTENSION" }

                                    if ($EnrollFlags.Count -gt 0) {
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $EnrollFlags
                                    } else {
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value @("NONE")
                                    }
                                } catch {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                }
                            } elseif ($PropNameLower -eq 'mspki-private-key-flag') {
                                # Convert Private Key Flag to readable flags
                                try {
                                    $PrivKeyFlag = [Int32]$PropValue[0]
                                    $PrivKeyFlags = @()

                                    # CT_FLAG_REQUIRE_PRIVATE_KEY_ARCHIVAL (0x00000001)
                                    if ($PrivKeyFlag -band 0x00000001) { $PrivKeyFlags += "REQUIRE_PRIVATE_KEY_ARCHIVAL" }
                                    # CT_FLAG_EXPORTABLE_KEY (0x00000010)
                                    if ($PrivKeyFlag -band 0x00000010) { $PrivKeyFlags += "EXPORTABLE_KEY" }
                                    # CT_FLAG_STRONG_KEY_PROTECTION_REQUIRED (0x00000020)
                                    if ($PrivKeyFlag -band 0x00000020) { $PrivKeyFlags += "STRONG_KEY_PROTECTION_REQUIRED" }
                                    # CT_FLAG_REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM (0x00000040)
                                    if ($PrivKeyFlag -band 0x00000040) { $PrivKeyFlags += "REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM" }
                                    # CT_FLAG_REQUIRE_SAME_KEY_RENEWAL (0x00000080)
                                    if ($PrivKeyFlag -band 0x00000080) { $PrivKeyFlags += "REQUIRE_SAME_KEY_RENEWAL" }
                                    # CT_FLAG_USE_LEGACY_PROVIDER (0x00000100)
                                    if ($PrivKeyFlag -band 0x00000100) { $PrivKeyFlags += "USE_LEGACY_PROVIDER" }
                                    # CT_FLAG_ATTEST_NONE (0x00000000) - implicit
                                    # CT_FLAG_ATTEST_REQUIRED (0x00002000)
                                    if ($PrivKeyFlag -band 0x00002000) { $PrivKeyFlags += "ATTEST_REQUIRED" }
                                    # CT_FLAG_ATTEST_PREFERRED (0x00001000)
                                    if ($PrivKeyFlag -band 0x00001000) { $PrivKeyFlags += "ATTEST_PREFERRED" }
                                    # CT_FLAG_ATTESTATION_WITHOUT_POLICY (0x00004000)
                                    if ($PrivKeyFlag -band 0x00004000) { $PrivKeyFlags += "ATTESTATION_WITHOUT_POLICY" }
                                    # CT_FLAG_EK_TRUST_ON_USE (0x00000200)
                                    if ($PrivKeyFlag -band 0x00000200) { $PrivKeyFlags += "EK_TRUST_ON_USE" }
                                    # CT_FLAG_EK_VALIDATE_CERT (0x00000400)
                                    if ($PrivKeyFlag -band 0x00000400) { $PrivKeyFlags += "EK_VALIDATE_CERT" }
                                    # CT_FLAG_EK_VALIDATE_KEY (0x00000800)
                                    if ($PrivKeyFlag -band 0x00000800) { $PrivKeyFlags += "EK_VALIDATE_KEY" }
                                    # CT_FLAG_HELLO_LOGON_KEY (0x00200000)
                                    if ($PrivKeyFlag -band 0x00200000) { $PrivKeyFlags += "HELLO_LOGON_KEY" }

                                    if ($PrivKeyFlags.Count -gt 0) {
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PrivKeyFlags
                                    } else {
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value @("NONE")
                                    }
                                } catch {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                }
                            } elseif ($PropNameLower -eq 'pkidefaultkeyspec') {
                                # Convert pKIDefaultKeySpec to readable value
                                try {
                                    $KeySpec = [Int32]$PropValue[0]
                                    $KeySpecName = switch ($KeySpec) {
                                        1 { "AT_KEYEXCHANGE (Key Exchange)" }
                                        2 { "AT_SIGNATURE (Digital Signature)" }
                                        default { "Unknown ($KeySpec)" }
                                    }
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $KeySpecName
                                } catch {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                }
                            } elseif ($PropNameLower -eq 'msrassavedframedipaddress') {
                                # Convert IP address from signed Int32 to dotted decimal notation
                                try {
                                    $IPBytes = [BitConverter]::GetBytes([Int32]$PropValue[0])
                                    $IPAddr = [System.Net.IPAddress]::new($IPBytes)
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $IPAddr.ToString()
                                } catch {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                }
                            } elseif ($PropNameLower -eq 'msexchversion') {
                                # Convert Exchange Version to readable format
                                try {
                                    $Version = [Int64]$PropValue[0]
                                    $Major = ($Version -shr 48) -band 0xFFFF
                                    $Minor = ($Version -shr 32) -band 0xFFFF
                                    $Build = ($Version -shr 16) -band 0xFFFF
                                    $Revision = $Version -band 0xFFFF
                                    $VersionString = "$Major.$Minor.$Build.$Revision"
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $VersionString
                                } catch {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                }
                            } elseif ($PropNameLower -eq 'msexchelcmailboxflags') {
                                # Convert Exchange ELC Mailbox Flags to readable flags
                                try {
                                    $ELCFlags = [Int32]$PropValue[0]
                                    $ELCFlagList = @()

                                    if ($ELCFlags -band 1) { $ELCFlagList += "MRM_POLICY_APPLIED" }
                                    if ($ELCFlags -band 2) { $ELCFlagList += "SINGLE_ITEM_RECOVERY" }
                                    if ($ELCFlags -band 4) { $ELCFlagList += "CALENDAR_VERSION_STORE" }
                                    if ($ELCFlags -band 8) { $ELCFlagList += "LITIGATION_HOLD" }
                                    if ($ELCFlags -band 16) { $ELCFlagList += "DUMPSTER_EXTENDED" }
                                    if ($ELCFlags -band 32) { $ELCFlagList += "SITE_MAILBOX_HOLD" }
                                    if ($ELCFlags -band 64) { $ELCFlagList += "ARCHIVE_ENABLED" }
                                    if ($ELCFlags -band 128) { $ELCFlagList += "ELC_PROCESSING_DISABLED" }

                                    if ($ELCFlagList.Count -gt 0) {
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $ELCFlagList
                                    } else {
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value @("NONE")
                                    }
                                } catch {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                }
                            } elseif ($PropNameLower -eq 'gplink') {
                                # GPO links - format for readability
                                try {
                                    $GPLinkString = $PropValue[0]

                                    # Parse GPO links: [LDAP://cn={GUID},cn=policies,cn=system,DC=...;LinkOptions]
                                    $GPLinks = @()
                                    $Pattern = '(?i)\[LDAP://cn=\{([^\}]+)\}[^\]]+;(\d+)\]'
                                    $GPLinkMatches = [regex]::Matches($GPLinkString, $Pattern)

                                    foreach ($Match in $GPLinkMatches) {
                                        $GUID = $Match.Groups[1].Value
                                        $LinkOptions = [int]$Match.Groups[2].Value

                                        # Link options: 0 = Enabled, 1 = Disabled, 2 = Enforced, 3 = Disabled+Enforced
                                        $Status = if ($LinkOptions -band 1) { "Disabled" } else { "Enabled" }
                                        if ($LinkOptions -band 2) { $Status += " (Enforced)" }

                                        $GPLinks += "GPO {$GUID} [$Status]"
                                    }

                                    if ($GPLinks.Count -gt 0) {
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $GPLinks
                                    } else {
                                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                    }
                                } catch {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                }
                            } elseif ($PropNameLower -match '^msexch.*quota$' -or $PropNameLower -eq 'mdbstoragequota' -or $PropNameLower -eq 'mdboverquotalimit' -or $PropNameLower -eq 'mdboverhardquotalimit') {
                                # Convert Exchange quota attributes from bytes to human-readable format
                                try {
                                    $QuotaBytes = [Int64]$PropValue[0]

                                    if ($QuotaBytes -eq 0) {
                                        $QuotaString = "Unlimited"
                                    } elseif ($QuotaBytes -lt 1KB) {
                                        $QuotaString = "$QuotaBytes bytes"
                                    } elseif ($QuotaBytes -lt 1MB) {
                                        $QuotaKB = [Math]::Round($QuotaBytes / 1KB, 2)
                                        $QuotaString = "$QuotaKB KB"
                                    } elseif ($QuotaBytes -lt 1GB) {
                                        $QuotaMB = [Math]::Round($QuotaBytes / 1MB, 2)
                                        $QuotaString = "$QuotaMB MB"
                                    } elseif ($QuotaBytes -lt 1TB) {
                                        $QuotaGB = [Math]::Round($QuotaBytes / 1GB, 2)
                                        $QuotaString = "$QuotaGB GB"
                                    } else {
                                        $QuotaTB = [Math]::Round($QuotaBytes / 1TB, 2)
                                        $QuotaString = "$QuotaTB TB"
                                    }

                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $QuotaString
                                } catch {
                                    $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                                }
                            } else {
                                # Default: add as-is
                                $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                            }
                        }
                    } else {
                        # Multiple values - add as array
                        $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value @($PropValue)
                    }
                }

                # Sort properties alphabetically for consistent output
                $SortedPropertyNames = $Obj.PSObject.Properties.Name | Sort-Object

                $SortedObj = [PSCustomObject]@{}
                foreach ($SortedPropName in $SortedPropertyNames) {
                    $SortedObj | Add-Member -Force -MemberType NoteProperty -Name $SortedPropName -Value $Obj.$SortedPropName
                }

                [void]$OutputObjects.Add($SortedObj)
            }

            Write-Log "[Invoke-LDAPSearch] Processing completed: $($OutputObjects.Count) objects"
            return $OutputObjects

        } catch {
            # Check if it's a "not found" error (expected case when SearchBase doesn't exist)
            # Uses central error handling from adPEAS-ErrorCodes.ps1
            if (Test-LDAPErrorNotFound -Exception $_.Exception) {
                # Not an error - just no results. Return empty array silently.
                Write-Log "[Invoke-LDAPSearch] SearchBase not found: $SearchBase"
                return @()
            } else {
                # Real error - log and re-throw
                Write-Log "[Invoke-LDAPSearch] Error during LDAP search: $_"
                throw
            }
        }
    }

    end {
    }
}
