function Get-ADCSVulnerabilities {
    <#
    .SYNOPSIS
    Detects Active Directory Certificate Services (AD CS) misconfigurations and vulnerabilities.

    .DESCRIPTION
    Enumerates AD CS certificate templates, Certificate Authorities, and PKI trust infrastructure to identify common security misconfigurations that could lead to privilege escalation.

    Checks for:
    - PKI Trust Infrastructure: Root CAs, NTAuth Store, AIA CAs
    - CA Certificate Security: Weak algorithms, short keys, expired certificates
    - ESC1: Client Authentication + Enrollee-Supplied Subject
    - ESC2: Any Purpose EKU
    - ESC3: Certificate Request Agent EKU
    - ESC4: Dangerous Template Permissions
    - ESC5: Vulnerable PKI Container Permissions
    - ESC9: No Security Extension + Client Authentication
    - ESC13: Issuance Policy Linked to AD Group
    - ESC15: Schema v1 + Enrollee-Supplied Subject (CVE-2024-49019)
    - Dangerous AD object permissions on Certificate Authorities

    .PARAMETER Domain
    Target domain (FQDN). If not specified, uses current domain from session.

    .PARAMETER Server
    Specific Domain Controller to query. If not specified, uses session server.

    .PARAMETER Credential
    PSCredential object for authentication. If not specified, uses session credentials.

    .PARAMETER IncludePrivileged
    Include privileged accounts (Domain Admin members) in dangerous permissions output.
    By default, accounts that are members of Domain Admins/Enterprise Admins are not shown in ESC4 findings since they already have admin rights.
    Use this switch to display them as well (shown in yellow instead of red).

    .EXAMPLE
    Get-ADCSVulnerabilities
    Performs AD CS security analysis using current session.

    .EXAMPLE
    Get-ADCSVulnerabilities -Domain "contoso.com" -Credential (Get-Credential)
    Performs AD CS security analysis with explicit credentials.

    .EXAMPLE
    Get-ADCSVulnerabilities -IncludePrivileged
    Performs AD CS security analysis and includes privileged accounts in dangerous permissions.

    .NOTES
    Category: ADCS
    Author: Alexander Sturz (@_61106960_)
    Based on Certipy by @ly4k (https://github.com/ly4k/Certipy)
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [switch]$IncludePrivileged
    )

    begin {
        # Helper function: Check if ALL enrollment principals are truly privileged
        # Uses central Test-IsPrivileged function from adPEAS-SIDs.ps1
        # "Truly privileged" = Category 'Privileged' (NOT Operator, NOT BroadGroup)
        # Uses SIDs when available (more reliable), falls back to names
        function Test-AllEnrollmentPrivileged {
            param(
                [string[]]$EnrollmentPrincipalSIDs,
                [string[]]$EnrollmentPrincipals,
                [hashtable]$CredParams = @{}
            )

            if (-not $EnrollmentPrincipals -or @($EnrollmentPrincipals).Count -eq 0) {
                # No enrollment principals = everyone can enroll = NOT privileged
                return $false
            }

            # Check each principal - use SID if available at same index, otherwise use name
            for ($i = 0; $i -lt $EnrollmentPrincipals.Count; $i++) {
                $principalName = $EnrollmentPrincipals[$i]
                $principalSID = if ($EnrollmentPrincipalSIDs -and $i -lt $EnrollmentPrincipalSIDs.Count) {
                    $EnrollmentPrincipalSIDs[$i]
                } else {
                    $null
                }

                # Use SID if available (more reliable), otherwise use name
                $identity = if ($principalSID) { $principalSID } else { $principalName }

                Write-Log "[Test-AllEnrollmentPrivileged] Checking: $principalName (SID: $principalSID, using: $identity)"

                # Use central Test-IsPrivileged function
                $result = Test-IsPrivileged -Identity $identity

                # Only Category 'Privileged' counts as truly privileged
                # Operators, BroadGroups, Standard, and Unknown are NOT privileged for enrollment purposes
                if ($result.Category -ne 'Privileged') {
                    Write-Log "[Test-AllEnrollmentPrivileged] Found non-privileged: $principalName (Category: $($result.Category), Reason: $($result.Reason))"
                    return $false
                }

                Write-Log "[Test-AllEnrollmentPrivileged] Privileged: $principalName (Category: $($result.Category))"
            }

            # All principals are truly privileged
            Write-Log "[Test-AllEnrollmentPrivileged] All enrollment principals are truly privileged"
            return $true
        }
    }

    process {
        # Build credential parameters for inner functions and DirectoryEntry calls (Pattern B)
        # MUST be defined BEFORE Ensure-LDAPConnection call!
        $CredParams = @{}
        if ($PSBoundParameters.ContainsKey('Domain')) { $CredParams['Domain'] = $Domain }
        if ($PSBoundParameters.ContainsKey('Server')) { $CredParams['Server'] = $Server }
        if ($PSBoundParameters.ContainsKey('Credential')) { $CredParams['Credential'] = $Credential }

        # Ensure LDAP connection (displays error if needed)
        if (-not (Ensure-LDAPConnection @CredParams)) {
            # Return without output to avoid redundant error display
            return
        }

        try {
            # Step 0: PKI Trust Infrastructure Overview (Root CAs, NTAuth Store)
            $configNC = $Script:LDAPContext.ConfigurationNamingContext
            Show-SubHeader "Checking PKI trust infrastructure..." -ObjectType "PKIInfrastructure"

            # --- Root CAs (trusted root certificates in AD) ---
            try {
                $rootCASearchBase = "CN=Certification Authorities,CN=Public Key Services,CN=Services,$configNC"
                $rootCAs = @(Invoke-LDAPSearch -Filter "(objectClass=certificationAuthority)" -SearchBase $rootCASearchBase -Properties 'cn','distinguishedName','cACertificate' -Scope OneLevel)

                if (@($rootCAs).Count -gt 0) {
                    Show-Line "Found $(@($rootCAs).Count) trusted Root CA(s) in AD configuration" -Class Note

                    foreach ($rootCA in $rootCAs) {
                        $rootCAName = if ($rootCA.cn -is [array]) { $rootCA.cn[0] } else { $rootCA.cn }
                        $rootCert = $rootCA.cACertificate
                        if ($rootCert -is [array]) { $rootCert = $rootCert[0] }

                        $rootCAObj = [PSCustomObject]@{
                            Name                   = $rootCAName
                            Subject                = if ($rootCert.SubjectFull) { $rootCert.SubjectFull } else { $rootCAName }
                            Issuer                 = if ($rootCert.IssuerFull) { $rootCert.IssuerFull } elseif ($rootCert.Issuer) { $rootCert.Issuer } else { $null }
                            SerialNumber           = if ($rootCert.SerialNumber) { $rootCert.SerialNumber } else { $null }
                            Thumbprint             = if ($rootCert.Thumbprint) { $rootCert.Thumbprint } else { "Unknown" }
                            Validity               = if ($rootCert.NotAfter) { "$($rootCert.NotBefore.ToString('yyyy-MM-dd')) to $($rootCert.NotAfter.ToString('yyyy-MM-dd'))" } else { "Unknown" }
                            Status                 = if ($rootCert.Status) { $rootCert.Status } else { "Unknown" }
                            SignatureAlgorithm     = if ($rootCert.SignatureAlgorithm) { $rootCert.SignatureAlgorithm } else { "Unknown" }
                            KeySize                = if ($rootCert.PublicKeyLength -and $rootCert.PublicKeyLength -gt 0) { "$($rootCert.PublicKeyLength) bit" } else { "Unknown" }
                            HasBasicConstraints    = if ($null -ne $rootCert.HasBasicConstraints) { $rootCert.HasBasicConstraints } else { $null }
                            CRLDistributionPoints  = if ($rootCert.CRLDistributionPoints -and @($rootCert.CRLDistributionPoints).Count -gt 0) { $rootCert.CRLDistributionPoints } else { $null }
                            OCSPURLs               = if ($rootCert.OCSPURLs -and @($rootCert.OCSPURLs).Count -gt 0) { $rootCert.OCSPURLs } else { $null }
                            AIAURLs                = if ($rootCert.AIAURLs -and @($rootCert.AIAURLs).Count -gt 0) { $rootCert.AIAURLs } else { $null }
                        }
                        $rootCAObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'RootCA' -Force
                        Show-Object $rootCAObj
                    }
                } else {
                    Show-Line "No trusted Root CAs found in AD configuration" -Class Note
                }
            }
            catch {
                Write-Log "[Get-ADCSVulnerabilities] Error querying Root CAs: $_" -Level Warning
            }

            # --- NTAuth Store (certificates trusted for domain authentication / PKINIT) ---
            try {
                $ntAuthSearchBase = "CN=Public Key Services,CN=Services,$configNC"
                $ntAuthResults = @(Invoke-LDAPSearch -Filter "(cn=NTAuthCertificates)" -SearchBase $ntAuthSearchBase -Properties 'cn','cACertificate' -Scope OneLevel)

                if (@($ntAuthResults).Count -gt 0) {
                    $ntAuthObj = $ntAuthResults[0]
                    $ntAuthCerts = $ntAuthObj.cACertificate

                    # cACertificate may be single object or array of objects
                    $certList = @()
                    if ($ntAuthCerts -is [array]) {
                        $certList = @($ntAuthCerts)
                    } elseif ($ntAuthCerts) {
                        $certList = @($ntAuthCerts)
                    }

                    if (@($certList).Count -gt 0) {
                        Show-Line "NTAuth Store contains $(@($certList).Count) certificate(s) trusted for domain authentication (PKINIT)" -Class Note
                        foreach ($ntCert in $certList) {
                            if ($ntCert -and $ntCert.Subject) {
                                $ntAuthCertObj = [PSCustomObject]@{
                                    Subject                = if ($ntCert.SubjectFull) { $ntCert.SubjectFull } elseif ($ntCert.Subject) { $ntCert.Subject } else { "Unknown" }
                                    Issuer                 = if ($ntCert.IssuerFull) { $ntCert.IssuerFull } elseif ($ntCert.Issuer) { $ntCert.Issuer } else { "Unknown" }
                                    SerialNumber           = if ($ntCert.SerialNumber) { $ntCert.SerialNumber } else { $null }
                                    Thumbprint             = if ($ntCert.Thumbprint) { $ntCert.Thumbprint } else { "Unknown" }
                                    Validity               = if ($ntCert.NotAfter) { "$($ntCert.NotBefore.ToString('yyyy-MM-dd')) to $($ntCert.NotAfter.ToString('yyyy-MM-dd'))" } else { "Unknown" }
                                    Status                 = if ($ntCert.Status) { $ntCert.Status } else { "Unknown" }
                                    SignatureAlgorithm     = if ($ntCert.SignatureAlgorithm) { $ntCert.SignatureAlgorithm } else { "Unknown" }
                                    KeySize                = if ($ntCert.PublicKeyLength -and $ntCert.PublicKeyLength -gt 0) { "$($ntCert.PublicKeyLength) bit" } else { "Unknown" }
                                    HasBasicConstraints    = if ($null -ne $ntCert.HasBasicConstraints) { $ntCert.HasBasicConstraints } else { $null }
                                    CRLDistributionPoints  = if ($ntCert.CRLDistributionPoints -and @($ntCert.CRLDistributionPoints).Count -gt 0) { $ntCert.CRLDistributionPoints } else { $null }
                                    OCSPURLs               = if ($ntCert.OCSPURLs -and @($ntCert.OCSPURLs).Count -gt 0) { $ntCert.OCSPURLs } else { $null }
                                    AIAURLs                = if ($ntCert.AIAURLs -and @($ntCert.AIAURLs).Count -gt 0) { $ntCert.AIAURLs } else { $null }
                                }
                                $ntAuthCertObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'NTAuthCertificate' -Force
                                Show-Object $ntAuthCertObj
                            }
                        }
                    } else {
                        Show-Line "NTAuth Store exists but contains no certificates" -Class Hint
                    }
                } else {
                    Show-Line "No NTAuth Store found - PKINIT certificate authentication may not be configured" -Class Note
                }
            }
            catch {
                Write-Log "[Get-ADCSVulnerabilities] Error querying NTAuth Store: $_" -Level Warning
            }

            # --- AIA CAs (Authority Information Access) ---
            try {
                $aiaSearchBase = "CN=AIA,CN=Public Key Services,CN=Services,$configNC"
                $aiaCAs = @(Invoke-LDAPSearch -Filter "(objectClass=certificationAuthority)" -SearchBase $aiaSearchBase -Properties 'cn','distinguishedName','cACertificate' -Scope OneLevel)

                if (@($aiaCAs).Count -gt 0) {
                    Show-Line "Found $(@($aiaCAs).Count) AIA (Authority Information Access) CA(s)" -Class Note
                    foreach ($aiaCA in $aiaCAs) {
                        $aiaCAName = if ($aiaCA.cn -is [array]) { $aiaCA.cn[0] } else { $aiaCA.cn }
                        $aiaCert = $aiaCA.cACertificate
                        if ($aiaCert -is [array]) { $aiaCert = $aiaCert[0] }

                        $aiaCAObj = [PSCustomObject]@{
                            Subject                = if ($aiaCert -and $aiaCert.SubjectFull) { $aiaCert.SubjectFull } elseif ($aiaCert -and $aiaCert.Subject) { $aiaCert.Subject } else { $aiaCAName }
                            Issuer                 = if ($aiaCert -and $aiaCert.IssuerFull) { $aiaCert.IssuerFull } elseif ($aiaCert -and $aiaCert.Issuer) { $aiaCert.Issuer } else { "Unknown" }
                            SerialNumber           = if ($aiaCert -and $aiaCert.SerialNumber) { $aiaCert.SerialNumber } else { $null }
                            Thumbprint             = if ($aiaCert.Thumbprint) { $aiaCert.Thumbprint } else { "Unknown" }
                            Validity               = if ($aiaCert.NotAfter) { "$($aiaCert.NotBefore.ToString('yyyy-MM-dd')) to $($aiaCert.NotAfter.ToString('yyyy-MM-dd'))" } else { "Unknown" }
                            Status                 = if ($aiaCert.Status) { $aiaCert.Status } else { "Unknown" }
                            SignatureAlgorithm     = if ($aiaCert.SignatureAlgorithm) { $aiaCert.SignatureAlgorithm } else { "Unknown" }
                            KeySize                = if ($aiaCert.PublicKeyLength -and $aiaCert.PublicKeyLength -gt 0) { "$($aiaCert.PublicKeyLength) bit" } else { "Unknown" }
                            HasBasicConstraints    = if ($aiaCert -and $null -ne $aiaCert.HasBasicConstraints) { $aiaCert.HasBasicConstraints } else { $null }
                            CRLDistributionPoints  = if ($aiaCert -and $aiaCert.CRLDistributionPoints -and @($aiaCert.CRLDistributionPoints).Count -gt 0) { $aiaCert.CRLDistributionPoints } else { $null }
                            OCSPURLs               = if ($aiaCert -and $aiaCert.OCSPURLs -and @($aiaCert.OCSPURLs).Count -gt 0) { $aiaCert.OCSPURLs } else { $null }
                            AIAURLs                = if ($aiaCert -and $aiaCert.AIAURLs -and @($aiaCert.AIAURLs).Count -gt 0) { $aiaCert.AIAURLs } else { $null }
                        }
                        $aiaCAObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'AIACA' -Force
                        Show-Object $aiaCAObj
                    }
                }
            }
            catch {
                Write-Log "[Get-ADCSVulnerabilities] Error querying AIA CAs: $_" -Level Warning
            }

            # Step 1: Enumerate Certificate Authorities (Infrastructure)
            Show-SubHeader "Searching for AD CS Infrastructure..." -ObjectType "CertificateAuthority"
            $caResults = @(Get-CertificateAuthority @CredParams)

            # Check if query failed (auth error, network issue, etc.)
            $queryError = $caResults | Where-Object { $_._QueryError -eq $true }
            if ($queryError) {
                Write-Log "[Get-ADCSVulnerabilities] CA query failed: $($queryError.ErrorMessage)"
                Show-Line "Failed to query Certificate Authorities - LDAP query failed (authentication/network issue)" -Class Finding
                return
            }

            # Filter out any error markers (should be none at this point)
            $cas = @($caResults | Where-Object { $_._QueryError -ne $true })

            if (@($cas).Count -eq 0) {
                Show-Line "No Certificate Authorities found - AD CS not deployed" -Class Note
                return
            }

            # Display CA count immediately after search
            Show-Line "Found $($cas.Count) Certificate Authority(s)" -Class Hint

            # Track CA vulnerabilities for summary
            $caVulnerabilityCount = 0

            # Display CA details
            foreach ($ca in $cas) {
                # ===== Web Enrollment Detection (ESC8 Infrastructure Check) =====
                # Check HTTP/HTTPS availability and authentication methods
                # This does NOT determine ESC8 vulnerability itself (requires manual verification)
                # but provides useful infrastructure information for the tester
                $webEnrollmentResult = $null

                if ($ca.DNSHostName) {
                    # Get the CA computer object to check activity
                    # Escape for LDAP filter to prevent injection (RFC 4515)
                    $escapedDnsHostName = Escape-LDAPFilterValue -Value $ca.DNSHostName
                    $caComputer = @(Get-DomainComputer -LDAPFilter "(dNSHostName=$escapedDnsHostName)" @CredParams)[0]

                    # Determine if CA server is inactive (skip HTTP check for inactive servers)
                    $skipHttpCheck = $false
                    if ($caComputer) {
                        $isInactive = $null -ne ($caComputer | Test-AccountActivity -IsInactive)
                        if ($isInactive) {
                            Write-Log "[Get-ADCSVulnerabilities] Skipping HTTP check for $($ca.DNSHostName) - CA server inactive"
                            $skipHttpCheck = $true
                        }
                    }
                    # No computer object (cross-domain) - still attempt HTTP check since we have the hostname

                    if (-not $skipHttpCheck) {
                        Write-Log "[Get-ADCSVulnerabilities] Checking web enrollment for $($ca.DNSHostName) (CA: $($ca.Name))..."

                        try {
                            # Pass CA name for CES endpoint detection
                            # The CES URL pattern is: https://<hostname>/<CAName>_CES_<AuthType>/service.svc
                            $webEnrollmentResult = Invoke-HTTPRequest -ScanADCS -Uri $ca.DNSHostName -CAName $ca.Name -TestEPA
                            if ($webEnrollmentResult.Success) {
                                Write-Log "[Get-ADCSVulnerabilities] Web enrollment check successful for $($ca.DNSHostName)"
                                if ($null -ne $webEnrollmentResult.EPAEnabled) {
                                    Write-Log "[Get-ADCSVulnerabilities] EPA detection: Enabled=$($webEnrollmentResult.EPAEnabled), Confidence=$($webEnrollmentResult.EPAConfidence)"
                                }
                            }
                        }
                        catch {
                            Write-Log "[Get-ADCSVulnerabilities] Web enrollment check failed: $_"
                        }
                    }
                }

                # ===== ESC7: NOT IMPLEMENTED VIA LDAP =====
                # IMPORTANT: ESC7 (ManageCA/ManageCertificates permissions) CANNOT be detected via LDAP!
                # The CA security permissions are stored in the CA's registry, not in Active Directory.
                # The AD object (pKIEnrollmentService) only contains Enrollment permissions.
                #
                # To check ESC7, you need:
                # - Direct access to the CA server (ICertAdmin2 COM interface)
                # - Or use tools like Certify.exe, Certipy, or certsrv.msc
                #
                # What we CAN check via LDAP on the AD object:
                # - GenericAll, WriteDacl, WriteOwner on the pKIEnrollmentService object (allows modifying CA enrollment settings)
                # - These are NOT the same as ManageCA/ManageCertificates!

                $dangerousACEs = @()
                try {
                    # CA objects live in the Configuration partition - use Invoke-LDAPSearch with
                    # the CA's own DN as SearchBase and Base scope. Get-DomainObject searches the
                    # domain partition and returns 0 results for Configuration partition DNs.
                    $caSDObj = @(Invoke-LDAPSearch -Filter "(objectClass=*)" -SearchBase $ca.DistinguishedName -Properties 'nTSecurityDescriptor' -Raw -Scope Base)[0]
                    $securityDescriptor = $null
                    if ($caSDObj -and $caSDObj.nTSecurityDescriptor) {
                        $securityDescriptor = New-Object System.DirectoryServices.ActiveDirectorySecurity
                        $securityDescriptor.SetSecurityDescriptorBinaryForm($caSDObj.nTSecurityDescriptor)
                    }

                    if ($securityDescriptor) {
                        $dacl = $securityDescriptor.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])

                        # Only check for dangerous AD object permissions (NOT CA permissions!)
                        # These allow modifying the CA's AD enrollment configuration
                        # Uses central $Script:GenericDangerousRights from adPEAS-GUIDs.ps1

                        foreach ($ace in $dacl) {
                            if ($ace.AccessControlType -ne 'Allow') { continue }

                            $aceSID = $ace.IdentityReference.Value
                            $aceRights = $ace.ActiveDirectoryRights.ToString()

                            $hasDangerousRight = $false
                            $matchedRight = ""

                            # Check generic dangerous rights on the AD object
                            foreach ($right in $Script:GenericDangerousRights) {
                                if ($aceRights -match $right) {
                                    $hasDangerousRight = $true
                                    $matchedRight = $right
                                    break
                                }
                            }

                            # Note: ExtendedRight with GUID 0e10c968-... is Certificate-Enrollment, NOT ManageCA!
                            # ManageCA/ManageCertificates are CA-level permissions stored in registry, not AD.
                            # We skip ExtendedRights here as Enroll is expected for most principals.

                            if (-not $hasDangerousRight) { continue }

                            $identityName = ConvertFrom-SID -SID $aceSID

                            # Use scope-based check for ADCS enrollment permissions
                            $scopeResult = Test-IsExpectedInScope -Identity $aceSID -Scope 'ADCSEnroll' -ReturnDetails

                            if ($scopeResult.Severity -eq 'Expected') {
                                Write-Log "[Get-ADCSVulnerabilities] Expected identity $aceSID has $aceRights on CA $($ca.Name)"
                                continue
                            }

                            # Check if identity is privileged (includes Domain Controllers via group membership)
                            # Test-IsPrivileged checks static SIDs, RID suffixes, AND recursive group membership
                            $privCheck = Test-IsPrivileged -Identity $aceSID
                            if ($privCheck.IsPrivileged -eq $true) {
                                Write-Log "[Get-ADCSVulnerabilities] Privileged identity $identityName ($($privCheck.Category): $($privCheck.Reason)) has $aceRights on CA $($ca.Name) - expected"
                                continue
                            }

                            # Additional check: Is this the CA server itself? (CA computer account has rights on its own AD object)
                            # This is expected behavior - the CA needs to manage its own configuration
                            if ($identityName -and $ca.DNSHostName) {
                                $caComputerName = ($ca.DNSHostName -split '\.')[0]
                                if ($identityName -match "\\$caComputerName`$" -or $identityName -eq "$caComputerName`$") {
                                    Write-Log "[Get-ADCSVulnerabilities] CA server $caComputerName has $aceRights on its own AD object - expected"
                                    continue
                                }
                            }

                            $dangerousACEs += [PSCustomObject]@{
                                Identity = $identityName
                                IdentitySID = $aceSID
                                Rights = $aceRights
                                DangerousRight = $matchedRight
                                Severity = $scopeResult.Severity
                            }
                        }
                    }
                }
                catch {
                    Write-Log "[Get-ADCSVulnerabilities] CA AD object ACL check failed for '$($ca.Name)': $_"
                }

                # ===== Display: CA info =====
                # Note: We can only detect dangerous AD object permissions, not ESC7 (ManageCA/ManageCertificates)
                $hasDangerousADPermissions = @($dangerousACEs).Count -gt 0
                if ($hasDangerousADPermissions) {
                    $caVulnerabilityCount++
                }

                # CA Server info - add dangerousRights and web enrollment attributes
                if ($ca.DNSHostName) {
                    # Use the already retrieved $caComputer from web enrollment check, or fetch if not available
                    if (-not $caComputer) {
                        # Escape for LDAP filter to prevent injection (RFC 4515)
                        $escapedDnsHostName2 = Escape-LDAPFilterValue -Value $ca.DNSHostName
                        $caComputer = @(Get-DomainComputer -LDAPFilter "(dNSHostName=$escapedDnsHostName2)" @CredParams)[0]
                    }

                    if ($caComputer) {
                        # Add CA displayName as first attribute (will be shown at top of object)
                        $caComputer | Add-Member -NotePropertyName 'displayName' -NotePropertyValue $ca.Name -Force

                        # Add dangerous AD object permissions as dangerousRights attribute
                        if ($hasDangerousADPermissions) {
                            $permissionStrings = $dangerousACEs | ForEach-Object { "$($_.Identity): $($_.DangerousRight)" }
                            $caComputer | Add-Member -NotePropertyName 'dangerousRights' -NotePropertyValue $permissionStrings -Force
                        }

                        # Add web enrollment attributes if check was successful
                        if ($webEnrollmentResult -and $webEnrollmentResult.Success) {
                            $caComputer | Add-Member -NotePropertyName 'HttpAvailable' -NotePropertyValue $webEnrollmentResult.HttpAvailable -Force
                            $caComputer | Add-Member -NotePropertyName 'HttpsAvailable' -NotePropertyValue $webEnrollmentResult.HttpsAvailable -Force

                            # Build active endpoints list with auth methods (new structure: Endpoints.<Name>.Available, Endpoints.<Name>.AuthMethods)
                            $activeEndpoints = @()
                            $endpointAuthMethods = @{}

                            if ($webEnrollmentResult.Endpoints.CertSrv.Available) {
                                $activeEndpoints += "CertSrv"
                                if ($webEnrollmentResult.Endpoints.CertSrv.AuthMethods) {
                                    $endpointAuthMethods['CertSrv'] = $webEnrollmentResult.Endpoints.CertSrv.AuthMethods
                                }
                            }
                            if ($webEnrollmentResult.Endpoints.CES.Available) {
                                $activeEndpoints += "CES"
                                if ($webEnrollmentResult.Endpoints.CES.AuthMethods) {
                                    $endpointAuthMethods['CES'] = $webEnrollmentResult.Endpoints.CES.AuthMethods
                                }
                            }
                            if ($webEnrollmentResult.Endpoints.CEP.Available) {
                                $activeEndpoints += "CEP"
                                if ($webEnrollmentResult.Endpoints.CEP.AuthMethods) {
                                    $endpointAuthMethods['CEP'] = $webEnrollmentResult.Endpoints.CEP.AuthMethods
                                }
                            }
                            if ($webEnrollmentResult.Endpoints.NDES.Available) {
                                $activeEndpoints += "NDES"
                                if ($webEnrollmentResult.Endpoints.NDES.AuthMethods) {
                                    $endpointAuthMethods['NDES'] = $webEnrollmentResult.Endpoints.NDES.AuthMethods
                                }
                            }

                            if (@($activeEndpoints).Count -gt 0) {
                                # Build array of endpoints with protocol, auth methods, and EPA status (multi-value, one per line)
                                # Show EACH available protocol separately (HTTP and HTTPS can both be available)
                                # EPA is only relevant for HTTPS - show it only on HTTPS lines
                                # ESC8 severity classification:
                                # - HTTP + NTLM = Critical (ESC8 directly exploitable, no EPA possible)
                                # - HTTPS + NTLM + EPA disabled = Finding (ESC8 possible)
                                # - HTTPS + NTLM + EPA enabled = Secure (protected)
                                # - HTTP + Negotiate = Hint (could have NTLM fallback)
                                # - HTTPS + Negotiate only = Standard (Kerberos-only is secure)
                                $endpointsWithAuth = @()
                                $httpAvailable = $webEnrollmentResult.HttpAvailable
                                $httpsAvailable = $webEnrollmentResult.HttpsAvailable

                                foreach ($ep in $activeEndpoints) {
                                    $authMethods = $endpointAuthMethods[$ep]
                                    $epData = $webEnrollmentResult.Endpoints.$ep

                                    # Show HTTP line if HTTP is available (no EPA - not applicable for HTTP)
                                    if ($httpAvailable) {
                                        $epString = "$ep via HTTP"
                                        if ($authMethods) {
                                            $epString += " ($authMethods)"
                                        }
                                        $endpointsWithAuth += $epString
                                    }

                                    # Show HTTPS line if HTTPS is available (with EPA status if tested)
                                    if ($httpsAvailable) {
                                        $epString = "$ep via HTTPS"
                                        if ($authMethods) {
                                            $epString += " ($authMethods)"
                                        }
                                        # Add EPA status only for HTTPS (EPA is TLS-based)
                                        if ($null -ne $epData.EPAEnabled) {
                                            $epaStatus = if ($epData.EPAEnabled -eq $true) { "Enabled" } else { "Disabled" }
                                            $epString += " [EPA: $epaStatus]"
                                        }
                                        $endpointsWithAuth += $epString
                                    }
                                }
                                $caComputer | Add-Member -NotePropertyName 'WebEnrollmentEndpoints' -NotePropertyValue $endpointsWithAuth -Force
                            }

                            # Add legacy EPA properties (backward compatibility - first endpoint with NTLM)
                            # EPA protects against NTLM relay attacks over HTTPS (ESC8 mitigation)
                            if ($null -ne $webEnrollmentResult.EPAEnabled) {
                                $caComputer | Add-Member -NotePropertyName 'EPAEnabled' -NotePropertyValue $webEnrollmentResult.EPAEnabled -Force
                                $caComputer | Add-Member -NotePropertyName 'EPAConfidence' -NotePropertyValue $webEnrollmentResult.EPAConfidence -Force
                            }
                        }

                        # ===== CA Certificate Analysis =====
                        # Parse CA certificate properties for security assessment
                        $caCert = $ca.CACertificate
                        if ($caCert -and $caCert -isnot [string]) {
                            # Invoke-LDAPSearch already converted to PSCustomObject via Convert-CertificateToInfo
                            # Handle array (multi-valued) - use first certificate
                            if ($caCert -is [array]) { $caCert = $caCert[0] }

                            if ($caCert.Subject) {
                                $caComputer | Add-Member -NotePropertyName 'CACertSubject' -NotePropertyValue $caCert.Subject -Force
                            }
                            if ($caCert.Thumbprint) {
                                $caComputer | Add-Member -NotePropertyName 'CACertThumbprint' -NotePropertyValue $caCert.Thumbprint -Force
                            }
                            if ($caCert.NotBefore -and $caCert.NotAfter) {
                                $caComputer | Add-Member -NotePropertyName 'CACertValidity' -NotePropertyValue "$($caCert.NotBefore.ToString('yyyy-MM-dd')) to $($caCert.NotAfter.ToString('yyyy-MM-dd')) ($($caCert.Status))" -Force
                            }
                            if ($caCert.SignatureAlgorithm) {
                                $caComputer | Add-Member -NotePropertyName 'CACertSignatureAlgorithm' -NotePropertyValue $caCert.SignatureAlgorithm -Force
                            }
                            if ($caCert.PublicKeyLength -and $caCert.PublicKeyLength -gt 0) {
                                $caComputer | Add-Member -NotePropertyName 'CACertKeySize' -NotePropertyValue "$($caCert.PublicKeyLength) bit" -Force
                            }

                            # Flag weak signature algorithms
                            if ($caCert.SignatureAlgorithm -and $caCert.SignatureAlgorithm -match 'sha1|md5|md2') {
                                $caComputer | Add-Member -NotePropertyName 'CACertWeakSignature' -NotePropertyValue "Weak signature algorithm: $($caCert.SignatureAlgorithm)" -Force
                                $caVulnerabilityCount++
                                Write-Log "[Get-ADCSVulnerabilities] CA '$($ca.Name)' uses weak signature algorithm: $($caCert.SignatureAlgorithm)"
                            }

                            # Flag short key length
                            if ($caCert.PublicKeyLength -gt 0 -and $caCert.PublicKeyLength -lt 2048) {
                                $caComputer | Add-Member -NotePropertyName 'CACertShortKey' -NotePropertyValue "Insufficient key length: $($caCert.PublicKeyLength) bit (minimum 2048 recommended)" -Force
                                $caVulnerabilityCount++
                                Write-Log "[Get-ADCSVulnerabilities] CA '$($ca.Name)' uses short key: $($caCert.PublicKeyLength) bit"
                            }

                            # Flag expired certificates
                            if ($caCert.Status -eq 'EXPIRED') {
                                $caComputer | Add-Member -NotePropertyName 'CACertExpired' -NotePropertyValue "CA certificate expired on $($caCert.NotAfter.ToString('yyyy-MM-dd'))" -Force
                                $caVulnerabilityCount++
                                Write-Log "[Get-ADCSVulnerabilities] CA '$($ca.Name)' certificate is EXPIRED"
                            }
                        }

                        # Add enrollment service properties from Configuration Partition
                        # (may differ from or supplement what's on the computer object)
                        if ($ca.CertificateTemplates -and @($ca.CertificateTemplates).Count -gt 0) {
                            $caComputer | Add-Member -NotePropertyName 'certificateTemplates' -NotePropertyValue ($ca.CertificateTemplates -join ', ') -Force
                        }
                        if ($ca.Modified) {
                            $caComputer | Add-Member -NotePropertyName 'CALastModified' -NotePropertyValue $ca.Modified.ToString('yyyy-MM-dd HH:mm:ss') -Force
                        }

                        # Add type marker for HTML report
                        $caComputer | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'CertificateAuthority' -Force

                        Show-Object $caComputer
                    } else {
                        # Computer object not found in current domain partition
                        # (e.g., CA server is in root domain but we query from sub-domain)
                        # Build a synthetic object from CA enrollment service data (Configuration Partition)
                        Write-Log "[Get-ADCSVulnerabilities] CA computer '$($ca.DNSHostName)' not found in current domain - using Configuration Partition data"
                        $syntheticCA = [PSCustomObject]@{
                            dNSHostName          = $ca.DNSHostName
                            displayName          = $ca.Name
                            caNote               = "CA server is not in the current domain partition - showing data from Configuration Partition only"
                            certificateTemplates = if ($ca.CertificateTemplates) { $ca.CertificateTemplates -join ', ' } else { $null }
                            CALastModified       = if ($ca.Modified) { $ca.Modified.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
                        }

                        # Add dangerous AD object permissions
                        if ($hasDangerousADPermissions) {
                            $permissionStrings = $dangerousACEs | ForEach-Object { "$($_.Identity): $($_.DangerousRight)" }
                            $syntheticCA | Add-Member -NotePropertyName 'dangerousRights' -NotePropertyValue $permissionStrings -Force
                        }

                        # Add web enrollment attributes if check was successful (same logic as caComputer path)
                        if ($webEnrollmentResult -and $webEnrollmentResult.Success) {
                            $syntheticCA | Add-Member -NotePropertyName 'HttpAvailable' -NotePropertyValue $webEnrollmentResult.HttpAvailable -Force
                            $syntheticCA | Add-Member -NotePropertyName 'HttpsAvailable' -NotePropertyValue $webEnrollmentResult.HttpsAvailable -Force

                            $activeEndpoints = @()
                            $endpointAuthMethods = @{}
                            foreach ($epName in @('CertSrv', 'CES', 'CEP', 'NDES')) {
                                if ($webEnrollmentResult.Endpoints.$epName.Available) {
                                    $activeEndpoints += $epName
                                    if ($webEnrollmentResult.Endpoints.$epName.AuthMethods) {
                                        $endpointAuthMethods[$epName] = $webEnrollmentResult.Endpoints.$epName.AuthMethods
                                    }
                                }
                            }

                            if (@($activeEndpoints).Count -gt 0) {
                                $endpointsWithAuth = @()
                                $httpAvailable = $webEnrollmentResult.HttpAvailable
                                $httpsAvailable = $webEnrollmentResult.HttpsAvailable
                                foreach ($ep in $activeEndpoints) {
                                    $authMethods = $endpointAuthMethods[$ep]
                                    $epData = $webEnrollmentResult.Endpoints.$ep
                                    if ($httpAvailable) {
                                        $epString = "$ep via HTTP"
                                        if ($authMethods) { $epString += " ($authMethods)" }
                                        $endpointsWithAuth += $epString
                                    }
                                    if ($httpsAvailable) {
                                        $epString = "$ep via HTTPS"
                                        if ($authMethods) { $epString += " ($authMethods)" }
                                        if ($null -ne $epData.EPAEnabled) {
                                            $epaStatus = if ($epData.EPAEnabled -eq $true) { "Enabled" } else { "Disabled" }
                                            $epString += " [EPA: $epaStatus]"
                                        }
                                        $endpointsWithAuth += $epString
                                    }
                                }
                                $syntheticCA | Add-Member -NotePropertyName 'WebEnrollmentEndpoints' -NotePropertyValue $endpointsWithAuth -Force
                            }

                            if ($null -ne $webEnrollmentResult.EPAEnabled) {
                                $syntheticCA | Add-Member -NotePropertyName 'EPAEnabled' -NotePropertyValue $webEnrollmentResult.EPAEnabled -Force
                                $syntheticCA | Add-Member -NotePropertyName 'EPAConfidence' -NotePropertyValue $webEnrollmentResult.EPAConfidence -Force
                            }
                        }

                        # CA Certificate Analysis (same as above)
                        $caCert = $ca.CACertificate
                        if ($caCert -and $caCert -isnot [string]) {
                            if ($caCert -is [array]) { $caCert = $caCert[0] }
                            if ($caCert.Subject) {
                                $syntheticCA | Add-Member -NotePropertyName 'CACertSubject' -NotePropertyValue $caCert.Subject -Force
                            }
                            if ($caCert.Thumbprint) {
                                $syntheticCA | Add-Member -NotePropertyName 'CACertThumbprint' -NotePropertyValue $caCert.Thumbprint -Force
                            }
                            if ($caCert.NotBefore -and $caCert.NotAfter) {
                                $syntheticCA | Add-Member -NotePropertyName 'CACertValidity' -NotePropertyValue "$($caCert.NotBefore.ToString('yyyy-MM-dd')) to $($caCert.NotAfter.ToString('yyyy-MM-dd')) ($($caCert.Status))" -Force
                            }
                            if ($caCert.SignatureAlgorithm) {
                                $syntheticCA | Add-Member -NotePropertyName 'CACertSignatureAlgorithm' -NotePropertyValue $caCert.SignatureAlgorithm -Force
                            }
                            if ($caCert.PublicKeyLength -and $caCert.PublicKeyLength -gt 0) {
                                $syntheticCA | Add-Member -NotePropertyName 'CACertKeySize' -NotePropertyValue "$($caCert.PublicKeyLength) bit" -Force
                            }
                            if ($caCert.SignatureAlgorithm -and $caCert.SignatureAlgorithm -match 'sha1|md5|md2') {
                                $syntheticCA | Add-Member -NotePropertyName 'CACertWeakSignature' -NotePropertyValue "Weak signature algorithm: $($caCert.SignatureAlgorithm)" -Force
                                $caVulnerabilityCount++
                            }
                            if ($caCert.PublicKeyLength -gt 0 -and $caCert.PublicKeyLength -lt 2048) {
                                $syntheticCA | Add-Member -NotePropertyName 'CACertShortKey' -NotePropertyValue "Insufficient key length: $($caCert.PublicKeyLength) bit (minimum 2048 recommended)" -Force
                                $caVulnerabilityCount++
                            }
                            if ($caCert.Status -eq 'EXPIRED') {
                                $syntheticCA | Add-Member -NotePropertyName 'CACertExpired' -NotePropertyValue "CA certificate expired on $($caCert.NotAfter.ToString('yyyy-MM-dd'))" -Force
                                $caVulnerabilityCount++
                            }
                        }

                        $syntheticCA | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'CertificateAuthority' -Force
                        Show-Object $syntheticCA
                    }
                } else {
                    # No DNS hostname - show permissions manually
                    if ($hasDangerousADPermissions) {
                        $permissionStrings = $dangerousACEs | ForEach-Object { "$($_.Identity): $($_.DangerousRight)" }
                        $permissionValue = $permissionStrings -join ", "
                        Show-KeyValue "dangerousADPermissions:" -Value $permissionValue -Class Finding
                    }
                    Show-EmptyLine
                }
            }

            # --- ESC5: Vulnerable PKI Object Access Control ---
            # Check for dangerous permissions on PKI container objects
            # If unprivileged users can write to these containers, they can:
            # - Create new vulnerable templates (ESC1-4)
            # - Modify existing templates
            # - Add themselves to enrollment permissions
            # - Manipulate NTAuth store
            try {
                Show-SubHeader "Checking PKI container permissions..." -ObjectType "PKIContainer"

                $pkiContainers = @(
                    @{
                        DN = "CN=Public Key Services,CN=Services,$configNC"
                        Name = "Public Key Services (Root)"
                        Description = "Root PKI container - controls entire PKI infrastructure"
                    },
                    @{
                        DN = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
                        Name = "Certificate Templates Container"
                        Description = "Allows creating/modifying certificate templates"
                    },
                    @{
                        DN = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"
                        Name = "Enrollment Services Container"
                        Description = "Controls certificate enrollment services"
                    },
                    @{
                        DN = "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,$configNC"
                        Name = "NTAuth Store Container"
                        Description = "Controls trusted CAs for Kerberos authentication"
                    },
                    @{
                        DN = "CN=OID,CN=Public Key Services,CN=Services,$configNC"
                        Name = "OID Container"
                        Description = "Controls issuance policies (ESC13-related)"
                    }
                )

                # Collect findings per container
                $allFindings = @()

                foreach ($container in $pkiContainers) {
                    Write-Log "[Get-ADCSVulnerabilities] ESC5: Checking $($container.Name)..."

                    try {
                        # Get ACL for container - use Invoke-LDAPSearch with explicit SearchBase and -Raw
                        # (Configuration partition DNs require SearchBase to be set to configNC)
                        # -Raw is required to get nTSecurityDescriptor as byte[] instead of converted object
                        $containerObj = @(Invoke-LDAPSearch -Filter "(distinguishedName=$($container.DN))" -SearchBase $configNC -Properties 'nTSecurityDescriptor' -Raw -Scope Subtree)[0]

                        $containerACL = @()
                        if ($containerObj -and $containerObj.nTSecurityDescriptor) {
                            $secDescriptor = New-Object System.DirectoryServices.ActiveDirectorySecurity
                            $secDescriptor.SetSecurityDescriptorBinaryForm($containerObj.nTSecurityDescriptor)
                            $dacl = $secDescriptor.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])

                            # Convert to PSCustomObject format
                            foreach ($ace in $dacl) {
                                $containerACL += [PSCustomObject]@{
                                    AccessControlType = $ace.AccessControlType
                                    IdentityReference = $ace.IdentityReference
                                    ActiveDirectoryRights = $ace.ActiveDirectoryRights
                                }
                            }
                        }

                        if ($containerACL) {
                            # Filter for dangerous permissions
                            $dangerousACEs = $containerACL | Where-Object {
                                $_.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner|GenericWrite' -and
                                $_.AccessControlType -eq 'Allow'
                            }

                            if ($dangerousACEs) {
                                # Analyze each ACE
                                foreach ($ace in $dangerousACEs) {
                                    $aceSID = $ace.IdentityReference.Value
                                    $aceRights = $ace.ActiveDirectoryRights.ToString()

                                    # Determine severity
                                    $severity = 'Finding'

                                    if (-not $IncludePrivileged) {
                                        # Use scope-based check for PKI container permissions
                                        $scopeResult = Test-IsExpectedInScope -Identity $aceSID -Scope 'PKIContainer' -ReturnDetails

                                        if ($scopeResult.Severity -eq 'Expected') {
                                            Write-Log "[Get-ADCSVulnerabilities] Expected identity $aceSID has $aceRights on $($container.Name)"
                                            continue
                                        }

                                        if ($scopeResult.Severity -eq 'Attention') {
                                            Write-Log "[Get-ADCSVulnerabilities] Privileged identity $aceSID has $aceRights on $($container.Name) - skipped (use -IncludePrivileged to include)"
                                            continue
                                        }

                                        $severity = $scopeResult.Severity
                                    } else {
                                        # -IncludePrivileged: Show ALL accounts, but mark privileged ones
                                        $scopeResult = Test-IsExpectedInScope -Identity $aceSID -Scope 'PKIContainer' -ReturnDetails
                                        $severity = $scopeResult.Severity
                                        Write-Log "[Get-ADCSVulnerabilities] IncludePrivileged: Including $aceSID with severity $severity"
                                    }

                                    # Add to findings
                                    $allFindings += [PSCustomObject]@{
                                        SID = $aceSID
                                        Rights = $aceRights
                                        Severity = $severity
                                        ContainerName = $container.Name
                                        ContainerDescription = $container.Description
                                    }
                                }
                            }
                        }
                    }
                    catch {
                        Write-Log "[Get-ADCSVulnerabilities] Error checking $($container.Name): $_" -Level Warning
                    }
                }

                # ===== Output findings with full AD objects =====
                if (@($allFindings).Count -gt 0) {
                    $countText = if ($IncludePrivileged) { "$(@($allFindings).Count) finding(s)" } else { "$(@($allFindings).Count) non-privileged finding(s)" }
                    Show-Line "Found $countText with dangerous PKI container permissions" -Class Finding

                    # Group by SID to consolidate multiple containers per principal
                    $groupedFindings = $allFindings | Group-Object -Property SID

                    foreach ($group in $groupedFindings) {
                        $sid = $group.Name
                        $findings = $group.Group
                        $allRights = @()
                        $allContainers = @()

                        foreach ($finding in $findings) {
                            $allRights += $finding.Rights
                            $allContainers += "$($finding.ContainerName) ($($finding.Rights))"
                        }

                        $allRights = $allRights | Select-Object -Unique
                        $severity = ($findings | Select-Object -First 1).Severity

                        # Try to resolve the SID to a full AD object
                        $sidHex = ConvertTo-LDAPSIDHex -SID $sid
                        $adObject = $null

                        if ($sidHex) {
                            $adObject = @(Get-DomainObject -LDAPFilter "(objectSid=$sidHex)" @CredParams)[0]
                        }

                        if ($adObject) {
                            $adObject | Add-Member -NotePropertyName 'dangerousRights' -NotePropertyValue ($allRights -join ', ') -Force
                            $adObject | Add-Member -NotePropertyName 'dangerousRightsSeverity' -NotePropertyValue $severity -Force
                            $adObject | Add-Member -NotePropertyName 'pkiContainersAffected' -NotePropertyValue $allContainers -Force
                            $adObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'PKIContainer' -Force
                            Show-Object $adObject
                        } else {
                            # Create synthetic object for unresolvable SIDs
                            $resolvedName = ConvertFrom-SID -SID $sid
                            $syntheticObject = [PSCustomObject]@{
                                sAMAccountName = $resolvedName
                                objectSid = $sid
                                objectClass = 'foreignSecurityPrincipal'
                                dangerousRights = $allRights -join ', '
                                dangerousRightsSeverity = $severity
                                pkiContainersAffected = $allContainers
                            }
                            $syntheticObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'PKIContainer' -Force
                            Show-Object $syntheticObject
                        }
                    }
                } else {
                    Show-Line "PKI container permissions are properly restricted" -Class Secure
                }
            }
            catch {
                Write-Log "[Get-ADCSVulnerabilities] Error during ESC5 check: $_" -Level Warning
                Show-Line "Error checking PKI container permissions" -Class Hint
            }

            # Step 2: Enumerate Certificate Templates (only enabled/published ones)
            Show-SubHeader "Searching for certificate templates..." -ObjectType "CertificateTemplate"
            $templateResults = @(Get-ADCSTemplate @CredParams)

            # Check if query failed (auth error, network issue, etc.)
            $templateQueryError = $templateResults | Where-Object { $_._QueryError -eq $true }
            if ($templateQueryError) {
                Write-Log "[Get-ADCSVulnerabilities] Template query failed: $($templateQueryError.ErrorMessage)"
                Show-Line "Failed to query certificate templates - LDAP query failed (authentication/network issue)" -Class Finding
                return
            }

            # Filter out any error markers (should be none at this point)
            $templates = @($templateResults | Where-Object { $_._QueryError -ne $true })

            if (@($templates).Count -eq 0) {
                Show-Line "No enabled certificate templates found" -Class Note
                return
            }

            # Track total vulnerabilities and interesting templates for summary
            $totalVulnerabilities = 0
            $interestingTemplates = @()

            # Pre-load issuance policy OID-to-group-link cache for ESC13 detection
            # Query once before template loop for performance
            $oidToGroupLink = @{}
            try {
                $oidSearchBase = "CN=OID,CN=Public Key Services,CN=Services,$configNC"
                $oidObjects = @(Invoke-LDAPSearch -Filter "(objectClass=msPKI-Enterprise-Oid)" `
                                                  -SearchBase $oidSearchBase `
                                                  -Properties 'cn','displayName','msPKI-Cert-Template-OID','msDS-OIDToGroupLink' `
                                                  -Scope OneLevel)

                foreach ($oidObj in $oidObjects) {
                    $oid = $oidObj.'msPKI-Cert-Template-OID'
                    if (-not $oid) { continue }
                    if ($oid -is [array]) { $oid = $oid[0] }

                    $groupLinkDN = $oidObj.'msDS-OIDToGroupLink'
                    if (-not $groupLinkDN) { continue }
                    if ($groupLinkDN -is [array]) { $groupLinkDN = $groupLinkDN[0] }

                    # Store group link DN and display name
                    $policyDisplayName = if ($oidObj.displayName) { $oidObj.displayName } else { $oidObj.cn }
                    if ($policyDisplayName -is [array]) { $policyDisplayName = $policyDisplayName[0] }

                    $oidToGroupLink[$oid] = @{
                        GroupLinkDN = $groupLinkDN
                        PolicyName  = $policyDisplayName
                    }
                }

                if ($oidToGroupLink.Count -gt 0) {
                    Write-Log "[Get-ADCSVulnerabilities] ESC13 cache: Found $($oidToGroupLink.Count) issuance policy OID(s) with group links"
                }
            }
            catch {
                Write-Log "[Get-ADCSVulnerabilities] ESC13: Error loading issuance policy cache: $_" -Level Warning
            }

            # Step 3: Analyze Templates for Vulnerabilities (only enabled templates)
            $totalTemplates = @($templates).Count
            $currentIndex = 0
            foreach ($template in $templates) {
                $currentIndex++
                if ($totalTemplates -gt $Script:ProgressThreshold) { Show-Progress -Activity "Analyzing templates for vulnerabilities" -Current $currentIndex -Total $totalTemplates -ObjectName $template.DisplayName }

                $templateVulns = @()

                # Pre-check: Are ALL enrollment principals truly privileged?
                # If yes, ESC1/2/3/9/15 are NOT real vulnerabilities (only admins can enroll)
                # ESC4 (template permissions) is still checked regardless
                $allEnrollmentPrivileged = Test-AllEnrollmentPrivileged -EnrollmentPrincipalSIDs $template.EnrollmentPrincipalSIDs -EnrollmentPrincipals $template.EnrollmentPrincipals -CredParams $CredParams
                if ($allEnrollmentPrivileged) {
                    Write-Log "[Get-ADCSVulnerabilities] Template '$($template.Name)': All enrollment principals are truly privileged - skipping ESC1/2/3/9/15"
                }

                # ===== ESC1: Client Authentication + Enrollee-Supplied Subject =====
                # Only flag if non-privileged users can enroll
                if ($template.EnrolleeSuppliesSubject -and $template.ClientAuthentication -and -not $allEnrollmentPrivileged) {
                    $templateVulns += [PSCustomObject]@{
                        ESC = "ESC1"
                        Title = "Client Authentication + Enrollee-Supplied Subject"
                        Severity = "Critical"
                        Description = "Template allows enrollee to specify arbitrary subject (SAN) and supports client authentication. Attacker can impersonate any user/computer."
                        Remediation = "Remove 'Enrollee supplies subject' flag OR remove client authentication EKUs."
                        Reference = "https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc1"
                    }
                }

                # ===== ESC2: Any Purpose EKU =====
                # Only flag if non-privileged users can enroll
                if ($template.AnyPurpose -and -not $allEnrollmentPrivileged) {
                    # Check if it's the dangerous variant (schema v1 + client auth, or schema v2+ with signatures)
                    $isDangerous = $false
                    if ($template.SchemaVersion -eq 1 -and $template.ClientAuthentication) {
                        $isDangerous = $true
                    } elseif ($template.SchemaVersion -ge 2 -and $template.RASignatureCount -gt 0) {
                        # Check if RA policy requires "Any Purpose"
                        if ($template.RAApplicationPolicies -contains '2.5.29.37.0') {
                            $isDangerous = $true
                        }
                    } elseif ($template.SchemaVersion -ge 2 -and $template.RASignatureCount -eq 0) {
                        $isDangerous = $true  # No signatures required
                    }

                    if ($isDangerous) {
                        $templateVulns += [PSCustomObject]@{
                            ESC = "ESC2"
                            Title = "Any Purpose EKU"
                            Severity = "High"
                            Description = "Template can be used for any purpose including client authentication. Can be abused for privilege escalation."
                            Remediation = "Specify explicit EKUs instead of 'Any Purpose' (OID 2.5.29.37.0)."
                            Reference = "https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc2"
                        }
                    }
                }

                # ===== ESC3: Certificate Request Agent EKU =====
                # Only flag if non-privileged users can enroll
                if ($template.EnrollmentAgent -and -not $allEnrollmentPrivileged) {
                    $templateVulns += [PSCustomObject]@{
                        ESC = "ESC3"
                        Title = "Certificate Request Agent EKU"
                        Severity = "High"
                        Description = "Template has 'Certificate Request Agent' EKU (1.3.6.1.4.1.311.20.2.1). Attacker can request certificates on behalf of other users."
                        Remediation = "Remove 'Certificate Request Agent' EKU unless required for legitimate enrollment agents."
                        Reference = "https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc3"
                    }
                }

                # ===== ESC4: Dangerous Template Permissions =====
                # Check if non-privileged users have dangerous permissions on this template
                try {
                    # Templates live in the Configuration partition - must use Invoke-LDAPSearch with
                    # the template's own DN as SearchBase and Base scope (single-object lookup).
                    # -Raw is required to get nTSecurityDescriptor as byte[] for parsing.
                    $templateSDObj = @(Invoke-LDAPSearch -Filter "(objectClass=*)" -SearchBase $template.DistinguishedName -Properties 'nTSecurityDescriptor' -Raw -Scope Base)[0]
                    $securityDescriptor = $null
                    if ($templateSDObj -and $templateSDObj.nTSecurityDescriptor) {
                        $securityDescriptor = New-Object System.DirectoryServices.ActiveDirectorySecurity
                        $securityDescriptor.SetSecurityDescriptorBinaryForm($templateSDObj.nTSecurityDescriptor)
                    }

                    if ($securityDescriptor) {
                        $dacl = $securityDescriptor.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])

                        $dangerousACEs = @()
                        # Note: WriteProperty is only dangerous if it applies to ALL properties (empty ObjectType)
                        # Property-specific WriteProperty (with ObjectType GUID) is NOT dangerous for ESC4
                        $dangerousRights = @('GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner')

                        # Uses central privileged SID definitions from ConvertFrom-SID.ps1

                        foreach ($ace in $dacl) {
                            if ($ace.AccessControlType -ne 'Allow') { continue }

                            $aceSID = $ace.IdentityReference.Value
                            $aceRights = $ace.ActiveDirectoryRights.ToString()

                            # Check if ACE has dangerous rights
                            $hasDangerousRight = $false
                            $matchedRight = ""

                            # First check the always-dangerous rights
                            foreach ($right in $dangerousRights) {
                                if ($aceRights -match $right) {
                                    $hasDangerousRight = $true
                                    $matchedRight = $right
                                    break
                                }
                            }

                            # WriteProperty is only dangerous if ObjectType is empty (applies to ALL properties)
                            # When ObjectType contains a GUID, it only grants write to a specific property (harmless for ESC4)
                            if (-not $hasDangerousRight -and $aceRights -match 'WriteProperty') {
                                $objectTypeGuid = $ace.ObjectType
                                # Empty GUID or all-zeros means "all properties" = dangerous
                                if ($null -eq $objectTypeGuid -or $objectTypeGuid -eq [Guid]::Empty) {
                                    $hasDangerousRight = $true
                                    $matchedRight = "WriteProperty (All)"
                                }
                                # else: property-specific WriteProperty is NOT dangerous
                            }

                            if (-not $hasDangerousRight) { continue }

                            # Resolve identity name for display
                            $identityName = ConvertFrom-SID -SID $aceSID

                            # Determine severity for this identity
                            $severity = 'Finding'

                            if (-not $IncludePrivileged) {
                                # Use scope-based check for ADCS template permissions (ESC4)
                                $scopeResult = Test-IsExpectedInScope -Identity $aceSID -Scope 'ADCSEnroll' -ReturnDetails

                                # Skip Expected (direct match like Domain Admins group)
                                if ($scopeResult.Severity -eq 'Expected') {
                                    Write-Log "[Get-ADCSVulnerabilities] Expected identity $aceSID has $aceRights on template $($template.Name)"
                                    continue
                                }

                                # Skip Attention (member of privileged group)
                                if ($scopeResult.Severity -eq 'Attention') {
                                    Write-Log "[Get-ADCSVulnerabilities] Privileged identity $aceSID (member of admin group) has $aceRights on template $($template.Name) - skipped (use -IncludePrivileged to include)"
                                    continue
                                }

                                $severity = $scopeResult.Severity
                            } else {
                                # -IncludePrivileged: Show ALL accounts, but mark privileged ones for yellow display
                                $scopeResult = Test-IsExpectedInScope -Identity $aceSID -Scope 'ADCSEnroll' -ReturnDetails
                                # Expected or Attention -> will be shown in yellow (Hint)
                                # Finding -> will be shown in red
                                $severity = $scopeResult.Severity
                                Write-Log "[Get-ADCSVulnerabilities] IncludePrivileged: Including $identityName ($aceSID) with severity $severity"
                            }

                            # Account with dangerous rights - ESC4
                            $dangerousACEs += [PSCustomObject]@{
                                Identity = $identityName
                                IdentitySID = $aceSID
                                Rights = $aceRights
                                DangerousRight = $matchedRight
                                Severity = $severity
                            }
                        }

                        if (@($dangerousACEs).Count -gt 0) {
                            $identities = ($dangerousACEs | ForEach-Object { $_.Identity }) -join ', '
                            $templateVulns += [PSCustomObject]@{
                                ESC = "ESC4"
                                Title = "Dangerous Template Permissions"
                                Severity = "Critical"
                                Description = "Non-privileged accounts have modify permissions on this template: $identities. Attackers can modify template settings to enable ESC1-3 vulnerabilities."
                                Remediation = "Remove write permissions for non-privileged accounts. Only Domain Admins and Enterprise Admins should modify templates."
                                Reference = "https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc4"
                                DangerousACEs = $dangerousACEs
                            }

                            Write-Log "[Get-ADCSVulnerabilities] ESC4: Template '$($template.Name)' has dangerous permissions for: $identities"
                        }
                    }
                }
                catch {
                    Write-Log "[Get-ADCSVulnerabilities] ESC4 check failed for template '$($template.Name)': $_"
                }

                # ===== ESC9: No Security Extension + Client Auth =====
                # Only flag if non-privileged users can enroll
                if ($template.NoSecurityExtension -and $template.ClientAuthentication -and -not $allEnrollmentPrivileged) {
                    $templateVulns += [PSCustomObject]@{
                        ESC = "ESC9"
                        Title = "No Security Extension + Client Authentication"
                        Severity = "High"
                        Description = "Template has NO_SECURITY_EXTENSION flag and supports client authentication. Attacker can modify userPrincipalName and request certificate for any user."
                        Remediation = "Remove NO_SECURITY_EXTENSION flag OR remove client authentication EKUs."
                        Reference = "https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc9"
                    }
                }

                # ===== ESC13: Issuance Policy Linked to Group =====
                # Only flag if non-privileged users can enroll
                if (-not $allEnrollmentPrivileged -and $oidToGroupLink.Count -gt 0 -and @($template.CertificatePolicies).Count -gt 0) {
                    $linkedPolicies = @()

                    foreach ($policyOID in @($template.CertificatePolicies)) {
                        if ($oidToGroupLink.ContainsKey($policyOID)) {
                            $linkInfo = $oidToGroupLink[$policyOID]

                            # Resolve group name from DN
                            $groupName = $linkInfo.GroupLinkDN
                            try {
                                $escapedDN = Escape-LDAPFilterValue -Value $linkInfo.GroupLinkDN
                                $groupObj = @(Get-DomainObject -LDAPFilter "(distinguishedName=$escapedDN)" @CredParams)[0]
                                if ($groupObj) {
                                    $groupName = if ($groupObj.sAMAccountName) { $groupObj.sAMAccountName } else { $groupObj.name }
                                }
                            }
                            catch {
                                Write-Log "[Get-ADCSVulnerabilities] ESC13: Error resolving group '$($linkInfo.GroupLinkDN)': $_" -Level Debug
                            }

                            $linkedPolicies += "$($linkInfo.PolicyName) (OID: $policyOID) -> $groupName"
                            Write-Log "[Get-ADCSVulnerabilities] ESC13: Template '$($template.Name)' - Policy '$($linkInfo.PolicyName)' linked to group '$groupName'"
                        }
                    }

                    if (@($linkedPolicies).Count -gt 0) {
                        $templateVulns += [PSCustomObject]@{
                            ESC = "ESC13"
                            Title = "Issuance Policy Linked to Group"
                            Severity = "High"
                            Description = "Template uses issuance policy OID(s) linked to AD groups via msDS-OIDToGroupLink. Enrollment grants automatic group membership."
                            Remediation = "Remove msDS-OIDToGroupLink from the issuance policy OID, OR remove the policy from the template's msPKI-Certificate-Policy, OR restrict enrollment to privileged users."
                            Reference = "https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53"
                        }

                        # Add linked policies info to template for display
                        $template | Add-Member -NotePropertyName 'IssuancePolicyGroupLinks' -NotePropertyValue $linkedPolicies -Force
                    }
                }

                # ===== ESC15: Schema v1 + Enrollee-Supplied Subject (CVE-2024-49019) =====
                # Only flag if non-privileged users can enroll
                if ($template.EnrolleeSuppliesSubject -and $template.SchemaVersion -eq 1 -and -not $allEnrollmentPrivileged) {
                    $templateVulns += [PSCustomObject]@{
                        ESC = "ESC15"
                        Title = "Schema v1 + Enrollee-Supplied Subject (CVE-2024-49019)"
                        Severity = "Critical"
                        Description = "Template allows enrollee to specify subject and uses schema version 1. Vulnerable to CVE-2024-49019."
                        Remediation = "Upgrade template to schema version 2+ OR remove 'Enrollee supplies subject' flag."
                        Reference = "https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15"
                    }
                }

                # Display findings for this template
                # Show template if:
                # 1. It has ESC vulnerabilities (Critical/High findings), OR
                # 2. It has non-privileged enrollment (interesting for enumeration, like v1)
                $hasVulnerabilities = @($templateVulns).Count -gt 0
                $hasNonPrivilegedEnrollment = -not $allEnrollmentPrivileged -and @($template.EnrollmentPrincipals).Count -gt 0

                if ($hasVulnerabilities -or $hasNonPrivilegedEnrollment) {
                    if ($hasVulnerabilities) {
                        $totalVulnerabilities++

                        # Collect ESC list and ESC4 DangerousACEs
                        $escList = $templateVulns | ForEach-Object { $_.ESC }
                        $allESCs = ($escList | Sort-Object -Unique) -join ", "
                        $esc4Vuln = $templateVulns | Where-Object { $_.ESC -eq "ESC4" } | Select-Object -First 1

                        # Enrich template with vulnerability info for Show-Object
                        $template | Add-Member -NotePropertyName 'Vulnerabilities' -NotePropertyValue $allESCs -Force
                        if ($esc4Vuln -and $esc4Vuln.DangerousACEs) {
                            $template | Add-Member -NotePropertyName 'DangerousACEs' -NotePropertyValue $esc4Vuln.DangerousACEs -Force
                        }
                    }

                    # Collect for later display
                    $interestingTemplates += $template
                }
            }
            if ($totalTemplates -gt $Script:ProgressThreshold) { Show-Progress -Activity "Analyzing templates for vulnerabilities" -Completed }

            # Display summary and templates
            $interestingCount = @($interestingTemplates).Count
            if ($interestingCount -gt 0) {
                # Show informative message about what we found
                if ($totalVulnerabilities -gt 0) {
                    Show-Line "Found $interestingCount of $($templates.Count) templates with findings" -Class Finding
                } else {
                    Show-Line "Found $interestingCount of $($templates.Count) templates with non-privileged enrollment" -Class Hint
                }

                # Display all interesting templates
                foreach ($tmpl in $interestingTemplates) {
                    # Add type marker for HTML report
                    $tmpl | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'CertificateTemplate' -Force
                    Show-Object $tmpl
                }
            } else {
                # No interesting templates found
                $totalFindings = $totalVulnerabilities + $caVulnerabilityCount
                if ($totalFindings -eq 0) {
                    Show-Line "No findings in $($templates.Count) analyzed template(s) - all enrollment restricted to privileged users" -Class Secure
                }
            }

        }
        catch {
            Write-Log "[Get-ADCSVulnerabilities] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-ADCSVulnerabilities] AD CS vulnerability scan complete"
    }
}


