function Get-ADCSTemplate {
    <#
    .SYNOPSIS
    Retrieves AD CS certificate templates with security-relevant analysis for vulnerability detection.

    .DESCRIPTION
    Wrapper around Get-CertificateTemplate (Core module) that adds security-focused computed properties for ESC vulnerability detection:
    - EnrolleeSuppliesSubject (ESC1)
    - ClientAuthentication (ESC1)
    - AnyPurpose (ESC2)
    - EnrollmentAgent (ESC3)
    - NoSecurityExtension (ESC9)
    - ManagerApprovalRequired
    - ExportableKey
    - EnrollmentPrincipals

    .PARAMETER Identity
    Specific certificate template name (cn) to query. If not specified, returns all templates.

    .PARAMETER ShowAll
    Include disabled (unpublished) templates. By default only enabled templates are returned.

    .PARAMETER Domain
    Target domain (FQDN). If not specified, uses current domain from session.

    .PARAMETER Server
    Specific Domain Controller to query. If not specified, uses session server.

    .PARAMETER Credential
    PSCredential object for authentication. If not specified, uses session credentials.

    .EXAMPLE
    Get-ADCSTemplate
    Returns all enabled certificate templates with security analysis.

    .EXAMPLE
    Get-ADCSTemplate -ShowAll
    Returns all templates (enabled and disabled).

    .NOTES
    Category: ADCS
    Author: Alexander Sturz (@_61106960_)
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Identity,

        [Parameter(Mandatory=$false)]
        [switch]$ShowAll,

        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential
    )

    begin {
        Write-Log "[Get-ADCSTemplate] Starting certificate template enumeration via Get-CertificateTemplate"
    }

    process {
        try {
            # Build connection parameters (only pass Domain/Server/Credential to Ensure-LDAPConnection)
            $ConnectionParams = @{}
            if ($Domain) { $ConnectionParams['Domain'] = $Domain }
            if ($Server) { $ConnectionParams['Server'] = $Server }
            if ($Credential) { $ConnectionParams['Credential'] = $Credential }

            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @ConnectionParams)) {
                # Return without output to avoid redundant error display
                return
            }

        # Get templates from Core module (with converted values)
        # Use @PSBoundParameters to pass all parameters directly (simple module, no inner functions)
        # Core module handles all LDAP attribute conversion (pKIExpirationPeriod, flags, etc.)
        $templateResults = @(Get-CertificateTemplate @PSBoundParameters)

        # Check if query failed (auth error, network issue, etc.)
        $queryError = $templateResults | Where-Object { $_._QueryError -eq $true }
        if ($queryError) {
            Write-Log "[Get-ADCSTemplate] Get-CertificateTemplate returned error: $($queryError.ErrorMessage)"
            # Pass through the error marker so caller can handle it
            return $queryError
        }

        # Filter out any error markers (should be none at this point)
        $templates = @($templateResults | Where-Object { $_._QueryError -ne $true })

        if (@($templates).Count -eq 0) {
            Write-Log "[Get-ADCSTemplate] No templates returned from Get-CertificateTemplate"
            return
        }

        Write-Log "[Get-ADCSTemplate] Processing $($templates.Count) template(s) for security analysis"

        $totalTemplates = @($templates).Count
        $currentIndex = 0
        foreach ($coreTemplate in $templates) {
            $currentIndex++
            if ($totalTemplates -gt $Script:ProgressThreshold) { Show-Progress -Activity "Analyzing certificate templates" -Current $currentIndex -Total $totalTemplates -ObjectName $coreTemplate.displayName }
            # Build enhanced template object with security-relevant properties
            # Core module already converted all values - we just restructure and add computed properties
            $template = [PSCustomObject]@{
                # Basic identification (from Core)
                Name = $coreTemplate.cn
                DisplayName = $coreTemplate.displayName
                DistinguishedName = $coreTemplate.distinguishedName

                # CA publishing info: which CAs have this template enabled (from Core)
                PublishedOn = if ($coreTemplate.PublishedOn) { @($coreTemplate.PublishedOn) } else { @() }

                # Schema Version (from Core)
                SchemaVersion = if ($coreTemplate.'msPKI-Template-Schema-Version') {
                    [int]$coreTemplate.'msPKI-Template-Schema-Version'
                } else { 1 }

                # Flags for security analysis - Core converts to string arrays like @('ENROLLEE_SUPPLIES_SUBJECT')
                # We keep original values for display AND extract raw integers for bitwise operations
                CertificateNameFlagDisplay = $coreTemplate.'msPKI-Certificate-Name-Flag'
                EnrollmentFlagDisplay = $coreTemplate.'msPKI-Enrollment-Flag'
                PrivateKeyFlagDisplay = $coreTemplate.'msPKI-Private-Key-Flag'

                # Signatures required (from Core)
                RASignatureCount = if ($coreTemplate.'msPKI-RA-Signature') {
                    [int]$coreTemplate.'msPKI-RA-Signature'
                } else { 0 }
                RAApplicationPolicies = if ($coreTemplate.'msPKI-RA-Application-Policies') {
                    @($coreTemplate.'msPKI-RA-Application-Policies')
                } else { @() }

                # EKUs (from Core - may include friendly names like "Client Authentication (1.3.6.1.5.5.7.3.2)")
                ExtendedKeyUsage = if ($coreTemplate.pKIExtendedKeyUsage) {
                    @($coreTemplate.pKIExtendedKeyUsage)
                } else { @() }
                ApplicationPolicies = if ($coreTemplate.'msPKI-Certificate-Application-Policy') {
                    @($coreTemplate.'msPKI-Certificate-Application-Policy')
                } else { @() }

                # Key settings (from Core)
                MinimalKeySize = if ($coreTemplate.'msPKI-Minimal-Key-Size') {
                    [int]$coreTemplate.'msPKI-Minimal-Key-Size'
                } else { 0 }

                # Validity Period (already converted by Core to "2 year(s)", "90 day(s)", etc.)
                ValidityPeriod = if ($coreTemplate.pKIExpirationPeriod) {
                    $coreTemplate.pKIExpirationPeriod
                } else { "Unknown" }

                # Certificate Policies (issuance policy OIDs - needed for ESC13 detection)
                CertificatePolicies = if ($coreTemplate.'msPKI-Certificate-Policy') {
                    @($coreTemplate.'msPKI-Certificate-Policy')
                } else { @() }

                # Security Descriptor (from Core - for enrollment permissions parsing)
                SecurityDescriptor = $coreTemplate.nTSecurityDescriptor
            }

            # ===== Computed Security Properties (Check module logic) =====
            # Parse flags from converted string arrays (e.g., @('ENROLLEE_SUPPLIES_SUBJECT', 'SUBJECT_ALT_REQUIRE_UPN'))
            $certNameFlags = $template.CertificateNameFlagDisplay
            $enrollFlags = $template.EnrollmentFlagDisplay
            $privKeyFlags = $template.PrivateKeyFlagDisplay

            # EnrolleeSuppliesSubject (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
            $template | Add-Member -NotePropertyName 'EnrolleeSuppliesSubject' -NotePropertyValue (
                ($certNameFlags -contains 'ENROLLEE_SUPPLIES_SUBJECT') -or
                ($certNameFlags -match 'ENROLLEE_SUPPLIES_SUBJECT')
            )

            # NoSecurityExtension (CT_FLAG_NO_SECURITY_EXTENSION)
            $template | Add-Member -NotePropertyName 'NoSecurityExtension' -NotePropertyValue (
                ($enrollFlags -contains 'NO_SECURITY_EXTENSION') -or
                ($enrollFlags -match 'NO_SECURITY_EXTENSION')
            )

            # Combine EKUs for analysis (Core may add friendly names, so match on OID)
            $allEKUs = @($template.ExtendedKeyUsage) + @($template.ApplicationPolicies) | Where-Object { $_ } | Select-Object -Unique
            $ekuString = $allEKUs -join ' '

            # ClientAuthentication - can be used for Kerberos auth
            $template | Add-Member -NotePropertyName 'ClientAuthentication' -NotePropertyValue (
                ($ekuString -match '1\.3\.6\.1\.5\.5\.7\.3\.2') -or      # Client Authentication
                ($ekuString -match '1\.3\.6\.1\.4\.1\.311\.20\.2\.2') -or # Smart Card Logon
                ($ekuString -match '2\.5\.29\.37\.0') -or                 # Any Purpose
                ($allEKUs.Count -eq 0)                                    # No EKUs = Any Purpose
            )

            # AnyPurpose EKU
            $template | Add-Member -NotePropertyName 'AnyPurpose' -NotePropertyValue (
                ($ekuString -match '2\.5\.29\.37\.0') -or ($allEKUs.Count -eq 0)
            )

            # EnrollmentAgent (Certificate Request Agent EKU)
            $template | Add-Member -NotePropertyName 'EnrollmentAgent' -NotePropertyValue (
                $ekuString -match '1\.3\.6\.1\.4\.1\.311\.20\.2\.1'
            )

            # ManagerApprovalRequired (PEND_ALL_REQUESTS)
            $template | Add-Member -NotePropertyName 'ManagerApprovalRequired' -NotePropertyValue (
                ($enrollFlags -contains 'PEND_ALL_REQUESTS') -or
                ($enrollFlags -match 'PEND_ALL_REQUESTS')
            )

            # ExportableKey (CT_FLAG_EXPORTABLE_KEY)
            $template | Add-Member -NotePropertyName 'ExportableKey' -NotePropertyValue (
                ($privKeyFlags -contains 'EXPORTABLE_KEY') -or
                ($privKeyFlags -match 'EXPORTABLE_KEY')
            )

            # Parse enrollment permissions from Security Descriptor
            # nTSecurityDescriptor is now a unified object with ACEs array
            $enrollmentPrincipals = @()
            $enrollmentPrincipalSIDs = @()

            # Access ACEs from the unified nTSecurityDescriptor structure
            $sdACEs = if ($coreTemplate.nTSecurityDescriptor -and $coreTemplate.nTSecurityDescriptor.ACEs) {
                $coreTemplate.nTSecurityDescriptor.ACEs
            } else {
                @()
            }

            if (@($sdACEs).Count -gt 0) {
                # Use structured ACEs (includes SIDs directly from SD)
                foreach ($ace in $sdACEs) {
                    # Only Allow ACEs
                    if ($ace.Type -ne 'Allow') { continue }

                    # Check for enrollment rights
                    $hasEnroll = $false
                    if ($ace.Rights -match 'ExtendedRight' -or $ace.Rights -match 'GenericAll') {
                        # Check if ExtendedRight is for Certificate-Enrollment or Certificate-AutoEnrollment
                        if ($ace.Rights -match 'GenericAll' -or
                            $ace.RightsDisplay -match 'Certificate-Enrollment' -or
                            $ace.RightsDisplay -match 'Certificate-AutoEnrollment' -or
                            $ace.RightsDisplay -match 'All-Extended-Rights') {
                            $hasEnroll = $true
                        }
                    }

                    if ($hasEnroll -and $ace.Name -and $enrollmentPrincipals -notcontains $ace.Name) {
                        $enrollmentPrincipals += $ace.Name
                        if ($ace.SID) {
                            $enrollmentPrincipalSIDs += $ace.SID
                        }
                    }
                }
            }
            $template | Add-Member -NotePropertyName 'EnrollmentPrincipals' -NotePropertyValue $enrollmentPrincipals
            $template | Add-Member -NotePropertyName 'EnrollmentPrincipalSIDs' -NotePropertyValue $enrollmentPrincipalSIDs

            Write-Output $template
        }
        if ($totalTemplates -gt $Script:ProgressThreshold) { Show-Progress -Activity "Analyzing certificate templates" -Completed }

        } catch {
            Write-Log "[Get-ADCSTemplate] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-ADCSTemplate] Enumeration complete"
    }
}
