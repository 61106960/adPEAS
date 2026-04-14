function Get-CertificateTemplate {
<#
.SYNOPSIS
    Retrieves ADCS certificate templates from Active Directory.

.DESCRIPTION
    Get-CertificateTemplate queries the Configuration partition for certificate templates (pKICertificateTemplate objects).
    Certificate templates define the settings for certificates issued by Active Directory Certificate Services (AD CS).

    This function returns certificate template objects with all attributes converted to readable formats (flags, OIDs, etc.) by Invoke-LDAPSearch.
    Use -Raw to get unconverted raw LDAP values for programmatic processing.

.PARAMETER Identity
    The name or distinguished name of a specific certificate template to retrieve.
    Supports wildcards when using -LDAPFilter.

.PARAMETER Name
    Alias for Identity. The display name of the certificate template.

.PARAMETER LDAPFilter
    Custom LDAP filter for querying certificate templates.
    Will be combined with (objectClass=pKICertificateTemplate).
    Example: "(msPKI-Certificate-Name-Flag=1)"

.PARAMETER Properties
    Array of properties to retrieve. If not specified, retrieves common certificate
    template properties.

    Common properties:
    - cn, displayName, distinguishedName
    - msPKI-Certificate-Name-Flag (naming options)
    - msPKI-Enrollment-Flag (enrollment options)
    - msPKI-Private-Key-Flag (private key options)
    - pKIExtendedKeyUsage (EKU OIDs)
    - msPKI-Certificate-Application-Policy (application policy OIDs)
    - pKICriticalExtensions (critical extension OIDs)
    - msPKI-Template-Schema-Version (template version)
    - msPKI-Template-Minor-Revision (minor revision)
    - pKIExpirationPeriod (validity period)
    - pKIOverlapPeriod (renewal overlap period)
    - pKIKeyUsage (key usage flags)
    - nTSecurityDescriptor (enrollment permissions)

.PARAMETER SearchBase
    Custom search base DN. If not specified, automatically uses the Configuration partition: CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=...

.PARAMETER Domain
    Target domain for the query. If not specified, uses the current domain.

.PARAMETER Server
    Specific domain controller to query.

.PARAMETER Credential
    PSCredential object for authentication.

.PARAMETER Raw
    Return raw LDAP attribute values without conversion.
    Useful for programmatic processing when you need the raw data.

.PARAMETER ShowAll
    Show ALL certificate templates (enabled and disabled).
    By default, only templates published to at least one CA are shown.
    Use -ShowAll to include unpublished templates that cannot be used for enrollment.

.PARAMETER EnrolleeSuppliesSubject
    Filter for templates with ENROLLEE_SUPPLIES_SUBJECT flag (ESC1 vulnerability).
    These templates allow the enrollee to specify arbitrary subject names, enabling privilege escalation attacks.

.PARAMETER NoSecurityExtension
    Filter for templates with NO_SECURITY_EXTENSION flag (ESC2 vulnerability).
    These templates do not include security extensions in issued certificates, making them vulnerable to certain attacks.

.PARAMETER ClientAuthentication
    Filter for templates with Client Authentication EKU (OID 1.3.6.1.5.5.7.3.2).
    These templates can be used for Kerberos authentication and are high-value targets.

.PARAMETER ExportableKey
    Filter for templates with EXPORTABLE_KEY flag.
    These templates allow private keys to be exported, enabling key theft attacks.

.PARAMETER NoManagerApproval
    Filter for templates that do NOT require manager approval (no PEND_ALL_REQUESTS flag).
    These templates can be enrolled immediately without approval, making them easier to exploit.

.EXAMPLE
    Get-CertificateTemplate

    Retrieves only enabled (published) certificate templates from the current forest.
    This is the default behavior - only templates available for enrollment are shown.

.EXAMPLE
    Get-CertificateTemplate -Identity "User"
    Retrieves the "User" certificate template.

.EXAMPLE
    Get-CertificateTemplate -LDAPFilter "(msPKI-Certificate-Name-Flag=1)"
    Finds all templates where the enrollee supplies the subject name (ESC1 vulnerability indicator).

.EXAMPLE
    Get-CertificateTemplate | Where-Object {
        $_.msPKI-Certificate-Name-Flag -contains "ENROLLEE_SUPPLIES_SUBJECT"
    }
    Finds all templates with ENROLLEE_SUPPLIES_SUBJECT flag (converted readable format).

.EXAMPLE
    Get-CertificateTemplate -Properties cn,msPKI-Enrollment-Flag,nTSecurityDescriptor
    Retrieves templates with specific properties only.

.EXAMPLE
    Get-CertificateTemplate -Raw
    Retrieves enabled templates with raw unconverted LDAP values.

.EXAMPLE
    Get-CertificateTemplate -ShowAll
    Retrieves ALL certificate templates (enabled and disabled).
    Useful for auditing all templates in AD, not just those available for enrollment.

.EXAMPLE
    Get-CertificateTemplate -EnrolleeSuppliesSubject
    Finds enabled templates with ESC1 vulnerability (ENROLLEE_SUPPLIES_SUBJECT).
    Quick way to identify templates allowing arbitrary subject names.

.EXAMPLE
    Get-CertificateTemplate -ClientAuthentication -NoManagerApproval
    Finds enabled templates with Client Authentication EKU that don't require manager approval.
    These are high-value targets for privilege escalation attacks.

.EXAMPLE
    Get-CertificateTemplate -ExportableKey
    Finds enabled templates that allow private key export.
    Useful for identifying templates vulnerable to key theft attacks.

.EXAMPLE
    Get-CertificateTemplate -EnrolleeSuppliesSubject -ClientAuthentication
    Combines filters to find ESC1-vulnerable templates with Client Auth EKU.
    This represents the most dangerous template configuration.

.EXAMPLE
    Get-CertificateTemplate -ShowAll -EnrolleeSuppliesSubject
    Finds ALL templates (enabled and disabled) with ESC1 vulnerability.
    Useful for complete auditing, not just immediate threats.

.EXAMPLE
    Get-CertificateTemplate -EnrollmentAllowed
    Finds enabled templates where enrollment permissions are granted.
    Not all published templates allow enrollment - this filters for actual enrollment rights.

.NOTES
    Author: Alexander Sturz (@_61106960_)

.LINK
    https://posts.specterops.io/certified-pre-owned-d95910965cd2
#>

    [CmdletBinding(DefaultParameterSetName='All')]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param(
        [Parameter(Mandatory=$false, Position=0, ParameterSetName='Identity')]
        [Alias('Name')]
        [string]$Identity,

        [Parameter(Mandatory=$false, ParameterSetName='Filter')]
        [string]$LDAPFilter,

        [Parameter(Mandatory=$false)]
        [string[]]$Properties,

        [Parameter(Mandatory=$false)]
        [string]$SearchBase,

        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [switch]$Raw,

        [Parameter(Mandatory=$false)]
        [switch]$ShowAll,

        [Parameter(Mandatory=$false)]
        [switch]$EnrolleeSuppliesSubject,

        [Parameter(Mandatory=$false)]
        [switch]$Export,

        [Parameter(Mandatory=$false)]
        [string]$ExportPath,

        [Parameter(Mandatory=$false)]
        [switch]$NoSecurityExtension,

        [Parameter(Mandatory=$false)]
        [switch]$ClientAuthentication,

        [Parameter(Mandatory=$false)]
        [switch]$ExportableKey,

        [Parameter(Mandatory=$false)]
        [switch]$NoManagerApproval,

        [Parameter(Mandatory=$false)]
        [switch]$EnrollmentAllowed
    )

    begin {
        Write-Log "[Get-CertificateTemplate] Starting certificate template enumeration"
    }

    process {
        # Ensure LDAP connection exists (pass only connection-related parameters)
        $ConnectionParams = @{}
        if ($Domain) { $ConnectionParams['Domain'] = $Domain }
        if ($Server) { $ConnectionParams['Server'] = $Server }
        if ($Credential) { $ConnectionParams['Credential'] = $Credential }

        if (-not (Ensure-LDAPConnection @ConnectionParams)) {
            return
        }

        try {
            # Export requires raw values for proper restoration
            # Automatically enable -Raw when -Export is specified
            if ($Export -and -not $Raw) {
                Write-Log "[Get-CertificateTemplate] Export mode: Automatically enabling -Raw to preserve original attribute values"
                $Raw = $true
            }

            # Build search base for Configuration partition if not provided
            if (-not $SearchBase) {
                # Get Configuration NC from RootDSE (stored in LDAPContext)
                $ConfigNC = $Script:LDAPContext.ConfigurationNamingContext

                if (-not $ConfigNC) {
                    Write-Error "Could not determine Configuration partition. Ensure LDAP connection is established."
                    return
                }

                # Build path to Certificate Templates container
                $SearchBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC"
                Write-Log "[Get-CertificateTemplate] Using SearchBase: $SearchBase"
            }

            # Build LDAP filter
            $Filter = "(objectClass=pKICertificateTemplate)"

            if ($PSCmdlet.ParameterSetName -eq 'Identity') {
                # Search by name (cn or displayName)
                $Filter = "(&(objectClass=pKICertificateTemplate)(|(cn=$Identity)(displayName=$Identity)(distinguishedName=$Identity)))"
            }
            elseif ($PSCmdlet.ParameterSetName -eq 'Filter') {
                # Combine custom filter with objectClass filter
                $Filter = "(&(objectClass=pKICertificateTemplate)$LDAPFilter)"
            }

            Write-Log "[Get-CertificateTemplate] Using filter: $Filter"

            # If user specified custom properties, add them to minimum required properties (always need cn, displayName for output and filtering)
            $RequiredProperties = @('cn', 'displayName', 'distinguishedName')

            if ($Properties) {
                # User specified custom properties - add them to required properties
                $AllProperties = $RequiredProperties + $Properties | Select-Object -Unique
            } else {
                # No custom properties - use full default set
                $AllProperties = @(
                    # Basic Identification
                    'cn',
                    'displayName',
                    'distinguishedName',
                    'objectGUID',
                    'whenCreated',
                    'whenChanged',
                    'revision',
                    # Template Flags (ESC1, ESC2, ESC9)
                    'flags',
                    'msPKI-Certificate-Name-Flag',
                    'msPKI-Enrollment-Flag',
                    'msPKI-Private-Key-Flag',
                    # Key and Signature Requirements
                    'msPKI-Minimal-Key-Size',
                    'msPKI-RA-Signature',
                    'pKIDefaultKeySpec',
                    'pKIKeyUsage',
                    # Schema and Versioning
                    'msPKI-Template-Schema-Version',
                    'msPKI-Template-Minor-Revision',
                    # EKU and Application Policy (ESC1, ESC3)
                    'pKIExtendedKeyUsage',
                    'msPKI-Certificate-Application-Policy',
                    'pKICriticalExtensions',
                    # Certificate Policy (ESC13 - OID Group Link)
                    'msPKI-Certificate-Policy',
                    # Validity and Issuance
                    'pKIMaxIssuingDepth',
                    'pKIExpirationPeriod',
                    'pKIOverlapPeriod',
                    # CSP and Cryptography
                    'pKIDefaultCSPs',
                    # Template Relationships
                    'msPKI-Supersede-Templates',
                    # Security and Permissions (ESC4, ESC5, ESC7)
                    'nTSecurityDescriptor',
                    # Publishing Information
                    'msPKI-Cert-Template-OID'
                )
            }

            # Build parameters for Get-DomainObject
            $GetParams = @{
                LDAPFilter = $Filter
                SearchBase = $SearchBase
                Properties = $AllProperties
            }

            # Pass through common parameters
            if ($Domain) { $GetParams['Domain'] = $Domain }
            if ($Server) { $GetParams['Server'] = $Server }
            if ($Credential) { $GetParams['Credential'] = $Credential }
            if ($Raw) { $GetParams['Raw'] = $true }

            # Query via Get-DomainObject (which calls Invoke-LDAPSearch)
            Write-Log "[Get-CertificateTemplate] Querying certificate templates via Get-DomainObject"
            $Templates = Get-DomainObject @GetParams

            # Force array to prevent pipeline pollution
            $Templates = @($Templates)

            if ($Templates -and $Templates.Count -gt 0) {
                Write-Log "[Get-CertificateTemplate] Found $($Templates.Count) certificate template(s)"

                # Query CAs to build template-to-CA mapping (always, regardless of -ShowAll)
                # This map is used both for filtering published templates and for the PublishedOn property
                $TemplateCAMap = @{}
                $EnrollmentServicesBase = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$ConfigNC"

                try {
                    Write-Log "[Get-CertificateTemplate] Querying Certificate Authorities for template-CA mapping"
                    $CAs = Get-DomainObject -LDAPFilter "(objectClass=pKIEnrollmentService)" -SearchBase $EnrollmentServicesBase -Properties @('cn', 'certificateTemplates') -Raw

                    if ($CAs) {
                        # Build reverse map: template CN → list of CA names
                        foreach ($CA in @($CAs)) {
                            if ($CA.certificateTemplates) {
                                $CAName = if ($CA.cn) { [string]$CA.cn } else { 'Unknown' }
                                foreach ($tmpl in @($CA.certificateTemplates)) {
                                    if (-not $TemplateCAMap.ContainsKey($tmpl)) {
                                        $TemplateCAMap[$tmpl] = [System.Collections.Generic.List[string]]::new()
                                    }
                                    $TemplateCAMap[$tmpl].Add($CAName)
                                }
                            }
                        }

                        Write-Log "[Get-CertificateTemplate] Found $($TemplateCAMap.Count) published template(s) across all CAs"

                        if (-not $ShowAll) {
                            Write-Log "[Get-CertificateTemplate] Filtering for enabled (published) templates only (use -ShowAll to see all templates)"

                            # Filter templates to only those published on at least one CA
                            $EnabledTemplates = $Templates | Where-Object { $TemplateCAMap.ContainsKey($_.cn) }

                            if ($EnabledTemplates) {
                                Write-Log "[Get-CertificateTemplate] Returning $(@($EnabledTemplates).Count) enabled template(s)"
                                $ResultTemplates = $EnabledTemplates
                            }
                            else {
                                Write-Log "[Get-CertificateTemplate] No enabled templates found (none are published to any CA)"
                                $ResultTemplates = $null
                            }
                        }
                        else {
                            Write-Log "[Get-CertificateTemplate] Returning all templates (enabled and disabled)"
                            $ResultTemplates = $Templates
                        }
                    }
                    else {
                        Write-Warning "No Certificate Authorities found. Cannot determine which templates are enabled."
                        Write-Warning "Returning all templates instead."
                        $ResultTemplates = $Templates
                    }
                }
                catch {
                    Write-Warning "Error querying CA enrollment services: $_"
                    Write-Warning "Returning all templates instead."
                    $ResultTemplates = $Templates
                }

                # Add PublishedOn property to each template (empty array for unpublished templates in -ShowAll mode)
                if ($ResultTemplates) {
                    foreach ($tmpl in @($ResultTemplates)) {
                        $caList = if ($TemplateCAMap.ContainsKey($tmpl.cn)) { @($TemplateCAMap[$tmpl.cn]) } else { @() }
                        $tmpl | Add-Member -NotePropertyName 'PublishedOn' -NotePropertyValue $caList -Force
                    }
                }

                # Apply security filters if specified
                if ($ResultTemplates -and ($EnrolleeSuppliesSubject -or $NoSecurityExtension -or $ClientAuthentication -or $ExportableKey -or $NoManagerApproval -or $EnrollmentAllowed)) {
                    Write-Log "[Get-CertificateTemplate] Applying security filters"

                    $FilteredTemplates = $ResultTemplates

                    # Filter: ENROLLEE_SUPPLIES_SUBJECT (ESC1 indicator)
                    if ($EnrolleeSuppliesSubject) {
                        Write-Log "[Get-CertificateTemplate] Filtering for ENROLLEE_SUPPLIES_SUBJECT"
                        $FilteredTemplates = $FilteredTemplates | Where-Object {
                            # Support both raw (integer) and converted (string array) values
                            if ($_.'msPKI-Certificate-Name-Flag' -is [int]) {
                                # Raw value: 0x00000001 = ENROLLEE_SUPPLIES_SUBJECT
                                ([int]$_.'msPKI-Certificate-Name-Flag') -band 0x00000001
                            } else {
                                # Converted value: Array contains string
                                $_.'msPKI-Certificate-Name-Flag' -contains 'ENROLLEE_SUPPLIES_SUBJECT'
                            }
                        }
                    }

                    # Filter: NO_SECURITY_EXTENSION (ESC9 indicator)
                    if ($NoSecurityExtension) {
                        Write-Log "[Get-CertificateTemplate] Filtering for NO_SECURITY_EXTENSION"
                        $FilteredTemplates = $FilteredTemplates | Where-Object {
                            # Support both raw (integer) and converted (string array) values
                            if ($_.'msPKI-Enrollment-Flag' -is [int]) {
                                # Raw value: 0x00080000 = CT_FLAG_NO_SECURITY_EXTENSION
                                ([int]$_.'msPKI-Enrollment-Flag') -band 0x00080000
                            } else {
                                # Converted value: Array contains string
                                $_.'msPKI-Enrollment-Flag' -contains 'NO_SECURITY_EXTENSION'
                            }
                        }
                    }

                    # Filter: Client Authentication EKU
                    if ($ClientAuthentication) {
                        Write-Log "[Get-CertificateTemplate] Filtering for Client Authentication EKU"
                        $FilteredTemplates = $FilteredTemplates | Where-Object {
                            # Client Auth OID: 1.3.6.1.5.5.7.3.2
                            # Check both pKIExtendedKeyUsage and msPKI-Certificate-Application-Policy
                            # Support both raw (string) and converted (string with friendly name) values
                            ($_.pKIExtendedKeyUsage -match '1\.3\.6\.1\.5\.5\.7\.3\.2') -or
                            ($_.'msPKI-Certificate-Application-Policy' -match '1\.3\.6\.1\.5\.5\.7\.3\.2')
                        }
                    }

                    # Filter: EXPORTABLE_KEY
                    if ($ExportableKey) {
                        Write-Log "[Get-CertificateTemplate] Filtering for EXPORTABLE_KEY"
                        $FilteredTemplates = $FilteredTemplates | Where-Object {
                            # Support both raw (integer) and converted (string array) values
                            if ($_.'msPKI-Private-Key-Flag' -is [int]) {
                                # Raw value: 0x00000010 = EXPORTABLE_KEY
                                ([int]$_.'msPKI-Private-Key-Flag') -band 0x00000010
                            } else {
                                # Converted value: Array contains string
                                $_.'msPKI-Private-Key-Flag' -contains 'EXPORTABLE_KEY'
                            }
                        }
                    }

                    # Filter: No Manager Approval Required
                    if ($NoManagerApproval) {
                        Write-Log "[Get-CertificateTemplate] Filtering for templates without manager approval"
                        $FilteredTemplates = $FilteredTemplates | Where-Object {
                            # Support both raw (integer) and converted (string array) values
                            if ($_.'msPKI-Enrollment-Flag' -is [int]) {
                                # Raw value: 0x00000002 = PEND_ALL_REQUESTS (manager approval required)
                                # We want templates WITHOUT this flag (i.e., flag NOT set)
                                -not (([int]$_.'msPKI-Enrollment-Flag') -band 0x00000002)
                            } else {
                                # Converted value: Array does NOT contain string
                                $_.'msPKI-Enrollment-Flag' -notcontains 'PEND_ALL_REQUESTS'
                            }
                        }
                    }

                    # Filter: Enrollment Allowed (check nTSecurityDescriptor for enrollment rights)
                    if ($EnrollmentAllowed) {
                        Write-Log "[Get-CertificateTemplate] Filtering for templates with enrollment permissions"
                        $FilteredTemplates = $FilteredTemplates | Where-Object {
                            if ($_.nTSecurityDescriptor) {
                                # Support both raw (byte array) and converted (string array) values
                                if ($_.nTSecurityDescriptor -is [byte[]]) {
                                    # Raw value: Parse Security Descriptor bytes for Certificate-Enrollment GUID
                                    # Certificate-Enrollment: 0e10c968-78fb-11d2-90d4-00c04f79dc55
                                    # Convert GUID to byte pattern and search in SD
                                    $SD = New-Object System.DirectoryServices.ActiveDirectorySecurity
                                    $SD.SetSecurityDescriptorBinaryForm($_.nTSecurityDescriptor)

                                    # Check for Certificate-Enrollment extended right
                                    $CertEnrollGuid = [Guid]"0e10c968-78fb-11d2-90d4-00c04f79dc55"
                                    $AllExtendedRightsGuid = [Guid]"00000000-0000-0000-0000-000000000000"

                                    $SD.Access | Where-Object {
                                        $_.AccessControlType -eq 'Allow' -and
                                        ($_.ObjectType -eq $CertEnrollGuid -or $_.ObjectType -eq $AllExtendedRightsGuid)
                                    }
                                } else {
                                    # Converted value: Array of formatted strings like:
                                    # "Allow - NT-AUTHORITY\Authenticated Users - ExtendedRight (Certificate-Enrollment)"
                                    $SDLines = $_.nTSecurityDescriptor
                                    # Check for Certificate-Enrollment or All-Extended-Rights in any ACE line
                                    ($SDLines -match 'Certificate-Enrollment' -or
                                     $SDLines -match 'Certificate-AutoEnrollment' -or
                                     $SDLines -match 'All-Extended-Rights').Count -gt 0
                                }
                            } else {
                                $false
                            }
                        }
                    }

                    if ($FilteredTemplates) {
                        Write-Log "[Get-CertificateTemplate] Filter applied: $($FilteredTemplates.Count) template(s) match criteria"

                        # Filter output properties if user specified custom properties
                        if ($Properties) {
                            # User wants specific properties - return only cn + PublishedOn + requested properties
                            $OutputProperties = @('cn', 'PublishedOn') + $Properties | Select-Object -Unique
                            return $FilteredTemplates | Select-Object $OutputProperties
                        } else {
                            return $FilteredTemplates
                        }
                    }
                    else {
                        Write-Log "[Get-CertificateTemplate] No templates match the specified filter criteria"
                        return $null
                    }
                }
                else {
                    # No filters applied - return templates as-is
                    # Filter output properties if user specified custom properties
                    if ($Properties) {
                        $OutputProperties = @('cn', 'PublishedOn') + $Properties
                        $UniqueProperties = @()
                        $SeenProperties = @{}
                        foreach ($prop in $OutputProperties) {
                            $propLower = $prop.ToLower()
                            if (-not $SeenProperties.ContainsKey($propLower)) {
                                $UniqueProperties += $prop
                                $SeenProperties[$propLower] = $true
                            }
                        }
                        $ResultTemplates = $ResultTemplates | Select-Object $UniqueProperties
                    }
                }

                # Export templates to JSON if -Export specified
                if ($Export) {
                    Write-Log "[Get-CertificateTemplate] Exporting template(s) to JSON"

                    # Determine export path (filename sanitization handled by Export-adPEASFile)
                    if (-not $ExportPath) {
                        $Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
                        if ($ResultTemplates.Count -eq 1) {
                            $TemplateName = $ResultTemplates[0].cn
                            $ExportPath = "CertTemplate_${TemplateName}_${Timestamp}.json"
                        } else {
                            $ExportPath = "CertTemplates_${Timestamp}.json"
                        }
                    }

                    # Prepare templates for export
                    $ExcludedAttributes = @(
                        'ntsecuritydescriptor',
                        'objectguid',
                        'whencreated',
                        'whenchanged'
                    )

                    $ExportData = @()
                    foreach ($template in $ResultTemplates) {
                        # Re-query template with ALL attributes (*) to ensure complete backup, $template only contains the ~30 properties we explicitly loaded
                        Write-Log "[Get-CertificateTemplate] Re-querying template '$($template.cn)' with all attributes for export"

                        $FullTemplateParams = @{
                            LDAPFilter = "(cn=$($template.cn))"
                            SearchBase = $SearchBase
                            Properties = @('*')  # Load ALL attributes
                            Raw = $true          # Raw values for restore
                        }
                        if ($Domain) { $FullTemplateParams['Domain'] = $Domain }
                        if ($Server) { $FullTemplateParams['Server'] = $Server }
                        if ($Credential) { $FullTemplateParams['Credential'] = $Credential }

                        $FullTemplate = @(Get-DomainObject @FullTemplateParams)[0]

                        if (-not $FullTemplate) {
                            Write-Warning "[Get-CertificateTemplate] Failed to re-query template '$($template.cn)' for export"
                            continue
                        }

                        $ExportObject = [ordered]@{}

                        # Copy all properties except excluded ones
                        $FullTemplate.PSObject.Properties | Where-Object {
                            $ExcludedAttributes -notcontains $_.Name.ToLower()
                        } | ForEach-Object {
                            $ExportObject[$_.Name] = $_.Value
                        }

                        $ExportData += $ExportObject
                    }

                    # Create export metadata
                    $ExportFile = @{
                        ExportedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                        ExportedBy = "$env:USERDOMAIN\$env:USERNAME"
                        Domain = $Script:LDAPContext.Domain
                        TemplateCount = $ExportData.Count
                        Templates = $ExportData
                    }

                    # Export to JSON using central helper function
                    $exportResult = Export-adPEASFile -Path $ExportPath -Content $ExportFile -Type Json -SanitizeFilename

                    if ($exportResult.Success) {
                        Write-Log "[Get-CertificateTemplate] Successfully exported $($ExportData.Count) template(s) to: $($exportResult.Path)"
                    } else {
                        Write-Error "Failed to export templates: $($exportResult.Message)"
                    }
                }

                return $ResultTemplates
            }
            else {
                Write-Log "[Get-CertificateTemplate] No certificate templates found"
                return $null
            }
        }
        catch {
            Write-Log "[Get-CertificateTemplate] Error querying certificate templates: $_"
            Write-Log "[Get-CertificateTemplate] Exception details: $($_.Exception.Message)"

            # Return error marker object so caller knows query failed vs. no templates found
            [PSCustomObject]@{
                _QueryError = $true
                ErrorMessage = $_.Exception.Message
            }
        }
    }

    end {
        Write-Log "[Get-CertificateTemplate] Certificate template enumeration complete"
    }
}
