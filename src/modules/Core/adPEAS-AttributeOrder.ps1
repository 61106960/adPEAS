<#
.SYNOPSIS
    Central attribute order definitions for adPEAS output formatting.

.DESCRIPTION
    Defines the display order of attributes for different object types.
    Used by Get-RenderModel.ps1 for both console and HTML output.

    Design principle:
    - Primary attributes are always displayed prominently
    - Extended attributes with non-Standard severity are promoted to primary
    - This ensures consistent output across console and HTML

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

# Primary attributes by object type
# These attributes are always shown in the main/primary section (in order)
#
# DESIGN: User and Computer share a harmonized structure for consistency:
#   1. Identity → 2. OS (Computer only) → 3. Groups → 4. SPNs → 5. Credentials
#   → 6. Description → 7. Delegation → 8. UAC → 9. Timestamps → 10. Activity
#   → 11. SID History → 12. Security Findings → 13. Roasting Hashes (User only)
#
$Script:PrimaryAttributes = @{

    # User objects (includes service accounts)
    User = @(
        # 1. IDENTITY BLOCK
        'displayName',
        'sAMAccountName', 'userPrincipalName', 'distinguishedName', 'objectSid',

        # 2. GROUP MEMBERSHIPS (security-critical)
        'memberOf', 'privilegedGroups',

        # 3. SERVICE PRINCIPAL NAMES (Kerberoasting indicator)
        'servicePrincipalName',

        # 4. CREDENTIAL EXPOSURE (passwords, LAPS)
        'unixUserPassword', 'userPassword', 'unicodePwd', 'msSFU30Password',
        'sambaNTPassword', 'sambaLMPassword',
        'ms-Mcs-AdmPwd', 'msLAPS-Password', 'msLAPS-EncryptedPassword', 'msLAPS-Account',

        # 5. DESCRIPTION/INFO (may contain credentials)
        'description', 'info',
        # Entra ID Connect information (parsed from description)
        'entraConnectServer', 'entraM365Tenant',

        # 6. DELEGATION SETTINGS
        'msDS-AllowedToDelegateTo', 'msDS-AllowedToActOnBehalfOfOtherIdentity',

        # 6b. SHADOW CREDENTIALS
        'msDS-KeyCredentialLink',

        # 7. ACCOUNT STATUS FLAGS
        'userAccountControl',

        # 8. TIMESTAMPS
        'pwdLastSet', 'lastLogonTimestamp',

        # 9. ACTIVITY STATUS
        'daysSinceLastLogon', 'isOrphaned', 'activityStatus',

        # 10. SID HISTORY (privilege escalation)
        'sIDHistory',

        # 11. SECURITY FINDINGS from check modules
        'dangerousRights', 'affectedOUs',

        # 12. ROASTING HASHES (ALWAYS LAST)
        'KerberoastingHash', 'KerberoastingHashType', 'ASREPRoastingHash', 'ASREPRoastingHashType'
    )

    # Computer objects
    Computer = @(
        # 1. IDENTITY BLOCK
        'displayName',
        'sAMAccountName', 'dNSHostName', 'distinguishedName', 'objectSid',

        # 2. OPERATING SYSTEM
        'operatingSystem',

        # 3. GROUP MEMBERSHIPS
        'memberOf', 'privilegedGroups',

        # 4. CREDENTIAL EXPOSURE (LAPS)
        # Note: servicePrincipalName moved to extended view (too verbose for primary display)
        'ms-Mcs-AdmPwd', 'msLAPS-Password', 'msLAPS-EncryptedPassword', 'msLAPS-Account',

        # 5. DESCRIPTION/INFO (may contain credentials)
        'description', 'info',

        # 6. DELEGATION SETTINGS
        'msDS-AllowedToDelegateTo', 'msDS-AllowedToActOnBehalfOfOtherIdentity',

        # 6b. SHADOW CREDENTIALS
        'msDS-KeyCredentialLink',

        # 7. ACCOUNT STATUS FLAGS
        'userAccountControl',

        # 8. TIMESTAMPS
        'pwdLastSet', 'lastLogonTimestamp',

        # 9. ACTIVITY STATUS
        'activityStatus', 'daysSinceLastLogon', 'isOrphaned',

        # 10. SID HISTORY (privilege escalation)
        'sIDHistory',

        # 11. SECURITY FINDINGS from check modules
        'dangerousRights', 'affectedOUs'
    )

    # Certificate Template objects
    CertificateTemplate = @(
        # 1. Identification
        'Name', 'displayName', 'DistinguishedName',
        # 2. CA publishing info
        'PublishedOn',
        # 3. Template info
        'SchemaVersion',
        # 3. EKU and flags (security-critical)
        # Note: ClientAuthentication is redundant - shown in ExtendedKeyUsage
        'ExtendedKeyUsage', 'CertificateNameFlagDisplay',
        # 4. Approval settings
        'ManagerApprovalRequired',
        # 5. Enrollment
        'EnrollmentPrincipals',
        # 6. Security findings
        'DangerousACEs',
        # 7. ESC13 - Issuance policy group links
        'IssuancePolicyGroupLinks'
    )

    # GPO objects (generic fallback for GPOs without specific _adPEASObjectType)
    GPO = @(
        'displayName', 'Name', 'distinguishedName', 'gPCFileSysPath',
        # LDAP security settings
        'LDAPSigning', 'ChannelBinding', 'AnonymousBinding', 'ServerSigning', 'ClientSigning',
        # Security findings
        'DangerousPermissions', 'DangerousSettings',
        # Linkage
        'Scope', 'LinkedOUs', 'AffectedComputers'
    )

    # SMB Signing GPO (only SMB-relevant attributes, no LDAP)
    SMBSigning = @(
        'displayName', 'Name', 'distinguishedName', 'gPCFileSysPath',
        'ServerSigning', 'ClientSigning',
        'Scope', 'LinkedOUs', 'IsEffectiveSetting'
    )

    # LDAP Configuration GPO (only LDAP-relevant attributes, no SMB)
    LDAPConfigGPO = @(
        'displayName', 'Name', 'distinguishedName', 'gPCFileSysPath',
        'LDAPSigning', 'ChannelBinding', 'AnonymousBinding',
        'Scope', 'LinkedOUs', 'IsEffectiveSetting'
    )

    # Domain Password Policy (all attributes are security-relevant)
    DomainPasswordPolicy = @(
        'minPwdLength', 'passwordComplexity',
        'minPwdAge', 'maxPwdAge',
        'reversibleEncryption',
        'lockoutThreshold', 'lockoutDuration', 'lockoutObservationWindow'
    )

    # Fine-Grained Password Policy (PSO)
    FineGrainedPasswordPolicy = @(
        'psoName', 'precedence',
        'minPwdLength', 'passwordComplexity',
        'reversibleEncryption',
        'lockoutThreshold',
        'appliesTo'
    )

    # Certificate Authority objects
    CertificateAuthority = @(
        # 1. CA Name (displayName added by check module)
        'displayName',
        # 2. Identification
        'sAMAccountName', 'dNSHostName', 'distinguishedName', 'objectSid',
        # 2a. Cross-domain note (when CA computer object is in different domain)
        'caNote',
        # 3. Operating System
        'operatingSystem',
        # 4. Group memberships
        'memberOf',
        # 5. CA Certificate properties
        'CACertSubject', 'CACertThumbprint', 'CACertValidity',
        'CACertSignatureAlgorithm', 'CACertKeySize',
        # 6. CA Certificate security findings
        'CACertWeakSignature', 'CACertShortKey', 'CACertExpired',
        # 7. Web enrollment (ESC8)
        'HttpAvailable', 'HttpsAvailable', 'WebEnrollmentEndpoints',
        # 8. Security
        'NTLMEnabled', 'EPAStatus',
        # 9. ADCS-specific
        'certificateTemplates',
        # 10. Enrollment service metadata
        'CALastModified'
    )

    # Root CA objects (PKI Trust Infrastructure)
    RootCA = @(
        'Subject', 'Issuer', 'SerialNumber', 'Thumbprint', 'Validity', 'Status',
        'SignatureAlgorithm', 'KeySize', 'HasBasicConstraints',
        'CRLDistributionPoints', 'OCSPURLs', 'AIAURLs'
    )

    # NTAuth Store certificate objects
    NTAuthCertificate = @(
        'Subject', 'Issuer', 'SerialNumber', 'Thumbprint', 'Validity', 'Status',
        'SignatureAlgorithm', 'KeySize', 'HasBasicConstraints',
        'CRLDistributionPoints', 'OCSPURLs', 'AIAURLs'
    )

    # AIA CA objects
    AIACA = @(
        'Subject', 'Issuer', 'SerialNumber', 'Thumbprint', 'Validity', 'Status',
        'SignatureAlgorithm', 'KeySize', 'HasBasicConstraints',
        'CRLDistributionPoints', 'OCSPURLs', 'AIAURLs'
    )

    # Domain Information object
    DomainInfo = @(
        'domainNameDNS', 'domainNameNetBIOS', 'domainSID',
        'domainFunctionalLevel', 'forestFunctionalLevel',
        'domainControllers', 'forestName',
        'parentDomain', 'childDomains',
        'anonymousLDAPAccess', 'anonymousReadableAttributes'
    )

    # Kerberos Policy object
    KerberosPolicy = @(
        'maxTicketAgeTGT', 'maxRenewalAge', 'krbtgtPasswordAge', 'domainControllerTime'
    )

    # Guest Account object (from Get-DomainInformation)
    GuestAccount = @(
        'accountStatus', 'memberOf'
    )

    # Domain Trust object (from Get-DomainTrusts)
    # Primary: trust identity only. All boolean flags are Extended but get auto-promoted
    # to Primary when their severity is non-Standard (Finding/Hint/Secure).
    # This means: isQuarantined=False on external trusts (Finding) → promoted to Primary.
    #             isQuarantined=False on within-forest trusts (Standard) → stays Extended.
    DomainTrust = @(
        'trustPartner',
        'flatName',
        'trustDirection',
        'trustType',
        'trustAttributes'
    )

    # Domain Controllers object
    DomainControllers = @(
        'domainControllers'
    )

    # Sites and Subnets object
    SitesSubnets = @(
        'siteName'
        'siteSubnets'
        'siteDomainControllers'
    )

    # Effective LDAP Security Configuration
    EffectiveLDAPConfig = @(
        'LDAPSigning', 'ChannelBinding', 'AnonymousBinding'
    )

    # Outdated Computer object
    OutdatedComputer = @(
        'name', 'dNSHostName', 'operatingSystem', 'operatingSystemVersion',
        'eolDate', 'daysSinceEoL', 'lastLogonTimestamp'
    )

    # Add Computer Rights findings (ACL-based)
    AddComputerRights = @(
        'sid', 'accountName', 'right', 'attributeName', 'value', 'isSecure',
        'gpoName', 'accounts', 'hasAuthenticatedUsers', 'severity'
    )

    # Machine Account Quota setting
    MachineAccountQuota = @(
        'ms-DS-MachineAccountQuota'
    )

    # GPO Scheduled Tasks (custom PSCustomObject from Get-GPOScheduledTasks)
    GPOScheduledTask = @(
        'GPOName', 'TaskName', 'Command', 'RunAs', 'Context',
        'Action', 'Trigger', 'LinkedOUs'
    )

    # GPO Script Paths (custom PSCustomObject from Get-GPOScriptPaths)
    GPOScriptPath = @(
        'GPOName', 'ScriptType', 'ScriptPath', 'Parameters', 'FullCommand',
        'ScriptLanguage', 'ExecutionContext', 'LinkedOUs'
    )

    # GPO Local Group Membership (custom PSCustomObject from Get-GPOLocalGroupMembership)
    GPOLocalGroup = @(
        'GPOName', 'Type', 'TargetGroup', 'MembersAdded',
        'RiskyMembers', 'LinkedOUs'
    )

    # GPO granting SeMachineAccountPrivilege (enriched native GPO object, same pattern as LDAPConfigGPO/SMBSigning)
    AddComputerGPO = @(
        'displayName', 'Name', 'distinguishedName', 'gPCFileSysPath',
        'Accounts',
        'Scope', 'LinkedOUs', 'IsEffectiveSetting'
    )

    # Credential findings (GPP and SYSVOL)
    GPPCredential = @(
        'credentialType', 'gpoName', 'filePath', 'userName', 'password', 'matchedLine', 'LinkedOUs'
    )
    SYSVOLCredential = @(
        'credentialType', 'gpoName', 'filePath', 'userName', 'password', 'matchedLine', 'LinkedOUs'
    )

    # ACL findings (users/computers/groups with dangerous permissions)
    ACLFinding = @(
        # 1. Identification
        'sAMAccountName', 'userPrincipalName', 'distinguishedName', 'objectSid',
        # 2. Security findings
        'dangerousRights', 'affectedOUs',
        # 3. Inheritance source (shows where inherited permissions came from)
        'inheritedFrom',
        # 4. Group memberships
        'memberOf',
        # 5. Account control
        'userAccountControl',
        # 6. Timestamps
        'pwdLastSet', 'lastLogonTimestamp'
    )

    # Exchange Infrastructure
    Exchange = @(
        'sAMAccountName', 'dNSHostName', 'distinguishedName', 'objectSid',
        'operatingSystem',
        'memberOf',
        'HttpAvailable', 'HttpsAvailable',
        'ExchangeVersion', 'ExchangeBuildNumber',
        'WebEndpoints',
        'DangerousPermissions'
    )

    # ExchangeOrganization (Config Partition overview from Get-ExchangeInfrastructure)
    ExchangeOrganization = @(
        'OrganizationName', 'ExchangeServerCount', 'AcceptedDomains', 'SMTPSendConnectors'
    )

    # ExchangeConfigServer (per-server details from Config Partition)
    # Primary: targeting-relevant info (Name, FQDN, version, external exposure, ports)
    # Extended: structural details (DN, domain, VDirs, connector count, build number)
    ExchangeConfigServer = @(
        'Name', 'dNSHostName',
        'ExchangeVersion',
        'ExternalHostnames', 'SMTPListeningPorts'
    )

    # ExchangeServer alias (used by _adPEASObjectType from Get-ExchangeInfrastructure)
    ExchangeServer = @(
        'sAMAccountName', 'dNSHostName', 'distinguishedName', 'objectSid',
        'operatingSystem',
        'memberOf',
        'HttpAvailable', 'HttpsAvailable',
        'ExchangeVersion', 'ExchangeBuildNumber',
        'WebEndpoints',
        'DangerousPermissions'
    )

    # LAPS Finding (OU without LAPS protection)
    LAPSFinding = @(
        'ouName', 'computerCount', 'lapsUnprotectedComputers'
    )

    # Operator Group Finding (from Get-ProtectedUsersStatus)
    # Note: MemberCount and ProtectedCount are kept in object but excluded from display
    OperatorGroup = @(
        'OperatorGroup', 'OperatorGroupDN', 'Members'
    )

    # SCCM Site (from Get-SCCMInfrastructure Step 3)
    SCCMSite = @(
        'SiteCode', 'SourceForest', 'SiteGUID', 'DistinguishedName'
    )

    # SCCM Management Point (from Get-SCCMInfrastructure Step 4)
    SCCMManagementPoint = @(
        'ManagementPoint', 'SiteCode', 'SiteType', 'CommandLineSiteCode', 'RootSiteCode', 'Forest'
    )

    # SCCM PXE/WDS Server (from Get-SCCMInfrastructure Step 7)
    SCCMPXEServer = @(
        'PXEServer', 'WDSServicePoint', 'ParentObject', 'BindingInfo'
    )

    # SCCM Group (from Get-SCCMInfrastructure Step 8)
    # NOTE: Deliberately excludes 'member' to avoid per-DN SID resolution (O(n) LDAP queries per group)
    SCCMGroup = @(
        'sAMAccountName', 'description', 'MemberCount', 'memberOf', 'managedBy',
        'whenCreated', 'distinguishedName'
    )

    # SCOM Group (from Get-SCOMInfrastructure)
    # NOTE: Same rationale as SCCMGroup — excludes 'member' for performance
    SCOMGroup = @(
        'sAMAccountName', 'description', 'MemberCount', 'memberOf', 'managedBy',
        'whenCreated', 'distinguishedName'
    )

    # AdminSDHolder ACL (from Get-PrivilegedGroupMembers Step 5)
    AdminSDHolderACL = @(
        'Trustee', 'TrusteeSID', 'dangerousRights'
    )

    # LDAP Statistics per module (from Invoke-adPEAS -Statistics)
    LDAPStatisticsModule = @(
        'Queries', 'Results', 'EstimatedTraffic'
    )

    # LDAP Statistics total (from Invoke-adPEAS -Statistics)
    LDAPStatisticsTotal = @(
        'Queries', 'Results', 'EstimatedTraffic'
    )
}

# Object types with strict attribute display: ONLY PrimaryAttributes are shown, no Extended overflow.
# Use this for specialized views of shared objects (e.g., same GPO object used by both LDAP and SMB checks)
# to prevent cross-contamination of attributes from other checks.
$Script:StrictAttributeTypes = @(
    'SMBSigning',
    'LDAPConfigGPO',
    'AddComputerGPO',
    'EffectiveLDAPConfig',
    'LDAPStatisticsModule',
    'LDAPStatisticsTotal',
    'DomainPasswordPolicy',
    'FineGrainedPasswordPolicy'
)

# Attributes to always exclude from display
# These are internal/technical attributes that should never be shown in output:
# - AD metadata (objectGUID, objectCategory, USN, whenCreated/Changed)
# - Security descriptors (handled separately)
# - Redundant attributes (already shown elsewhere)
# - Internal adPEAS markers (_adPEASObjectType, _adPEASContext)
$Script:ExcludeAttributes = @(
    'objectClass', 'objectGUID', 'objectCategory', 'instanceType',
    'uSNCreated', 'uSNChanged', 'whenCreated', 'whenChanged',
    'nTSecurityDescriptor',
    # Certificate Template internal attributes
    'PrivateKeyFlagDisplay', 'SecurityDescriptor',
    # EnrolleeSuppliesSubject is redundant - already shown in CertificateNameFlagDisplay as ENROLLEE_SUPPLIES_SUBJECT
    'EnrolleeSuppliesSubject',
    # ClientAuthentication is redundant - already shown in ExtendedKeyUsage as "Client Authentication"
    'ClientAuthentication',
    # Internal classification attribute for Exchange groups - not for display
    'dangerousRightsSeverity',
    # Operator Group internal counts - kept in object but not displayed
    'MemberCount', 'ProtectedCount',
    # Internal adPEAS type markers and transport properties - not for display
    '_adPEASObjectType', '_adPEASContext', '_Severity', '_Risk',
    # GPO check internal analysis flags - used for severity calculation, not for display
    'GPOGUID', 'Risk', 'Severity',
    'IsSystemAccount', 'IsPrivilegedAccount',
    'HasUNCPath', 'HasRiskyPath', 'HasUnquotedPath', 'IsPowerShell', 'IsScript',
    'RunsAsSystem', 'TargetGroupSID', 'MemberSIDs',
    # Name is used for HTML card title resolution ({Name} in TitleFormat) but excluded from
    # extended attribute display to avoid redundancy. ObjectTypes that need Name visible
    # (CertificateTemplate, GPO) list it in their PrimaryAttributes, which takes precedence.
    'Name'
)

<#
.SYNOPSIS
    Detects the object type for attribute ordering.
.PARAMETER Object
    The object to analyze.
.RETURNS
    String identifying the object type (User, Computer, CertificateTemplate, GPO, etc.)
#>
function Get-ObjectTypeForOrdering {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Object
    )

    try {
        # If _adPEASObjectType is set and has a PrimaryAttributes entry, use it directly
    # This is the most authoritative source for custom PSCustomObjects (SCCM, GPO tasks, etc.)
    if ($Object._adPEASObjectType -and $Script:PrimaryAttributes.ContainsKey($Object._adPEASObjectType)) {
        return $Object._adPEASObjectType
    }

    # Domain Information objects (from Get-DomainInformation)
    if ($Object.domainNameDNS -and $Object.domainSID) {
        return 'DomainInfo'
    }

    # Kerberos Policy
    if ($Object.maxTicketAgeTGT -and $Object.maxRenewalAge) {
        return 'KerberosPolicy'
    }

    # Guest Account
    if ($Object.accountStatus -and $Object.passwordAge -and $Object._adPEASObjectType -eq 'GuestAccount') {
        return 'GuestAccount'
    }

    # Domain Controllers
    if ($Object.domainControllers -and -not $Object.domainNameDNS) {
        return 'DomainControllers'
    }

    # Sites and Subnets
    if ($Object.siteName -and $Object.siteSubnets) {
        return 'SitesSubnets'
    }

    # Effective LDAP Security Configuration
    if ($Object.LDAPSigning -and $Object.ChannelBinding -and $Object.AnonymousBinding -and -not $Object.gPCFileSysPath) {
        return 'EffectiveLDAPConfig'
    }

    # GPO (has gPCFileSysPath or GUID name pattern)
    if ($Object.gPCFileSysPath -or ($Object.Name -match '^\{[0-9a-fA-F-]+\}$')) {
        return 'GPO'
    }

    # Certificate Template
    if (($null -ne $Object.EnrolleeSuppliesSubject) -or ($null -ne $Object.CertificateNameFlagDisplay)) {
        return 'CertificateTemplate'
    }

    # Certificate Authority (CA computer object with ADCS-specific attributes)
    # HttpAvailable/WebEnrollmentEndpoints/certificateTemplates are only set by ADCS check module
    if (($null -ne $Object.HttpAvailable) -or ($null -ne $Object.WebEnrollmentEndpoints) -or
        ($null -ne $Object.certificateTemplates -and @($Object.objectClass) -contains 'computer')) {
        return 'CertificateAuthority'
    }

    # Operator Group Finding (from Get-ProtectedUsersStatus)
    if ($Object.OperatorGroup -and $null -ne $Object.MemberCount -and $null -ne $Object.ProtectedCount) {
        return 'OperatorGroup'
    }

    # Outdated Computer
    if ($Object.eolDate -and $Object.daysSinceEoL) {
        return 'OutdatedComputer'
    }

    # Add Computer Rights (ACL-based)
    if ($Object.sid -and $Object.accountName -and $Object.right) {
        return 'AddComputerRights'
    }

    # Machine Account Quota
    if ($Object.PSObject.Properties['ms-DS-MachineAccountQuota']) {
        return 'MachineAccountQuota'
    }

    # GPO granting SeMachineAccountPrivilege (enriched native GPO object with Accounts property)
    if ($Object._adPEASObjectType -eq 'AddComputerGPO') {
        return 'AddComputerGPO'
    }

    # Credential finding
    if ($Object.credentialType -and ($Object.password -or $Object.matchedLine)) {
        return 'GPPCredential'
    }

    # ACL Finding (has dangerousRights or affectedOUs)
    if ($Object.dangerousRights -or $Object.affectedOUs) {
        return 'ACLFinding'
    }

    # LAPS Finding (OU without LAPS protection)
    if ($Object.ouName -and $Object.lapsUnprotectedComputers -and $null -ne $Object.computerCount) {
        return 'LAPSFinding'
    }

    # Exchange Infrastructure
    if ($Object.ExchangeVersion -or $Object.ExchangeBuildNumber) {
        return 'Exchange'
    }

    # Computer (objectClass or $ suffix)
    # Use @() wrapper to ensure -contains works even if objectClass is a single value
    if ((@($Object.objectClass) -contains 'computer') -or ($Object.sAMAccountName -like '*$')) {
        return 'Computer'
    }

    # Default: User
    return 'User'

    } catch {
        # On any error during type detection, fall back to User
        Write-Debug "[Get-ObjectTypeForOrdering] Error detecting object type: $_"
        return 'User'
    }
}

<#
.SYNOPSIS
    Gets ordered attributes for an object, separating primary from extended.
.DESCRIPTION
    Returns attributes in defined order, with option to promote non-Standard
    severity attributes to primary section.
.PARAMETER Object
    The AD object to process.
.PARAMETER PromoteNonStandard
    If set, attributes with non-Standard severity (Finding, Hint, Secure, Note)
    are promoted to primary even if not in the primary list.
.PARAMETER IsComputer
    Hint for Get-AttributeSeverity classification.
.RETURNS
    PSCustomObject with Primary and Extended arrays, each containing
    @{ Name; Value; Severity } objects.
#>
function Get-OrderedAttributes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Object,

        [switch]$PromoteNonStandard,

        [bool]$IsComputer = $false
    )

    try {
        # Detect object type
        $objectType = Get-ObjectTypeForOrdering -Object $Object

    # Get primary attributes for this type
    $primaryAttrNames = $Script:PrimaryAttributes[$objectType]
    if (-not $primaryAttrNames) {
        $primaryAttrNames = $Script:PrimaryAttributes['User']  # Fallback
    }

    $result = [PSCustomObject]@{
        ObjectType = $objectType
        Primary = [System.Collections.ArrayList]@()
        Extended = [System.Collections.ArrayList]@()
    }

    $processedAttrs = @{}

    # 1. Process defined primary attributes in order
    foreach ($attrName in $primaryAttrNames) {
        $value = $Object.$attrName
        if ($null -ne $value -and ($value -is [bool] -or $value -ne '')) {
            $severity = Get-AttributeSeverity -Name $attrName -Value $value -IsComputer $IsComputer -SourceObject $Object
            [void]$result.Primary.Add(@{
                Name = $attrName
                Value = $value
                Severity = $severity
            })
            $processedAttrs[$attrName] = $true
        }
    }

    # 2. Process remaining attributes
    # Skip entirely for strict types (only PrimaryAttributes are shown)
    $isStrictType = $objectType -in $Script:StrictAttributeTypes
    if ($isStrictType) {
        return $result
    }

    foreach ($prop in $Object.PSObject.Properties) {
        # Skip already processed
        if ($processedAttrs.ContainsKey($prop.Name)) { continue }

        # Skip excluded attributes
        if ($prop.Name -in $Script:ExcludeAttributes) { continue }

        # Skip null/empty (but keep boolean $false)
        if ($null -eq $prop.Value -or ($prop.Value -isnot [bool] -and $prop.Value -eq '')) { continue }

        $severity = Get-AttributeSeverity -Name $prop.Name -Value $prop.Value -IsComputer $IsComputer -SourceObject $Object

        # Special handling for Owner: Determine severity based on default owner status
        # Non-default owners are a security risk (owner has implicit full control)
        if ($prop.Name -ieq 'Owner') {
            $ownerSID = $Object.OwnerSID
            if ($ownerSID) {
                $isDefaultOwner = Test-IsDefaultOwner -SID $ownerSID
                if ($isDefaultOwner) {
                    # Default owner - Standard severity, goes to Extended
                    $severity = 'Standard'
                } else {
                    # Non-default owner - Finding severity (red), will be promoted if PromoteNonStandard is set
                    $severity = 'Finding'
                }
            }
        }

        $attrInfo = @{
            Name = $prop.Name
            Value = $prop.Value
            Severity = $severity
        }

        # Promote to primary if non-Standard severity and switch is set
        if ($PromoteNonStandard -and $severity -ne 'Standard') {
            [void]$result.Primary.Add($attrInfo)
        } else {
            [void]$result.Extended.Add($attrInfo)
        }
    }

    return $result

    } catch {
        # On any error, return empty result with User type
        Write-Debug "[Get-OrderedAttributes] Error processing attributes: $_"
        return [PSCustomObject]@{
            ObjectType = 'User'
            Primary = [System.Collections.ArrayList]@()
            Extended = [System.Collections.ArrayList]@()
        }
    }
}
