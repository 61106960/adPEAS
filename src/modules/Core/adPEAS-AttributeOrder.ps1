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
#   1. Identity -> 2. OS (Computer only) -> 3. Groups -> 4. SPNs -> 5. Credentials
#   -> 6. Description -> 7. Delegation -> 8. UAC -> 9. Timestamps -> 10. Activity
#   -> 11. SID History -> 12. Security Findings -> 13. Roasting Hashes (User only)
#
$Script:PrimaryAttributes = @{

    # User objects (includes service accounts)
    User = @(
        # 1. IDENTITY BLOCK
        'displayName',
        'sAMAccountName', 'userPrincipalName', 'distinguishedName', 'objectSid',

        # 2. GROUP MEMBERSHIPS (security-critical)
        # memberOfNested: the primary group and the nested groups, from
        # Get-DomainUser -ResolveGroups.
        #
        # adminCount is not in this list on purpose. It reaches the console when the
        # ADMIN_COUNT_INDICATOR trigger promotes it - an account with the mark and no
        # protected membership, the orphan the card describes. On a privileged account
        # privilegedGroups already says why SDProp protects it, and "1" beside that adds a
        # line to every administrator (decided 2026-10-18, confirmed 2026-10-21).
        'memberOf', 'memberOfNested', 'privilegedGroups',

        # 3. SERVICE PRINCIPAL NAMES (Kerberoasting indicator)
        #
        # The encryption type belongs beside the SPN: for an account that can be roasted
        # it is the one property that decides what a captured ticket is worth, and it sat
        # in no PrimaryAttributes list at all - so it landed uncoloured in the collapsed
        # Extended block while the check description said it had been examined.
        'servicePrincipalName', 'msDS-SupportedEncryptionTypes',

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
        # memberOfNested: a managed service account from Get-DomainUser -GMSA -ResolveGroups
        # is rendered as a computer. adminCount as on a user: promoted only as an orphan.
        'memberOf', 'memberOfNested', 'privilegedGroups',

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
        # 4b. Registration Authority requirement (ESC3 condition 2).
        # A template that demands a co-signature from an enrollment agent is both a barrier for
        # direct abuse and the target of an "enroll on behalf of" attack - it must be visible on
        # the console, not only in the HTML extended block.
        'RASignatureCount', 'RAApplicationPolicies',
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
        'LDAPSigning', 'ChannelBinding', 'anonymousSamEnumeration', 'anonymousSidNameTranslation', 'ServerSigning', 'ClientSigning',
        # Security findings
        'DangerousPermissions', 'SysvolPermissions', 'GPOOwner', 'DangerousSettings',
        # Linkage
        'LinkedOUs', 'oneLinkAway', 'reachesDomainControllers', 'wmiFilter', 'loopbackProcessing', 'GPOStatus', 'affectedComputerCount', 'affectedComputersNote'
    )

    # SMB Signing GPO (only SMB-relevant attributes, no LDAP)
    SMBSigning = @(
        'displayName', 'Name', 'distinguishedName', 'gPCFileSysPath',
        'ServerSigning', 'ClientSigning',
        'LinkedOUs', 'GPOStatus', 'EffectiveSetting'
    )

    # LDAP Configuration GPO (only LDAP-relevant attributes, no SMB)
    LDAPConfigGPO = @(
        'displayName', 'Name', 'distinguishedName', 'gPCFileSysPath',
        'LDAPSigning', 'ChannelBinding',
        'LinkedOUs', 'GPOStatus', 'EffectiveSetting'
    )

    # Null session settings in a GPO (Get-LDAPConfiguration). They used to be rows of
    # LDAPConfigGPO; they are SMB and RPC controls and have a section of their own.
    NullSessionGPO = @(
        'displayName', 'Name', 'distinguishedName', 'gPCFileSysPath',
        'anonymousSamEnumeration', 'anonymousSidNameTranslation',
        'LinkedOUs', 'GPOStatus', 'EffectiveSetting'
    )

    # dsHeuristics on CN=Directory Service, decoded (Get-LDAPConfiguration). It was typed
    # LDAPConfigGPO, whose card title is "LDAP Configuration GPO: {Name}" - and it is no
    # GPO and has no name.
    DSHeuristics = @(
        'dSHeuristics', 'anonymousLDAPAccess', 'anonymousNSPIAccess', 'adminSDHolderExclusion',
        'principalNameUniqueness'
    )

    # GPO-deployed dangerous registry settings (Get-GPORegistrySettings)
    GPORegistrySetting = @(
        'GPOName', 'GPOGUID', 'GPOPath', 'SourceFile', 'RegistryKey', 'ConfiguredValue',
        'VulnerabilityName', 'RiskReason',
        'LinkedOUs', 'reachesDomainControllers', 'wmiFilter', 'loopbackProcessing', 'GPOStatus'
    )

    # Point and Print printer driver policy per GPO (Get-GPOPointAndPrint).
    # Exploitability comes first: it is the verdict the whole check exists to produce, and
    # the individual values below it are the evidence it was derived from.
    # Scope here is not the linkage Scope the other GPO types used to carry: it names the
    # hive the settings were read from, "Computer Configuration" or "User Configuration".
    PointAndPrintPolicy = @(
        'GPOName', 'GPOGUID', 'GPOPath', 'Scope', 'SourceFile',
        'Exploitability',
        'DriverInstallRestriction', 'PointAndPrintRestrictions',
        'NewConnectionPrompt', 'DriverUpdatePrompt',
        'ApprovedDriverSource', 'ApprovedServerList',
        'SpoolerClientConnections', 'QueueSpecificFiles',
        'WebDriverDownload', 'HTTPPrinting', 'InstallDriversSecurityOption',
        'LinkedOUs', 'reachesDomainControllers', 'wmiFilter', 'loopbackProcessing', 'GPOStatus'
    )

    # LAPS policy settings deployed via GPO (Get-LAPSConfiguration, Step 3)
    LAPSGPOConfig = @(
        # The unlinked statement first: a policy that reaches no computer makes every
        # setting below it moot, and the row carries the only card this check has for it.
        'lapsGpoNotLinked',
        # Second for the same reason the unlinked statement is first: a policy that turns
        # LAPS off makes every value below it moot.
        'lapsPolicyState',
        'GPOName', 'GPOGUID', 'GPOPath', 'SourceFile', 'LAPSVersion', 'ManagedAccount',
        'BackupDirectory', 'PasswordEncryption', 'EncryptionPrincipal',
        'PasswordComplexity', 'PasswordLength', 'PassphraseLength', 'PasswordAgeDays',
        'ExpirationProtection', 'PostAuthActions',
        'LinkedOUs', 'GPOStatus'
    )

    # Domain Password Policy (all attributes are security-relevant)
    DomainPasswordPolicy = @(
        'minPwdLength', 'passwordComplexity',
        'minPwdAge', 'maxPwdAge', 'pwdHistoryLength',
        'reversibleEncryption',
        'lockoutThreshold', 'lockoutDuration', 'lockoutObservationWindow',
        'passwordProperties'
    )

    # Fine-Grained Password Policy (PSO)
    FineGrainedPasswordPolicy = @(
        'psoName', 'precedence',
        # settings stands in for the rows below on a policy found by its assignment,
        # whose settings this account cannot read.
        'settings',
        'minPwdLength', 'passwordComplexity',
        'minPwdAge', 'maxPwdAge', 'pwdHistoryLength',
        'reversibleEncryption',
        'lockoutThreshold', 'lockoutDuration', 'lockoutObservationWindow',
        # appliesToPrivileged exists only where a target of the policy is privileged,
        # inEffectForThisAccount only on the policy that wins for the scanning account,
        # and this type is strict - a row the list does not name is dropped in silence.
        'appliesTo', 'appliesToPrivileged', 'inEffectForThisAccount'
    )

    # Certificate Authority objects
    CertificateAuthority = @(
        # 1. CA Common Name (from pKIEnrollmentService, added by check module)
        'caName',
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
        'Subject', 'EnterpriseCA', 'Issuer', 'SerialNumber', 'Thumbprint', 'Validity', 'Status',
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
        'anonymousLDAPAccess', 'anonymousReadableAttributes',
        'tombstoneLifetime', 'recycleBin', 'deletedObjectLifetime', 'sysvolReplication'
    )

    # Kerberos Policy object
    KerberosPolicy = @(
        # ticketLifetime carries the verdict on the values below it and exists only when
        # one of them was widened past the Microsoft default.
        'ticketLifetime', 'maxTicketAgeTGT', 'maxRenewalAge', 'maxServiceTicketAge', 'maxClockSkew',
        'krbtgtPasswordAge', 'domainControllerTime'
    )

    # Guest Account object (from Get-DomainInformation)
    GuestAccount = @(
        'accountStatus', 'memberOf'
    )

    # Domain Trust object (from Get-DomainTrusts)
    # Primary: trust identity only. All boolean flags are Extended but get auto-promoted
    # to Primary when their severity is non-Standard (Finding/Hint/Secure).
    # This means: isQuarantined=False on external trusts (Finding) -> promoted to Primary.
    #             isQuarantined=False on within-forest trusts (Standard) -> stays Extended.
    DomainTrust = @(
        'trustPartner',
        'flatName',
        'partnerDomainSID',
        'trustDirection',
        'trustType',
        'trustAttributes',
        # On every trust, not only where it is coloured: "Not applied - within the
        # forest" is the answer a reader of a child-domain trust needs as much as a red
        # one, and a summary line under all trusts said the opposite.
        'sidFiltering',
        'trustEncryptionTypes',
        'trustPasswordLastSet'
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

    # Effective LDAP Security Configuration - what is in force on the domain controllers,
    # value by value, by policy precedence (Get-LDAPConfiguration)
    EffectiveLDAPConfig = @(
        'LDAPSigning', 'ChannelBinding',
        'decidedBy'
    )

    # The same for the two null session settings (Get-LDAPConfiguration)
    EffectiveNullSession = @(
        'anonymousSamEnumeration', 'anonymousSidNameTranslation', 'decidedBy'
    )

    # The same for SMB signing (Get-SMBSigningStatus)
    EffectiveSMBSigning = @(
        'ServerSigning', 'ClientSigning', 'decidedBy'
    )

    # And for the member computers, when no signing policy reaches them
    EffectiveSMBSigningMembers = @(
        'ServerSigning', 'ClientSigning', 'decidedBy'
    )

    # A policy that weakens SMB signing where it reaches, and where that is
    # (Get-SMBSigningStatus). It was a line naming the policy and nothing else.
    SMBSigningWeakened = @(
        'displayName', 'Name', 'ServerSigning', 'ClientSigning', 'LinkedOUs'
    )

    # Outdated Computer object
    #
    # osRelease names the Windows 11 release the build identifies, which is the property
    # that decides whether the machine still gets updates at all - without it the row said
    # "Windows 11 Enterprise" and nothing more. osExtendedSecurityUpdates carries the ESU
    # caveat for a machine between its general support end and the end of the paid
    # extension.
    OutdatedComputer = @(
        'name', 'dNSHostName', 'operatingSystem', 'operatingSystemVersion', 'osRelease',
        'eolDate', 'daysSinceEoL', 'osExtendedSecurityUpdates', 'lastLogonTimestamp'
    )

    # GPO User Rights Assignment findings ([Privilege Rights] in GptTmpl.inf)
    #
    # GPOUserRights is a strict type: what is not named here is not rendered, in the
    # console or in the report. The holder lists are the finding - the check compares the
    # GPO's holders against the Windows default and the difference is the whole result -
    # so leaving them out reduced every row to "this GPO touches this right", with no way
    # to tell which identity gained it, and two rows differing only in their holders
    # printed as exact duplicates.
    #
    # whyItMatters stays off the list on purpose. It is on the finding object and reads
    # well, but no other check prints its own prose next to the data, and the ObjectType
    # entry already carries the explanation for the whole section.
    GPOUserRights = @(
        'GPOName', 'GPOGUID', 'GPOPath', 'SourceFile', 'UserRight', 'UserRightName',
        'GrantedBeyondDefault', 'RemovedFromDefault',
        'AppliesTo', 'LinkedOUs', 'reachesDomainControllers', 'wmiFilter', 'loopbackProcessing', 'GPOStatus'
    )

    # Machine Account Quota setting
    MachineAccountQuota = @(
        'ms-DS-MachineAccountQuota', 'whoCanAddComputers', 'privilegeGrantedBy'
    )

    # The coverage summary of Get-LAPSConfiguration, in the order the figures depend on
    # each other: what was measured, how much of it is protected, whether that protection
    # works, what is left, and the domain controllers last.
    LAPSCoverage = @(
        'activeComputers', 'excludedFromCount', 'domainControllerLookup',
        'lapsProtected', 'lapsRotation', 'lapsExpiryNotADate',
        'lapsUnprotected', 'lapsBackupOutsideAD',
        'dsrmPassword'
    )

    # GPO Scheduled Tasks (custom PSCustomObject from Get-GPOScheduledTasks)
    GPOScheduledTask = @(
        'GPOName', 'GPOGUID', 'GPOPath', 'SourceFile', 'TaskName', 'Command', 'UNCPathPermissions',
        'RunAs', 'Context', 'Action', 'Trigger', 'LinkedOUs', 'reachesDomainControllers', 'wmiFilter', 'loopbackProcessing', 'GPOStatus'
    )

    # GPO Script Paths (custom PSCustomObject from Get-GPOScriptPaths)
    GPOScriptPath = @(
        'GPOName', 'GPOGUID', 'GPOPath', 'SourceFile', 'ScriptType', 'ScriptPath', 'Parameters', 'FullCommand',
        'ScriptLanguage', 'ExecutionContext', 'LinkedOUs', 'reachesDomainControllers', 'wmiFilter', 'loopbackProcessing', 'GPOStatus'
    )

    # GPO Local Group Membership (custom PSCustomObject from Get-GPOLocalGroupMembership)
    #
    # Mode, MembersRemoved and groupEmptied say what the policy does to the members that
    # are already in the group - a Members list replaces it, a Memberof entry only adds,
    # and a preferences item can clear it first. All three used to be absent, so a policy
    # that removes Domain Admins from the local administrators of every machine in scope
    # was reported as one that adds somebody.
    GPOLocalGroup = @(
        'GPOName', 'GPOGUID', 'GPOPath', 'SourceFile', 'Type', 'TargetGroup', 'Mode',
        'MembersAdded', 'MembersRemoved', 'groupEmptied',
        'LinkedOUs', 'reachesDomainControllers', 'wmiFilter', 'loopbackProcessing', 'GPOStatus'
    )

    # GPO granting SeMachineAccountPrivilege (enriched native GPO object, same pattern as LDAPConfigGPO/SMBSigning)
    AddComputerGPO = @(
        'displayName', 'Name', 'distinguishedName', 'gPCFileSysPath',
        'Accounts',
        'LinkedOUs', 'GPOStatus', 'EffectiveSetting'
    )

    # BitLocker Recovery Key (readable msFVE-RecoveryInformation child object)
    BitLockerRecoveryKey = @(
        'ComputerName',
        'msFVE-RecoveryPassword',
        'msFVE-RecoveryGuid',
        'msFVE-VolumeGuid',
        'whenCreated',
        'distinguishedName'
    )

    # Roamed credential material on a user object (Get-CredentialRoaming).
    # ReadableBy carries the verdict that decides the severity, so it sits next to the
    # material rather than at the end.
    CredentialRoaming = @(
        'sAMAccountName', 'distinguishedName', 'RoamedMaterial', 'ReadableBy',
        'PrivilegedAccount', 'RoamingTimeStamp'
    )

    # A delegated read of those attributes (Get-CredentialRoaming, step 3). dangerousRights
    # and affectedOUs keep the names the other ACL findings use, so the same transformer
    # splits the rights into per-value tooltips. EffectiveToday follows immediately, because
    # it is what turns the same ACE into a finding in one forest and a dormant right in
    # another.
    CredentialRoamingPermission = @(
        'sAMAccountName', 'objectSid', 'dangerousRights', 'EffectiveToday',
        'PrivilegedPrincipal', 'affectedOUs'
    )
    BitLockerRecoveryPermission = @(
        'sAMAccountName', 'objectSid', 'dangerousRights', 'ReadableToday',
        'PrivilegedPrincipal', 'affectedOUs'
    )

    # One card per group of held-back policies (Get-GPOEffectiveness Show-GPOSuppressedGroup).
    # Group is first so it reads as the heading of the card in the console, where an object has
    # no title line of its own; Policies is the newline-joined "Name  {GUID}" list, rendered the
    # same way domainControllers is.
    GPOSuppressedGroup = @(
        'Group', 'Reason', 'Count', 'Policies'
    )

    # Credential findings (GPP and SYSVOL)
    # FilePath stays the complete path here, rather than being split into GPOGUID plus a
    # relative SourceFile like the other GPO findings. These checks also scan NETLOGON and
    # a caller-supplied -Path, where there is no GPO folder to be relative to, and for a
    # finding that does come from a GPO the full path already contains the GUID.
    GPPCredential = @(
        'CredentialType', 'GPOName', 'FilePath', 'RegistryValue', 'UnattendSetting', 'UserName', 'accountInAD', 'Password', 'MatchedLine', 'LinkedOUs'
    )
    SYSVOLCredential = @(
        'CredentialType', 'GPOName', 'FilePath', 'UserName', 'accountInAD', 'Password', 'MatchedLine', 'LinkedOUs'
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
        'OrganizationName', 'ExchangeServerCount', 'ConfigurationVisibility', 'NotReadable', 'AcceptedDomains', 'SMTPSendConnectors'
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

    # Exchange hybrid relationship with Exchange Online (Get-ExchangeInfrastructure)
    ExchangeHybridConfiguration = @(
        'HybridStatus', 'HybridEvidence',
        'CoexistenceDomains', 'CoexistenceTransportServers',
        'CoexistenceExternalIPAddresses', 'CoexistenceSmartHost'
    )

    # SMTP receive connector verdict (Get-ExchangeInfrastructure).
    # RelayStatus first: it is the answer, and the bindings and grants below are the
    # evidence for it.
    ExchangeReceiveConnector = @(
        'Name', 'RelayStatus', 'ExchangeServer',
        'GrantedSMTPRights', 'Bindings', 'RemoteIPRanges',
        'distinguishedName'
    )

    # Shared vs. split permissions on the domain object (Get-ExchangeInfrastructure).
    # The effective ACEs and the inherit-only ones are separate rows on purpose: one is
    # the finding, the other is the mitigated shape Microsoft's guidance produces, and in
    # a single list the reader could not tell which line drove the verdict.
    ExchangePermissionsModel = @(
        'PermissionsModel', 'EffectiveDomainACEs', 'InheritOnlyDomainACEs', 'ADSplitPermissions',
        'ExchangeGroupsFrom'
    )

    # Exchange RBAC role assignments (Get-ExchangeRBACAssignments).
    # Role and assignee first - the pair is the finding; the verdict explains it.
    ExchangeRoleAssignment = @(
        'RoleName', 'Assignee', 'AssigneeType', 'assigneeMembers', 'AssignmentType', 'RiskVerdict',
        'AssignmentScope', 'AssigneeDN', 'distinguishedName'
    )

    # The three Exchange service groups (Get-ExchangeInfrastructure).
    #
    # They need an entry of their own for two reasons that are really one.
    # Get-ObjectTypeForOrdering honours _adPEASObjectType only when a key of that name
    # exists here; without one these groups fell through the whole detection cascade to
    # 'User', and the User list has no 'member', because a user has none. So the check
    # announced "Found 2 member(s) in Exchange Trusted Subsystem" and then showed the
    # group with not one member on it - and the judgement the member renderer performs
    # for exactly these groups (Get-ExchangeGroupMemberClass, which clears Exchange
    # servers, computer accounts and nested Exchange groups and flags everything else as
    # EXCHANGE_GROUP_LOW_PRIV_MEMBER) never reached a reader. The whole point of the
    # check is who is in the group that does not belong there.
    #
    # 'member' sits directly after the identity block rather than at the end: it is the
    # answer, and behind a long description it reads as an afterthought.
    ExchangeTrustedSubsystem = @(
        'sAMAccountName', 'distinguishedName', 'objectSid',
        'member', 'memberOf', 'description'
    )

    ExchangeWindowsPermissions = @(
        'sAMAccountName', 'distinguishedName', 'objectSid',
        'member', 'memberOf', 'description'
    )

    ExchangeOrganizationManagement = @(
        'sAMAccountName', 'distinguishedName', 'objectSid',
        'member', 'memberOf', 'description'
    )

    ComputerObjectACL = @(
        'Computer', 'Trustee', 'TrusteeSID', 'explicitRights', 'distinguishedName'
    )

    CriticalObjectACL = @(
        'Trustee', 'TrusteeSID', 'criticalObject', 'criticalObjectRights'
    )

    ExchangeServersGroup = @(
        'sAMAccountName', 'distinguishedName', 'objectSid',
        'member', 'memberOf', 'description'
    )

    # LAPS Finding (OU without LAPS protection)
    LAPSFinding = @(
        'ouName', 'computerCount', 'lapsUnprotectedComputers', 'lapsBackupOutsideAD'
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
        'sAMAccountName', 'description', 'MemberCount', 'memberNames', 'broadMembers', 'memberOf', 'managedBy',
        'whenCreated', 'distinguishedName'
    )

    # SCOM Group (from Get-SCOMInfrastructure)
    # NOTE: Same rationale as SCCMGroup - excludes 'member' for performance
    SCOMGroup = @(
        'sAMAccountName', 'description', 'MemberCount', 'memberOf', 'managedBy',
        'whenCreated', 'distinguishedName'
    )

    # AdminSDHolder ACL (from Get-PrivilegedGroupMembers Step 5)
    AdminSDHolderACL = @(
        'Trustee', 'TrusteeSID', 'dangerousRights'
    )
    PrivilegedGroupACL = @(
        'Trustee', 'TrusteeSID', 'dangerousRights', 'affectedGroups'
    )
    # What step 5b read (Get-PrivilegedGroupMembers): the groups, the ones read despite
    # adminCount=1 because dsHeuristics excludes their operator group, and the unreadable.
    UnprotectedPrivilegedGroups = @(
        'groupsRead', 'readDespiteAdminCount', 'groupsNotRead'
    )
    PrivilegedAccountACL = @(
        'Trustee', 'TrusteeSID', 'dangerousRights', 'affectedAccounts'
    )
    # What step 5c read (Get-PrivilegedGroupMembers): how many accounts, how many of them
    # AdminSDHolder protects, and the unreadable.
    PrivilegedAccountsRead = @(
        'accountsRead', 'protectedByAdminSDHolder', 'accountsNotRead'
    )

    # Logon scripts of accounts a principal beyond the administrators may change
    # (Get-LogonScriptPermissions)
    LogonScriptPermission = @(
        'logonScript', 'logonScriptRisk', 'logonScriptPermissions', 'runByAccounts', 'runByPrivilegedAccounts'
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

# A Tier-0 account (Get-ProtectedUsersStatus) is a user with rows of its own: the Tier-0
# groups that make it one, and why an account cannot be in Protected Users. Without an
# entry here it fell back to the User list, and tier0Groups - the answer to "why is this
# account Tier-0" - and excludedReason went to the Extended block, which the console never
# shows. Whether Protected Users covers it is no row: the line above the accounts says it.
# Built from the User list so that the two cannot drift apart.
$tier0AccountRows = [System.Collections.ArrayList]$Script:PrimaryAttributes['User']
$tier0AccountRows.Insert($tier0AccountRows.IndexOf('privilegedGroups') + 1, 'tier0Groups')
$Script:PrimaryAttributes['Tier0Account'] = @($tier0AccountRows) + @('excludedReason')
Remove-Variable -Name tier0AccountRows

# Object types with strict attribute display: ONLY PrimaryAttributes are shown, no Extended overflow.
# Use this for specialized views of shared objects (e.g., same GPO object used by both LDAP and SMB checks)
# to prevent cross-contamination of attributes from other checks.
$Script:StrictAttributeTypes = @(
    'SMBSigning',
    'LDAPConfigGPO',
    'NullSessionGPO',
    'AddComputerGPO',
    'EffectiveLDAPConfig',
    'EffectiveNullSession',
    'EffectiveSMBSigning',
    'EffectiveSMBSigningMembers',
    'SMBSigningWeakened',
    'LDAPStatisticsModule',
    'LDAPStatisticsTotal',
    'DomainPasswordPolicy',
    'FineGrainedPasswordPolicy',
    'BitLockerRecoveryKey',
    'GPOUserRights',
    'LAPSCoverage',
    'UnprotectedPrivilegedGroups',
    'PrivilegedAccountsRead'
)

# Per-ObjectType row labels: what a row is called, where the property it comes from is
# not what a reader should be shown.
#
# Ten checks report something about a Group Policy. Four of them report the GPO itself as
# the finding and carry a native LDAP object; the other six report a setting found inside
# a GPO and build their own object, naming the policy GPOName / GPOGUID / GPOPath. Left
# alone, the same three facts appeared under two sets of labels depending on which check
# a reader happened to be looking at - and one of the LDAP names, `Name`, is a GPO's GUID,
# which is accurate and unreadable unless you already know that.
#
# Relabelled rather than renamed, because these are real LDAP attributes: `Name` is what
# the HTML card title resolution reads, `displayName` and `gPCFileSysPath` are consumed by
# other checks, and renaming them would also change the JSON export of an object that
# genuinely is a directory object. Only the label changes. RawName on the row keeps the
# property name, so finding triggers and the HTML data attributes are unaffected.
#
# distinguishedName keeps its own name: it has no counterpart among the setting-level
# findings, so there is nothing for it to be consistent with.
#
# A transformer that supplies its own DisplayName still wins - see Build-RenderRow.
$Script:AttributeLabels = @{
    GPO            = @{ 'displayName' = 'GPOName'; 'Name' = 'GPOGUID'; 'gPCFileSysPath' = 'GPOPath' }
    SMBSigning     = @{ 'displayName' = 'GPOName'; 'Name' = 'GPOGUID'; 'gPCFileSysPath' = 'GPOPath' }
    SMBSigningWeakened = @{ 'displayName' = 'GPOName'; 'Name' = 'GPOGUID' }
    LDAPConfigGPO  = @{ 'displayName' = 'GPOName'; 'Name' = 'GPOGUID'; 'gPCFileSysPath' = 'GPOPath' }
    NullSessionGPO = @{ 'displayName' = 'GPOName'; 'Name' = 'GPOGUID'; 'gPCFileSysPath' = 'GPOPath' }
    AddComputerGPO = @{ 'displayName' = 'GPOName'; 'Name' = 'GPOGUID'; 'gPCFileSysPath' = 'GPOPath' }
}

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
    # EnrollmentAgentSignatureRequired is redundant for display - the underlying facts are shown as
    # RASignatureCount and RAApplicationPolicies. The property is kept on the object because the
    # ra_signature_gated finding trigger evaluates it via SourceObject.
    'EnrollmentAgentSignatureRequired',
    # EnrollmentAgentChainReachable records whether an enrollment agent certificate is obtainable
    # in this domain. Never displayed - picking the template to abuse for that is the tester's
    # call; the flag only feeds the ra_signature_gated severity trigger.
    'EnrollmentAgentChainReachable',
    # Internal classification attribute for Exchange groups - not for display
    'dangerousRightsSeverity',
    # RiskyMembers named the same principals a second time, one row below the
    # MembersAdded list they were already part of. The risk is shown where the members
    # are instead - Convert-MembersAddedToRenderValues colours the risky ones and reads
    # this property to know which, so it stays on the object and off the report.
    'RiskyMembers',
    # What each added member is worth (Broad, Privileged, Other) and what the target group
    # is worth - read by the MembersAdded and TargetGroup transformers, shown as colours.
    '_memberVerdicts', '_groupBaseSeverity',
    # Operator Group internal counts - kept in object but not displayed
    'MemberCount', 'ProtectedCount',
    # Internal adPEAS type markers and transport properties - not for display.
    # _isExchangeGroup tells the member renderer to judge members against what belongs in
    # an Exchange service group rather than against privilege; it is read from the source
    # object by Get-RenderModel and has no business being a row.
    '_adPEASObjectType', '_adPEASContext', '_Severity', '_Risk', '_isExchangeGroup',
    # The gMSA check's verdict per password reader, keyed by SID. Read by the transformer of
    # msDS-GroupMSAMembership, which colours each reader by it; the reader sees the colours.
    '_gmsaReaderVerdicts',
    # Precedence bookkeeping behind the EffectiveSetting sentence. _IsEffective is the
    # boolean the row colouring still needs; the sentence is what a reader gets.
    '_IsEffective', '_HasAnyLink',
    # Which half of the policy a finding depends on, so Split-GPOFindingByReach can judge
    # it per finding rather than per check, and the reach verdict where a check stamps it
    # instead of partitioning. Internal bookkeeping, never a row.
    '_ReachScope', '_ReachInactive', '_ReachUnlinked',
    # Roamed credential material. These hold DPAPI master keys and DPAPI-protected private
    # keys, and Get-CredentialRoaming deliberately never retrieves them - presence comes
    # from an LDAP filter instead. Excluded here as well so that another check fetching a
    # full user object cannot put base64-encoded master keys into an HTML report somebody
    # then mails around, which would create the exposure that check exists to report.
    'msPKIAccountCredentials', 'msPKIDPAPIMasterKeys',
    # Whether a delegated roaming read is live, dormant or undecidable. Decides the colour of
    # the row; the reader sees the verdict in EffectiveToday instead.
    '_IsFinding',
    # GPO check internal analysis flags - used for severity calculation, not for display.
    # ConsoleClass decides the colour a row is rendered in and must not appear as a row.
    #
    # GPOGUID used to be excluded here as an internal flag. It is not one: the GUID is the
    # folder name under \\<domain>\SYSVOL\<domain>\Policies\, and without it a reader who
    # wants to inspect the policy that produced a finding has only its display name - which
    # is not unique, not a path, and not searchable in SYSVOL. Every GPO ObjectType now
    # lists it in its PrimaryAttributes instead, so it appears in a fixed place next to the
    # name rather than wherever the extended overflow happens to put it.
    'Risk', 'Severity', 'ConsoleClass',
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

    # Effective LDAP Security Configuration. The null session values are no rows of it any
    # more, so they cannot be part of how it is recognised.
    if ($Object.LDAPSigning -and $Object.ChannelBinding -and -not $Object.gPCFileSysPath) {
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

    # Machine Account Quota
    if ($Object.PSObject.Properties['ms-DS-MachineAccountQuota']) {
        return 'MachineAccountQuota'
    }

    # GPO granting SeMachineAccountPrivilege (enriched native GPO object with Accounts property)
    if ($Object._adPEASObjectType -eq 'AddComputerGPO') {
        return 'AddComputerGPO'
    }

    # Credential finding
    if ($Object.CredentialType -and ($Object.Password -or $Object.MatchedLine)) {
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
        Write-Warning "[Get-ObjectTypeForOrdering] Error detecting object type: $_"
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
    # Attributes that should be rendered even when empty - their absence carries meaning
    # (e.g. an unlinked GPO is a security-relevant fact that users will miss if the row is suppressed).
    $alwaysShowEmpty = @('LinkedOUs')

    foreach ($attrName in $primaryAttrNames) {
        $value = $Object.$attrName
        $isEmpty = ($null -eq $value) -or ($value -isnot [bool] -and $value -eq '')
        if (-not $isEmpty -or ($attrName -in $alwaysShowEmpty -and $Object.PSObject.Properties[$attrName])) {
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

        # Skip null/empty (but keep boolean $false, and keep AlwaysShow attributes whose
        # absence is itself meaningful - e.g. unlinked GPO LinkedOUs).
        $isEmptyValue = ($null -eq $prop.Value) -or ($prop.Value -isnot [bool] -and $prop.Value -eq '')
        if ($isEmptyValue -and $prop.Name -notin $alwaysShowEmpty) { continue }

        $severity = Get-AttributeSeverity -Name $prop.Name -Value $prop.Value -IsComputer $IsComputer -SourceObject $Object

        # Special handling for Owner: Determine severity based on default owner status
        # Non-default owners are a security risk (owner has implicit full control)
        if ($prop.Name -ieq 'Owner') {
            $ownerSID = $Object.OwnerSID
            if ($ownerSID) {
                if (Test-IsDefaultOwner -SID $ownerSID) {
                    # Default owner - Standard severity, goes to Extended
                    $severity = 'Standard'
                } else {
                    # Non-default owner. What this decides is placement: any answer
                    # other than Standard promotes the row out of Extended, which is
                    # where a takeover path belongs.
                    #
                    # It used to be the literal 'Finding' - a second place deciding a
                    # fact the trigger and the card already decide, and after the
                    # renderer was corrected to follow them it was the only statement
                    # left saying Finding. Asking the same source costs nothing here,
                    # because Hint promotes the row just as Finding did.
                    $ownerContext = if ($IsComputer) { 'NonDefaultOwner' } else { 'NonDefaultUserOwner' }
                    $ownerMatch = Get-TriggerMatch -Name 'Owner' -Value $prop.Value -Context $ownerContext
                    $severity = if ($ownerMatch -and $ownerMatch.Severity -and $ownerMatch.Severity -ne 'Standard') {
                        [string]$ownerMatch.Severity
                    } else {
                        'Hint'
                    }
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
        # Surface as warning so silent breakage (e.g. invalid transformer call) is visible.
        Write-Warning "[Get-OrderedAttributes] Error processing attributes: $_"
        return [PSCustomObject]@{
            ObjectType = 'User'
            Primary = [System.Collections.ArrayList]@()
            Extended = [System.Collections.ArrayList]@()
        }
    }
}
