<#
.SYNOPSIS
    Central ObjectType definitions for adPEAS - Single Source of Truth.

.DESCRIPTION
    This file serves as the Single Source of Truth for all ObjectType definitions.
    Each ObjectType used in Check modules must be defined here with:
    - Module: adPEAS module name (Domain, Creds, Rights, Delegation, ADCS, Accounts, GPO, Computer, Application, Bloodhound)
    - TitleFormat: Template for object card titles (e.g., "User: {Name}")
    - Category: Grouping category for organization
    - SectionTitle: Section header text (for HTML report sections)
    - Summary: Brief description of what the check does
    - WhyItMatters: Security impact explanation
    - WhatWeCheck: Array of bullet points describing the check
    - SecureMessage: (optional) Message shown when finding is secure
    - FilteringNote: (optional) Note about what is filtered from output

    Benefits:
    - Eliminates manual synchronization between Check modules and Export-HTMLReport
    - Build-time validation catches undefined ObjectTypes
    - Consistent title formatting across all reports
    - All metadata in one place for easy maintenance

.NOTES
    Author: Alexander Sturz (@_61106960_)

    How to add a new ObjectType:
    1. Add entry to $Script:ObjectTypeDefinitions below
    2. Use in Check module: $obj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'YourType' -Force
    3. Build will validate that the type exists

    Title format placeholders:
    - {Name}    : Object name (sAMAccountName, Name, displayName, or CN)
    - {Context} : Value from _adPEASContext property (optional)
    - {DN}      : Distinguished Name path (for showing hierarchy)
#>

# Central ObjectType definitions
# Key = ObjectType value used in Check modules
# Value = Hashtable with TitleFormat, Category, SectionTitle, Summary, WhyItMatters, WhatWeCheck, and optional SecureMessage/FilteringNote
$Script:ObjectTypeDefinitions = [ordered]@{

    # ============================================================================
    # DOMAIN CONFIGURATION
    # ============================================================================

    'DomainBasicInfo' = @{
        TitleFormat = "Domain Information"
        Module = "Domain"
        Category = "Domain"
        SectionTitle = "Domain Information"
        Summary = "Gathers basic information about the Active Directory domain."
        WhyItMatters = "Understanding the domain structure, functional levels, and key configurations provides the foundation for all security assessments. Old functional levels may indicate legacy systems with known vulnerabilities."
        WhatWeCheck = @(
            "Domain and forest names, SIDs, and functional levels"
            "Domain Controller locations and FSMO role holders"
            "Anonymous LDAP access settings"
        )
    }

    'KerberosPolicy' = @{
        TitleFormat = "Kerberos Policy"
        Module = "Domain"
        Category = "Domain"
        SectionTitle = "Kerberos Policy"
        Summary = "Reviews Kerberos ticket lifetime and password policies."
        WhyItMatters = "Kerberos policies control ticket lifetimes and the krbtgt password age. Long-lived tickets or old krbtgt passwords increase the window for Golden Ticket attacks."
        WhatWeCheck = @(
            "TGT maximum lifetime (should be 10 hours or less)"
            "TGT renewal lifetime (should be 7 days or less)"
            "krbtgt password age (should be changed at least yearly)"
        )
        SecureMessage = "Kerberos policy settings are properly configured. Ticket lifetimes are within recommended limits and the krbtgt password has been rotated within the last 180 days."
    }

    'GuestAccount' = @{
        TitleFormat = "Guest Account Status"
        Module = "Domain"
        Category = "Domain"
        SectionTitle = "Guest Account Status"
        Summary = "Checks if the built-in Guest account (RID 501) is enabled and reviews group memberships."
        WhyItMatters = "The Guest account allows anonymous access with minimal authentication. An enabled Guest account, especially with privileged group memberships, poses a significant security risk."
        WhatWeCheck = @(
            "Guest account enabled/disabled status"
            "Guest account membership in privileged groups (via Test-IsPrivileged)"
        )
        SecureMessage = "Guest account is disabled (secure default configuration)."
    }

    'DomainControllers' = @{
        TitleFormat = "Domain Controllers"
        Module = "Domain"
        Category = "Domain"
        SectionTitle = "Domain Controllers"
        Summary = "Lists all Domain Controllers in the domain."
        WhyItMatters = "Domain Controllers are Tier-0 assets containing all domain secrets. Understanding the DC infrastructure helps identify critical assets requiring maximum protection."
        WhatWeCheck = @(
            "All computers with the DC role"
            "FSMO role assignments"
            "Global Catalog servers"
        )
    }

    'SitesAndSubnets' = @{
        TitleFormat = "Sites and Subnets: {Name}"
        Module = "Domain"
        Category = "Domain"
        SectionTitle = "Sites and Subnets"
        Summary = "Maps AD Sites with associated IP subnets and Domain Controllers."
        WhyItMatters = "Sites and subnets control DC selection for authentication. Misconfigured subnets can cause clients to authenticate to DCs across WAN links, enabling interception. Knowing which DCs serve which site helps identify lateral movement paths."
        WhatWeCheck = @(
            "All configured AD sites"
            "IP subnet assignments per site"
            "Domain Controllers assigned to each site"
        )
    }

    'DomainPasswordPolicy' = @{
        TitleFormat = "Password Policy"
        Module = "Domain"
        Category = "Domain"
        SectionTitle = "Domain Password Policy"
        Summary = "Reviews the domain's default password policy settings."
        WhyItMatters = "Weak password policies allow users to set easily guessable passwords, making the domain vulnerable to password spraying and brute force attacks."
        WhatWeCheck = @(
            "Minimum password length and complexity requirements"
            "Password history and maximum age settings"
            "Account lockout threshold and duration"
            "Lockout observation window"
        )
        SecureMessage = "The domain password policy meets security best practices with adequate password length (14+ characters), complexity requirements enabled, and appropriate lockout settings configured."
    }

    'FineGrainedPasswordPolicy' = @{
        TitleFormat = "Fine-Grained Password Policy: {Name}"
        Module = "Domain"
        Category = "Domain"
        SectionTitle = "Fine-Grained Password Policies"
        Summary = "Identifies Fine-Grained Password Policies that override the default domain policy."
        WhyItMatters = "FGPPs allow different password requirements for different user groups. Misconfigured FGPPs may allow weaker passwords for certain accounts, including privileged ones."
        WhatWeCheck = @(
            "Existing Password Settings Objects (PSOs)"
            "Which users or groups each PSO applies to"
            "Password requirements defined in each PSO"
            "Priority/precedence of overlapping policies"
        )
        SecureMessage = "All Fine-Grained Password Policies are properly configured with strong password requirements. No PSO allows weaker passwords than the domain default policy."
    }

    'DomainTrust' = @{
        TitleFormat = "Domain Trust: {Name}"
        Module = "Domain"
        Category = "Domain"
        SectionTitle = "Domain Trusts"
        Summary = "Discovers trust relationships with other domains or forests."
        WhyItMatters = "Trust relationships extend the security boundary. Misconfigured trusts can allow attackers in one domain to compromise another. SID filtering and selective authentication are critical controls."
        WhatWeCheck = @(
            "All inbound, outbound, and bidirectional trusts"
            "Trust type (forest, external, shortcut)"
            "SID filtering status (quarantine)"
            "Selective authentication settings"
            "Trust transitivity"
        )
        SecureMessage = "All domain trusts are properly secured with SID filtering enabled and appropriate authentication settings. No misconfigured or overly permissive trusts were found."
    }

    'LDAPConfigGPO' = @{
        TitleFormat = "LDAP Configuration GPO: {Name}"
        Module = "Domain"
        Category = "Domain"
        SectionTitle = "LDAP Signing Configuration"
        Summary = "Checks if LDAP signing and channel binding are configured via GPO."
        WhyItMatters = "Without LDAP signing and channel binding, attackers can perform NTLM relay attacks against LDAP services, potentially adding users to groups or modifying AD objects."
        WhatWeCheck = @(
            "LDAP server signing requirements on Domain Controllers"
            "LDAP client signing requirements"
            "Channel binding token requirements"
            "GPO configurations enforcing these settings"
        )
        SecureMessage = "LDAP signing and channel binding are properly configured via GPO. All Domain Controllers require LDAP signing and enforce channel binding, blocking NTLM relay attacks against LDAP services."
    }

    'SMBSigning' = @{
        TitleFormat = "SMB Signing GPO: {Name}"
        Module = "Domain"
        Category = "Domain"
        SectionTitle = "SMB Signing Configuration"
        Summary = "Checks if SMB signing is required on domain systems."
        WhyItMatters = "Without SMB signing, attackers can intercept and relay SMB authentication, gaining unauthorized access to file shares and enabling remote code execution on target systems."
        WhatWeCheck = @(
            "SMB server signing requirements"
            "SMB client signing requirements"
            "GPO configurations enforcing SMB signing"
            "Systems that may not require signing"
        )
        SecureMessage = "SMB signing is required on both servers and clients via GPO. NTLM relay attacks targeting SMB file shares are blocked, preventing unauthorized access and lateral movement."
    }

    # ============================================================================
    # INFRASTRUCTURE SERVERS
    # ============================================================================

    'DomainController' = @{
        TitleFormat = "Domain Controller: {Name}"
        Module = "Application"
        Category = "Infrastructure"
        SectionTitle = "Domain Controllers"
        Summary = "Enumerates all Domain Controllers in the domain."
        WhyItMatters = "Domain Controllers are the highest-value targets. Understanding the DC infrastructure helps identify Tier 0 assets that require maximum protection."
        WhatWeCheck = @(
            "All computers with the DC role"
            "DC operating system versions"
            "Read-Only Domain Controllers (RODCs)"
        )
    }

    'ExchangeServer' = @{
        TitleFormat = "Exchange Server: {Name}{Context}"
        Module = "Application"
        Category = "Infrastructure"
        SectionTitle = "Exchange Servers"
        Summary = "Discovers Microsoft Exchange infrastructure with detailed analysis."
        WhyItMatters = "Exchange servers often have dangerous AD permissions and are frequently targeted. Vulnerabilities like ProxyLogon/ProxyShell have enabled widespread compromises."
        WhatWeCheck = @(
            "Exchange servers and their versions"
            "Exchange roles (Mailbox, CAS, etc.)"
            "Web enrollment endpoints and NTLM status"
            "Exchange security groups and permissions"
        )
        SecureMessage = "Exchange infrastructure is running a supported version with proper security configuration. Web services use HTTPS with EPA, and Exchange permissions follow expected patterns."
    }

    'ExchangeServerBasic' = @{
        TitleFormat = "Exchange Server: {Name}"
        Module = "Application"
        Category = "Infrastructure"
        SectionTitle = "Exchange Servers (Basic)"
        Summary = "Identifies Microsoft Exchange servers via group membership."
        WhyItMatters = "Exchange servers have significant AD privileges and are high-value targets. Basic detection via 'Exchange Servers' group membership."
        WhatWeCheck = @(
            "Members of the Exchange Servers group"
            "Server computer accounts"
        )
    }

    'ExchangeOrganization' = @{
        TitleFormat = "Exchange Organization: {Name}"
        Module = "Application"
        Category = "Infrastructure"
        SectionTitle = "Exchange Organization"
        Summary = "Exchange Organization overview from the Configuration partition (forest-wide)."
        WhyItMatters = "Exchange Organization data in the Configuration partition is visible from any domain in the forest. This provides a complete picture of the Exchange infrastructure even when querying from a child domain."
        WhatWeCheck = @(
            "Exchange Organization name"
            "Accepted mail domains and SMTP send connectors"
            "Number of Exchange servers across the forest"
        )
    }

    'ExchangeConfigServer' = @{
        TitleFormat = "Exchange Server: {Name}"
        Module = "Application"
        Category = "Infrastructure"
        SectionTitle = "Exchange Server (Config Partition)"
        Summary = "Exchange server details from the Configuration partition (forest-wide, visible from any domain)."
        WhyItMatters = "The Configuration partition provides Exchange server details visible from any domain in the forest. This includes virtual directories, SMTP connectors and listening ports that reveal the server's attack surface."
        WhatWeCheck = @(
            "Server FQDN, Exchange version and hosting domain"
            "Virtual directories with external hostnames"
            "SMTP receive connectors and listening ports"
        )
    }

    'MSSQLServer' = @{
        TitleFormat = "MSSQL Server: {Name}"
        Module = "Application"
        Category = "Infrastructure"
        SectionTitle = "SQL Servers"
        Summary = "Identifies Microsoft SQL Server instances via SPN discovery."
        WhyItMatters = "SQL Servers often contain sensitive data and may have linked servers or xp_cmdshell enabled. They're common targets for lateral movement and data exfiltration."
        WhatWeCheck = @(
            "MSSQLSvc Service Principal Names"
            "SQL Server instances and their hosts"
        )
    }

    'SCCMServer' = @{
        TitleFormat = "SCCM Server: {Name}"
        Module = "Application"
        Category = "Infrastructure"
        SectionTitle = "SCCM Infrastructure"
        Summary = "Discovers System Center Configuration Manager infrastructure."
        WhyItMatters = "SCCM enables code execution on all managed clients. Compromising SCCM infrastructure provides domain-wide access, making it a Tier 0 asset."
        WhatWeCheck = @(
            "SCCM site servers and management points"
            "System Management container permissions"
            "SCCM-related service accounts and groups"
        )
        SecureMessage = "SCCM infrastructure follows security best practices. System Management container permissions are properly restricted and no credential exposure was found."
    }

    'SCCMServerBasic' = @{
        TitleFormat = "SCCM Server: {Name}"
        Module = "Application"
        Category = "Infrastructure"
        SectionTitle = "SCCM Servers (Basic)"
        Summary = "Identifies SCCM/ConfigMgr servers via SPN discovery."
        WhyItMatters = "SCCM servers are Tier-0 assets. Basic detection via SMS/CCM Service Principal Names."
        WhatWeCheck = @(
            "Computers with SMS* or CCM* SPNs"
        )
    }

    'SCCMServiceAccount' = @{
        TitleFormat = "SCCM Service Account: {Name}"
        Module = "Application"
        Category = "Infrastructure"
        SectionTitle = "SCCM Service Accounts"
        Summary = "Identifies service accounts used by SCCM infrastructure."
        WhyItMatters = "SCCM service accounts often have elevated privileges across managed systems."
        WhatWeCheck = @(
            "Service accounts with SCCM-related attributes"
            "Privilege level and access scope"
        )
    }

    'SCCMGroup' = @{
        TitleFormat = "SCCM Group: {Name}"
        Module = "Application"
        Category = "Infrastructure"
        SectionTitle = "SCCM Groups"
        Summary = "Identifies security groups used by SCCM."
        WhyItMatters = "SCCM groups may grant elevated access to SCCM infrastructure."
        WhatWeCheck = @(
            "Groups with SCCM-related names or attributes"
        )
    }

    'SCCMSite' = @{
        TitleFormat = "SCCM Site: {Name}"
        Module = "Application"
        Category = "Infrastructure"
        SectionTitle = "SCCM Sites"
        Summary = "Identifies SCCM site codes and site hierarchy via AD schema objects."
        WhyItMatters = "SCCM site codes identify individual SCCM sites. A Central Administration Site (CAS) controls the entire hierarchy and is a Tier 0 asset."
        WhatWeCheck = @(
            "mSSMSSite objects in System Management container"
            "Site codes and source forests"
            "CAS vs Primary vs Secondary site identification"
        )
    }

    'SCCMManagementPoint' = @{
        TitleFormat = "SCCM Management Point: {Name}"
        Module = "Application"
        Category = "Infrastructure"
        SectionTitle = "SCCM Management Points"
        Summary = "Identifies SCCM Management Points published to Active Directory."
        WhyItMatters = "Management Points are the primary communication interface for SCCM clients. They reveal site hierarchy and are targets for client poisoning attacks."
        WhatWeCheck = @(
            "mSSMSManagementPoint objects in System Management container"
            "Management Point hostnames and associated site codes"
            "Site hierarchy via mSSMSCapabilities XML"
        )
    }

    'SCCMPXEServer' = @{
        TitleFormat = "PXE/WDS Server: {Name}"
        Module = "Application"
        Category = "Infrastructure"
        SectionTitle = "PXE/WDS Boot Servers"
        Summary = "Identifies PXE boot and WDS servers used for OS deployment."
        WhyItMatters = "PXE boot servers can be targeted for credential theft or OS deployment manipulation. Compromised PXE infrastructure enables large-scale system compromise."
        WhatWeCheck = @(
            "connectionPoint objects with netbootserver attribute"
            "intellimirrorSCP service connection points"
        )
    }

    'SCOMServer' = @{
        TitleFormat = "SCOM Server: {Name}"
        Module = "Application"
        Category = "Infrastructure"
        SectionTitle = "SCOM Infrastructure"
        Summary = "Identifies System Center Operations Manager infrastructure."
        WhyItMatters = "SCOM Run As accounts often have elevated privileges across monitored systems. SCOM infrastructure is a valuable target for lateral movement."
        WhatWeCheck = @(
            "SCOM management servers"
            "SCOM service accounts"
            "SCOM-related security groups"
        )
        SecureMessage = "SCOM infrastructure is properly configured. Run As accounts use least-privilege principles and no exposed credentials were found."
    }

    'SCOMServerBasic' = @{
        TitleFormat = "SCOM Server: {Name}"
        Module = "Application"
        Category = "Infrastructure"
        SectionTitle = "SCOM Servers (Basic)"
        Summary = "Identifies SCOM servers via SPN discovery."
        WhyItMatters = "SCOM agents run with elevated privileges on monitored systems. Basic detection via SCOM SPNs."
        WhatWeCheck = @(
            "Computers with MSOMHSvc or MSOMSdkSvc SPNs"
        )
    }

    'SCOMServiceAccount' = @{
        TitleFormat = "SCOM Service Account: {Name}"
        Module = "Application"
        Category = "Infrastructure"
        SectionTitle = "SCOM Service Accounts"
        Summary = "Identifies service accounts used by SCOM infrastructure."
        WhyItMatters = "SCOM service accounts often have elevated privileges for monitoring."
        WhatWeCheck = @(
            "Service accounts with SCOM-related attributes"
        )
    }

    'SCOMGroup' = @{
        TitleFormat = "SCOM Group: {Name}"
        Module = "Application"
        Category = "Infrastructure"
        SectionTitle = "SCOM Groups"
        Summary = "Identifies security groups used by SCOM."
        WhyItMatters = "SCOM groups may grant elevated access to monitoring infrastructure."
        WhatWeCheck = @(
            "Groups with SCOM-related names or attributes"
        )
    }

    'EntraConnect' = @{
        TitleFormat = "Entra ID Connect: {Name}{Context}"
        Module = "Application"
        Category = "Infrastructure"
        SectionTitle = "Entra ID Connect"
        Summary = "Discovers Azure AD Connect / Entra ID Connect indicators."
        WhyItMatters = "AD Connect servers synchronize identities to the cloud and have DCSync rights. Compromise enables both on-premises and cloud domain takeover."
        WhatWeCheck = @(
            "MSOL_ and ADSync service accounts"
            "Servers with Azure AD Connect SPNs"
            "Connected M365 tenant information"
        )
        SecureMessage = "Entra ID Connect infrastructure is properly identified and secured. Sync accounts follow security best practices with appropriate permissions."
    }

    # ============================================================================
    # EXCHANGE GROUPS
    # ============================================================================

    'ExchangeTrustedSubsystem' = @{
        TitleFormat = "Exchange Trusted Subsystem Member: {Name}"
        Module = "Application"
        Category = "Exchange"
        SectionTitle = "Exchange Trusted Subsystem Members"
        Summary = "Identifies members of the Exchange Trusted Subsystem group."
        WhyItMatters = "Exchange Trusted Subsystem has WriteDACL permissions on the domain object by default, enabling domain privilege escalation (PrivExchange, Exchange-related vulnerabilities). This is one of the most dangerous Exchange groups."
        WhatWeCheck = @(
            "Members of Exchange Trusted Subsystem"
            "Computer accounts (typically Exchange servers)"
            "Potential for DCSync or domain takeover via WriteDACL abuse"
        )
        SecureMessage = "Exchange Trusted Subsystem contains only expected Exchange server computer accounts."
    }

    'ExchangeWindowsPermissions' = @{
        TitleFormat = "Exchange Windows Permissions Member: {Name}"
        Module = "Application"
        Category = "Exchange"
        SectionTitle = "Exchange Windows Permissions Members"
        Summary = "Identifies members of the Exchange Windows Permissions group."
        WhyItMatters = "Exchange Windows Permissions group has powerful AD permissions including WriteDACL on the domain. Members can potentially grant themselves DCSync rights or modify security descriptors."
        WhatWeCheck = @(
            "Members of Exchange Windows Permissions"
            "Groups nested within (often Exchange Trusted Subsystem)"
            "Potential for privilege escalation via permission modification"
        )
        SecureMessage = "Exchange Windows Permissions membership follows expected patterns with only Exchange-related principals."
    }

    'ExchangeOrganizationManagement' = @{
        TitleFormat = "Organization Management Member: {Name}"
        Module = "Application"
        Category = "Exchange"
        SectionTitle = "Exchange Organization Management Members"
        Summary = "Identifies members of the Organization Management group."
        WhyItMatters = "Organization Management is the highest Exchange administrative role. Members have full control over Exchange configuration and can manage all Exchange objects. Often a path to domain admin via Exchange permission abuse."
        WhatWeCheck = @(
            "Members of Organization Management"
            "User accounts with Exchange admin privileges"
            "Service accounts or unexpected members"
        )
        SecureMessage = "Organization Management contains only designated Exchange administrators."
    }

    # ============================================================================
    # ADCS (CERTIFICATE SERVICES)
    # ============================================================================

    'CertificateAuthority' = @{
        TitleFormat = "Certificate Authority: {DisplayName}"
        Module = "ADCS"
        Category = "ADCS"
        SectionTitle = "Certificate Authorities"
        Summary = "Discovers Active Directory Certificate Services deployment and analyzes CA certificate security."
        WhyItMatters = "ADCS misconfigurations enable privilege escalation through certificate abuse. Weak CA certificates (short keys, deprecated algorithms, expired) undermine the entire PKI trust chain."
        WhatWeCheck = @(
            "Enterprise and Standalone Certificate Authorities"
            "CA certificate properties (signature algorithm, key length, validity)"
            "CA enrollment endpoints (including web enrollment)"
            "NTLM authentication on CA web services (ESC8)"
            "CA permissions and security settings"
        )
        SecureMessage = "Certificate Authority configuration is secure. CA certificates use strong algorithms, web enrollment endpoints use HTTPS with EPA enabled, and CA permissions follow least privilege principles."
    }

    'CertificateTemplate' = @{
        TitleFormat = "Certificate Template: {Name}"
        Module = "ADCS"
        Category = "ADCS"
        SectionTitle = "Certificate Templates"
        Summary = "Analyzes certificate templates for escalation vulnerabilities."
        WhyItMatters = "Vulnerable certificate templates (ESC1-ESC4, ESC13, ESC15) allow attackers to obtain certificates for any user or gain group membership, enabling domain compromise through certificate-based authentication."
        WhatWeCheck = @(
            "Templates allowing enrollee-supplied SANs (ESC1)"
            "Any Purpose or SubCA templates (ESC2)"
            "Certificate Request Agent templates (ESC3)"
            "Template ACLs allowing modification (ESC4)"
            "Schema version and security extension inclusion (ESC9, ESC15)"
            "Issuance policies linked to AD groups (ESC13)"
        )
        SecureMessage = "No vulnerable certificate templates found. All templates restrict enrollment to privileged users and do not allow dangerous configurations like enrollee-supplied SANs."
    }

    'PKIContainer' = @{
        TitleFormat = "PKI Container ACL: {Name}"
        Module = "ADCS"
        Category = "ADCS"
        SectionTitle = "PKI Container Permissions"
        Summary = "Reviews permissions on critical PKI containers in the Configuration partition."
        WhyItMatters = "Write access to PKI containers allows attackers to create or modify certificate templates, manipulate the NTAuth store, or modify enrollment services - enabling escalation vulnerabilities (ESC1-4) even if none currently exist."
        WhatWeCheck = @(
            "GenericAll, WriteDACL, WriteOwner, or GenericWrite permissions on Public Key Services container"
            "Permissions on Certificate Templates container"
            "Permissions on Enrollment Services container"
            "Permissions on NTAuth Store container"
            "Permissions on OID container (ESC13-related)"
        )
        FilteringNote = "High-privileged accounts (Domain Admins, Enterprise Admins, SYSTEM, Cert Publishers) are filtered from output as they are expected to manage PKI infrastructure."
        SecureMessage = "No vulnerabilities detected - PKI container permissions are properly restricted to authorized administrators."
    }

    'PKIInfrastructure' = @{
        TitleFormat = "PKI Trust Infrastructure"
        Module = "ADCS"
        Category = "ADCS"
        SectionTitle = "PKI Trust Infrastructure"
        Summary = "Enumerates the AD PKI trust infrastructure including Root CAs, NTAuth Store, and AIA CAs."
        WhyItMatters = "The PKI trust infrastructure defines which Certificate Authorities are trusted for domain authentication (PKINIT). Rogue or misconfigured trust entries can enable certificate-based attacks across the entire domain or forest."
        WhatWeCheck = @(
            "Trusted Root CAs in AD configuration partition"
            "NTAuth Store certificates (trusted for domain authentication / PKINIT)"
            "Authority Information Access (AIA) CAs"
        )
        SecureMessage = "PKI trust infrastructure is properly configured with valid Root CAs and NTAuth Store entries."
    }

    'RootCA' = @{
        TitleFormat = "Root CA: {Name}"
        Module = "ADCS"
        Category = "ADCS"
        SectionTitle = "Trusted Root CAs"
        Summary = "A trusted Root Certificate Authority registered in the AD configuration partition."
        WhyItMatters = "Root CAs define the top of the certificate trust chain. Rogue or compromised Root CAs allow attackers to issue trusted certificates for any purpose, including domain authentication."
        WhatWeCheck = @(
            "Certificate subject and thumbprint"
            "Certificate validity period and expiration status"
            "Signature algorithm strength (SHA-256 or stronger)"
            "Public key length (2048 bits or more)"
        )
        SecureMessage = "Root CA certificate uses strong cryptographic algorithms and is within its validity period."
    }

    'NTAuthCertificate' = @{
        TitleFormat = "NTAuth Certificate: {Name}"
        Module = "ADCS"
        Category = "ADCS"
        SectionTitle = "NTAuth Store"
        Summary = "A certificate in the NTAuth Store, trusted for domain authentication via Kerberos PKINIT."
        WhyItMatters = "Only certificates issued by CAs listed in the NTAuth Store are accepted for Kerberos PKINIT authentication. Unauthorized entries allow rogue CAs to issue domain authentication certificates."
        WhatWeCheck = @(
            "Certificate issuer and subject"
            "Certificate thumbprint for identification"
            "Certificate validity and expiration"
        )
        SecureMessage = "NTAuth Store contains only legitimate CA certificates for domain authentication."
    }

    'AIACA' = @{
        TitleFormat = "AIA CA: {Name}"
        Module = "ADCS"
        Category = "ADCS"
        SectionTitle = "AIA CAs"
        Summary = "An Authority Information Access CA used for certificate chain building and validation."
        WhyItMatters = "AIA CAs provide intermediate certificates needed to build complete trust chains. Missing or misconfigured AIA entries can break certificate validation, while unauthorized entries may enable cross-forest trust abuse."
        WhatWeCheck = @(
            "Certificate thumbprint and validity"
            "Certificate expiration status"
        )
        SecureMessage = "AIA CA certificates are valid and properly configured for chain building."
    }

    # ============================================================================
    # DELEGATION
    # ============================================================================

    'UnconstrainedDelegation' = @{
        TitleFormat = "Unconstrained Delegation: {Name}"
        Module = "Delegation"
        Category = "Delegation"
        SectionTitle = "Unconstrained Delegation"
        Summary = "Identifies computers and users configured for unconstrained Kerberos delegation."
        WhyItMatters = "Unconstrained delegation stores TGTs of all authenticating users. Attackers who compromise these systems can steal TGTs and impersonate any user, including Domain Admins."
        WhatWeCheck = @(
            "Computers with TRUSTED_FOR_DELEGATION flag"
            "Users with TRUSTED_FOR_DELEGATION flag"
            "Whether these systems could be coerced to receive DC TGTs"
        )
        SecureMessage = "No accounts with unconstrained delegation found (excluding Domain Controllers). TGT theft through delegation abuse is not possible in this environment."
        PrimaryFindingId = 'UNCONSTRAINED_DELEGATION'
    }

    'ConstrainedDelegation' = @{
        TitleFormat = "Constrained Delegation: {Name}"
        Module = "Delegation"
        Category = "Delegation"
        SectionTitle = "Constrained Delegation"
        Summary = "Identifies accounts configured for constrained Kerberos delegation."
        WhyItMatters = "Constrained delegation with protocol transition allows impersonating any user to specific services. If those services include LDAP or CIFS on DCs, it enables privilege escalation."
        WhatWeCheck = @(
            "Accounts with msDS-AllowedToDelegateTo configured"
            "Whether protocol transition (S4U2Self) is enabled"
            "Target services that could enable privilege escalation"
        )
        SecureMessage = "No accounts with dangerous constrained delegation found. No delegation targets include sensitive services like LDAP or CIFS on Domain Controllers that could enable privilege escalation."
        PrimaryFindingId = 'CONSTRAINED_DELEGATION_PROTOCOL_TRANSITION'
    }

    'RBCDelegation' = @{
        TitleFormat = "RBCD: {Name}"
        Module = "Delegation"
        Category = "Delegation"
        SectionTitle = "Resource-Based Constrained Delegation"
        Summary = "Identifies computers with Resource-Based Constrained Delegation settings."
        WhyItMatters = "RBCD allows specified accounts to impersonate users to the target computer. If attackers can write to this attribute or control a listed principal, they can compromise the target."
        WhatWeCheck = @(
            "Computers with msDS-AllowedToActOnBehalfOfOtherIdentity"
            "Which principals are allowed to delegate"
            "Whether those principals could be compromised or created"
        )
        SecureMessage = "No dangerous RBCD configurations found. RBCD settings only allow expected privileged accounts to delegate, preventing impersonation-based attacks."
        PrimaryFindingId = 'RBCD_DANGEROUS_PRINCIPALS'
    }

    # ============================================================================
    # ACCOUNTS
    # ============================================================================

    'PasswordNeverExpires' = @{
        TitleFormat = "Password Never Expires: {Name}"
        Module = "Accounts"
        Category = "Accounts"
        SectionTitle = "Password Never Expires"
        Summary = "Identifies administrative accounts exempt from password expiration."
        WhyItMatters = "Passwords that never expire remain valid indefinitely if compromised. Privileged accounts should rotate passwords regularly to limit credential exposure windows."
        WhatWeCheck = @(
            "Privileged accounts with DONT_EXPIRE_PASSWORD flag"
            "Whether these are legitimate service accounts"
            "Last password change date"
        )
        SecureMessage = "No privileged accounts have the 'password never expires' flag set. All administrative accounts follow the domain password expiration policy."
        PrimaryFindingId = 'PASSWORD_NEVER_EXPIRES'
    }

    'ReversibleEncryption' = @{
        TitleFormat = "Reversible Encryption: {Name}"
        Module = "Accounts"
        Category = "Accounts"
        SectionTitle = "Reversible Encryption"
        Summary = "Finds administrative accounts storing passwords with reversible encryption."
        WhyItMatters = "Reversible encryption allows the actual password to be recovered from AD, effectively storing it in cleartext. This is a severe security risk for any account, especially privileged ones."
        WhatWeCheck = @(
            "Accounts with 'Store password using reversible encryption' enabled"
            "Whether this setting is actually required"
            "Impact on credential security"
        )
        SecureMessage = "No privileged accounts store passwords with reversible encryption. Password hashes cannot be recovered to plaintext from Active Directory."
        PrimaryFindingId = 'REVERSIBLE_ENCRYPTION'
    }

    'PasswordNotRequired' = @{
        TitleFormat = "Password Not Required: {Name}"
        Module = "Accounts"
        Category = "Accounts"
        SectionTitle = "Password Not Required Accounts"
        Summary = "Identifies enabled user accounts with the PASSWD_NOTREQD flag set."
        WhyItMatters = "Accounts with the 'Password Not Required' flag can bypass the domain password policy and may have an empty password. While the flag alone does not guarantee an empty password, it indicates a hygiene issue and potential attack vector."
        WhatWeCheck = @(
            "Enabled user accounts with PASSWD_NOTREQD flag (UAC bit 32)"
            "Whether affected accounts are privileged or service accounts"
            "Last password change date for risk assessment"
        )
        SecureMessage = "No enabled user accounts have the 'Password Not Required' flag set. All accounts require passwords according to domain password policy."
        PrimaryFindingId = 'PASSWORD_NOT_REQUIRED'
    }

    'InactiveAdmin' = @{
        TitleFormat = "Inactive Admin: {Name}"
        Module = "Accounts"
        Category = "Accounts"
        SectionTitle = "Inactive Admin Accounts"
        Summary = "Finds administrative accounts that haven't been used recently."
        WhyItMatters = "Inactive privileged accounts increase attack surface. They may have weak passwords, be forgotten during password rotations, or indicate compromised credentials."
        WhatWeCheck = @(
            "Privileged accounts with no recent logon activity (>180 days)"
            "Last logon timestamp for each account"
            "Group memberships of inactive accounts"
            "Orphaned admin accounts (AdminCount but no privileges)"
        )
        SecureMessage = "No inactive privileged accounts were found. All administrative accounts show recent activity, indicating proper account lifecycle management."
        PrimaryFindingId = 'INACTIVE_PRIVILEGED_ACCOUNT'
    }

    'gMSA' = @{
        TitleFormat = "gMSA: {Name}{Context}"
        Module = "Accounts"
        Category = "Accounts"
        SectionTitle = "Group Managed Service Accounts"
        Summary = "Reviews Group Managed Service Account configurations and security."
        WhyItMatters = "gMSAs provide automatic password management but require proper configuration. Excessive password retrieval permissions reduce security benefits and enable credential theft."
        WhatWeCheck = @(
            "gMSA accounts in the domain"
            "msDS-GroupMSAMembership (who can retrieve passwords)"
            "Whether password access follows least privilege"
            "Non-privileged principals with password access"
        )
        SecureMessage = "All gMSA password access is properly restricted to privileged accounts. No non-privileged principals can retrieve gMSA passwords."
        PrimaryFindingId = 'GMSA_PASSWORD_READABLE'
    }

    'gMSAPassword' = @{
        TitleFormat = "gMSA Password: {Name}"
        Module = "Accounts"
        Category = "Accounts"
        SectionTitle = "gMSA Password Access"
        Summary = "Reports gMSA passwords that the current user can retrieve."
        WhyItMatters = "gMSA password retrieval allows impersonation of the service account. Successfully retrieved passwords indicate the current user has access to these service accounts."
        WhatWeCheck = @(
            "gMSAs where current user can retrieve msDS-ManagedPassword"
            "NT hash extraction for Pass-the-Hash attacks"
            "Password rotation intervals"
        )
        PrimaryFindingId = 'GMSA_PASSWORD_READABLE'
    }

    'MSA' = @{
        TitleFormat = "MSA: {Name}"
        Module = "Accounts"
        Category = "Accounts"
        SectionTitle = "Standalone Managed Service Accounts"
        Summary = "Identifies standalone Managed Service Accounts (legacy sMSAs)."
        WhyItMatters = "Standalone MSAs are less secure than gMSAs - they're tied to a single host and don't support automatic password rotation across multiple servers. They should be migrated to gMSAs."
        WhatWeCheck = @(
            "Legacy sMSA accounts in the domain"
            "Recommendation to migrate to gMSAs"
        )
        SecureMessage = "No legacy standalone Managed Service Accounts (sMSAs) found. All service accounts use the more secure gMSA technology with automatic password rotation."
        PrimaryFindingId = 'STANDALONE_MSA_LEGACY'
    }

    'NonDefaultOwner' = @{
        TitleFormat = "Non-Default Owner: {Name}"
        Module = "Accounts"
        Category = "Accounts"
        SectionTitle = "Non-Default User Owners"
        Summary = "Identifies user objects with unexpected ownership."
        WhyItMatters = "Object owners have implicit full control over the object. Non-default user owners may indicate privilege escalation paths - the owner can reset passwords or modify attributes."
        WhatWeCheck = @(
            "Users where owner is not Domain Admins"
            "Users created via delegation (owner = delegated admin)"
            "Potential for privilege escalation via ownership"
        )
        SecureMessage = "All user objects have expected default owners (Domain Admins). No privilege escalation paths through unexpected object ownership were found."
        PrimaryFindingId = 'NON_DEFAULT_USER_OWNERS'
    }

    'Tier0Account' = @{
        TitleFormat = "Tier-0 Account: {Name}{Context}"
        Module = "Accounts"
        Category = "Accounts"
        SectionTitle = "Tier-0 Account Protection"
        Summary = "Evaluates Protected Users coverage for true Tier-0 accounts."
        WhyItMatters = "The Protected Users group provides critical protection against credential theft by disabling NTLM, disallowing delegation, and enforcing Kerberos constraints. Tier-0 accounts (Domain Admins, Enterprise Admins, Schema Admins, Administrators) should be protected."
        WhatWeCheck = @(
            "Members of Domain Admins, Enterprise Admins, Schema Admins, Administrators"
            "Which Tier-0 accounts are in Protected Users group"
            "Coverage percentage (protected / eligible accounts)"
            "Excludes krbtgt, DC$, and gMSA accounts (not applicable)"
        )
        SecureMessage = "All Tier-0 accounts are members of the Protected Users group. Credential theft via NTLM capture, delegation abuse, and ticket attacks is effectively mitigated for administrative accounts."
        PrimaryFindingId = 'PRIVILEGED_GROUP_MEMBERSHIP'
    }

    'PrivilegedGroupMember' = @{
        TitleFormat = "Privileged Group Member: {Name}"
        Module = "Accounts"
        Category = "Accounts"
        SectionTitle = "Privileged Group Members"
        Summary = "Enumerates members of administrative and privileged groups."
        WhyItMatters = "Privileged accounts are high-value targets. Understanding who has elevated access helps identify excessive privileges, orphaned accounts, and potential attack paths."
        WhatWeCheck = @(
            "Domain Admins, Enterprise Admins, Schema Admins"
            "Account Operators, Server Operators, Backup Operators"
            "Administrators and other built-in privileged groups"
            "Nested group memberships that grant privileges"
            "Service accounts with privileged access"
        )
        SecureMessage = "Privileged group membership follows least privilege principles. No excessive or unexpected memberships were found in high-value administrative groups."
        PrimaryFindingId = 'PRIVILEGED_GROUP_MEMBERSHIP'
    }

    'OperatorGroup' = @{
        TitleFormat = "Operator Group: {Name}"
        Module = "Accounts"
        Category = "Accounts"
        SectionTitle = "Operator Group Members"
        Summary = "Lists Operator groups with members that could benefit from Protected Users."
        WhyItMatters = "Operator groups (Account, Backup, Server, Print Operators) have elevated privileges. Members should consider Protected Users membership for additional credential protection."
        WhatWeCheck = @(
            "Operator groups with non-empty membership"
            "Current Protected Users coverage for these members"
        )
        SecureMessage = "All Operator groups are either empty or their members are protected via Protected Users group. Credential theft risk for operator-level accounts is minimized."
        PrimaryFindingId = 'OPERATOR_GROUP_MEMBERSHIP'
    }

    'SIDHistory' = @{
        TitleFormat = "SID History: {Name}{Context}"
        Module = "Accounts"
        Category = "Accounts"
        SectionTitle = "SID History Injection"
        Summary = "Detects accounts with SID History entries."
        WhyItMatters = "SID History grants access based on historical SIDs. Attackers can inject privileged SIDs for persistent access that's invisible in normal group membership queries. Legitimate SID History from migrations should be cleaned up."
        WhatWeCheck = @(
            "Accounts with SID History containing privileged SIDs"
            "Domain Admin, Enterprise Admin, and other high-value SIDs"
            "Non-privileged SID History entries (migration artifacts)"
            "Whether SID History is legitimate or suspicious"
        )
        SecureMessage = "No accounts with privileged SIDs in sIDHistory found. Hidden privilege escalation through SID History injection is not present in this environment."
        PrimaryFindingId = 'SID_HISTORY_INJECTION'
    }

    'AdminSDHolderACL' = @{
        TitleFormat = "AdminSDHolder ACL: {Name}"
        Module = "Accounts"
        Category = "Accounts"
        SectionTitle = "AdminSDHolder ACLs"
        Summary = "Analyzes ACLs on the AdminSDHolder container."
        WhyItMatters = "AdminSDHolder ACLs propagate to all protected objects (Domain Admins, etc.) hourly via SDProp. Unauthorized ACEs grant persistent backdoor access to privileged accounts that survives permission resets."
        WhatWeCheck = @(
            "Non-default ACEs on AdminSDHolder container"
            "Permissions that could allow privilege escalation"
            "Write permissions from non-admin principals"
            "ACEs that would propagate to protected groups"
        )
        SecureMessage = "The AdminSDHolder container has only default ACLs. No unauthorized permissions were found that could be used for privilege escalation or persistence."
    }

    'PreWindows2000Access' = @{
        TitleFormat = "Pre-Windows 2000 Compatible Access: {Name}"
        Module = "Accounts"
        Category = "Accounts"
        SectionTitle = "Pre-Windows 2000 Compatible Access"
        Summary = "Checks the Pre-Windows 2000 Compatible Access group membership."
        WhyItMatters = "This group grants read access to all users and groups. If 'Anonymous Logon' or 'Everyone' is a member, unauthenticated attackers can enumerate the entire domain without credentials."
        WhatWeCheck = @(
            "Group membership including Anonymous Logon"
            "Whether Everyone or Authenticated Users is a member"
            "Potential for unauthenticated enumeration"
        )
        SecureMessage = "The Pre-Windows 2000 Compatible Access group does not contain dangerous members like Anonymous Logon or Everyone. Unauthenticated domain enumeration is not possible through this group."
    }

    # ============================================================================
    # CREDENTIALS
    # ============================================================================

    'Kerberoastable' = @{
        TitleFormat = "Kerberoastable: {Name}"
        Module = "Creds"
        Category = "Credentials"
        SectionTitle = "Kerberoastable Accounts"
        Summary = "Identifies user accounts with Service Principal Names that can be Kerberoasted."
        WhyItMatters = "Any domain user can request service tickets for accounts with SPNs. These tickets are encrypted with the account's password hash and can be cracked offline to reveal the password."
        WhatWeCheck = @(
            "User accounts (not computers) with servicePrincipalName"
            "Whether these accounts have weak or old passwords"
            "Privilege level of Kerberoastable accounts"
            "Encryption types supported (RC4 is easier to crack)"
        )
        SecureMessage = "No user accounts with Service Principal Names found (excluding computer accounts and gMSAs). Kerberoasting attacks are not possible in this environment."
        PrimaryFindingId = 'KERBEROASTABLE_SPN'
    }

    'ASREPRoastable' = @{
        TitleFormat = "AS-REP Roastable: {Name}"
        Module = "Creds"
        Category = "Credentials"
        SectionTitle = "AS-REP Roastable Accounts"
        Summary = "Identifies accounts vulnerable to AS-REP Roasting attacks."
        WhyItMatters = "Accounts with pre-authentication disabled can have their password hashes obtained without any authentication. Anyone can request an AS-REP and crack the password offline."
        WhatWeCheck = @(
            "Accounts with DONT_REQUIRE_PREAUTH flag"
            "Whether this setting is intentional or misconfiguration"
            "Privilege level of vulnerable accounts"
        )
        SecureMessage = "No accounts with Kerberos pre-authentication disabled found. AS-REP Roasting attacks are not possible in this environment."
        PrimaryFindingId = 'ASREP_ROASTABLE'
    }

    'UnixPassword' = @{
        TitleFormat = "Unix Password: {Name}"
        Module = "Creds"
        Category = "Credentials"
        SectionTitle = "Unix Password Attributes"
        Summary = "Identifies accounts with Unix or legacy password attributes that may be readable."
        WhyItMatters = "Unix integration attributes like userPassword and sambaNTPassword may contain password hashes readable by non-privileged users, enabling offline cracking."
        WhatWeCheck = @(
            "Accounts with userPassword, unixUserPassword attributes"
            "Accounts with sambaNTPassword, sambaLMPassword"
            "Accounts with msSFU30Password"
            "Whether these attributes are readable"
        )
        SecureMessage = "No accounts with readable Unix password attributes found. Legacy password attributes that could expose credentials are not present in the domain."
        PrimaryFindingId = 'READABLE_UNIX_PASSWORD_ATTRIBUTES'
    }

    'GPPCredential' = @{
        TitleFormat = "GPP Credential: {Name}"
        Module = "Creds"
        Category = "Credentials"
        SectionTitle = "GPP Credential Exposure"
        Summary = "Discovers credentials stored in Group Policy Preference files."
        WhyItMatters = "GPP passwords are encrypted with a publicly known AES key (MS14-025). Any domain user can decrypt these passwords, providing immediate credential access without any exploitation."
        WhatWeCheck = @(
            "Groups.xml, ScheduledTasks.xml, and similar GPP files"
            "cpassword attributes and their decryption"
            "AutoAdminLogon credentials in Registry.xml"
        )
        SecureMessage = "No credentials were found in Group Policy Preference files. GPP password storage (cpassword) is not used in this domain."
    }

    'SYSVOLCredential' = @{
        TitleFormat = "SYSVOL Credential: {Name}"
        Module = "Creds"
        Category = "Credentials"
        SectionTitle = "SYSVOL Script Credential Exposure"
        Summary = "Discovers credentials stored in SYSVOL and NETLOGON scripts."
        WhyItMatters = "Login scripts, batch files, and configuration files in SYSVOL/NETLOGON are readable by all domain users. Administrators often embed credentials in these files, exposing them to any authenticated user."
        WhatWeCheck = @(
            "Login scripts with embedded credentials"
            "net use commands with passwords"
            "Configuration files with sensitive data"
        )
        SecureMessage = "No credentials or sensitive information were found in SYSVOL/NETLOGON scripts and configuration files."
    }

    'LAPSCredential' = @{
        TitleFormat = "LAPS Credential: {Name}"
        Module = "Creds"
        Category = "Credentials"
        SectionTitle = "LAPS Credential Access"
        Summary = "Tests which LAPS passwords the current user can read."
        WhyItMatters = "LAPS passwords provide local administrator access to computers. Unexpected read access indicates potential privilege escalation paths or misconfigured permissions."
        WhatWeCheck = @(
            "Computers where current user can read ms-Mcs-AdmPwd"
            "Computers where current user can read msLAPS-Password"
            "Scope of LAPS password access"
        )
        SecureMessage = "No readable LAPS passwords found. The current user does not have access to any local administrator passwords managed by LAPS, indicating proper access controls are in place."
        PrimaryFindingId = 'LAPS_PASSWORD_READABLE'
    }

    'PasswordInDescription' = @{
        TitleFormat = "Password in Description: {Name}"
        Module = "Creds"
        Category = "Credentials"
        SectionTitle = "Passwords in Description/Info"
        Summary = "Detects user and computer accounts with potential credentials in description or info attributes."
        WhyItMatters = "Administrators sometimes store passwords directly in the description or info attributes of AD objects. These attributes are readable by all authenticated domain users, exposing credentials to anyone with basic domain access."
        WhatWeCheck = @(
            "Description and info attributes of user accounts"
            "Description and info attributes of computer accounts"
            "High-confidence password assignments (e.g., password=value)"
            "Lower-confidence credential mentions for manual review"
        )
        SecureMessage = "No credentials were found in description or info attributes. Account descriptions do not contain exposed passwords or credential patterns."
        PrimaryFindingId = 'CREDENTIAL_IN_DESCRIPTION'
    }

    # ============================================================================
    # RIGHTS/ACLS
    # ============================================================================

    'DangerousACL' = @{
        TitleFormat = "Dangerous ACL: {Name}"
        Module = "Rights"
        Category = "Rights"
        SectionTitle = "Domain Root ACLs"
        Summary = "Reviews dangerous permissions on the domain root object."
        WhyItMatters = "Permissions on the domain root can grant DCSync rights, allow GPO linking, or enable domain-wide modifications. Non-default permissions here are critical findings."
        WhatWeCheck = @(
            "Principals with GenericAll, WriteDACL, WriteOwner"
            "Replicating Directory Changes permissions (DCSync)"
            "Write permissions on critical attributes"
        )
        FilteringNote = "High-privileged accounts (Domain Admins, Enterprise Admins, SYSTEM) are filtered from output as they are expected to have these rights."
        SecureMessage = "No dangerous ACLs detected on the domain root. Only expected privileged accounts have sensitive permissions like DCSync or write access."
        PrimaryFindingId = 'DANGEROUS_ACL_DCSYNC'
    }

    'DangerousOUPermission' = @{
        TitleFormat = "Dangerous OU Permission: {Name}"
        Module = "Rights"
        Category = "Rights"
        SectionTitle = "Dangerous OU Permissions"
        Summary = "Identifies dangerous permissions on Organizational Units."
        WhyItMatters = "OU permissions can be inherited by all objects within. Attackers with OU write access can modify user/computer objects, reset passwords, or enable delegation."
        WhatWeCheck = @(
            "Non-default permissions on OUs"
            "Principals with write access to OUs"
            "Permissions that could enable account takeover"
        )
        FilteringNote = "High-privileged accounts (Domain Admins, Enterprise Admins, SYSTEM) are filtered from output as they are expected to have these rights."
        SecureMessage = "No dangerous OU permissions detected. OU ACLs follow expected patterns with only privileged accounts having write access."
        PrimaryFindingId = 'OU_PERM_WRITEPROPERTY_ALL'
    }

    'PasswordResetRight' = @{
        TitleFormat = "Password Reset Right: {Name}"
        Module = "Rights"
        Category = "Rights"
        SectionTitle = "Password Reset Rights"
        Summary = "Maps who can reset passwords of privileged accounts."
        WhyItMatters = "Password reset rights enable account takeover without knowing the current password. These rights on privileged accounts create direct escalation paths."
        WhatWeCheck = @(
            "Reset Password permissions on OUs containing admins"
            "Principals who can reset privileged account passwords"
            "Whether these rights follow least privilege"
        )
        FilteringNote = "Only Critical/High severity findings are shown. High-privileged accounts with these rights are classified as expected and filtered from output."
        SecureMessage = "No dangerous password reset rights detected. Only expected privileged accounts can reset passwords for administrative users."
        PrimaryFindingId = 'OU_PERM_PASSWORD_RESET'
    }

    'AddComputerRight' = @{
        TitleFormat = "Add Computer Right: {Name}"
        Module = "Rights"
        Category = "Rights"
        SectionTitle = "Add Computer Rights"
        Summary = "Identifies who can join computers to the domain."
        WhyItMatters = "Machine accounts can be used in RBCD attacks and relay scenarios. Excessive rights to create computer accounts expand the attack surface."
        WhatWeCheck = @(
            "ms-DS-MachineAccountQuota setting"
            "SeMachineAccountPrivilege assignments via GPO"
            "Explicit create permissions on computer containers"
        )
        SecureMessage = "Computer creation is properly restricted. ms-DS-MachineAccountQuota is set to 0, preventing regular users from joining computers to the domain."
    }

    'MachineAccountQuota' = @{
        TitleFormat = "Machine Account Quota Configuration"
        Module = "Rights"
        Category = "Rights"
        SectionTitle = "Machine Account Quota"
        Summary = "Displays the ms-DS-MachineAccountQuota domain setting."
        WhyItMatters = "This setting controls how many computers any authenticated user can join to the domain. Default is 10, which allows RBCD attacks."
        WhatWeCheck = @(
            "Current quota value"
            "Whether it's the default (10) or has been modified"
        )
        SecureMessage = "ms-DS-MachineAccountQuota is set to 0. Only authorized accounts can join computers to the domain."
    }

    'AddComputerGPO' = @{
        TitleFormat = "GPO: {Name}"
        Module = "Rights"
        Category = "Rights"
        SectionTitle = "Add Computer GPO Settings"
        Summary = "Identifies GPOs granting SeMachineAccountPrivilege."
        WhyItMatters = "GPOs can grant the right to add computers to the domain, bypassing the quota setting."
        WhatWeCheck = @(
            "GPOs with SeMachineAccountPrivilege configured"
            "Which principals are granted this right"
        )
    }

    'LAPSPermission' = @{
        TitleFormat = "LAPS Permission: {Name}"
        Module = "Rights"
        Category = "Rights"
        SectionTitle = "LAPS Read Permissions"
        Summary = "Maps which principals can read LAPS passwords in each OU."
        WhyItMatters = "LAPS password read access should follow least privilege. Excessive access enables lateral movement for anyone who can read the passwords."
        WhatWeCheck = @(
            "ACLs granting LAPS password read access"
            "Principals with read access per OU"
            "Whether access follows tiered administration model"
        )
        FilteringNote = "Only Critical/High/Medium severity findings are shown. Domain Admins and Enterprise Admins with LAPS read access are filtered as expected."
        SecureMessage = "LAPS password read access is properly restricted. No non-privileged accounts have access to LAPS passwords, following the principle of least privilege."
        PrimaryFindingId = 'LAPS_PASSWORD_READ_ACCESS'
    }

    # ============================================================================
    # COMPUTERS
    # ============================================================================

    'OutdatedComputer' = @{
        TitleFormat = "Outdated Computer: {Name}"
        Module = "Computer"
        Category = "Computers"
        SectionTitle = "Outdated Operating Systems"
        Summary = "Finds computers running end-of-life operating systems."
        WhyItMatters = "EOL systems no longer receive security updates. They have known, unpatched vulnerabilities that attackers can exploit for initial access or lateral movement."
        WhatWeCheck = @(
            "Windows XP, Vista, 7, 8/8.1, Server 2003/2008/2012"
            "Last logon timestamp to filter active vs stale"
            "Operating system version details"
        )
        SecureMessage = "No active computers running end-of-life operating systems found. All systems are running supported operating systems that receive security updates."
        PrimaryFindingId = 'OUTDATED_OS'
    }

    'NonDefaultComputerOwner' = @{
        TitleFormat = "Non-Default Computer Owner: {Name}"
        Module = "Computer"
        Category = "Computers"
        SectionTitle = "Non-Default Computer Owners"
        Summary = "Identifies computer objects with unexpected ownership."
        WhyItMatters = "Object owners have implicit full control. Non-default computer owners may indicate privilege escalation paths or allow RBCD attacks."
        WhatWeCheck = @(
            "Computers where owner is not Domain Admins or SYSTEM"
            "Whether the owner could be compromised"
            "Potential for RBCD-based attacks"
        )
        SecureMessage = "All computer objects have expected default owners. No RBCD attack paths through unexpected object ownership were identified."
        PrimaryFindingId = 'NON_DEFAULT_COMPUTER_OWNERS'
    }

    'LAPSConfiguration' = @{
        TitleFormat = "LAPS Configuration: {Name}"
        Module = "Computer"
        Category = "Computers"
        SectionTitle = "LAPS Configuration"
        Summary = "Analyzes LAPS deployment and coverage across the domain."
        WhyItMatters = "Computers without LAPS likely share local admin passwords. Compromising one system enables lateral movement to all systems with the same password."
        WhatWeCheck = @(
            "Presence of LAPS schema attributes (Legacy and Windows LAPS)"
            "Computers with LAPS password attributes populated"
            "Computers missing LAPS protection"
            "Coverage percentage across the domain"
            "OUs with low LAPS adoption"
        )
        SecureMessage = "LAPS is properly deployed with high coverage across the domain. Local administrator passwords are unique per computer, preventing lateral movement through password reuse."
    }

    # ============================================================================
    # GPO
    # ============================================================================

    'GPOPermission' = @{
        TitleFormat = "GPO Permission: {Name}"
        Module = "GPO"
        Category = "GPO"
        SectionTitle = "GPO Permissions"
        Summary = "Identifies Group Policy Objects with risky permissions."
        WhyItMatters = "GPO modification rights enable code execution on all computers where the GPO is applied. Attackers can deploy malware, create scheduled tasks, or modify security settings."
        WhatWeCheck = @(
            "GPOs with write permissions for non-admins"
            "Which computers/users are affected by each GPO"
            "Potential impact of GPO modification"
        )
        SecureMessage = "No dangerous GPO permissions found. Only privileged accounts have write access to Group Policy Objects."
        PrimaryFindingId = 'GPO_DANGEROUS_PERMISSIONS'
    }

    'GPOLocalGroup' = @{
        TitleFormat = "GPO Local Group: {Name}"
        Module = "GPO"
        Category = "GPO"
        SectionTitle = "GPO Local Group Assignments"
        Summary = "Reviews GPO-based local group membership configurations."
        WhyItMatters = "GPOs can add principals to local Administrators groups on target systems. This is legitimate for administration but dangerous if misconfigured or overly broad."
        WhatWeCheck = @(
            "Restricted Groups settings adding local admins"
            "Group Policy Preferences modifying local groups"
            "Scope of these configurations"
        )
        SecureMessage = "No vulnerable GPO local group assignments found. Local administrator configurations through GPO are properly scoped and controlled."
    }

    'GPOScheduledTask' = @{
        TitleFormat = "GPO Scheduled Task: {Name}"
        Module = "GPO"
        Category = "GPO"
        SectionTitle = "GPO Scheduled Tasks"
        Summary = "Analyzes scheduled tasks deployed via Group Policy."
        WhyItMatters = "GPO scheduled tasks run with specified privileges on target systems. Tasks running as SYSTEM from writable paths or UNC shares enable privilege escalation."
        WhatWeCheck = @(
            "Scheduled tasks in GPO configurations"
            "Execution context (SYSTEM, user, etc.)"
            "Executable paths and whether they're writable"
            "UNC paths that could enable relay attacks"
        )
        SecureMessage = "No vulnerable GPO scheduled tasks found. All scheduled tasks use secure local paths and do not expose systems to privilege escalation through writable paths or UNC relay attacks."
    }

    'GPOScriptPath' = @{
        TitleFormat = "GPO Script: {Name}"
        Module = "GPO"
        Category = "GPO"
        SectionTitle = "GPO Script Paths"
        Summary = "Detects Logon/Logoff/Startup/Shutdown scripts deployed via Group Policy."
        WhyItMatters = "GPO scripts execute automatically on target systems. Startup and Shutdown scripts run as SYSTEM, making them high-value targets for privilege escalation. Scripts loaded from UNC paths expose machine credentials on the network."
        WhatWeCheck = @(
            "Startup/Shutdown scripts (run as SYSTEM)"
            "Logon/Logoff scripts (run as user)"
            "UNC paths (credential exposure risk)"
            "PowerShell scripts via psscripts.ini"
        )
        SecureMessage = "No scripts distributed via GPO. No Logon/Logoff/Startup/Shutdown scripts were found in Group Policy configurations."
    }

    # ============================================================================
    # BLOODHOUND COLLECTOR
    # ============================================================================

    'BloodHoundCollector' = @{
        TitleFormat = "BloodHound Collection: {Name}"
        Module = "Bloodhound"
        Category = "BloodHound"
        SectionTitle = "BloodHound Data Collection"
        Summary = "Collects AD data in BloodHound Community Edition format using adPEAS native collector."
        WhyItMatters = "BloodHound enables graph-based attack path analysis. The collected data helps identify privilege escalation paths, ACL abuses, and delegation attacks that might be missed by individual checks."
        WhatWeCheck = @(
            "Users, Groups, Computers, OUs, GPOs, Containers"
            "Group memberships and nested membership chains"
            "ACLs and dangerous permissions (GenericAll, WriteDACL, etc.)"
            "Kerberos delegation configurations (Unconstrained, Constrained, RBCD)"
            "DCOnly mode: No session collection, pure LDAP queries"
        )
        FilteringNote = "adPEAS uses its own native collector (no SharpHound dependency). Collection mode is DCOnly - all data is retrieved via LDAP without requiring local admin access or session enumeration. Output is BloodHound CE v6 JSON format."
    }

    # ============================================================================
    # LDAP STATISTICS
    # ============================================================================

    'LDAPStatisticsModule' = @{
        TitleFormat = "Module: {Name}"
        Module = "Statistics"
        Category = "Statistics"
        SectionTitle = "LDAP Statistics"
        Summary = "LDAP query statistics per module."
        WhyItMatters = "Shows the LDAP query load per module to identify expensive operations and estimate network traffic."
        WhatWeCheck = @(
            "Number of LDAP queries sent"
            "Number of result entries received"
            "Estimated network traffic volume"
        )
    }

    'LDAPStatisticsTotal' = @{
        TitleFormat = "Total"
        Module = "Statistics"
        Category = "Statistics"
        SectionTitle = "LDAP Statistics"
        Summary = "Total LDAP query statistics across all modules."
        WhyItMatters = "Provides a complete picture of the scan's LDAP footprint."
        WhatWeCheck = @(
            "Aggregated LDAP query count and result count"
            "Total estimated network traffic"
        )
    }
}

<#
.SYNOPSIS
    Gets the display title for an AD object based on its ObjectType.

.DESCRIPTION
    Central function for generating object card titles in HTML reports.
    Replaces the switch statement in Export-HTMLReport.ps1 with data-driven approach.

.PARAMETER Object
    The AD object with _adPEASObjectType property.

.OUTPUTS
    String - The formatted title for display.

.EXAMPLE
    $title = Get-ObjectTypeTitle -Object $adObject
#>
function Get-ObjectTypeTitle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Object
    )

    # Get the ObjectType from the object
    $objectType = $Object._adPEASObjectType

    # Get object name (try various properties)
    # Note: displayName comes before Name because GPOs have Name=GUID but displayName=readable name
    # gpoName is used by custom GPO objects (e.g., AddComputerGPO from Get-AddComputerRights)
    $objName = $Object.sAMAccountName
    if (-not $objName) { $objName = $Object.gpoName }
    if (-not $objName) { $objName = $Object.ouName }
    if (-not $objName) { $objName = $Object.displayName }
    if (-not $objName) { $objName = $Object.Name }
    if (-not $objName) {
        # Try to extract from DN
        if ($Object.distinguishedName -match '^CN=([^,]+)') {
            $objName = $Matches[1]
        }
    }
    if (-not $objName) { $objName = "Unknown" }

    # Get context if available
    $context = $Object._adPEASContext
    $contextStr = if ($context) { " ($context)" } else { "" }

    # If no ObjectType defined, return just the name
    if (-not $objectType) {
        return $objName
    }

    # Look up definition
    $definition = $Script:ObjectTypeDefinitions[$objectType]

    if (-not $definition) {
        # Unknown ObjectType - return with warning indicator
        Write-Verbose "[Get-ObjectTypeTitle] Unknown ObjectType: $objectType"
        # Generate title from PascalCase (fallback)
        $autoTitle = $objectType -creplace '([a-z])([A-Z])', '$1 $2'
        return "${autoTitle}: $objName"
    }

    # Format the title using the template
    $title = $definition.TitleFormat

    # Replace placeholders
    $title = $title -replace '\{Name\}', $objName
    $title = $title -replace '\{Context\}', $contextStr

    # Handle {DisplayName} placeholder - prefers displayName over sAMAccountName
    if ($title -match '\{DisplayName\}') {
        $displayName = if ($Object.displayName) { $Object.displayName } else { $objName }
        $title = $title -replace '\{DisplayName\}', $displayName
    }

    # Handle DN placeholder if present
    if ($title -match '\{DN\}' -and $Object.distinguishedName) {
        # Extract OU path from DN
        $dn = $Object.distinguishedName
        if ($dn -match ',(.+)$') {
            $ouPath = $Matches[1]
            $title = $title -replace '\{DN\}', $ouPath
        } else {
            $title = $title -replace '\{DN\}', ''
        }
    }

    return $title
}


<#
.SYNOPSIS
    Validates that all ObjectTypes used in source files are defined.

.DESCRIPTION
    Build-time validation function that scans source files for _adPEASObjectType
    assignments and verifies each one exists in $Script:ObjectTypeDefinitions.

.PARAMETER SourcePath
    Path to the source directory to scan.

.OUTPUTS
    PSCustomObject with validation results.

.EXAMPLE
    $result = Test-ObjectTypeDefinitions -SourcePath ".\src\modules\Checks"
    if (-not $result.Valid) { throw "ObjectType validation failed" }
#>
function Test-ObjectTypeDefinitions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourcePath
    )

    $results = @{
        Valid = $true
        DefinedTypes = @($Script:ObjectTypeDefinitions.Keys)
        UsedTypes = @()
        UndefinedTypes = @()
        UnusedTypes = @()
        Details = @()
    }

    # Scan all PS1 files for ObjectType assignments
    $files = Get-ChildItem -Path $SourcePath -Filter "*.ps1" -Recurse -ErrorAction SilentlyContinue

    foreach ($file in $files) {
        $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $content) { continue }

        # Find all _adPEASObjectType assignments
        $regexMatches = [regex]::Matches($content, "'_adPEASObjectType'\s*-NotePropertyValue\s+'([^']+)'")

        foreach ($match in $regexMatches) {
            $objectType = $match.Groups[1].Value

            if ($objectType -notin $results.UsedTypes) {
                $results.UsedTypes += $objectType
            }

            if (-not $Script:ObjectTypeDefinitions.Contains($objectType)) {
                $results.Valid = $false
                if ($objectType -notin $results.UndefinedTypes) {
                    $results.UndefinedTypes += $objectType
                    $results.Details += [PSCustomObject]@{
                        Type = "Undefined"
                        ObjectType = $objectType
                        File = $file.Name
                        Line = ($content.Substring(0, $match.Index) -split "`n").Count
                    }
                }
            }
        }
    }

    # Find unused definitions
    foreach ($definedType in $results.DefinedTypes) {
        if ($definedType -notin $results.UsedTypes) {
            $results.UnusedTypes += $definedType
        }
    }

    return [PSCustomObject]$results
}


<#
.SYNOPSIS
    Gets the list of all defined ObjectTypes.

.DESCRIPTION
    Returns all ObjectType keys defined in $Script:ObjectTypeDefinitions.
    Useful for documentation and validation.

.OUTPUTS
    String[] - Array of ObjectType names.
#>
function Get-DefinedObjectTypes {
    return @($Script:ObjectTypeDefinitions.Keys | Sort-Object)
}


<#
.SYNOPSIS
    Gets the category for an ObjectType.

.DESCRIPTION
    Returns the category associated with an ObjectType, or "Unknown" if not defined.

.PARAMETER ObjectType
    The ObjectType to look up.

.OUTPUTS
    String - The category name.
#>
function Get-ObjectTypeCategory {
    param([string]$ObjectType)

    $definition = $Script:ObjectTypeDefinitions[$ObjectType]
    if ($definition -and $definition.Category) {
        return $definition.Category
    }
    return "Unknown"
}


<#
.SYNOPSIS
    Gets the check description for a specific ObjectType.

.DESCRIPTION
    Returns the full definition hashtable for an ObjectType including
    SectionTitle, Summary, WhyItMatters, WhatWeCheck, and optional fields.

.PARAMETER ObjectType
    The _adPEASObjectType value.

.OUTPUTS
    Hashtable with check description or $null if not found.

.EXAMPLE
    $desc = Get-CheckDescription -ObjectType 'Kerberoastable'
#>
function Get-CheckDescription {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ObjectType
    )

    if ($Script:ObjectTypeDefinitions.Contains($ObjectType)) {
        return $Script:ObjectTypeDefinitions[$ObjectType]
    }
    return $null
}


<#
.SYNOPSIS
    Gets all available ObjectTypes with descriptions.

.DESCRIPTION
    Returns all ObjectType keys defined in $Script:ObjectTypeDefinitions.

.OUTPUTS
    Array of ObjectType strings.

.EXAMPLE
    $types = Get-CheckObjectTypes
#>
function Get-CheckObjectTypes {
    [CmdletBinding()]
    param()

    return $Script:ObjectTypeDefinitions.Keys | Sort-Object
}


<#
.SYNOPSIS
    Exports check descriptions as JSON for embedding in HTML.

.DESCRIPTION
    Converts all ObjectType definitions to a JSON format suitable for
    embedding in HTML reports for JavaScript-based tooltip display.

.PARAMETER Minified
    If set, outputs minified JSON without indentation.

.OUTPUTS
    JSON string of all check descriptions keyed by ObjectType.

.EXAMPLE
    $json = Export-CheckDescriptionsJson -Minified
#>
function Export-CheckDescriptionsJson {
    [CmdletBinding()]
    param(
        [switch]$Minified
    )

    # Convert hashtable to format suitable for JSON
    $jsonObject = @{}

    foreach ($key in $Script:ObjectTypeDefinitions.Keys) {
        $desc = $Script:ObjectTypeDefinitions[$key]

        $jsonObject[$key] = @{
            title = $desc.SectionTitle
            summary = $desc.Summary
            whyItMatters = $desc.WhyItMatters
            whatWeCheck = $desc.WhatWeCheck
        }

        # Include FilteringNote only when privilege filtering is active (not -IncludePrivileged)
        # When -IncludePrivileged is used, privileged accounts ARE shown, so the note is misleading
        if ($desc.FilteringNote -and -not $Script:IncludePrivilegedMode) {
            $jsonObject[$key].filteringNote = $desc.FilteringNote
        }

        # Include SecureMessage if present (explains why secure finding is good)
        if ($desc.SecureMessage) {
            $jsonObject[$key].secureMessage = $desc.SecureMessage
        }

        # Include PrimaryFindingId if present (overrides automatic findingId detection in Top Priority Actions)
        if ($desc.PrimaryFindingId) {
            $jsonObject[$key].primaryFindingId = $desc.PrimaryFindingId
        }
    }

    if ($Minified) {
        return ($jsonObject | ConvertTo-Json -Depth 10 -Compress)
    } else {
        return ($jsonObject | ConvertTo-Json -Depth 10)
    }
}


