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
            "Anonymous LDAP access: 'Refused' means an anonymous bind was attempted in this session and could not read the domain object. 'Not tested' names why in brackets: LDAPS and global catalog sessions skip the test, and a bind that got no answer from the server or failed before one is no verdict either way - the log has the error"
            "What a deletion leaves behind: with the Recycle Bin, a deleted object stays restorable with all its attributes for the deleted-object lifetime, then remains as a stripped recycled object for the tombstone lifetime before it is removed for good. The tombstone lifetime also bounds the age of a backup that can still be restored. An unset deleted-object lifetime takes the tombstone lifetime"
            "Without the Recycle Bin a deleted object keeps only a few attributes and cannot be restored with its group memberships; the Recycle Bin needs forest functional level Windows Server 2008 R2"
            "Which service replicates SYSVOL: FRS is deprecated, and no domain controller from Windows Server 1709 on can be added while it still replicates SYSVOL. 'FRS and DFSR' is a migration that has not reached Eliminated, shown with its global state"
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
            "Service ticket lifetime (600 minutes) and the tolerated clock skew (5 minutes)"
            "Read from the [Kerberos Policy] section of the domain-linked GPOs: '(default)' is the Windows default value, '(not set)' means no domain-linked GPO sets it, and a value off the default names the GPO that sets it"
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
        SectionTitle = "Domain Controllers and FSMO Roles"
        Summary = "Lists the Domain Controllers of the domain and the FSMO roles each of them holds."
        WhyItMatters = "Domain Controllers are Tier-0 assets containing all domain secrets. Understanding the DC infrastructure helps identify critical assets requiring maximum protection."
        WhatWeCheck = @(
            "All computers with the DC role"
            "Which Domain Controller holds each of the five FSMO roles"
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
            "Without Domain Admin rights: by default only Domain Admins may read a PSO, so it is found by assignment - through msDS-PSOApplied on the users and groups it applies to, and msDS-ResultantPSO of the scanning account (inEffectForThisAccount: the PSO that wins for it). That gives the name and the direct targets, not the settings or the precedence"
            "Not visible that way: a PSO assigned to nobody, and an assignment on a user or group this account may not read - msDS-PSOApplied needs Read all properties, which Pre-Windows 2000 Compatible Access holds on users and groups"
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
            "SID filtering, per trust (sidFiltering): whether SID history from the partner is filtered here. 'Not applied - within the forest' means it is honoured - a forest is one security boundary, and whoever controls one of its domains can reach the others. On a trust this domain does not extend, the exposure is the partner's"
            "Selective authentication settings"
            "Trust transitivity"
            "The Kerberos encryption types allowed across the trust (msDS-SupportedEncryptionTypes on the trust object). 'Not set' means RC4 and no AES. The USES_RC4_ENCRYPTION bit in trustAttributes is defined for a realm trust to MIT Kerberos only; on any other trust it says nothing about the key"
            "The domain SID of the partner, and on an inbound trust when the password of its interdomain trust account was last changed"
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

    # The two null session settings, read in the same SYSVOL scan as LDAP signing and
    # reported in a section of their own: they are SMB and RPC controls, not LDAP.
    'NullSessionGPO' = @{
        TitleFormat = "Null Session GPO: {Name}"
        Module = "Domain"
        Category = "Domain"
        SectionTitle = "Null Session Configuration"
        Summary = "Checks which GPOs set the null session controls for anonymous SAM enumeration and anonymous SID/name translation."
        WhyItMatters = "A null session is an anonymous connection over SMB. Where anonymous enumeration of SAM accounts and shares is allowed, it lists the accounts and shares of the machine; where anonymous SID/name translation is allowed, it turns SIDs into account names and back. On a domain controller that is the account list of the domain, without a password."
        WhatWeCheck = @(
            "anonymousSamEnumeration - RestrictAnonymous, 'Network access: Do not allow anonymous enumeration of SAM accounts and shares': Allowed at 0"
            "anonymousSidNameTranslation - LSAAnonymousNameLookup, 'Network access: Allow anonymous SID/Name translation': Allowed at 1"
            "Which policy reaches the domain controllers, and which value is in force there"
            "Not tested: anonymous LDAP, which is decided by dsHeuristics in its own section"
        )
        SecureMessage = "The policies in force on the domain controllers restrict anonymous SAM enumeration and anonymous SID/name translation."
    }

    # dsHeuristics, read by Get-LDAPConfiguration in a section of its own ahead of the GPO
    # rows: one forest-wide string, and no GPO governs any of its characters.
    'DSHeuristics' = @{
        TitleFormat = "Directory Service Heuristics"
        Module = "Domain"
        Category = "Domain"
        SectionTitle = "Directory Service Heuristics"
        Summary = "Reads the characters of dsHeuristics that switch a protection off for the whole forest."
        WhyItMatters = "dsHeuristics is one string on CN=Directory Service in the configuration partition, and each of its characters changes how every domain controller of the forest behaves. Four of them switch a protection off: anonymous LDAP operations, anonymous calls to the NSPI address book, AdminSDHolder protection of the operator groups, and the uniqueness checks on UPN and SPN values. None of them is on by default, and no GPO governs them."
        WhatWeCheck = @(
            "anonymousLDAPAccess - character 7 (fLDAPBlockAnonOps): anonymous LDAP operations beyond rootDSE, allowed at 2"
            "anonymousNSPIAccess - character 8 (fAllowAnonNSPI): anonymous calls to the NSPI address book interface, allowed at anything but 0"
            "adminSDHolderExclusion - character 16 (dwAdminSDExMask): operator groups excluded from AdminSDHolder protection, one bit each"
            "principalNameUniqueness - character 21 (DoNotVerifyUPNAndOrSPNUniqueness): UPN and SPN uniqueness checks switched off, one bit each"
            "dSHeuristics 'Not set' is the default, in which every one of them is at its secure value"
        )
        SecureMessage = "dsHeuristics leaves every protection it governs in place: anonymous LDAP and NSPI access are blocked, AdminSDHolder protects every operator group, and the domain controllers check UPN and SPN values for uniqueness."
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
            "A server-side value the policy leaves unset, read against where it is linked: on the Domain Controllers OU the Default Domain Controllers Policy requires signing (DC default: required); elsewhere a server before Windows Server 2025 enables signing without requiring it"
        )
        SecureMessage = "SMB signing is required on both servers and clients via GPO. NTLM relay attacks targeting SMB file shares are blocked, preventing unauthorized access and lateral movement."
    }

    # What is in force on the domain controllers, value by value, decided per setting by
    # GPO precedence - shown under the GPO rows of the two signing checks above.
    'EffectiveLDAPConfig' = @{
        TitleFormat = "In force on the domain controllers"
        Module = "Domain"
        Category = "Domain"
        SectionTitle = "LDAP Signing Configuration"
        Summary = "The LDAP security values in force on the domain controllers, each taken from the highest-ranked policy that sets it."
        WhyItMatters = "Group Policy precedence is per setting: a policy that leaves a value unset does not override another policy's value for it. What the domain controllers enforce is therefore assembled from several policies, and reading one policy alone gives the wrong answer."
        WhatWeCheck = @(
            "Every policy linked to the Domain Controllers OU or the domain root"
            "For each value, the highest-ranked policy that sets it - enforced links first, then the Domain Controllers OU, then the domain root, then link order"
            "decidedBy lists each policy with the values it decides in brackets"
            "Not tested: the registry of the domain controllers. The values are read from the policies, and a value a policy wrote can stay on a domain controller after the policy stops applying (tattooing) - the registry is the ground truth"
        )
        SecureMessage = "The policies in force on the domain controllers require LDAP signing and channel binding."
    }

    'EffectiveNullSession' = @{
        TitleFormat = "In force on the domain controllers"
        Module = "Domain"
        Category = "Domain"
        SectionTitle = "Null Session Configuration"
        Summary = "The two null session values in force on the domain controllers, each taken from the highest-ranked policy that sets it."
        WhyItMatters = "Group Policy precedence is per setting: a policy that leaves a value unset does not override another policy's value for it. What the domain controllers enforce is therefore assembled from several policies, and reading one policy alone gives the wrong answer."
        WhatWeCheck = @(
            "Every policy linked to the Domain Controllers OU or the domain root"
            "For each value, the highest-ranked policy that sets it - enforced links first, then the Domain Controllers OU, then the domain root, then link order"
            "decidedBy lists each policy with the values it decides in brackets"
            "Not Configured: no policy that reaches the domain controllers sets the value, and they keep the OS default"
            "Not tested: the registry of the domain controllers. The values are read from the policies, and a value a policy wrote can stay on a domain controller after the policy stops applying (tattooing) - the registry is the ground truth"
        )
        SecureMessage = "The policies in force on the domain controllers restrict anonymous SAM enumeration and anonymous SID/name translation."
    }

    'EffectiveSMBSigning' = @{
        TitleFormat = "In force on the domain controllers"
        Module = "Domain"
        Category = "Domain"
        SectionTitle = "SMB Signing Configuration"
        Summary = "The SMB signing values in force on the domain controllers, each taken from the highest-ranked policy that sets it."
        WhyItMatters = "Group Policy precedence is per setting: a policy that leaves a value unset does not override another policy's value for it. What the domain controllers enforce is therefore assembled from several policies, and reading one policy alone gives the wrong answer."
        WhatWeCheck = @(
            "Every policy linked to the Domain Controllers OU or the domain root"
            "For each value, the highest-ranked policy that sets it - enforced links first, then the Domain Controllers OU, then the domain root, then link order"
            "decidedBy lists each policy with the values it decides in brackets"
            "Not tested: the registry of the domain controllers. The values are read from the policies, and a value a policy wrote can stay on a domain controller after the policy stops applying (tattooing) - the registry is the ground truth"
        )
        SecureMessage = "The policies in force on the domain controllers require SMB signing on both the server and the client side."
    }

    # The member computers' side, shown when every policy that sets SMB signing is linked
    # to the Domain Controllers OU only - so no policy reaches a member server or client.
    'EffectiveSMBSigningMembers' = @{
        TitleFormat = "In force on member servers and clients"
        Module = "Domain"
        Category = "Domain"
        SectionTitle = "SMB Signing Configuration"
        Summary = "The SMB signing values in force on member servers and clients when every signing policy is linked to the Domain Controllers OU only."
        WhyItMatters = "A policy that requires signing on the domain controllers protects connections to the domain controllers. Member servers and clients then sign as their Windows version does by default: before Windows Server 2025 a server enables signing without requiring it, which is the state an SMB relay needs."
        WhatWeCheck = @(
            "Whether any linked and enabled policy outside the Domain Controllers OU sets SMB signing"
            "The Windows default the members fall back to, server side and client side"
            "Not tested: the computers themselves - a value set locally or left behind by a former policy is not visible here, and Windows 11 24H2 and Windows Server 2025 require signing by default"
        )
        SecureMessage = "A policy that reaches member servers and clients sets SMB signing for them."
    }

    # A linked and enabled policy that weakens SMB signing, shown below the postures with
    # the OUs it reaches.
    'SMBSigningWeakened' = @{
        TitleFormat = "SMB Signing Weakened: {Name}"
        Module = "Domain"
        Category = "Domain"
        SectionTitle = "SMB Signing Configuration"
        Summary = "A linked and enabled policy that sets SMB server signing to Disabled or Optional, or client signing to Disabled."
        WhyItMatters = "A policy linked to an OU applies to the computers in it ahead of a domain-wide policy, unless the domain-wide link is enforced. Server signing that is not required on those computers lets an attacker relay an NTLM authentication to their SMB service - whatever the domain-wide policy and the domain controllers require."
        WhatWeCheck = @(
            "ServerSigning: Disabled or Optional - the server does not require signing"
            "ClientSigning: Disabled - the client does not sign"
            "LinkedOUs: where the policy is linked, and so which computers it reaches"
            "Not tested: whether an enforced domain-wide link overrides the policy on those OUs, and the computers themselves - a value set locally is not visible here"
        )
        SecureMessage = "No linked and enabled policy weakens SMB signing."
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
            "Computers whose primary group is Domain Controllers without the role flag"
            "Whether each of them is registered as a Domain Controller - an NTDS Settings object under CN=Sites in the configuration partition, which a promotion creates and the role flag alone does not"
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
        Summary = "Identifies Microsoft Exchange servers from the Configuration partition."
        WhyItMatters = "Exchange servers have significant AD privileges and are high-value targets. The build number decides whether the server still receives security updates, and ProxyLogon and ProxyShell show what an unpatched one is worth."
        WhatWeCheck = @(
            "msExchExchangeServer objects under CN=Services in the Configuration partition, which is Exchange's own record of its servers"
            "The build carried in serialNumber"
            "The exchangeAB/, exchangeRFR/ and exchangeMDB/ SPNs as a fallback, with domain controllers excluded - every DC registers them for Autodiscover"
        )
    }

    'ExchangeOrganization' = @{
        TitleFormat = "Exchange Organization: {Name}"
        Module = "Application"
        Category = "Infrastructure"
        SectionTitle = "Exchange Organization"
        Summary = "Exchange Organization overview from the Configuration partition (forest-wide)."
        WhyItMatters = "The Configuration partition is replicated to every domain controller of the forest, so the Exchange organization can be read from any of its domains, a child domain included - as far as the account may read it. Measured against Exchange SE, a domain user sees the organization and its servers, but not its accepted domains, connectors or virtual directories."
        WhatWeCheck = @(
            "Exchange Organization name"
            "Accepted mail domains and SMTP send connectors"
            "Number of Exchange servers across the forest"
            "Whether this account can read the organization's configuration at all, and which parts of it came back empty because it cannot"
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

    'ExchangeHybridConfiguration' = @{
        TitleFormat = "Exchange Hybrid: {Name}"
        Module = "Application"
        Category = "Exchange"
        SectionTitle = "Exchange Hybrid Deployment"
        Summary = "Detects whether the Exchange organization is in a hybrid relationship with Exchange Online."
        WhyItMatters = "A hybrid organization shares one service principal between the on-premises servers and the cloud tenant, and that shared trust is an escalation path: administrative access to an on-premises Exchange server reaches Exchange Online through it, without the trace a cloud-side administrative action would leave. It also changes what an on-premises Exchange finding is worth - the blast radius of every other Exchange issue in this report now includes the tenant. Whether the dedicated hybrid application has been deployed cannot be read from Active Directory, so what is reported is the exposure, not the patch state."
        WhatWeCheck = @(
            "msExchCoexistenceRelationship objects in the Configuration partition, which the Hybrid Configuration Wizard creates"
            "Coexistence domains, transport servers and external addresses where present"
        )
        # Not checked, deliberately: the account named Exchange Online-ApplicationAccount.
        # Exchange setup creates it on every /PrepareAD in every organization, so it says
        # nothing about hybrid despite the name.
        SecureMessage = "No hybrid configuration was found - the organization appears to be purely on-premises."
    }

    'ExchangeReceiveConnector' = @{
        TitleFormat = "Receive Connector: {Name}"
        Module = "Application"
        Category = "Exchange"
        SectionTitle = "Exchange SMTP Receive Connectors"
        Summary = "Judges each SMTP receive connector by the rights its security descriptor grants to unauthenticated senders."
        WhyItMatters = "A receive connector's own DACL decides what an SMTP session that presented no credential may do. Granting ms-Exch-SMTP-Accept-Any-Recipient to ANONYMOUS LOGON makes the server relay to any domain; granting the accept-sender rights lets an anonymous sender put an internal address in the From header, which is a phishing campaign that passes SPF, DKIM and every mail-client trust indicator at once. Both are ordinary application-relay configurations that were scoped too widely, and both are invisible from the connector's name."
        WhatWeCheck = @(
            "ms-Exch-SMTP-* extended rights granted to Anonymous Logon and Everyone"
            "The same rights granted to broad principals such as Authenticated Users"
            "Connector bindings and the remote IP ranges the grants apply from"
        )
        SecureMessage = "No receive connector grants relay or sender-spoofing rights to unauthenticated senders."
    }

    'ExchangePermissionsModel' = @{
        TitleFormat = "Exchange Permissions Model: {Name}"
        Module = "Application"
        Category = "Exchange"
        SectionTitle = "Exchange Permissions Model"
        Summary = "Reports whether an Exchange group holds WriteDACL on the domain object - the escalation half of PrivExchange."
        WhyItMatters = "WriteDACL on the domain object means being able to rewrite the domain's own access control list - and an entry granting DS-Replication-Get-Changes and -All is DCSync, every password hash in the domain. In the shared permissions model Exchange setup grants that right to an Exchange group, which is what makes the group's membership worth anything to an attacker. The ACE is not immovable: Microsoft documents narrowing it with the inherit-only flag so it no longer applies to the domain object, and preparing the forest with /ActiveDirectorySplitPermissions removes the Exchange Windows Permissions entries from it entirely. The generic ACL check classifies every Exchange group as an expected trustee and hides it unless -IncludePrivileged is set, on the grounds that Exchange permissions are by design - for this one entry that is not true, which is why the distinction is made here instead. Read the two ACE rows together: the effective one is what the verdict rests on, and the inherit-only ones are listed so a reader can see that the same group's other grants stop at child objects rather than reaching the domain."
        WhatWeCheck = @(
            "WriteDACL, WriteOwner and GenericAll entries on the domain object held by Exchange groups"
            "Which of them apply to the domain object itself, and which are inherit-only and only reach child objects of a named class"
            "Whether the forest was prepared with AD split permissions, which the Microsoft Exchange Protected Groups OU records"
        )
        SecureMessage = "No Exchange group holds effective escalation rights on the domain object."
    }

    'ExchangeRoleAssignment' = @{
        TitleFormat = "Exchange Role Assignment: {Name}"
        Module = "Application"
        Category = "Exchange"
        SectionTitle = "Exchange Management Role Assignments"
        Summary = "Reports who holds the Exchange roles that reach mailbox content or allow self-escalation inside Exchange."
        WhyItMatters = "Exchange RBAC assignments live in the Configuration partition and any domain user can read them. Checking the Organization Management group is not enough, because a role can be assigned directly to one user and that assignment appears in no group membership at all. ApplicationImpersonation lets its holder act as every mailbox in the organization over EWS; Mailbox Import Export exports any mailbox to a file; Role Management lets its holder assign itself the other two. Exchange ships some of these assigned to a role group and others assigned to nobody, so an assignment that is not the shipped one was made deliberately."
        WhatWeCheck = @(
            "msExchRoleAssignment objects linking a role to a principal"
            "Mailbox Import Export, ApplicationImpersonation, Role Management, Unscoped Role Management, Mailbox Search, Active Directory Permissions"
            "Whether the assignee is the role group Exchange ships the role on, a custom group, a single user, or a role assignment policy"
        )
        SecureMessage = "None of the high-value Exchange roles is assigned outside the role groups Exchange ships them on."
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
            "Domain accounts the instances run under, and whether any of them is privileged in the domain"
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
        SecureMessage = "No principal outside the site servers and management points can write to the System Management container. Credentials are not part of this statement: network access accounts live in the Configuration Manager database and in client policies, not in Active Directory, so nothing here can say whether any are exposed."
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
            "Their direct members, by name"
            "Whether a broad group - Domain Users, Domain Computers, Authenticated Users, Everyone - is among them"
            "Not tested: what the group grants inside SCCM, which the site database records, not Active Directory"
        )
    }

    'SCCMContainerPermission' = @{
        TitleFormat = "System Management Container Write Access: {Name}"
        Module = "Application"
        Category = "Infrastructure"
        SectionTitle = "System Management Container Permissions"
        Summary = "Identifies principals that can write to the container Configuration Manager publishes its management points in."
        WhyItMatters = "A client configured for Active Directory site discovery takes its management point from CN=System Management. Whoever can write there can publish one of their own, and every client that picks it up takes its policy - and its software - from a server the attacker controls. The container is created by hand before setup runs, which is where the extra permissions usually come from."
        WhatWeCheck = @(
            "Allow ACEs granting GenericAll, GenericWrite, WriteDacl, WriteOwner, WriteProperty or CreateChild"
            "The discovered site servers are excluded - they are supposed to have Full Control here"
            "SYSTEM, BUILTIN\Administrators, Domain Admins and Enterprise Admins are excluded as expected administrators"
        )
        SecureMessage = "Only the site servers and the expected administrators can write to the System Management container. No principal can publish a management point that clients would trust."
        PrimaryFindingId = 'SCCM_SYSTEM_MANAGEMENT_ACL'
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
        SecureMessage = "The SCOM service accounts found in the directory hold no privileged group membership. What a Run As account is allowed to do on its targets is configured inside SCOM, not in Active Directory, so this says nothing about least privilege there - and credentials for those accounts are stored by SCOM itself."
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

    'ADFSServer' = @{
        TitleFormat = "AD FS: {Name}"
        Module = "Application"
        Category = "Infrastructure"
        SectionTitle = "AD FS"
        Summary = "Discovers Active Directory Federation Services deployments."
        WhyItMatters = "AD FS issues the SAML tokens that federated applications and the connected cloud tenant trust. Whoever obtains the token-signing key can mint a token for any user - Golden SAML - and neither an on-premises password reset nor MFA enforced at the identity provider revokes it."
        WhatWeCheck = @(
            "The DKM container under CN=ADFS,CN=Microsoft,CN=Program Data, which holds the key protecting the token-signing certificate"
            "Computers registering the adfssrv/ service principal name"
        )
        SecureMessage = "No AD FS deployment was found in this domain. There is no on-premises federation service whose signing key could be used to forge tokens for the cloud tenant."
        PrimaryFindingId = 'ADFS_DKM_CONTAINER'
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
        TitleFormat = "Exchange Group: Exchange Trusted Subsystem"
        Module = "Application"
        Category = "Exchange"
        SectionTitle = "Exchange Trusted Subsystem"
        Summary = "Shows the Exchange Trusted Subsystem group and judges each member against what belongs in it."
        WhyItMatters = "Exchange Trusted Subsystem has WriteDACL permissions on the domain object by default, enabling domain privilege escalation (PrivExchange, Exchange-related vulnerabilities). This is one of the most dangerous Exchange groups."
        WhatWeCheck = @(
            "Members of Exchange Trusted Subsystem"
            "Computer accounts (typically Exchange servers)"
            "Potential for DCSync or domain takeover via WriteDACL abuse"
        )
        SecureMessage = "Exchange Trusted Subsystem contains only expected Exchange server computer accounts."
    }

    'ExchangeWindowsPermissions' = @{
        TitleFormat = "Exchange Group: Exchange Windows Permissions"
        Module = "Application"
        Category = "Exchange"
        SectionTitle = "Exchange Windows Permissions"
        Summary = "Shows the Exchange Windows Permissions group and judges each member against what belongs in it."
        WhyItMatters = "Exchange Windows Permissions group has powerful AD permissions including WriteDACL on the domain. Members can potentially grant themselves DCSync rights or modify security descriptors."
        WhatWeCheck = @(
            "Members of Exchange Windows Permissions"
            "Groups nested within (often Exchange Trusted Subsystem)"
            "Potential for privilege escalation via permission modification"
        )
        SecureMessage = "Exchange Windows Permissions membership follows expected patterns with only Exchange-related principals."
    }

    'ExchangeOrganizationManagement' = @{
        TitleFormat = "Exchange Group: Organization Management"
        Module = "Application"
        Category = "Exchange"
        SectionTitle = "Exchange Organization Management"
        Summary = "Shows the Organization Management group and judges each member against what belongs in it."
        WhyItMatters = "Organization Management is the highest Exchange administrative role. Members have full control over Exchange configuration and can manage all Exchange objects. Often a path to domain admin via Exchange permission abuse."
        WhatWeCheck = @(
            "Members of Organization Management"
            "User accounts with Exchange admin privileges"
            "Service accounts or unexpected members"
        )
        SecureMessage = "Organization Management contains only designated Exchange administrators."
    }

    'ExchangeServersGroup' = @{
        TitleFormat = "Exchange Group: Exchange Servers"
        Module = "Application"
        Category = "Exchange"
        SectionTitle = "Exchange Servers Group"
        Summary = "Shows the Exchange Servers group and judges each member against what belongs in it."
        WhyItMatters = "Exchange Servers holds the computer accounts of the Exchange servers and with them their rights on the Exchange organization. A user account in it holds those rights as well."
        WhatWeCheck = @(
            "Members of Exchange Servers"
            "Members that are neither Exchange servers, computer accounts, nested Exchange groups nor privileged principals"
        )
        SecureMessage = "Exchange Servers contains only Exchange server computer accounts and Exchange groups."
    }

    # ============================================================================
    # ADCS (CERTIFICATE SERVICES)
    # ============================================================================

    'CertificateAuthority' = @{
        TitleFormat = "Certificate Authority: {CAName}"
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
            "Certificate Request Agent templates (ESC3 condition 1)"
            "Templates requiring an enrollment agent co-signature (ESC3 condition 2, on-behalf-of target)"
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
        PrimaryFindingId = 'ESC5_PKI_CONTAINER_ACL'
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
        WhyItMatters = "Only certificates issued by CAs listed in the NTAuth Store are accepted for Kerberos PKINIT authentication. Every issuer listed may issue a certificate that logs on as any account, so each entry should be one the forest knows: an Enterprise CA publishes its own certificate there, and anything else was added by other means - a third-party smart card CA, a CA that was removed, or a rogue one."
        WhatWeCheck = @(
            "Whether an Enterprise CA of this forest holds the certificate, or an earlier certificate of one (renewed since)"
            "Certificate validity and expiration"
            "Weak signature algorithms (SHA1, MD5)"
            "How many different CAs the store trusts"
        )
        FilteringNote = "The store is read from the directory. An issuer added on a single machine with certutil -enterprise -addstore NTAuth is not in the directory and cannot be seen here."
        SecureMessage = "NTAuth Store contains only certificates of this forest's Enterprise CAs."
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
            "Managed service accounts with TRUSTED_FOR_DELEGATION flag"
            "Whether the account is a Domain Controller, which carries the flag by design"
            "Which privileged accounts are neither marked as sensitive nor in Protected Users, and so hand their TGT to these hosts"
            "Not tested: whether a Domain Controller can be coerced into authenticating to the system - that needs a connection to the host, not an LDAP query"
        )
        SecureMessage = "No account other than the Domain Controllers has unconstrained delegation, so no member server stores the TGT of everyone who authenticates to it. Constrained and resource-based delegation are separate sections."
        PrimaryFindingId = 'UNCONSTRAINED_DELEGATION'
    }

    'ConstrainedDelegation' = @{
        TitleFormat = "Constrained Delegation: {Name}"
        Module = "Delegation"
        Category = "Delegation"
        SectionTitle = "Constrained Delegation"
        Summary = "Identifies accounts configured for constrained Kerberos delegation."
        WhyItMatters = "Constrained delegation with protocol transition allows impersonating any user to the configured services. Restricting the service class is no protection: S4U2Proxy returns a ticket encrypted with the target host's account key, and every SPN registered to that account shares it, so a ticket for time/DC01 can be rewritten to ldap/DC01. Any target on a Domain Controller is therefore a direct path to Domain Admin."
        WhatWeCheck = @(
            "Accounts with msDS-AllowedToDelegateTo configured"
            "Whether protocol transition (S4U2Self) is enabled"
            "Whether any target SPN points at a Domain Controller, matched on the host and not the service class"
            "Accounts carrying protocol transition without any target list"
        )
        SecureMessage = "No accounts with dangerous constrained delegation found. No account delegates to a Domain Controller, and none carries protocol transition without a target list."
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
            "Computers, users and managed service accounts with msDS-AllowedToActOnBehalfOfOtherIdentity"
            "Which principals are allowed to delegate to the resource"
            "Whether any of them is a broad group, or an identity this domain does not expect to delegate"
            "Whether the resource itself is a Domain Controller"
            "Not tested: who may write the attribute, which decides who can add themselves to it - the ACL and ownership sections answer that"
        )
        SecureMessage = "No account in this domain has Resource-Based Constrained Delegation configured - msDS-AllowedToActOnBehalfOfOtherIdentity is not set anywhere. Nothing was assessed because there was nothing to assess."
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
        Summary = "Finds every account storing its password with reversible encryption, and names the privileged ones."
        WhyItMatters = "Reversible encryption allows the actual password to be recovered from AD, effectively storing it in cleartext. This is a severe security risk for any account, especially privileged ones."
        WhatWeCheck = @(
            "Accounts with 'Store password using reversible encryption' enabled"
            "Whether this setting is actually required"
            "Impact on credential security"
        )
        SecureMessage = "No account stores its password with reversible encryption. No password can be recovered to plaintext from Active Directory through this setting."
        PrimaryFindingId = 'REVERSIBLE_ENCRYPTION'
    }

    'ComputerObjectACL' = @{
        TitleFormat = "Explicit Computer Permission: {Computer}"
        Module = "Computer"
        Category = "Computers"
        SectionTitle = "Explicit Permissions on Computer Objects"
        Summary = "Finds permissions written on individual computer objects that give a principal outside Tier-0 control over the computer."
        WhyItMatters = "An entry on the computer object itself - not inherited from an OU - is invisible to a review of OU delegations. Full control, RBCD or key credential writes, the password reset right and all extended rights each end in administrative access to the machine."
        WhatWeCheck = @(
            "Explicit entries on every computer object, from the descriptors the owner check reads"
            "GenericAll, GenericWrite, WriteDacl, WriteOwner, WriteProperty on everything, all extended rights and the password reset right"
            "WriteProperty on msDS-AllowedToActOnBehalfOfOtherIdentity, msDS-KeyCredentialLink, servicePrincipalName and dNSHostName"
            "The entries the default descriptor writes for the owner, the creator, SELF, the operators and the administrators are left out"
        )
        PrimaryFindingId = 'COMPUTER_OBJECT_EXPLICIT_RIGHT'
    }

    'CriticalObjectACL' = @{
        TitleFormat = "Critical Object Control: {Trustee}"
        Module = "Rights"
        Category = "Rights"
        SectionTitle = "Schema, Partitions and Role Object ACLs"
        Summary = "Finds principals outside Tier-0 that control the schema, the partitions container, the RID Manager, the infrastructure object or a site."
        WhyItMatters = "These four objects carry the schema, the naming contexts of the forest and two of the operations master roles. Control over the schema changes the default security descriptor of every new object; control over a role object moves the role or, for the RID Manager, exhausts the identifiers the domain is built from."
        WhatWeCheck = @(
            "Owner, GenericAll, GenericWrite, WriteDacl, WriteOwner and unrestricted WriteProperty on each of the four objects"
            "The role transfer right of each object, and all extended rights"
            "WriteProperty on rIDAvailablePool of the RID Manager"
            "WriteProperty on gPLink of every site, where a linked GPO reaches every computer of the site, domain controllers included"
            "Only principals outside Tier-0 - an operator group counts"
        )
        SecureMessage = "No principal outside Tier-0 controls the schema, the partitions container, the RID Manager, the infrastructure object or a site."
        PrimaryFindingId = 'CRITICAL_OBJECT_CONTROL'
    }

    'RODCPasswordReplication' = @{
        TitleFormat = "RODC Password Replication: {Name}"
        Module = "Accounts"
        Category = "Accounts"
        SectionTitle = "RODC Password Replication Policy"
        Summary = "Checks which privileged accounts a read-only Domain Controller may cache, or has cached, the password of."
        WhyItMatters = "A read-only Domain Controller stands where physical security is weakest, and every password it caches can be taken from it. Its password replication policy decides which accounts it may cache; a privileged account allowed there is a privileged account outside the Tier-0 boundary."
        WhatWeCheck = @(
            "Each read-only Domain Controller's allow list (msDS-RevealOnDemandGroup) and deny list (msDS-NeverRevealGroup) against the token of every privileged account, primary group included - deny wins"
            "The privileged accounts whose secrets it has received already (msDS-RevealedUsers)"
            "Whether the Denied RODC Password Replication Group is still on its deny list"
        )
        SecureMessage = "No read-only Domain Controller may cache the password of a privileged account, and none holds one."
        PrimaryFindingId = 'RODC_PRIVILEGED_PASSWORD_ALLOWED'
    }

    'PasswordNotRequired' = @{
        TitleFormat = "Password Not Required: {Name}"
        Module = "Accounts"
        Category = "Accounts"
        SectionTitle = "Password Not Required Accounts"
        Summary = "Identifies enabled user and computer accounts with the PASSWD_NOTREQD flag set."
        WhyItMatters = "Accounts with the 'Password Not Required' flag can bypass the domain password policy and may have an empty password. While the flag alone does not guarantee an empty password, it indicates a hygiene issue and potential attack vector. A computer account created ahead of its computer carries the flag until a computer joins with it, and created as a pre-Windows 2000 computer it has its name in lowercase as password."
        WhatWeCheck = @(
            "Enabled user accounts with PASSWD_NOTREQD flag (UAC bit 32)"
            "Whether affected accounts are privileged or service accounts"
            "Last password change date for risk assessment"
            "Enabled computer accounts with the flag, and whether they have ever logged on"
            "Not tested: whether a pre-created computer account's password is its name - that needs a logon attempt, not an LDAP query"
        )
        SecureMessage = "No enabled user or computer account has the 'Password Not Required' flag set. All accounts require passwords according to domain password policy."
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
            "The owner of that descriptor, who may rewrite the DACL inside it"
            "msDS-ManagedPasswordInterval (how long a stolen password stays valid)"
            "accountExpires (when the account stops authenticating)"
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
            "Which domain each entry comes from - this one, another one, or no domain at all"
            "Non-privileged SID History entries (migration artifacts)"
        )
        # "Whether SID History is legitimate or suspicious" used to stand in the list
        # above while the check compared the RID suffix alone, which cannot tell the two
        # apart: a migrated administrator and an injected SID have the same RID. The line
        # it has been replaced with is the question that actually decides it.
        SecureMessage = "No account holds a privileged SID in sIDHistory that did not come from a source domain. Entries that did are reported separately, because a migration leaves them behind legitimately and only SID filtering on the trust decides whether they still grant anything."
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

    'PrivilegedGroupACL' = @{
        TitleFormat = "Privileged Group ACL: {Name}"
        Module = "Accounts"
        Category = "Accounts"
        SectionTitle = "Privileged Groups Outside AdminSDHolder"
        Summary = "Analyzes who may change the privileged groups that AdminSDHolder does not protect."
        WhyItMatters = "SDProp resets only the groups AdminSDHolder protects. Every other group keeps whatever ACEs it is given, and several are privileged in all but name - DnsAdmins load code into the DNS service on the domain controllers, Group Policy Creator Owners create policy, the Exchange groups hold rights on the domain, and a group nested into one of them passes its membership on. Whoever may add a member to such a group, or rewrite its DACL or owner, can make any account a member."
        WhatWeCheck = @(
            "Every privileged group without adminCount=1, the groups nested into them, and the Exchange groups - and the operator groups dsHeuristics takes out of AdminSDHolder protection, whatever their adminCount says"
            "WriteProperty on member, the Self-Membership validated write, WriteDacl, WriteOwner, GenericAll and GenericWrite - explicit and inherited"
            "The owner of each group"
            "The same identity gate as the AdminSDHolder check; Exchange service groups count as by design"
        )
        FilteringNote = "Which groups are unprotected is read from adminCount, which SDProp sets and never clears: a group protected once and no longer keeps a stale 1 and is not read - except the operator groups character 16 of dsHeuristics excludes, and the groups reached only through them, which are read. A holder is a finding where a group it can take over is worth the domain - DnsAdmins, ESX Admins, the Exchange groups, a Tier-0 group or one nested into it - and a hint where all of them are operator-level, such as Group Policy Creator Owners, Cert Publishers, Remote Management Users or Hyper-V Administrators. Account Operators control every unprotected group through the default security descriptor of the group class; that is said once, as a hint while the group has members, instead of once per group. Expected and privileged holders are hidden unless -IncludePrivileged. Groups in another domain of the forest are not read."
        SecureMessage = "No principal beyond the expected ones can change the privileged groups AdminSDHolder does not protect."
        PrimaryFindingId = 'PRIVILEGED_GROUP_ACL'
    }

    # What step 5b of Get-PrivilegedGroupMembers read, ahead of who may change it.
    'UnprotectedPrivilegedGroups' = @{
        TitleFormat = "Privileged Groups Outside AdminSDHolder"
        Module = "Accounts"
        Category = "Accounts"
        SectionTitle = "Privileged Groups Outside AdminSDHolder"
        Summary = "The privileged groups AdminSDHolder does not protect whose DACL was read."
        WhyItMatters = "SDProp resets the DACL of the groups AdminSDHolder protects every hour. Every other privileged group keeps whatever entries it is given, so who may change it has to be read group by group - these are the groups that were."
        WhatWeCheck = @(
            "groupsRead - the privileged groups without adminCount=1, the groups nested into them (with the group they are nested in) and the Exchange groups"
            "readDespiteAdminCount - groups with adminCount=1 from an earlier SDProp run that are read anyway, because character 16 of dsHeuristics takes the operator group they were reached from out of the protection"
            "groupsNotRead - groups whose security descriptor could not be read; who may change them was not evaluated"
        )
        SecureMessage = "Every privileged group found is protected by AdminSDHolder."
    }

    'PrivilegedAccountACL' = @{
        TitleFormat = "Privileged Account ACL: {Name}"
        Module = "Accounts"
        Category = "Accounts"
        SectionTitle = "Control Over Privileged Accounts"
        Summary = "Analyzes who may take over a privileged user or managed service account through the account's own DACL."
        WhyItMatters = "Whoever may reset the password of a privileged account, add a key credential to it, give it an SPN, map a certificate onto it or rewrite its DACL can act as that account and holds its group rights. AdminSDHolder resets the accounts it protects every hour; every other privileged account - a DnsAdmins member, a Group Policy Creator Owner - keeps the entries it is given, including what an OU delegation passes down."
        WhatWeCheck = @(
            "Every user and managed service account of this domain found in a privileged group"
            "GenericAll, WriteDacl, WriteOwner, writes of every attribute, all extended rights, the password reset right, and writes of msDS-KeyCredentialLink, servicePrincipalName, altSecurityIdentities, userAccountControl, scriptPath and - on a gMSA - msDS-GroupMSAMembership; explicit and inherited"
            "The owner of each account"
            "On an account AdminSDHolder protects, only what its template does not grant"
        )
        FilteringNote = "Computers are reported by the computer owner check, which reads the explicit entries on every computer object. On an account with adminCount=1 an entry the AdminSDHolder template grants the same trustee is reported with AdminSDHolder rather than once per account. Account Operators control every account AdminSDHolder does not protect through the default security descriptor of the user class; that is said once. Key Admins and Enterprise Key Admins write msDS-KeyCredentialLink by design. A holder is a finding where an account it can take over is in a group worth the domain - a Tier-0 group or one nested into it, DnsAdmins, ESX Admins - and a hint where every one is in operator-level groups only, such as Group Policy Creator Owners, Cert Publishers or Backup Operators. Whether an entry is inherited is not said on the row; an inherited one has to be removed at the container it comes from. Expected and privileged holders are hidden unless -IncludePrivileged. Accounts in another domain of the forest are not read."
        SecureMessage = "No principal beyond the expected ones can take over a privileged account."
        PrimaryFindingId = 'PRIVILEGED_ACCOUNT_ACL'
    }

    # What step 5c of Get-PrivilegedGroupMembers read, ahead of who may take it over.
    'PrivilegedAccountsRead' = @{
        TitleFormat = "Privileged Accounts Read"
        Module = "Accounts"
        Category = "Accounts"
        SectionTitle = "Control Over Privileged Accounts"
        Summary = "The privileged user and managed service accounts whose DACL was read."
        WhyItMatters = "Whoever may take over a privileged account holds the rights of its groups. AdminSDHolder resets the DACL of the accounts it protects every hour; every other account keeps whatever entries it is given, so each one is read."
        WhatWeCheck = @(
            "accountsRead - the users and managed service accounts of this domain found in a privileged group whose security descriptor was read; computers are left to the computer owner check"
            "protectedByAdminSDHolder - how many of them carry adminCount=1. On these, what the AdminSDHolder template grants is reported once, with AdminSDHolder, and only what is beyond it per account"
            "accountsNotRead - accounts whose security descriptor could not be read; who may take them over was not evaluated"
        )
        SecureMessage = "No privileged user or service account of this domain was found to read."
    }

    'LogonScriptPermission' = @{
        TitleFormat = "Logon Script: {Name}"
        Module = "Accounts"
        Category = "Accounts"
        SectionTitle = "Logon Scripts of Accounts"
        Summary = "Analyzes who may change the logon scripts that accounts run from NETLOGON."
        WhyItMatters = "Windows runs the logon script an account's scriptPath names at every logon of that account, as that account. Whoever may change the script runs code as every account that has it set, an administrator among them with the administrator's rights. NETLOGON is the scripts folder of SYSVOL, and its file permissions are nobody's GPO permissions."
        WhatWeCheck = @(
            "The scriptPath of every enabled account, a relative one resolved to \\<domain>\NETLOGON"
            "The NTFS permissions of each distinct script and of its folder, read over SMB from the domain's own name and enabled computers of the domain"
            "Writers beyond the administrators and privileged accounts, the number of accounts that run the script, and the privileged ones among them by name"
        )
        FilteringNote = "A local path exists on each computer and is not read. A path that could not be read is listed with the reason. The share permissions are not read. -OPSEC reads nothing."
        SecureMessage = "Only administrators and privileged accounts may change the logon scripts accounts run."
        PrimaryFindingId = 'LOGON_SCRIPT_WRITABLE'
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
            "Privilege level of Kerberoastable accounts"
            "How old the password is - pwdLastSet, flagged above one year and again above five"
            "Encryption types supported (RC4 is easier to crack)"
            "Not tested: whether the password is weak - adPEAS extracts the hash, cracking it happens offline"
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
            "Privilege level of vulnerable accounts"
            "Whether the account is in Protected Users, where RC4 is refused and the AS-REP comes back AES-encrypted"
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

    'CredentialRoaming' = @{
        TitleFormat = "Roamed Credentials: {Name}"
        Module = "Creds"
        Category = "Credentials"
        SectionTitle = "Roamed Credential Material"
        Summary = "Finds users whose DPAPI master keys and private keys are stored in Active Directory."
        WhyItMatters = "Credential Roaming copies a user's certificates, private keys and DPAPI master keys into attributes on their user object so the profile follows them between machines. A DPAPI master key protects everything else that user stored under DPAPI - saved RDP credentials, browser secrets, WLAN keys, the Credential Manager. The attributes hold ciphertext, not plaintext: a master key is sealed with a pre-key derived from the user's password and with the domain backup key, and the private keys are sealed with those master keys in turn. So the material becomes usable with the user's password or hash, or with the domain backup key that every domain administrator holds - and a roamed client-authentication certificate then impersonates that user without their password."
        WhatWeCheck = @(
            "Which users carry msPKIDPAPIMasterKeys or msPKIAccountCredentials"
            "Whether those attributes are marked confidential in the schema (searchFlags bit 7)"
            "Whether a roamed account is privileged"
        )
        FilteringNote = "The blob attributes are never retrieved. Their presence is established with an LDAP presence filter and only the name, the DN and the sync timestamp are read back, so no ciphertext travels and none reaches the report. Both attributes are also excluded from display centrally, so another check fetching a full user object cannot surface them either. Not covered yet: who holds an explicit read permission on these attributes. The confidential flag answers the blanket readability that comes from the default ACL, but a right delegated to one group by accident is invisible here. Nothing here constrains DCSync, a copy of ntds.dit or an AD backup, which read the material regardless of the flag."
        SecureMessage = "No user object carries roamed credential material. Credential Roaming is either not in use or has never synchronised, so no private keys or DPAPI master keys are stored in the directory."
        PrimaryFindingId = 'CREDENTIAL_ROAMING_READABLE'
    }

    'CredentialRoamingPermission' = @{
        TitleFormat = "Roaming Read Delegated: {Name}"
        Module = "Creds"
        Category = "Credentials"
        SectionTitle = "Delegated Credential Roaming Read"
        Summary = "Finds principals that have been given an explicit read of another user's private keys and DPAPI master keys."
        WhyItMatters = "The confidential flag decides whether every authenticated user can read the roaming attributes. A delegated read is the case it says nothing about, and the one most likely to have happened by accident: a delegation wizard pointed at the wrong attribute set, or a script copied from a Credential Roaming rollout guide, hands a helpdesk group a read of another user's private keys. Nothing about the result looks unusual afterwards, and the holder needs no exploit - a plain LDAP read returns the material, and the domain backup key or the target's hash turns it into their private keys and every DPAPI secret of their profile."
        WhatWeCheck = @(
            "ReadProperty on ms-PKI-DPAPIMasterKeys, ms-PKI-AccountCredentials or ms-PKI-RoamingTimeStamp"
            "Reads granted through All Properties or GenericAll"
            "Whether the ACE also carries Control Access, which is what defeats the confidential flag"
            "Whether the holder is privileged, and could read the material anyway"
        )
        FilteringNote = "Scoped to the containers that hold users with roamed material - a delegation on a container whose users have never roamed anything reaches nothing to read, and becomes visible as soon as the first user synchronises. The containers are read once each rather than once per user, because a container's DACL already carries what it inherits from above; the consequence is that an ACE set directly on a single user object, bypassing the container, is not seen. Reads that only cover the roaming timestamp are rated Low and drop out of a default report: a timestamp is a date, not a credential. Privileged principals are hidden unless -IncludePrivileged, since they can read the material regardless. A right that the confidential flag currently blocks is reported as a hint rather than dropped - the delegation is still there, and clearing the flag makes every one of them live at once."
        SecureMessage = "No principal holds a delegated read of the Credential Roaming attributes on the containers that hold roamed material."
        PrimaryFindingId = 'CREDENTIAL_ROAMING_DELEGATED'
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
            "String registry values named like a password - Password, ProxyPassword, Pwd - in Registry.xml and in the Administrative Template file Registry.pol"
            "VNC passwords a policy deploys for RealVNC, TightVNC, TigerVNC or UltraVNC, decrypted (one DES key shared by every VNC installation)"
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
            "VNC viewer connection files (.vnc) and VNC .ini files, with the password decrypted"
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

    'BitLockerRecoveryKey' = @{
        TitleFormat = "BitLocker Recovery Key: {ComputerName}"
        Module = "Creds"
        Category = "Credentials"
        SectionTitle = "BitLocker Recovery Key Access"
        Summary = "Tests which BitLocker recovery keys the current user can read from AD."
        WhyItMatters = "BitLocker recovery keys are escrowed in AD as msFVE-RecoveryInformation child objects, with read access controlled by ACLs. Being able to read a recovery key is often legitimate (recovery and helpdesk roles) and is not by itself a vulnerability, but it is worth reviewing: a readable key lets the holder unlock the computer's encrypted volume offline. Unexpectedly broad read access can indicate over-permissive delegation on the computer OUs."
        WhatWeCheck = @(
            "msFVE-RecoveryInformation objects where the current user can read msFVE-RecoveryPassword"
            "The 48-digit recovery password, recovery/volume GUID and escrow time"
            "The computer each recovery key belongs to"
        )
        SecureMessage = "No readable BitLocker recovery keys found. The account running the scan cannot read any escrowed BitLocker recovery password - which says nothing about other principals; their delegated reads are the next section."
        PrimaryFindingId = 'BITLOCKER_KEY_READABLE'
    }

    'BitLockerRecoveryPermission' = @{
        TitleFormat = "Recovery Read Delegated: {Name}"
        Module = "Creds"
        Category = "Credentials"
        SectionTitle = "Delegated BitLocker Recovery Read"
        Summary = "Finds principals that may read the BitLocker recovery passwords of the computers below a container."
        WhyItMatters = "A recovery password unlocks its volume offline, given the disk or an image of it - a stolen laptop, a retired drive, a virtual machine's disk file. The schema grants the recovery objects to Domain Admins and SYSTEM only, so every other reader was given the right by somebody, usually through the delegation wizard for a helpdesk or recovery role. That can be intended; the row says who holds it, on how many computers, and whether the confidential flag on the attribute lets it work today."
        WhatWeCheck = @(
            "ReadProperty and ControlAccess on msFVE-RecoveryPassword reaching the msFVE-RecoveryInformation objects below the computers"
            "Reads granted through all properties, all extended rights or full control"
            "Whether both halves of the confidential-attribute read reach the same computers, and whether the confidential flag is set"
            "Whether the holder is privileged, and reads the recovery passwords anyway"
        )
        FilteringNote = "Scoped to the containers that hold computer objects, disabled ones included - a recovery password stays valid for its disk after the computer account is disabled. The account running a scan normally cannot see the recovery objects themselves, since the schema grants them to Domain Admins and SYSTEM only, so whether a computer has a key escrowed is not known here and the row counts computers. The containers are read once each, because a container's DACL already carries what it inherits from above; an ACE set directly on one computer or one recovery object is not seen. Privileged principals are hidden unless -IncludePrivileged. A right the confidential flag currently blocks is reported as a hint rather than dropped, since clearing the flag makes every one of them live at once. Control access without any read of the recovery objects reads nothing and is not listed."
        SecureMessage = "No principal holds a delegated read of the BitLocker recovery passwords on the containers holding computers."
        PrimaryFindingId = 'BITLOCKER_RECOVERY_DELEGATED'
    }

    'PasswordInDescription' = @{
        TitleFormat = "Password in Description: {Name}"
        Module = "Creds"
        Category = "Credentials"
        SectionTitle = "Passwords in Free-Text Attributes"
        Summary = "Finds credentials typed into the free-text attributes of any directory object."
        WhyItMatters = "Administrators store passwords in the attributes they type into: description, info, comment, adminDescription, and above all extensionAttribute1-15, which is where an initial password tends to end up. Every one of them is readable by any authenticated domain user, so a password there is a password handed to the whole domain - and it sits on groups, organizational units and service accounts as often as on user accounts."
        WhatWeCheck = @(
            "description, info, comment and adminDescription on every object class"
            "wWWHomePage and url, for credentials written into a link, and scriptPath, homeDirectory and profilePath for what is typed beside a path"
            "extensionAttribute1-15 and msDS-cloudExtensionAttribute1-20, where the schema defines them"
            "Groups, organizational units, contacts, managed service accounts and Group Policy objects, not only user and computer accounts"
            "High-confidence password assignments (e.g., password=value) and credentials embedded in a URL (user:password@host)"
            "Lower-confidence credential mentions for manual review, outside the link and path attributes"
        )
        SecureMessage = "No credentials were found in the free-text attributes of any object. The attributes a password tends to be typed into - description, info, comment, adminDescription, the link attributes, extensionAttribute1-15 and msDS-cloudExtensionAttribute1-20 - carry none."
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

    'WeakCertificateMapping' = @{
        TitleFormat = "Explicit Certificate Mapping: {Name}"
        Module = "ADCS"
        Category = "ADCS"
        SectionTitle = "Explicit Certificate Mappings"
        Summary = "Finds accounts a certificate can be mapped to without the CA's SID extension."
        WhyItMatters = "altSecurityIdentities binds a certificate to an account explicitly, bypassing the SID extension the CA writes. Three of the six formats Active Directory accepts name something an attacker can reproduce in a certificate of their own - a subject name or an e-mail address - so anyone who can enrol for such a certificate authenticates as that account."
        WhatWeCheck = @(
            "Principals carrying a weak mapping: X509IssuerSubject, X509SubjectOnly, X509RFC822"
            "Whether the mapped account is privileged"
            "Who may write altSecurityIdentities on a privileged account"
        )
        FilteringNote = "Strong mappings (X509IssuerSerialNumber, X509SKI, X509SHA1PublicKey) are not reported. Write access is examined for privileged principals only, and trustees that are already privileged are filtered out. The Exchange service groups are reported separately, in their own attribute: their rights on user objects are written by the Exchange setup and land on every privileged account at once, which makes them an escalation path through Exchange rather than a delegation on this account. Both findings are reported as a hint instead of a vulnerability when no issuer is published in this domain's NTAuth store, because nothing can then authenticate against the mapping - neither through PKINIT nor through Schannel, which needs NTAuth as well. A published root CA does not change that: it governs chain validation in general, not permission to authenticate as an account. The dampening is not a clearance - the Enterprise NTAuth store is a machine store as well as a directory object, so an issuer added straight onto a domain controller is invisible from the directory, and publishing one makes every mapping live again. If the Configuration partition cannot be read, nothing is dampened: unknown is not absent."
        SecureMessage = "No weak explicit certificate mapping found, and no non-privileged principal can add one to a privileged account."
        PrimaryFindingId = 'ESC14_WEAK_EXPLICIT_MAPPING'
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

    'GPOUserRights' = @{
        TitleFormat = "GPO User Right: {UserRightName}"
        Module = "Rights"
        Category = "Rights"
        SectionTitle = "User Rights via GPO That Depart From the Windows Default"
        Summary = "Compares the user rights a GPO assigns against the set Windows ships, and reports the difference."
        WhyItMatters = "User Rights Assignment in a GPO grants low-level privileges - SeDebugPrivilege, SeBackupPrivilege, SeImpersonatePrivilege, Remote Desktop logon - across every computer the policy reaches, and the [Privilege Rights] section is absolute: what it lists becomes the complete set of holders. So the question is not who holds a right but whether the assignment departs from what Windows ships. A holder beyond the default is an escalation or lateral-movement path; a default holder removed is usually hardening and occasionally a service about to break."
        WhatWeCheck = @(
            "GptTmpl.inf [Privilege Rights] in every GPO, compared against the documented Windows defaults"
            "Holders granted a right beyond the default - including operator groups, which an identity filter would hide"
            "Default holders the GPO removes, reported as a note rather than a finding"
            "The right baseline for the machines the policy reaches: domain controllers and member computers differ"
            "Rights granted to broad principals (Everyone, Authenticated Users, Domain Users), which outrank the right's own tier"
            "Whether the GPO currently applies at all"
        )
        SecureMessage = "Every user right assigned via GPO matches the Windows default. No policy grants a privilege beyond the set Windows ships."
        # GPO_DANGEROUS_USER_RIGHT no longer exists - the check now has one FindingId per
        # right (GPO_USERRIGHT_*) rather than one generic tooltip for all 22. SeDebugPrivilege
        # is the anchor here as the most universally recognized of the set; the client-side
        # fallback (findingIds carried by the section's own findings) picks up the specific
        # right actually reported when this override does not apply.
        PrimaryFindingId = 'GPO_USERRIGHT_SEDEBUG'
    }

    'MachineAccountQuota' = @{
        TitleFormat = "Machine Account Quota Configuration"
        Module = "Rights"
        Category = "Rights"
        SectionTitle = "Machine Account Quota"
        Summary = "Displays the ms-DS-MachineAccountQuota domain setting and who can use it."
        WhyItMatters = "This setting controls how many computers any authenticated user can join to the domain. Default is 10, which allows RBCD attacks. The quota is a ceiling on SeMachineAccountPrivilege, so it is reachable only by the accounts that hold the privilege on the domain controllers."
        WhatWeCheck = @(
            "Current quota value"
            "Whether it's the default (10) or has been modified"
            "Who holds SeMachineAccountPrivilege on the domain controllers - by the policy that wins there, or by the Windows default when no policy sets it"
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

    'ComputerPasswordAge' = @{
        TitleFormat = "Machine Password Not Rotated: {Name}"
        Module = "Computer"
        Category = "Computers"
        SectionTitle = "Machine Account Password Age"
        Summary = "Finds active computers whose machine account password is not rotated."
        WhyItMatters = "A domain member changes its machine account password itself, every 30 days by default. One that does not keeps a key that never ages out: whoever extracted it once can forge service tickets to the host, and for a Domain Controller the key replicates the whole directory."
        WhatWeCheck = @(
            "Enabled computers that logged on within the last 30 days and whose machine account password is 90 days old or older"
            "Whether the computer is a Domain Controller, which is reported as a finding"
            "Not tested: the cause on the computer itself - a policy, a non-Windows join tool or a clone - which needs access to the host"
        )
        SecureMessage = "Every computer that logged on in the last 30 days has changed its machine account password within 90 days."
        PrimaryFindingId = 'COMPUTER_PASSWORD_NOT_ROTATED'
    }

    'OutdatedComputer' = @{
        TitleFormat = "Outdated Computer: {Name}"
        Module = "Computer"
        Category = "Computers"
        SectionTitle = "Outdated Microsoft Operating Systems"
        Summary = "Finds computers running an end-of-life Microsoft operating system."
        WhyItMatters = "EOL systems no longer receive security updates. They have known, unpatched vulnerabilities that attackers can exploit for initial access or lateral movement."
        WhatWeCheck = @(
            "Windows XP, Vista, 7, 8/8.1, 10 and 11, Server 2003 through 2022"
            "Windows 11 per release, from the build in operatingSystemVersion, with the earlier end date for Home and Pro and the later one for Enterprise and Education"
            "The general support end separately from the end of the paid Extended Security Updates window, because a machine between the two is patched only if that extension was bought"
            "Last logon timestamp to filter active vs stale"
        )
        FilteringNote = "The subject is the Microsoft lifecycle. A member whose operatingSystem is not a Microsoft product - a Linux host, an appliance, a network printer - has no support date to run out and is not part of the figures. A Microsoft product the table cannot place, such as a Windows 11 build it does not know, is counted and named separately: not assessable is not the same as supported."
        SecureMessage = "No active computers running an end-of-life Microsoft operating system found. Every machine the lifecycle table could place is on a release that still receives security updates."
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
            "Computers where owner is not Domain Admins, Enterprise Admins, BUILTIN\Administrators or SYSTEM"
            "Whether the owner is also the principal that created the account (mS-DS-CreatorSID) - a join leaves the joiner as owner, a later re-assignment does not happen by itself"
            "What kind of principal the owner is: a computer account is how a cluster owns the objects it creates, a group hands ownership to its members, a user account is the case to act on"
            "Disabled accounts as well: ownership survives the disable and the owner can re-enable the account"
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
            "Coverage percentage across the domain, with domain controllers left out - a DC has no local Administrator for LAPS to manage"
            "Whether a GPO configures DSRM password backup, which is the only LAPS setting that reaches a domain controller"
            "Which domain controllers have their DSRM password managed by Windows LAPS, read from the domain controllers themselves"
            "OUs with low LAPS adoption"
        )
        SecureMessage = "LAPS is properly deployed with high coverage across the domain. Local administrator passwords are unique per computer, preventing lateral movement through password reuse."
    }

    'LAPSCoverage' = @{
        TitleFormat = "LAPS Deployment Coverage"
        Module = "Computer"
        Category = "Computers"
        SectionTitle = "LAPS Deployment Coverage"
        Summary = "How many active computers have their local administrator password managed by LAPS, whether those passwords rotate, and whether Windows LAPS manages the DSRM password of the domain controllers."
        WhyItMatters = "Computers without LAPS likely share local admin passwords, and a LAPS password that stopped rotating is as old as the day it stopped. Compromising one such system enables lateral movement to every system with the same password."
        WhatWeCheck = @(
            "The active computers the figures are measured against, and what was left out - inactive computers and domain controllers"
            "How many of them carry a LAPS attribute, by generation"
            "Whether the LAPS passwords rotate on schedule"
            "How many carry no LAPS attribute at all"
            "Whether Windows LAPS manages the DSRM password of each domain controller"
        )
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
            "GPOs with write permissions for non-admins, inherited delegations included, with Deny ACEs netted out"
            "The owner of each GPO, which holds WRITE_DAC implicitly and needs no ACE at all"
            "Which attribute an attribute-scoped write is restricted to, since only a few of them carry the policy content"
            "The NTFS permissions of each policy folder in SYSVOL, where the policy content actually lives - write access there needs no permission on the directory object"
            "Which computers/users are affected by each GPO"
            "Potential impact of GPO modification"
        )
        SecureMessage = "No dangerous permissions and no non-default owner on the GPO directory objects, and no unexpected write access to the policy folders in SYSVOL that could be read."
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
            "Every member added, by SID: a broad group is marked in the colour of the assignment, any other principal that is not Tier 0 in the colour of the target group, a Tier 0 principal not at all - it holds these rights already"
        )
        FilteringNote = "An assignment that adds Tier 0 principals only - Domain Admins to the local Administrators, say - is a note rather than a finding, unless it empties the group first. The target group is coloured only where a member that is not Tier 0 is added."
        SecureMessage = "No vulnerable GPO local group assignments found. Local administrator configurations through GPO are properly scoped and controlled."
    }

    'GPOSuppressedGroup' = @{
        # The card for a group of policies a GPO check counted but held back: dormant policies
        # under a dampening summary, assignments that only remove default holders, Point and
        # Print configurations that expose nothing. One card per group, not per policy - the
        # whole reason these are held back is that they are not worth a finding each.
        #
        # No TitleFormat: the title varies by group and by count, so Get-ObjectCardTitle builds
        # it from the Group and Count fields instead of a {Name} template.
        Module = "GPO"
        Category = "GPO"
        SectionTitle = "Held Back From This Check"
        Summary = "Policies a check counted but did not report in full, because each is low-priority on its own."
        WhyItMatters = "A full scan would otherwise bury the findings that matter under policies that reach no machine, assignments that only harden, or configurations that expose nothing. They are collected here so the count is never silently absent and every policy can still be identified by name and GUID - the GUID being the folder under \\<domain>\SYSVOL\<domain>\Policies\. None of them is an exposure by itself; they are shown so a reader can confirm that for themselves rather than take it on trust."
        WhatWeCheck = @(
            "Why the group was held back - not linked, disabled, hardening-only, or exposes nothing"
            "How many findings it covers, and across how many distinct policies"
            "Each policy by display name and GUID"
        )
    }

    'GPOScheduledTask' = @{
        TitleFormat = "GPO Scheduled Task: {Name}"
        Module = "GPO"
        Category = "GPO"
        SectionTitle = "GPO Scheduled Tasks"
        Summary = "Analyzes scheduled tasks deployed via Group Policy."
        WhyItMatters = "GPO scheduled tasks run with specified privileges on target systems. Tasks running as SYSTEM from writable paths or UNC shares enable privilege escalation."
        WhatWeCheck = @(
            "Scheduled tasks in GPO configurations, every Exec action of each"
            "Execution context (SYSTEM, a Tier 0 account, an operator account, any other account)"
            "Whether a path lies in a directory where every user may change or add files by Windows default"
            "UNC paths, whose share decides what the task runs - who may write the share is not read"
            "cmd.exe /c lines with an unquoted program path, which cmd.exe splits at the first space"
            "Not tested: the permissions on the hosts themselves, and who may write the share a UNC path names"
        )
        SecureMessage = "No vulnerable GPO scheduled tasks found. No task starts code from a UNC path or from a directory that ordinary users can write by Windows default."
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
            "Whether the script comes out of the policy's own Scripts folder or from somewhere else"
            "Whether the parameter line carries something that looks like a credential"
            "PowerShell scripts via psscripts.ini"
            "Who may write a script outside the policy's own folder - the NTFS permissions of the file and its folder, read over SMB from the domain's own name and enabled computers of the domain; not under -OPSEC, and not the share permissions"
        )
        SecureMessage = "No scripts distributed via GPO. No Logon/Logoff/Startup/Shutdown scripts were found in Group Policy configurations."
    }

    'GPORegistrySetting' = @{
        TitleFormat = "GPO Registry Setting: {Name}"
        Module = "GPO"
        Category = "GPO"
        SectionTitle = "GPO Registry Settings"
        Summary = "Detects security-relevant registry values deployed via Group Policy that, when set, enable an attack."
        WhyItMatters = "Group Policy can push registry values to every linked system. A single value such as WDigest cleartext caching, AlwaysInstallElevated, RDP Restricted Admin, the Zerologon/OneLogon allow-list, or WSUS-over-HTTP turns the whole scope into an attack surface for credential theft, lateral movement, or privilege escalation. This check parses both delivery mechanisms (Registry.pol and Registry.xml) and reports only values that are actively set to a dangerous state. It sees what is deployed via GPO, not what is set locally on a host."
        WhatWeCheck = @(
            "Administrative Templates (Registry.pol, PReg binary)"
            "Group Policy Preferences (Registry.xml)"
            "Credential-theft enablers (WDigest, LM/NTLMv1, LSA/Credential Guard disabled)"
            "Lateral-movement enablers (Remote UAC, RDP Restricted Admin, Zerologon allow-list)"
            "Privilege-escalation enablers (AlwaysInstallElevated, WSUS over HTTP)"
            "Remote access and name resolution (WinRM unencrypted or Basic, CredSSP delegation to any server, LLMNR, unsolicited Remote Assistance, LDAP client signing off)"
            "Kerberos DES or RC4, cached logons above the default, Office macros enabled without a prompt"
            "Not tested: every value outside the list - an application's settings, Windows settings without a rule. Counted, not judged; -IncludeUnknown lists them"
        )
        SecureMessage = "No known vulnerable registry setting deployed via GPO. No Group Policy was found pushing one of the registry values this check knows in a state that enables an attack; values outside its list are counted, not judged."
    }

    'GPORegistryValue' = @{
        TitleFormat = "GPO Registry Values: {Name}"
        Module = "GPO"
        Category = "GPO"
        SectionTitle = "GPO Registry Settings"
        Summary = "Lists the registry values a policy file deploys that no rule of Get-GPORegistrySettings judges (-IncludeUnknown)."
        WhyItMatters = "The list of dangerous registry settings covers known Windows attack paths. An application's settings - macro security, remote access tools, update channels - and Windows settings without a rule are not on it. Listed here so that someone who knows the applications can read them."
        WhatWeCheck = @(
            "Every value a policy deploys through Registry.pol, Registry.xml or GptTmpl.inf that no rule names and no other check reads"
            "Not judged: the values are listed as they are, without a severity"
        )
        SecureMessage = "No registry value outside the list of the check is deployed."
    }

    'PointAndPrintPolicy' = @{
        TitleFormat = "Point and Print GPO: {Name}"
        Module = "GPO"
        Category = "GPO"
        SectionTitle = "Point and Print Printer Driver Policies"
        Summary = "Shows the Point and Print configuration deployed by each GPO and whether it lets a non-administrator install a printer driver."
        WhyItMatters = "Installing a printer driver means running code as SYSTEM, so Point and Print decides who may execute code on every machine in the GPO scope. No single value settles that question. Since the August 2021 update, RestrictDriverInstallationToAdministrators blocks the install outright unless it is explicitly set to 0, which makes a lone prompt-suppression setting a very common but inert legacy leftover - and makes the combination of both values a straight path from any domain user to SYSTEM. The approved-server settings decide where a driver may come from, but they never compensate for a suppressed elevation prompt. Settings placed in User Configuration are ignored by Windows entirely and only look like a control."
        WhatWeCheck = @(
            "Point and Print Restrictions (Restricted, prompt settings, trusted servers, forest restriction)"
            "RestrictDriverInstallationToAdministrators, the gate that overrides the prompt settings"
            "Package Point and Print enforcement and its approved server list"
            "Remote spooler RPC endpoint, queue-specific files, driver download over HTTP"
            "The Security Option 'Devices: Prevent users from installing printer drivers' from GptTmpl.inf"
            "The OUs, domains and sites each GPO is linked to"
        )
        SecureMessage = "No GPO configures Point and Print or printer driver policies. The Windows default since the August 2021 update limits printer driver installation to administrators."
    }

    'LAPSStalePassword' = @{
        TitleFormat = "LAPS Password Not Rotating: {Name}"
        Module = "Computer"
        Category = "Computers"
        SectionTitle = "LAPS Passwords That Stopped Rotating"
        Summary = "Computers that have LAPS but whose password expiration time lies in the past."
        WhyItMatters = "Coverage counts a machine as protected the moment the LAPS attribute exists, which says nothing about whether the password behind it ever changed. An expiration time in the past means the client did not rotate when it was due - and a local administrator password that stopped rotating is as good to an attacker as no LAPS at all."
        WhatWeCheck = @(
            "ms-Mcs-AdmPwdExpirationTime and msLAPS-PasswordExpirationTime against the current time"
            "The later of the two, so a machine migrated between LAPS generations is judged on the generation in use"
            "A 30 day grace period, so a machine that was merely switched off is not reported"
        )
        SecureMessage = "Every computer with LAPS rotated its password on schedule. No machine is carrying a local administrator password that outlived its rotation interval."
        PrimaryFindingId = 'LAPS_PASSWORD_NOT_ROTATED'
    }

    'LAPSGPOConfig' = @{
        TitleFormat = "LAPS GPO: {Name}"
        Module = "Computer"
        Category = "Computer"
        SectionTitle = "LAPS GPO Configuration"
        Summary = "Shows the LAPS policy settings deployed via Group Policy and where they apply."
        WhyItMatters = "The LAPS policy in a GPO decides which local account is managed, how strong the password is, and - for Windows LAPS - whether the password is encrypted in Active Directory and escrowed there at all. These settings are readable from SYSVOL without any LAPS password permissions, so they disclose the managed account name and reveal misconfigurations before a single computer object is touched. A policy with encryption disabled writes the password in cleartext to msLAPS-Password, and a policy with the backup target disabled or pointed only at Microsoft Entra ID leaves this Active Directory without any escrowed password despite LAPS appearing to be deployed."
        WhatWeCheck = @(
            "Managed account name (AdminAccountName / AdministratorAccountName)"
            "Windows LAPS AD password encryption and the principal allowed to decrypt"
            "Windows LAPS backup target (Active Directory, Microsoft Entra ID, or disabled)"
            "Password complexity, length, passphrase length and maximum age"
            "Password expiration protection"
            "The OUs, domains and sites each GPO is linked to"
        )
        SecureMessage = "No LAPS policy settings deployed via Group Policy were found."
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
    # GPOName is what every custom GPO finding calls the policy it came from
    $objName = $Object.sAMAccountName
    if (-not $objName) { $objName = $Object.GPOName }
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

    # Replace placeholders. Literal .Replace(), not -replace: the replacement text is
    # untrusted (an AD object name/context), and -replace treats it as a regex
    # replacement pattern, where a literal '$' in the name silently corrupts the title
    # ('$1' is read as a backreference, '$$' collapses to one '$') - the same defect
    # class already fixed below for the generic {propertyName} fallback loop, just not
    # yet here for the named placeholders.
    $title = $title.Replace('{Name}', $objName)
    $title = $title.Replace('{Context}', $contextStr)

    # Handle {DisplayName} placeholder - prefers displayName over sAMAccountName
    if ($title -match '\{DisplayName\}') {
        $displayName = if ($Object.displayName) { $Object.displayName } else { $objName }
        $title = $title.Replace('{DisplayName}', $displayName)
    }

    # Handle {CAName} placeholder - used by CertificateAuthority titles
    if ($title -match '\{CAName\}') {
        $caName = if ($Object.caName) { $Object.caName } else { $objName }
        $title = $title.Replace('{CAName}', $caName)
    }

    # Handle DN placeholder if present
    if ($title -match '\{DN\}' -and $Object.distinguishedName) {
        # Extract OU path from DN
        $dn = $Object.distinguishedName
        if ($dn -match ',(.+)$') {
            $ouPath = $Matches[1]
            $title = $title.Replace('{DN}', $ouPath)
        } else {
            $title = $title.Replace('{DN}', '')
        }
    }

    # Generic fallback: resolve any remaining {propertyName} placeholders
    # directly from a matching object property (e.g. {UserRightName}, {ComputerName}).
    # Falls back to the object name when the property is absent. Uses literal
    # string replacement so property values containing '$' are not treated as
    # regex replacement tokens.
    foreach ($match in [regex]::Matches($title, '\{(\w+)\}')) {
        $propName = $match.Groups[1].Value
        $propValue = $Object.$propName
        $replacement = if ($propValue) { [string]$propValue } else { $objName }
        $title = $title.Replace($match.Value, $replacement)
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


