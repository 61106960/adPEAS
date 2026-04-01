# Security Checks Reference

Complete reference of all security checks performed by adPEAS v2.

---

## Output Filtering (Noise Reduction)

Several security checks filter out high-privileged accounts from the output to reduce noise and focus on actionable findings. This is by design: Domain Admins and Enterprise Admins are **expected** to have rights like DCSync, GenericAll, or password reset capabilities - showing them would obscure the real security issues.

### Filtered Checks

The following checks filter high-privileged accounts by default:

| Check | What's Filtered | Override Parameter |
|-------|-----------------|-------------------|
| **Get-DangerousACLs** | Domain Admins, Enterprise Admins, SYSTEM with GenericAll/WriteDACL/WriteOwner/DCSync rights | `-IncludePrivileged` |
| **Get-PrivilegedGroupMembers** | AdminSDHolder ACL analysis excludes expected privileged principals | `-IncludePrivileged` |
| **Get-PasswordResetRights** | Only Critical/High severity findings shown; privileged accounts with reset rights are low severity | `-IncludePrivileged` |
| **Get-LAPSPermissions** | Only Critical/High/Medium severity; Domain Admins with LAPS read are expected | `-IncludePrivileged` |
| **Get-GPOPermissions** | Group Policy Creator Owners, Domain Admins with GPO modification rights | `-IncludePrivileged` |
| **Get-ADCSVulnerabilities** | Domain Admins, Enterprise Admins with certificate enrollment | `-IncludePrivileged` |
| **Get-AddComputerRights** | Domain Admins, Account Operators with computer creation rights | `-IncludePrivileged` |

### How Filtering Works

adPEAS uses a **SID-based classification system** that's language-independent (works in English, German, French, etc.):

1. **Test-IsPrivileged**: Classifies identities into categories:
   - `Privileged`: Domain Admins (-512), Enterprise Admins (-519), Schema Admins (-518), Administrators (S-1-5-32-544), SYSTEM (S-1-5-18)
   - `Operator`: Account Operators, Server Operators, Backup Operators, Print Operators
   - `BroadGroup`: Everyone, Authenticated Users, Domain Users
   - `Standard`: Regular users and groups

2. **Test-IsExpectedInScope**: Applies context-aware filtering based on the type of check:
   - Returns `Expected` for accounts that should have the right (filtered from output)
   - Returns `Attention` for technically expected but security-relevant (shown in yellow when `-IncludePrivileged`)
   - Returns `Finding` for accounts that should NOT have the right (always shown)

### Viewing All Results

To see all results including privileged accounts, use the `-IncludePrivileged` switch:

```powershell
# Shows only unexpected/dangerous findings (default)
Get-DangerousACLs

# Shows all findings including Domain Admins, Enterprise Admins (yellow highlighting)
Get-DangerousACLs -IncludePrivileged
```

### Checks Without Filtering

These checks intentionally show ALL accounts regardless of privilege level:

- **Get-KerberoastableAccounts** - Even admin accounts can be Kerberoasted
- **Get-ASREPRoastableAccounts** - Pre-auth disabled is dangerous for any account
- **Get-UnconstrainedDelegation** - Unconstrained delegation is risky regardless of account type
- **Get-ConstrainedDelegation** - Shows all delegation configurations
- **Get-InactiveAdminAccounts** - Purpose is to find inactive admin accounts
- **Get-AdminPasswordNeverExpires** - Purpose is to find admin accounts with this setting

### Admin-Only Checks (adminCount=1)

Some checks are scoped exclusively to accounts with `adminCount=1` — accounts that Active Directory marks as having (or having had) privileged group membership:

| Check | LDAP Scope | Additional Validation |
|-------|------------|----------------------|
| **Get-InactiveAdminAccounts** | `adminCount=1` + enabled only | `Test-AccountActivity` for inactivity detection |
| **Get-AdminPasswordNeverExpires** | `adminCount=1` + password never expires | `Test-IsPrivileged` to filter out orphaned adminCount |
| **Get-AdminReversibleEncryption** | `adminCount=1` + reversible encryption | None (any admin with this setting is a finding) |

**Note on orphaned adminCount:** When a user is removed from a privileged group, Active Directory does **not** automatically clear `adminCount=1`. Get-AdminPasswordNeverExpires validates via `Test-IsPrivileged` whether the account is still actually privileged, and flags orphaned adminCount accounts separately.

### Disabled Account Handling

adPEAS does **not** globally exclude disabled accounts. Most checks return both enabled and disabled accounts, because disabled accounts can still represent security risks (e.g., a disabled account with Kerberoastable SPN can be re-enabled by an attacker with the right permissions).

Exceptions where disabled accounts are excluded:

| Check | Why |
|-------|-----|
| **Get-InactiveAdminAccounts** | Only enabled accounts — purpose is to find *active* admins who are not being used |
| **Get-LAPSPermissions** | Only enabled computers — LAPS passwords for disabled computers are not actionable |

---

## Overview

adPEAS performs 41+ security checks organized into 9 categories:

| Module        | Checks | Description                               |
| ------------- | ------ | ----------------------------------------- |
| Domain        | 5      | Domain configuration, trusts, policies    |
| Creds         | 6      | Credential exposure vectors               |
| Rights        | 5      | ACL and permission analysis               |
| Delegation    | 3      | Kerberos delegation misconfigurations     |
| ADCS          | 2      | Certificate Services vulnerabilities      |
| Accounts      | 9      | Privileged accounts and security settings |
| GPO           | 4      | Group Policy security                     |
| Computer      | 4      | Computer account security                 |
| Application   | 3      | Enterprise application infrastructure     |

---

## Domain Module

Analyzes domain-level configuration and security settings.

### Get-DomainInformation

**Purpose**: Retrieves basic domain information and functional level.

**What it checks**:
- Domain functional level
- Forest functional level
- Domain Controllers

**Security Impact**: Outdated functional levels may lack security features and indicate older, vulnerable DCs.

| Functional Level | Severity |
|-----------------|----------|
| Windows 2000/2003 | Critical (EOL) |
| Windows 2008/R2 | High (EOL) |
| Windows 2012/R2 | Medium |
| Windows 2016 | Low |
| Windows 2019+ | Info |

**Usage**:
```powershell
Get-DomainInformation
```

---

### Get-DomainPasswordPolicy

**Purpose**: Analyzes the default domain password policy.

**What it checks**:
- Maximum password age (disabled = passwords never expire)
- Minimum password length (below 8 = weak)
- Password complexity requirement
- Account lockout threshold
- Reversible encryption setting

**Security Impact**: Weak password policies allow attackers to crack passwords more easily or use brute-force attacks without lockout.

**Usage**:
```powershell
Get-DomainPasswordPolicy
```

---

### Get-DomainTrusts

**Purpose**: Enumerates domain and forest trusts.

**What it checks**:
- Trust direction (Inbound, Outbound, Bidirectional)
- Trust type (Forest, External, Shortcut)
- SID filtering status
- Selective authentication configuration

**Security Impact**: External trusts may allow lateral movement. Bidirectional trusts expose both domains. SID filtering disabled enables SID history attacks.

**Usage**:
```powershell
Get-DomainTrusts
```

---

### Get-LDAPConfiguration

**Purpose**: Checks LDAP security configuration on Domain Controllers.

**What it checks**:
- LDAP signing requirement
- LDAP channel binding enforcement
- Anonymous LDAP access

**Security Impact**: Without LDAP signing, attackers can perform man-in-the-middle attacks. Anonymous access enables reconnaissance without credentials.

**Usage**:
```powershell
Get-LDAPConfiguration
```

---

### Get-SMBSigningStatus

**Purpose**: Checks SMB signing configuration on Domain Controllers.

**What it checks**:
- SMB signing requirement on DCs
- SMB signing enablement status

**Security Impact**: Without SMB signing, attackers can perform SMB relay attacks to capture and relay authentication.

**Usage**:
```powershell
Get-SMBSigningStatus
```

---

## Creds Module

Identifies credential exposure vectors.

### Get-LAPSCredentialAccess

**Purpose**: Tests if current user can read LAPS passwords.

**What it checks**:
- Actual read access to LAPS password attributes
- Which computers' LAPS passwords are accessible

**Security Impact**: If the current user can read LAPS passwords, they can obtain local admin credentials for those computers, enabling lateral movement.

**Usage**:
```powershell
Get-LAPSCredentialAccess
```

---

### Get-CredentialExposure

**Purpose**: Detects credential exposure in SYSVOL, NETLOGON scripts, and Group Policy Preferences.

**What it checks**:
- GPP passwords in SYSVOL XML files (cpassword attribute, MS14-025)
- AutoAdminLogon passwords in Registry.xml (plaintext)
- Hardcoded credentials in NETLOGON/SYSVOL scripts (.bat, .cmd, .vbs, .vbe, .txt, .ini, .conf, .kix)
- Net use commands with embedded passwords
- VBScript Encoded (.vbe) files (automatically decoded)
- Custom UNC paths or local directories (standalone mode)

**Detection Tiers**:

| Tier | Severity | Pattern Examples |
|------|----------|-----------------|
| Tier 1 (High Confidence) | Finding | GPP cpassword, `password=Secret123`, `net use ... /user:admin pass`, PSExec with `-p`, connection strings |
| Tier 2 (Lower Confidence) | Hint | Generic mentions of `password`, `credential`, XML password elements |

**Security Impact**: GPP passwords use a published Microsoft AES key and are trivially decryptable. Credentials in SYSVOL scripts are readable by all authenticated domain users.

**Usage**:
```powershell
# Domain-based scan (SYSVOL/NETLOGON)
Get-CredentialExposure

# Scan custom UNC path (requires separate Connect-adPEAS session or -Credential)
Get-CredentialExposure -Path "\\server\share"
```

---

### Get-PasswordInDescription

**Purpose**: Detects user and computer accounts with potential credentials in description or info attributes.

**What it checks**:
- Description and info attributes of user accounts
- Description and info attributes of computer accounts
- High-confidence password assignments (e.g., `password=Secret123`)
- Lower-confidence credential mentions for manual review

**Security Impact**: Administrators sometimes store passwords directly in the description or info attributes of AD objects. These attributes are readable by all authenticated domain users, exposing credentials to anyone with basic domain access.

**Detection Tiers**:

| Tier | Severity | Pattern Examples |
|------|----------|-----------------|
| Tier 1 (High Confidence) | Finding | `password=Secret123`, `pwd: admin`, `kennwort=pass` |
| Tier 2 (Lower Confidence) | Hint | Generic mentions of `password`, `credentials`, `secret=...` |

**Exclusion patterns** filter false positives from password policy text, help text, and placeholders.

**Usage**:
```powershell
Get-PasswordInDescription
```

---

### Get-KerberoastableAccounts

**Purpose**: Finds accounts vulnerable to Kerberoasting.

**What it checks**:
- User accounts with servicePrincipalName attribute
- Account status (enabled, not krbtgt)
- Encryption types supported

**Security Impact**: Service tickets can be requested for any SPN and cracked offline. Weak passwords are cracked within hours. Output includes Hashcat-compatible hashes.

**OPSEC Note**: This check requests TGS tickets from the KDC. Use `-OPSEC` flag to skip.

**Usage**:
```powershell
Get-KerberoastableAccounts
```

---

### Get-ASREPRoastableAccounts

**Purpose**: Finds accounts vulnerable to AS-REP Roasting.

**What it checks**:
- Accounts with DONT_REQUIRE_PREAUTH flag
- Account enabled status

**Security Impact**: AS-REP can be requested without credentials and cracked offline. Output includes Hashcat-compatible hashes.

**OPSEC Note**: This check requests AS-REP from the KDC. Use `-OPSEC` flag to skip.

**Usage**:
```powershell
Get-ASREPRoastableAccounts
```

---

### Get-UnixPasswordAccounts

**Purpose**: Finds accounts with passwords stored in Unix attributes.

**What it checks**:
- `unixUserPassword` attribute
- `userPassword` attribute
- `msSFU30Password` attribute
- `sambaNTPassword` attribute (Samba NT hash)
- `sambaLMPassword` attribute (Samba LM hash)

**Security Impact**: These attributes may contain passwords in cleartext or weak hash formats (DES, MD5). Samba NT hashes are directly usable for Pass-the-Hash attacks. Any domain user can read these attributes.

**Usage**:
```powershell
Get-UnixPasswordAccounts
```

---

## Rights Module

Analyzes Access Control Lists and permissions.

### Get-DangerousACLs

**Purpose**: Identifies dangerous permissions on the domain root object.

**What it checks**:
- DCSync rights (DS-Replication-Get-Changes + Get-Changes-All)
- GenericAll (Full Control)
- GenericWrite
- WriteDacl
- WriteOwner

**Security Impact**: Non-privileged accounts with these rights can escalate to Domain Admin through DCSync attacks or by modifying privileged objects.

**Usage**:
```powershell
# Show non-privileged accounts with dangerous rights (default)
Get-DangerousACLs

# Include privileged accounts (Domain Admins, Enterprise Admins, etc.)
Get-DangerousACLs -IncludePrivileged
```

**Parameters**:

| Parameter | Description |
|-----------|-------------|
| `-IncludePrivileged` | Include privileged accounts in output (shown in yellow) |

---

### Get-DangerousOUPermissions

**Purpose**: Scans all OUs for dangerous permissions.

**What it checks**:
- GenericAll on OUs containing privileged users
- Password reset rights on OUs
- Account control modification rights
- Group membership modification rights
- Object creation rights

**Security Impact**: Dangerous OU permissions enable attackers to reset passwords, modify group memberships, or create new privileged accounts within the OU.

**Usage**:
```powershell
Get-DangerousOUPermissions
```

---

### Get-PasswordResetRights

**Purpose**: Identifies who can reset passwords on privileged OUs.

**What it checks**:
- Accounts with User-Force-Change-Password right
- Accounts with AllExtendedRights on user objects
- Scope of password reset permissions

**Security Impact**: Password reset rights on admin accounts enable immediate account takeover without knowing the current password.

**Usage**:
```powershell
Get-PasswordResetRights
```

---

### Get-AddComputerRights

**Purpose**: Analyzes "Add Computer to Domain" permissions.

**What it checks**:
- `ms-DS-MachineAccountQuota` attribute (default: 10)
- ACLs on CN=Computers container
- GPO User Rights Assignment (SeMachineAccountPrivilege)

**Security Impact**: Creating rogue computer accounts enables RBCD attacks. Attackers can add a computer they control and configure delegation to compromise other resources.

**Usage**:
```powershell
# Show non-privileged accounts with add computer rights (default)
Get-AddComputerRights

# Include privileged accounts (Domain Admins, Account Operators, etc.)
Get-AddComputerRights -IncludePrivileged
```

**Parameters**:

| Parameter | Description |
|-----------|-------------|
| `-IncludePrivileged` | Include privileged accounts in output (shown in yellow) |

---

### Get-LAPSPermissions

**Purpose**: Identifies who can read LAPS passwords.

**What it checks**:
- Read permissions on `ms-Mcs-AdmPwd` (Legacy LAPS)
- Read permissions on `msLAPS-Password` (Windows LAPS)
- Non-privileged accounts with LAPS read access

**Security Impact**: Non-privileged accounts with LAPS read access can obtain local administrator passwords for computers, enabling lateral movement.

**Usage**:
```powershell
Get-LAPSPermissions
```

---

## Delegation Module

Identifies Kerberos delegation misconfigurations.

### Get-UnconstrainedDelegation

**Purpose**: Finds accounts with unconstrained delegation.

**What it checks**:
- User accounts with TRUSTED_FOR_DELEGATION flag
- Computer accounts with unconstrained delegation (excluding DCs)

**Security Impact**: Accounts can impersonate any user to any service. Attackers can use print spooler coercion or similar techniques to capture TGTs and impersonate any domain user.

**Usage**:
```powershell
Get-UnconstrainedDelegation
```

---

### Get-ConstrainedDelegation

**Purpose**: Finds accounts with constrained delegation.

**What it checks**:
- `msDS-AllowedToDelegateTo` attribute
- Protocol transition capability (S4U2Self)
- Delegation to sensitive services (LDAP, CIFS, HTTP)

**Security Impact**: While more restricted than unconstrained, constrained delegation to sensitive services like LDAP can enable privilege escalation to Domain Admin.

**Usage**:
```powershell
Get-ConstrainedDelegation
```

---

### Get-ResourceBasedConstrainedDelegation

**Purpose**: Finds Resource-Based Constrained Delegation (RBCD) configurations.

**What it checks**:
- `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute
- Which accounts can delegate to which resources

**Security Impact**: RBCD can be exploited if an attacker can modify the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on a computer object, enabling impersonation attacks.

**Usage**:
```powershell
Get-ResourceBasedConstrainedDelegation
```

---

## ADCS Module

Analyzes Active Directory Certificate Services.

### Get-CertificateAuthority

**Purpose**: Enumerates Certificate Authority infrastructure.

**What it checks**:
- CA servers and their configuration
- Published certificate templates
- Enrollment endpoints (HTTP, RPC)

**Security Impact**: Informational - provides an overview of the PKI infrastructure for further analysis. Identifies attack surface for ADCS exploits.

**Usage**:
```powershell
Get-CertificateAuthority
```

---

### Get-ADCSTemplate

**Purpose**: Lists all certificate templates and their configuration.

**What it checks**:
- Template name and OID
- Enrollment permissions
- Extended Key Usage (EKU)
- Authentication capability settings

**Security Impact**: Informational - required to understand which templates might be vulnerable. Templates with Client Authentication EKU are particularly interesting.

**Usage**:
```powershell
Get-ADCSTemplate
```

---

### Get-ADCSVulnerabilities

**Purpose**: Identifies vulnerable ADCS configurations.

**What it checks**:

| ESC   | Vulnerability                                            |
| ----- | -------------------------------------------------------- |
| ESC1  | Template allows enrollee-supplied SAN + client auth      |
| ESC2  | Template allows any purpose EKU                          |
| ESC3  | Enrollment agent template abuse                          |
| ESC4  | Template with vulnerable ACLs                            |
| ESC5  | Vulnerable PKI container permissions                     |
| ESC8  | Web enrollment detection (HTTP/HTTPS + NTLM/EPA config)  |
| ESC9  | No security extension + client auth (StrongCertificateBindingEnforcement) |
| ESC13 | Issuance policy linked to AD group                       |
| ESC15 | Schema v1 + enrollee-supplied subject (CVE-2024-49019)   |

**Not implemented**: ESC6 (EDITF flag requires registry access, not LDAP), ESC7 (ManageCA/ManageCertificates permissions require DCOM/RPC, not LDAP)

**ESC5 Details**: Checks dangerous permissions on PKI container objects:
- `CN=Public Key Services` - Root PKI container
- `CN=Certificate Templates` - Allows creating/modifying templates
- `CN=Enrollment Services` - Controls enrollment services
- `CN=NTAuthCertificates` - Controls trusted CAs for Kerberos
- `CN=OID` - Controls issuance policies (ESC13-related)

Dangerous rights: GenericAll, WriteDacl, WriteOwner, GenericWrite. If unprivileged users have these permissions, they can manipulate the entire PKI infrastructure.

**Security Impact**: ADCS vulnerabilities can allow any domain user to obtain certificates for any other user, including Domain Admins, leading to full domain compromise.

**Usage**:
```powershell
# Show non-privileged accounts with enrollment rights (default)
Get-ADCSVulnerabilities

# Include privileged accounts (Domain Admins, Enterprise Admins, etc.)
Get-ADCSVulnerabilities -IncludePrivileged
```

**Parameters**:

| Parameter | Description |
|-----------|-------------|
| `-IncludePrivileged` | Include privileged accounts in output (shown in yellow) |

---

## Accounts Module

Analyzes privileged account security.

### Get-PrivilegedGroupMembers

**Purpose**: Lists members of privileged groups.

**What it checks**:
- Domain Admins members
- Enterprise Admins members
- Schema Admins members
- Administrators members
- Account Operators members
- Backup Operators members
- Server Operators members
- Print Operators members

**Security Impact**: Identifies all accounts with elevated privileges. Large numbers of privileged accounts increase attack surface.

**Usage**:
```powershell
# Show non-privileged accounts with group membership (default)
Get-PrivilegedGroupMembers

# Include privileged accounts (Domain Admins, etc.) in output
Get-PrivilegedGroupMembers -IncludePrivileged
```

**Parameters**:

| Parameter | Description |
|-----------|-------------|
| `-IncludePrivileged` | Include privileged accounts in output (shown in yellow) |

---

### Get-SIDHistoryInjection

**Purpose**: Detects accounts with privileged SIDs in sIDHistory (SID History Injection attack vector).

**What it checks**:
- User and computer accounts with sIDHistory attribute set
- Privileged SIDs in sIDHistory (Domain Admins, Enterprise Admins, Administrators, etc.)
- Operator group SIDs (Account Operators, Backup Operators, etc.)
- Non-privileged SIDs as migration artifacts (optional)

**Security Impact**: SID History Injection allows attackers to add privileged SIDs to an account's sIDHistory, granting those privileges without being a direct member of the privileged group. This is a critical persistence and privilege escalation technique.

| SID Type in sIDHistory | Severity |
|-----------------------|----------|
| Domain Admins (-512) | Critical |
| Enterprise Admins (-519) | Critical |
| Administrators (S-1-5-32-544) | Critical |
| Account Operators (S-1-5-32-548) | High |
| Backup Operators (S-1-5-32-551) | High |
| Non-privileged SIDs | Info (migration artifact) |

**Usage**:
```powershell
# Check for privileged SIDs only
Get-SIDHistoryInjection

# Include non-privileged SIDs (migration artifacts)
Get-SIDHistoryInjection -IncludeNonPrivileged
```

**Parameters**:

| Parameter | Description |
|-----------|-------------|
| `-IncludeNonPrivileged` | Also report accounts whose sIDHistory contains only non-privileged SIDs (domain migration artifacts). These are shown in a separate section as Hints. Without this switch, only accounts with privileged SIDs (Domain Admins, Operators, etc.) in sIDHistory are reported. |

**Output Properties**:
- `privilegedSIDHistory`: Formatted list of privileged SIDs found
- `privilegedSIDHistoryCount`: Number of privileged SIDs
- `sidHistoryInjectionRisk`: Risk level (CRITICAL for privileged SIDs)

---

### Get-ManagedServiceAccountSecurity

**Purpose**: Analyzes security of (Group) Managed Service Accounts.

**What it checks**:
- gMSA password readers (who can read the managed password)
- Constrained delegation configuration
- Password age and rotation status

**Security Impact**: Overly permissive gMSA password readers can obtain service account credentials. Misconfigured delegation enables privilege escalation.

**Usage**:
```powershell
Get-ManagedServiceAccountSecurity
```

---

### Get-ProtectedUsersStatus

**Purpose**: Identifies privileged accounts not in Protected Users group.

**What it checks**:
- Membership of privileged accounts in Protected Users group
- Which admin accounts are missing protection

**Security Impact**: Protected Users group provides: no NTLM authentication, no delegation, no DES/RC4 encryption, Kerberos TGT limited to 4 hours. Accounts outside this group are more vulnerable to credential theft.

**Usage**:
```powershell
Get-ProtectedUsersStatus
```

---

### Get-InactiveAdminAccounts

**Purpose**: Finds privileged accounts that haven't been used.

**What it checks**:
- Accounts inactive for 90+ days
- Accounts that have never logged on
- Enabled accounts with old passwords

**Security Impact**: Inactive admin accounts are forgotten attack vectors. They may have weak/known passwords and can be compromised without detection.

**Usage**:
```powershell
Get-InactiveAdminAccounts
```

---

### Get-AdminPasswordNeverExpires

**Purpose**: Identifies privileged accounts with non-expiring passwords.

**What it checks**:
- Password expiration flag on privileged accounts
- Which admin accounts bypass password rotation

**Security Impact**: Violates password rotation policies and increases exposure window. Compromised passwords remain valid indefinitely.

**Usage**:
```powershell
Get-AdminPasswordNeverExpires
```

---

### Get-AdminReversibleEncryption

**Purpose**: Finds privileged accounts storing passwords with reversible encryption.

**What it checks**:
- Reversible encryption flag on privileged accounts
- Which admin accounts have this dangerous setting

**Security Impact**: Passwords can be decrypted from ntds.dit if an attacker obtains the database.

**Usage**:
```powershell
Get-AdminReversibleEncryption
```

---

### Get-PasswordNotRequired

**Purpose**: Detects enabled user accounts with the PASSWD_NOTREQD flag set.

**What it checks**:
- Enabled user accounts with PASSWD_NOTREQD flag (UAC bit 32)
- Whether affected accounts are privileged or service accounts
- Last password change date for risk assessment

**Security Impact**: Accounts with the "Password Not Required" flag can bypass the domain password policy and may have an empty password. While the flag alone does not guarantee an empty password (a password may have been set later), it indicates a hygiene issue and potential attack vector.

**Usage**:
```powershell
Get-PasswordNotRequired
```

---

### Get-NonDefaultUserOwners

**Purpose**: Finds user accounts owned by non-default principals.

**What it checks**:
- User account owner attribute (nTSecurityDescriptor)
- Users owned by accounts other than Domain Admins

**Security Impact**: Object owners have implicit WriteDACL permission, allowing them to modify the object's security descriptor. If a low-privileged user owns a user account, they can grant themselves full control over that account, potentially leading to account takeover.

| Owner Type | Severity |
|------------|----------|
| Domain Admins | Expected (default) |
| Enterprise Admins | Expected |
| Regular user | Medium (privilege escalation risk) |
| Service account | Medium |

**Noise Reduction**: Exchange Health Mailboxes (`HealthMailbox*` in `CN=Monitoring Mailboxes,CN=Microsoft Exchange System Objects`) are filtered by default as they are expected to be owned by the Exchange server that created them.

**Usage**:
```powershell
# Default (excludes Exchange Health Mailboxes)
Get-NonDefaultUserOwners

# Include Exchange Health Mailboxes
Get-NonDefaultUserOwners -IncludeHealthMailboxes
```

**Parameters**:

| Parameter | Description |
|-----------|-------------|
| `-IncludeHealthMailboxes` | Include Exchange Health Mailboxes in output |

**Output Properties**:
- `Owner`: Name of the account that owns the user object
- `OwnerSID`: SID of the owner

**Common Causes**:
- User created by a non-admin via delegation
- Ownership explicitly changed post-creation
- Migration artifacts

---

## GPO Module

Analyzes Group Policy security.

### Get-GPOPermissions

**Purpose**: Identifies who can modify Group Policy Objects.

**What it checks**:
- Write permissions on GPO objects
- Non-privileged accounts with GPO edit rights
- GPO linkage to sensitive OUs
- Affected computer count (including Domain Controllers)

**Security Impact**: GPO modification enables code execution on all computers where the GPO is linked. An attacker with GPO write access can deploy malware domain-wide.

**Usage**:
```powershell
# Show non-privileged accounts with GPO modification rights (default)
Get-GPOPermissions

# Include privileged accounts (Domain Admins, Group Policy Creator Owners, etc.)
Get-GPOPermissions -IncludePrivileged
```

**Parameters**:

| Parameter | Description |
|-----------|-------------|
| `-IncludePrivileged` | Include privileged accounts in output (shown in yellow) |

**Output Properties**:
- `VulnerableIdentity`: Account(s) with dangerous GPO permissions
- `Scope`: GPO scope (DOMAIN-WIDE, Linked to X OU(s), or NOT LINKED)
- `LinkedOUs`: Full DN of OUs where the GPO is linked
- `AffectedComputers`: Number of computers affected by this GPO

---

### Get-GPOLocalGroupMembership

**Purpose**: Analyzes GPO-defined local group memberships.

**What it checks**:
- Local Administrators group additions via GPO
- Remote Desktop Users additions
- Other privileged local group modifications

**Security Impact**: GPOs adding users to local admin groups can provide persistent privileged access across many systems.

**Usage**:
```powershell
Get-GPOLocalGroupMembership
```

---

### Get-GPOScheduledTasks

**Purpose**: Finds scheduled tasks configured via GPO.

**What it checks**:
- Immediate scheduled tasks in GPOs
- Scheduled task run-as accounts
- Embedded credentials in tasks

**Security Impact**: Scheduled tasks may run with elevated privileges or contain cleartext credentials. Attackers can modify tasks for persistence.

**Usage**:
```powershell
Get-GPOScheduledTasks
```

---

### Get-GPOScriptPaths

**Purpose**: Detects Logon/Logoff/Startup/Shutdown scripts distributed via Group Policy.

**What it checks**:
- Startup/Shutdown scripts (run as SYSTEM in Machine context)
- Logon/Logoff scripts (run in user context)
- Scripts loaded from UNC paths (credential exposure risk)
- PowerShell scripts configured via psscripts.ini

**Security Impact**: GPO scripts execute automatically on target systems. Startup and Shutdown scripts run as SYSTEM, making them high-value targets for privilege escalation. Scripts loaded from UNC paths expose machine credentials on the network.

**Usage**:
```powershell
Get-GPOScriptPaths
```

**Output Properties**:
- `GPOName`: Name of the GPO deploying the script
- `ScriptType`: Startup, Shutdown, Logon, or Logoff
- `ScriptPath`: Path to the script
- `Parameters`: Script parameters (if configured)
- `ExecutionContext`: SYSTEM or User
- `ScriptLanguage`: PowerShell, Batch, VBScript, etc.
- `HasUNCPath`: Whether the script is loaded from a network share

---

## Computer Module

Analyzes computer account security.

### Get-LAPSConfiguration

**Purpose**: Checks LAPS deployment status across the domain.

**What it checks**:
- Computers without LAPS configured
- LAPS schema presence vs. actual deployment

**Security Impact**: Computers without LAPS use shared or predictable local admin passwords, enabling pass-the-hash attacks for lateral movement.

**Usage**:
```powershell
Get-LAPSConfiguration
```

---

### Get-OutdatedComputers

**Purpose**: Finds computers running outdated operating systems.

**What it checks**:
Uses a central lifecycle database (`adPEAS-SoftwareLifecycle.ps1`) with EOL dates from Microsoft. Detection is dynamic — as dates pass, systems are automatically flagged.

| Operating System | EOL Date | Status (as of 2026) |
|-----------------|----------|---------------------|
| Windows XP | 2014-04-08 | EOL |
| Windows Vista | 2017-04-11 | EOL |
| Windows 7 | 2023-01-10 | EOL (incl. ESU) |
| Windows 8 / 8.1 | 2016/2023 | EOL |
| Windows 10 | 2025-10-14 | EOL |
| Windows Server 2003 | 2015-07-14 | EOL |
| Windows Server 2008 (R2) | 2023-01-10 | EOL (incl. ESU) |
| Windows Server 2012 (R2) | 2026-10-13 | EOL (incl. ESU) |
| Windows Server 2016 | 2027-01-12 | Approaching EOL |

**Security Impact**: End-of-life systems no longer receive security patches and are vulnerable to known exploits.

**Usage**:
```powershell
Get-OutdatedComputers
```

---

### Get-InfrastructureServers

**Purpose**: Identifies critical infrastructure servers.

**What it checks**:
- Domain Controllers
- Exchange Servers
- MSSQL Servers (via `MSSQLSvc/` SPN)
- SCCM/ConfigMgr Servers
- SCOM Servers
- Entra ID Connect (Azure AD Connect)

**Security Impact**: Informational - identifies high-value targets for attackers. Compromise of these systems often leads to domain compromise.

**Usage**:
```powershell
Get-InfrastructureServers
```

---

### Get-NonDefaultComputerOwners

**Purpose**: Finds computers owned by non-privileged users.

**What it checks**:
- Computer object owner attribute
- Computers owned by regular users instead of Domain Admins

**Security Impact**: Computer owners can modify the object, potentially adding themselves to `msDS-AllowedToActOnBehalfOfOtherIdentity` and enabling RBCD attacks.

**Usage**:
```powershell
Get-NonDefaultComputerOwners
```

---

## Application Module

Analyzes enterprise application infrastructure.

### Get-ExchangeInfrastructure

**Purpose**: Enumerates Exchange Server infrastructure.

**What it checks**:
- Exchange Organization presence (msExchOrganizationContainer)
- Exchange server versions via LDAP attributes and HTTP endpoint probing
- Extended Protection for Authentication (EPA) status on Exchange web endpoints
- Exchange Trusted Subsystem group membership (high-privilege service accounts)
- Exchange Windows Permissions group membership (can have DCSync rights via WriteDacl on domain root)
- Organization Management group membership (full Exchange admin control)

**Security Impact**: Exchange servers often have high privileges in AD. The "Exchange Windows Permissions" group has WriteDacl on the domain root by default, which can be abused for DCSync. "Exchange Trusted Subsystem" members can modify any Exchange object. Outdated Exchange versions have known vulnerabilities (ProxyLogon, ProxyShell). Missing EPA enables NTLM relay attacks against Exchange endpoints.

**Usage**:
```powershell
Get-ExchangeInfrastructure
```

---

### Get-SCCMInfrastructure

**Purpose**: Enumerates SCCM/MECM infrastructure using LDAP queries against Active Directory.

**What it checks**:
- System Management container presence
- SCCM site codes and site hierarchy via `mSSMSSite` AD objects
- Management Points and site type determination (CAS / Primary / Secondary) via `mSSMSManagementPoint` objects with XML capabilities parsing
- SCCM server identification via SPNs (SMS*, SMSSQLBKUP*)
- SCCM client count via CmRcService SPN (compromise blast radius)
- PXE/WDS boot servers (connectionPoint, intellimirrorSCP objects)
- SCCM service accounts
- SCCM-related security groups

**Security Impact**: SCCM can deploy software to all managed systems. A Central Administration Site (CAS) controls the entire hierarchy and is a Tier 0 asset. PXE boot servers can be targeted for credential theft or OS deployment manipulation. The number of SCCM clients indicates the blast radius of a potential compromise.

**Usage**:
```powershell
Get-SCCMInfrastructure
```

---

### Get-SCOMInfrastructure

**Purpose**: Enumerates SCOM infrastructure.

**What it checks**:
- SCOM management servers
- Agent configuration
- RunAs accounts

**Security Impact**: SCOM runs agents on many systems with local admin rights. RunAs accounts are often overly privileged. Compromise enables lateral movement.

**Usage**:
```powershell
Get-SCOMInfrastructure
```

---

## Navigation

- [Previous: Authentication-Methods](03-Authentication-Methods.md)
- [Next: BloodHound-Collector](05-BloodHound-Collector.md)
- [Back to Home](00-Home.md)