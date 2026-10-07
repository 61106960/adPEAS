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

adPEAS performs 43+ security checks organized into 9 categories:

| Module        | Checks | Description                               |
| ------------- | ------ | ----------------------------------------- |
| Domain        | 5      | Domain configuration, trusts, policies    |
| Creds         | 7      | Credential exposure vectors               |
| Rights        | 6      | ACL and permission analysis               |
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

### Get-BitLockerRecoveryKeyAccess

**Purpose**: Tests which BitLocker recovery keys the current user can read from AD.

**What it checks**:
- Readable `msFVE-RecoveryPassword` on `msFVE-RecoveryInformation` objects (escrowed as child objects below each computer)
- The 48-digit recovery password, recovery/volume GUID and escrow time
- The computer each recovery key belongs to (derived from the parent DN)

**How it works**: A single domain-wide, server-side filtered subtree query `(&(objectClass=msFVE-RecoveryInformation)(msFVE-RecoveryPassword=*))`. The presence filter is ACL-gated, so the DC only returns recovery objects whose password the current user is actually allowed to read — no per-computer enumeration. If BitLocker recovery escrow is not used in the domain (no `msFVE-RecoveryInformation` schema/objects), the expensive query is skipped and the result is cached for the session.

**Security Impact**: Reading a recovery key is often legitimate (recovery/helpdesk roles) and is reported as a *Hint*, not a Finding. A readable key lets the holder unlock the computer's BitLocker-protected volume offline (given physical access or a disk image), so unexpectedly broad read access can indicate over-permissive delegation on the computer OUs.

**Usage**:
```powershell
Get-BitLockerRecoveryKeyAccess
```

---

### Get-CredentialRoaming

**Purpose**: Reports users whose DPAPI master keys and private keys are stored in Active Directory, and whether anybody can read them.

**What it checks**:
- Which user objects carry roamed credential material (`msPKIDPAPIMasterKeys`, `msPKIAccountCredentials`), and when it last synchronised (`msPKIRoamingTimeStamp`)
- Whether those two attributes are marked confidential in the schema (`searchFlags` bit 7, `fCONFIDENTIAL`, value 128)
- Which principals hold a **delegated** read of the attributes on the containers that carry the material
- Whether any of the affected accounts, or any of the delegated principals, are privileged

**How it works**: Two server-side presence filters, `(msPKIDPAPIMasterKeys=*)` and `(msPKIAccountCredentials=*)`. The blob attributes themselves are deliberately **not** retrieved — only the account name, DN and timestamp travel. adPEAS has no use for the ciphertext, and writing base64-encoded DPAPI master keys into an HTML report would create the very exposure the check reports. Both attributes are also excluded from display centrally, so no other check can surface them either. Readability is then read once per forest from the two `attributeSchema` objects; the schema object names (`ms-PKI-DPAPIMasterKeys`) differ from the attribute names, so both are matched. The weaker of the two attributes decides, and a forest whose schema cannot be read is reported as *unknown* rather than as either verdict. Finally the containers holding those users are analysed for delegated read ACEs via `Get-OUPermissions -CheckType CredentialRoaming` — once per container, not once per user, since a container's DACL already carries what it inherits from above.

**Security Impact**: The attributes hold ciphertext, not plaintext — a master key blob is sealed with a pre-key derived from the user's password **and** with the domain backup key, and the private keys are sealed with those master keys in turn. Material present is therefore a *Hint*: private keys are sitting in the directory where they need not be, and anybody who later obtains the user's hash or the domain backup key can use them. Material a low-privileged account can read is a *Finding*: without the confidential flag, readability follows the ordinary read ACEs of the user object, so in a default domain every authenticated user harvests the roamed material of every other user with a plain LDAP read. Combined with the domain backup key — which every domain administrator holds — that yields another user's private keys offline, and a roamed client-authentication certificate then authenticates as that user without their password. None of this constrains anybody with DCSync, a copy of `ntds.dit` or an AD backup.

**Delegated reads**: the confidential flag covers the blanket case; a delegated read is the one it says nothing about, and the one most likely to have happened by accident. Whether such a right is live depends on the schema, so the same ACE is a *Finding* in one forest and a dormant *Hint* in another:

| ACE grants | Attributes confidential | Verdict |
|---|---|---|
| `ReadProperty` | no | works today — Finding |
| `ReadProperty` | yes | blocked by the flag — Hint (live the moment it is cleared) |
| `ReadProperty` + `ControlAccess`, or `GenericAll` | either | works today — Finding |

A `ControlAccess`-only ACE scoped to one of the attributes counts as a grant: the `ReadProperty` half usually needs no delegation at all, because the default ACL already gives every authenticated user a blanket read of all properties. An *unscoped* `ControlAccess` ACE ("all extended rights") is not claimed here — that is `Get-DangerousACLs`' business. Reads covering only `ms-PKI-RoamingTimeStamp` are rated Low and drop out of a default report: a timestamp is a date, not a credential. Privileged holders are hidden unless `-IncludePrivileged`.

**Not covered**: an ACE set directly on a single user object, bypassing the container; and a delegation on a container whose users have never roamed anything — there is nothing there to read, and it becomes visible as soon as the first user synchronises.

**Usage**:
```powershell
Get-CredentialRoaming

# Also list privileged principals holding a delegated read
Get-CredentialRoaming -IncludePrivileged
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

### Get-GPOUserRightsAssignment

**Purpose**: Compares the Windows user rights a GPO assigns against the set Windows ships, and reports the difference.

**Why a comparison**: the `[Privilege Rights]` section of `GptTmpl.inf` is absolute, not additive. The principals a GPO lists for a right become the complete set of holders on every computer the policy reaches. The GPO's list and the documented default list therefore describe the same thing, and the difference between them is what matters — in both directions.

**What it checks**:
- The `[Privilege Rights]` section of `GptTmpl.inf` in every GPO
- **Holders beyond the Windows default** — the escalation risk, reported at the right's own tier. Privilege-escalation/credential privileges (SeDebug, SeBackup, SeRestore, SeTakeOwnership, SeImpersonate, SeAssignPrimaryToken, SeCreateToken, SeTcb, SeLoadDriver, SeEnableDelegation, SeSyncAgent, SeManageVolume, SeSecurity, SeRelabel, SeTrustedCredManAccess) are Findings; logon rights (RDP / service / batch / interactive logon, change system time, shutdown) are Hints
- **Default holders the GPO removes** — reported as a Note. Usually deliberate hardening, occasionally a service about to break
- Rights granted to broad principals (Everyone, Authenticated Users, Domain Users) — escalated to Finding regardless of tier
- The correct baseline for the machines the policy reaches: domain controllers and member computers have different defaults, and a policy reaching both is measured against the union
- Whether the GPO currently applies at all (disabled half, no link)
- Maps each finding to the affected OUs / domain-wide scope via GPO links

**Why not a filter on the holder**: an identity filter — hide privileged SIDs, operator groups, service identities — fails in both directions. `Backup Operators` holding `SeDebugPrivilege` is not a Windows default and is a clean path to SYSTEM, and an identity filter hides it because the group looks privileged. Meanwhile which principals hold a right by default depends on the right, not on how privileged the holder looks.

**Baseline gaps are visible, not guessed**: a right whose default set is not established carries no baseline, and the finding says so. `SeServiceLogonRight` is that case — what holds it depends on which products are installed — and the check falls back to an identity filter for that one right.

**Security Impact**: A single GPO can grant a low-level privilege (e.g. SeDebugPrivilege → SYSTEM, SeBackupPrivilege → read SAM/NTDS) across every computer it applies to — a direct, often domain-wide privilege-escalation and lateral-movement path. `SeMachineAccountPrivilege` is covered separately by Get-AddComputerRights; `Se*Deny*` rights take access away and are not evaluated.

**Usage**:
```powershell
# Show the assignments that depart from the Windows default (default)
Get-GPOUserRightsAssignment

# Show every assignment, including the ones matching the default
Get-GPOUserRightsAssignment -IncludeDefaults
```

**Parameters**:

| Parameter | Description |
|-----------|-------------|
| `-IncludeDefaults` | Also report assignments that match the Windows default |
| `-IncludePrivileged` | Alias of `-IncludeDefaults`, kept so existing invocations keep working |

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
- Delegation whose target SPN points at a Domain Controller

**Security Impact**: While more restricted than unconstrained, constrained delegation to a Domain Controller enables privilege escalation to Domain Admin. The service class in the SPN is not a limit: all SPNs registered to one host account share a single key, so a ticket issued for one service can be rewritten to another.

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
| ESC3  | Enrollment agent template abuse (both the agent template and its target) |
| ESC4  | Template with vulnerable ACLs                            |
| ESC5  | Vulnerable PKI container permissions                     |
| ESC8  | Web enrollment detection (HTTP/HTTPS + NTLM/EPA config)  |
| ESC9  | No security extension + client auth                      |
| ESC13 | Issuance policy linked to AD group                       |
| ESC15 | Schema v1 + enrollee-supplied subject (CVE-2024-49019)   |

Two more are covered by other checks, because the misconfiguration does not live on a
template or a CA:

| ESC   | Vulnerability                                            | Check |
| ----- | -------------------------------------------------------- | ----- |
| ESC10 | Weak certificate mapping on the domain controllers - `StrongCertificateBindingEnforcement=0`, or the UPN bit in `CertificateMappingMethods` | `Get-GPORegistrySettings`, where Group Policy deploys them |
| ESC14 | Weak explicit mapping in `altSecurityIdentities`, and write access to that attribute on a privileged account | `Get-WeakCertificateMapping` |

**Deliberately not implemented**: ESC6 (`EDITF_ATTRIBUTESUBJECTALTNAME2`), ESC7
(`ManageCA` / `ManageCertificates`), ESC11 (`IF_ENFORCEENCRYPTICERTREQUEST`) and ESC16
(`DisableExtensionList`).

All four live in the registry of the CA host, under
`HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration`, and reading them needs
administrative access to that host - either remote registry as a local administrator, or
the `ICertAdminD2` RPC interface with `ManageCA`. adPEAS is built to run as an ordinary
domain user. A check that answers "cannot tell" in the normal case is worse than no check:
a quiet result reads as a clean domain. Where those rights do exist, Certipy reports all
four.

ESC12 (private key on a YubiHSM, extractable with shell access to the CA) is outside what
any directory scan can see.

**ESC5 Details**: Checks dangerous permissions on PKI container objects:
- `CN=Public Key Services` - Root PKI container
- `CN=Certificate Templates` - Allows creating/modifying templates
- `CN=Enrollment Services` - Controls enrollment services
- `CN=NTAuthCertificates` - Controls trusted CAs for Kerberos
- `CN=AIA` - Controls the CA certificates published for chain building
- `CN=CDP` - Controls where revocation lists are looked up
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

**Locating a reported GPO in SYSVOL**: every finding that comes from a Group Policy names
the policy the same way, whichever check produced it, so it can be opened without guessing:

- `GPOName` - the display name. Convenient, but not unique and not a path.
- `GPOGUID` - the policy's identifier, and literally its folder name under
  `\\<domain>\SYSVOL\<domain>\Policies\`.
- `GPOPath` - the full path to that folder, as the directory records it in
  `gPCFileSysPath`. Read from LDAP rather than assembled from the GUID, so that it is the
  same string in every section: `gPCFileSysPath` names the domain, while adPEAS reads
  SYSVOL through one specific domain controller, and the two spell the same folder
  differently.

Checks that report a **setting found inside** a policy add one more row:

- `SourceFile` - the file inside the GPO folder the setting was read from, relative to it,
  for example `Machine\Registry.pol` or
  `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf`. The leading `Machine` or `User`
  matters: both halves of a policy carry files of the same name and they reach different
  targets.

So the full path to the evidence behind such a finding is `<GPOPath>\<SourceFile>`.

Checks that report the **GPO object itself** - `Get-GPOPermissions`, the SMB and LDAP
signing checks, `Get-AddComputerRights` - have no `SourceFile`, because the policy is the
finding rather than a file inside it. They additionally show `distinguishedName`, which has
no counterpart among the setting-level findings. Under the hood these are native LDAP
objects and the three shared rows are relabelled for display only, so `displayName`, `Name`
and `gPCFileSysPath` keep their LDAP names as properties and in the JSON export.

One deliberate departure: the credential checks (`Get-CredentialExposure`) print the
complete path to the file as `FilePath` instead, because they also scan NETLOGON and a
caller-supplied `-Path`, where there is no GPO folder to be relative to - and for a finding
that does come from a GPO, that full path already contains the GUID.

**Dormant policies are held back by default**: a service provider who ships a library of
Group Policies and links a handful of them leaves the rest configured and applying nowhere.
Reporting their settings buries the policies that are live, so a finding whose policy is
not linked or not enabled is not listed. A summary gives the count and the reason, and names
each policy that was held back:

```
[*] 34 finding(s) hidden on 4 GPO(s):
[*] Not linked (2):
[*]   Addon AppServer-VIM V25.09             {A9420797-B784-487A-BA44-A0D972CE4527}
[*]   Systemhaertung Ws2022 Basis V25.02     {0217CBDE-4840-4E06-B245-D91F8B4B3C19}
[*] Disabled (2):
[*]   Addon WSUS V1.0                        {51462F84-B01D-4104-A4E5-BA2CF3C8AACC}
[*]   HL-MMI V25.09                          {C6372006-3F3F-4D9E-AD99-C8A99D743ABF}
```

One line per **policy**, not per finding, so ten registry values in one unlinked GPO are one
line. The headline counts findings and the group headers count policies, which is why it names
its unit whenever the two numbers differ.

Laid out as every other adPEAS row is: display name left, GUID on column 45. Both, because the
name is what a reader recognises and the GUID is the folder under
`\\<domain>\SYSVOL\<domain>\Policies\` they need in order to go and look. A name longer than
the column pushes its own GUID right rather than being truncated — a cut-off GPO name is no
longer findable in SYSVOL.

Unlinked policies come first, since an unlinked policy is a cleanup candidate while a disabled
one is a switch somebody threw on purpose, and within a group the order is by name so two runs
against the same domain print the same thing. When only one reason occurs there is no group
header: the summary keeps the sentence and the rows follow it directly. The list is not
truncated — its length is bounded by the number of policies in the domain, and cutting it off
would leave `-IncludeInactive` as the only way to learn the missing names, which prints every
held-back finding and is far more output than a cap saves.

**A configuration that exposes nothing is counted, not printed.** The same reasoning in a
second direction: adPEAS reports a right or a setting granted to somebody who should not have
it, so the opposite - a GPO that hardens - is worth one line and not a block. Two checks apply
it today, both behind `-IncludeDefaults` (aliased `-IncludePrivileged`, which `Invoke-adPEAS`
passes, so the hint naming it is reachable from a full scan):

- `Get-GPOUserRightsAssignment`: an assignment that only *removes* default holders. Nine of
  those printed as full blocks ahead of two real findings is how the rule was arrived at. An
  assignment that adds *and* removes keeps its `RemovedFromDefault` row - there the removals
  are the rest of that right's holder set, not a separate claim.
- `Get-GPOPointAndPrint`: a configuration whose verdict is *Hardened* or *controls no driver
  installation*. Printing one meant eight rows agreeing in green with the `Exploitability`
  line above them. The User Configuration case stays visible: Windows ignores it (KB2307161),
  so it is not an exposure either, but somebody hardened and it does not take effect - a
  different statement from a hardening that works.

It is held back, not dropped. `-IncludeInactive` on the individual check lists them,
greyed, with `LinkedOUs` and `GPOStatus` on the row saying why. The switch is deliberately
not available on `Invoke-adPEAS`, so the hint naming it appears only when a check was
called directly.

Three things worth knowing about where the line is drawn:

- It applies to checks that report a **setting inside** a policy. The credential checks are
  exempt: a `cpassword` in `Groups.xml` is readable by Authenticated Users whether the
  policy is linked or not, so linkage has no bearing on the exposure. `Get-GPOPermissions`
  is exempt too - who may edit a dormant policy still matters, because editing it and then
  linking it is a two-step path - and it shows `LinkedOUs` and `GPOStatus` anyway.
- "Not linked or not enabled" is read from the directory: no enabled link, or the relevant
  configuration half switched off. It is **not** an RSoP answer. A WMI filter that matches
  nothing, security filtering on the Apply Group Policy right, Enforced and block
  inheritance are all invisible, and a policy linked to an OU holding no computer counts as
  active.
- Nothing is held back when the linkage could not be read. An enumeration that failed
  answers unknown, and a finding is never demoted on missing information.

Suppressing a finding also keeps it out of the HTML report and the JSON export, so a scan
comparison will show such a finding as gone once someone disables a link.

**Reading `EffectiveSetting`**: where several GPOs configure the same thing, this row says
which of them decides the value, and why. It replaced a `True`/`False` called
`IsEffectiveSetting`, which could not express the answer - a `False` meant either "a
higher-priority policy overrides this one" or "this policy reaches no machine at all", and
those call for completely different work.

| Row reads | Means |
|-----------|-------|
| `Yes - wins precedence on the Domain Controllers OU` | Linked at or below the Domain Controllers OU and first in link order. This is the value the DCs run with. |
| `Yes - wins precedence at the domain root` | Linked at the domain root, with no Domain Controllers OU policy outranking it. |
| `Yes - applies on its linked OUs; no precedence comparison there` | Linked to ordinary OUs and applies to the machines in them. The caveat is literal: adPEAS does not compare link order below the domain level, so two policies on the same OU with opposite values are both reported this way. |
| `No - overridden by '<name>' (link order <n>)` | Configured, reaches machines, but another policy wins. Read the named policy to see what actually applies. |
| `No - the policy is linked nowhere` | Configured and linked to nothing. It changes nothing today, and is worth cleaning up or linking. |
| `No - every link is disabled` | Linked, but every link is switched off, so it reaches nothing either. `GPOStatus` says the same in its own row. |

`EffectiveSetting` only weighs linkage and link order. Whether the policy's computer
configuration is switched off is a separate question, answered by `GPOStatus`.

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
- `GPOGUID`: The GPO's folder name under SYSVOL
- `GPOPath`: Full path to that folder
- `SourceFile`: The `scripts.ini` / `psscripts.ini` the entry was parsed from, relative to
  the GPO folder - not to be confused with `ScriptPath` below, which is the script that
  .ini points at
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