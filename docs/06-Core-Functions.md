# Core Functions Reference

Reference documentation for adPEAS v2 core data retrieval functions.

---

## Overview

Core functions provide LDAP-based data retrieval and manipulation for Active Directory. They are the foundation for all security checks and can be used independently for custom operations.

### Query Functions

| Function | Purpose |
|----------|---------|
| [Get-DomainUser](#get-domainuser) | Query user accounts |
| [Get-DomainComputer](#get-domaincomputer) | Query computer accounts |
| [Get-DomainGroup](#get-domaingroup) | Query groups and membership |
| [Get-DomainGPO](#get-domaingpo) | Query Group Policy Objects |
| [Get-DomainObject](#get-domainobject) | Generic AD object query |
| [Get-ObjectACL](#get-objectacl) | Retrieve Access Control Lists |
| [Get-CertificateTemplate](#get-certificatetemplate) | Query certificate templates |

### Modification & Creation Functions

For detailed documentation of `Set-*` and `New-*` functions (operations, attack techniques, cleanup), see [Set- & New-Module Reference](07-Set-Modules.md).

| Function | Purpose |
|----------|---------|
| [Set-DomainObject](07-Set-Modules.md#set-domainobject) | Modify AD objects (attributes and ACLs) — low-level base function |
| [Set-DomainUser](07-Set-Modules.md#set-domainuser) | Modify user accounts (password, SPN, delegation, etc.) |
| [Set-DomainComputer](07-Set-Modules.md#set-domaincomputer) | Modify computer accounts (RBCD, delegation, etc.) |
| [Set-DomainGroup](07-Set-Modules.md#set-domaingroup) | Modify groups (add/remove members) |
| [Set-DomainGPO](07-Set-Modules.md#set-domaingpo) | Modify GPO attributes and links |
| [Set-CertificateTemplate](07-Set-Modules.md#set-certificatetemplate) | Modify certificate template settings |
| [New-DomainUser](07-Set-Modules.md#new-domainuser) | Create new user accounts |
| [New-DomainComputer](07-Set-Modules.md#new-domaincomputer) | Create new computer accounts |
| [New-DomainGroup](07-Set-Modules.md#new-domaingroup) | Create new groups |
| [New-DomainGPO](07-Set-Modules.md#new-domaingpo) | Create new Group Policy Objects |

---

## Get-DomainUser

Retrieves user objects from Active Directory (wrapper for Get-DomainObject).

> **Note:** By default, attributes are returned in human-readable, converted format (e.g., timestamps as `DateTime`, UAC as flag names, SIDs resolved). Use `-Raw` to get the original LDAP values without conversion.

### Syntax

```powershell
Get-DomainUser
    [-Identity <String>]
    [-LDAPFilter <String>]
    [-SearchBase <String>]
    [-Properties <String[]>]
    [-SPN]
    [-AdminCount]
    [-Unconstrained]
    [-Constrained]
    [-RBCD]
    [-TrustedToAuth]
    [-DisallowDelegation]
    [-PreauthNotRequired]
    [-PasswordNotRequired]
    [-PasswordNeverExpires]
    [-PasswordMustChange]
    [-Enabled]
    [-Disabled]
    [-LockedOut]
    [-SmartcardRequired]
    [-AccountExpired]
    [-AccountNeverExpires]
    [-DESOnly]
    [-ReversibleEncryption]
    [-GMSA]
    [-ShowGMSADetails]
    [-ShowOwner]
    [-Raw]
    [-ResultLimit <Int>]
    [-Domain <String>]
    [-Server <String>]
    [-Credential <PSCredential>]
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-Identity` | String | User identity (sAMAccountName, DN, SID, or DOMAIN\user). Wildcards supported. |
| `-LDAPFilter` | String | Custom LDAP filter for special queries |
| `-SearchBase` | String | Alternative SearchBase (DN). Default: Domain DN |
| `-Properties` | String[] | Array of attribute names to return |
| `-SPN` | Switch | Return only users with Service Principal Names (Kerberoastable) |
| `-AdminCount` | Switch | Return only users with adminCount=1 (privileged accounts) |
| `-Unconstrained` | Switch | Users with Unconstrained Delegation (TRUSTED_FOR_DELEGATION flag) |
| `-Constrained` | Switch | Users with Constrained Delegation (msDS-AllowedToDelegateTo attribute) |
| `-RBCD` | Switch | Users with Resource-Based Constrained Delegation (msDS-AllowedToActOnBehalfOfOtherIdentity attribute) |
| `-TrustedToAuth` | Switch | Users with Protocol Transition / S4U2Self (TRUSTED_TO_AUTH_FOR_DELEGATION flag) |
| `-DisallowDelegation` | Switch | Users NOT allowed for delegation (NOT_DELEGATED flag set) |
| `-PreauthNotRequired` | Switch | Users with DONT_REQ_PREAUTH flag (AS-REP Roastable) |
| `-PasswordNotRequired` | Switch | Users with PASSWD_NOTREQD flag |
| `-PasswordNeverExpires` | Switch | Users with DONT_EXPIRE_PASSWORD flag |
| `-PasswordMustChange` | Switch | Users where pwdLastSet=0 (must change password at next logon) |
| `-Enabled` | Switch | Only enabled users (ACCOUNTDISABLE flag not set) |
| `-Disabled` | Switch | Only disabled users (ACCOUNTDISABLE flag set) |
| `-LockedOut` | Switch | Only locked out users (lockoutTime > 0) |
| `-SmartcardRequired` | Switch | Users with SMARTCARD_REQUIRED flag set |
| `-AccountExpired` | Switch | Users where accountExpires is in the past |
| `-AccountNeverExpires` | Switch | Users where accountExpires is 0 or never set |
| `-DESOnly` | Switch | Users with USE_DES_KEY_ONLY flag set (weak encryption) |
| `-ReversibleEncryption` | Switch | Users with ENCRYPTED_TEXT_PWD_ALLOWED flag set (security risk) |
| `-GMSA` | Switch | Return only Managed Service Accounts (MSA and gMSA) |
| `-ShowGMSADetails` | Switch | Shows extended MSA/gMSA information (password access, rotation, SPNs). Use with -GMSA |
| `-ShowOwner` | Switch | Include Owner and OwnerSID properties on returned objects |
| `-Raw` | Switch | Return raw DirectoryEntry objects without processing |
| `-ResultLimit` | Int | Limit the number of results returned. Default: 0 (unlimited) |
| `-Domain` | String | Target domain (FQDN) |
| `-Server` | String | Specific Domain Controller to query |
| `-Credential` | PSCredential | PSCredential object for authentication |

### Examples

```powershell
# Get specific user
Get-DomainUser -Identity "administrator"

# Get all Kerberoastable users (with SPNs)
Get-DomainUser -SPN

# Get all privileged users
Get-DomainUser -AdminCount

# Get users with Unconstrained Delegation
Get-DomainUser -Unconstrained

# Get users with Constrained Delegation
Get-DomainUser -Constrained

# Get users with Protocol Transition (S4U2Self)
Get-DomainUser -TrustedToAuth

# Get users with Resource-Based Constrained Delegation
Get-DomainUser -RBCD

# Get AS-REP Roastable users
Get-DomainUser -PreauthNotRequired

# Get all gMSAs with details
Get-DomainUser -GMSA -ShowGMSADetails

# Get disabled accounts
Get-DomainUser -Disabled

# Get locked out users
Get-DomainUser -LockedOut

# Get users with password never expires
Get-DomainUser -PasswordNeverExpires -Enabled

# Get users from specific OU
Get-DomainUser -SearchBase "OU=Admins,DC=contoso,DC=com"

# Custom LDAP filter
Get-DomainUser -LDAPFilter "(description=*admin*)"

# Combine multiple filters
Get-DomainUser -SPN -Enabled -AdminCount
```

### Output Properties

Common properties returned:

- `sAMAccountName` - Login name
- `distinguishedName` - Full DN path
- `userPrincipalName` - UPN (user@domain.com)
- `objectSid` - Security Identifier
- `memberOf` - Group memberships
- `userAccountControl` - Account flags
- `pwdLastSet` - Password last changed
- `lastLogon` - Last logon timestamp
- `servicePrincipalName` - SPNs (if any)
- `msDS-AllowedToDelegateTo` - Delegation targets

---

## Get-DomainComputer

Retrieves computer accounts from Active Directory (wrapper for Get-DomainObject).

> **Note:** By default, attributes are returned in human-readable, converted format (e.g., timestamps as `DateTime`, UAC as flag names, SIDs resolved). Use `-Raw` to get the original LDAP values without conversion.

### Syntax

```powershell
Get-DomainComputer
    [-Identity <String>]
    [-LDAPFilter <String>]
    [-SearchBase <String>]
    [-Properties <String[]>]
    [-OperatingSystem <String>]
    [-SPN]
    [-Unconstrained]
    [-Constrained]
    [-RBCD]
    [-TrustedToAuth]
    [-LAPS]
    [-Enabled]
    [-Disabled]
    [-HighValueSPN]
    [-KnownSPN <String>]
    [-ShowOwner]
    [-Raw]
    [-ResultLimit <Int>]
    [-Domain <String>]
    [-Server <String>]
    [-Credential <PSCredential>]
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-Identity` | String | Computer identity (name, DN, SID). Wildcards supported. |
| `-LDAPFilter` | String | Custom LDAP filter for special queries |
| `-SearchBase` | String | Alternative SearchBase (DN). Default: Domain DN |
| `-Properties` | String[] | Array of attribute names to return |
| `-OperatingSystem` | String | Filter by operating system (e.g. "Windows Server 2019", "*2016*"). Wildcards supported. |
| `-SPN` | Switch | Return only computers with Service Principal Names |
| `-Unconstrained` | Switch | Computers with Unconstrained Delegation (excludes Domain Controllers) |
| `-Constrained` | Switch | Computers with Constrained Delegation (msDS-AllowedToDelegateTo attribute) |
| `-RBCD` | Switch | Computers with Resource-Based Constrained Delegation (msDS-AllowedToActOnBehalfOfOtherIdentity attribute) |
| `-TrustedToAuth` | Switch | Computers with Protocol Transition / S4U2Self |
| `-LAPS` | Switch | Computers with LAPS enabled (Legacy or Windows LAPS) |
| `-Enabled` | Switch | Only enabled computers |
| `-Disabled` | Switch | Only disabled computers |
| `-HighValueSPN` | Switch | Computers running high-value services (MSSQL, Exchange, SCCM, CA, etc.) |
| `-KnownSPN` | String | Filter by specific service type. Valid values: `MSSQL`, `Exchange`, `SCCM`, `WSUS`, `ADFS`, `CA`, `SCOM`, `Backup`, `HyperV`, `RDP`, `WinRM`, `HTTP`, `FTP` |
| `-ShowOwner` | Switch | Include Owner and OwnerSID properties on returned objects |
| `-Raw` | Switch | Return raw DirectoryEntry objects without processing |
| `-ResultLimit` | Int | Limit the number of results returned. Default: 0 (unlimited) |
| `-Domain` | String | Target domain (FQDN) |
| `-Server` | String | Specific Domain Controller to query |
| `-Credential` | PSCredential | PSCredential object for authentication |

### KnownSPN Values

| Value | Description |
|-------|-------------|
| `MSSQL` | SQL Server instances (MSSQLSvc/*) |
| `Exchange` | Exchange servers (excludes DCs) |
| `SCCM` | SCCM/MECM servers |
| `WSUS` | WSUS servers |
| `ADFS` | AD Federation Services |
| `CA` | Certificate Authorities |
| `SCOM` | System Center Operations Manager |
| `Backup` | Backup servers (Windows Backup, Veeam) |
| `HyperV` | Hyper-V hosts |
| `RDP` | RDP-enabled servers (TERMSRV/*) |
| `WinRM` | WinRM-enabled servers (WSMAN/*) |
| `HTTP` | Web servers (HTTP/*) |
| `FTP` | FTP servers (FTP/*) |

### Examples

```powershell
# Get specific computer
Get-DomainComputer -Identity "DC01"

# Get computers by OS
Get-DomainComputer -OperatingSystem "Windows Server 2019"
Get-DomainComputer -OperatingSystem "*Server*"

# Get computers with Unconstrained Delegation (excluding DCs)
Get-DomainComputer -Unconstrained

# Get computers with Constrained Delegation
Get-DomainComputer -Constrained

# Get computers with Resource-Based Constrained Delegation
Get-DomainComputer -RBCD

# Get computers with LAPS
Get-DomainComputer -LAPS

# Get all high-value targets
Get-DomainComputer -HighValueSPN

# Get SQL Servers only
Get-DomainComputer -KnownSPN MSSQL

# Get Exchange servers (enabled only)
Get-DomainComputer -KnownSPN Exchange -Enabled

# Get Certificate Authorities
Get-DomainComputer -KnownSPN CA

# Get Domain Controllers
Get-DomainComputer -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=8192)"

# Get computers from specific OU
Get-DomainComputer -SearchBase "OU=Servers,DC=contoso,DC=com"
```

### Output Properties

Common properties returned:

- `name` - Computer name
- `dNSHostName` - FQDN
- `operatingSystem` - OS name
- `operatingSystemVersion` - OS version
- `userAccountControl` - Account flags
- `ms-Mcs-AdmPwd` - LAPS password (if readable)
- `ms-Mcs-AdmPwdExpirationTime` - LAPS expiration (Legacy)
- `msLAPS-PasswordExpirationTime` - LAPS expiration (Windows LAPS)
- `msDS-AllowedToDelegateTo` - Constrained delegation targets

---

## Get-DomainGroup

Retrieves groups and their membership (wrapper for Get-DomainObject).

> **Note:** By default, attributes are returned in human-readable, converted format (e.g., timestamps as `DateTime`, UAC as flag names, SIDs resolved). Use `-Raw` to get the original LDAP values without conversion.

### Syntax

```powershell
Get-DomainGroup
    [-Identity <String>]
    [-LDAPFilter <String>]
    [-SearchBase <String>]
    [-Properties <String[]>]
    [-AdminCount]
    [-GroupScope <String>]
    [-GroupCategory <String>]
    [-ShowMembers]
    [-ShowOwner]
    [-Raw]
    [-Domain <String>]
    [-Server <String>]
    [-Credential <PSCredential>]
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-Identity` | String | Group identity (sAMAccountName, DN, SID, or DOMAIN\group). Wildcards supported. |
| `-LDAPFilter` | String | Custom LDAP filter for special queries |
| `-SearchBase` | String | Alternative SearchBase (DN). Default: Domain DN |
| `-Properties` | String[] | Array of attribute names to return |
| `-AdminCount` | Switch | Only groups with adminCount=1 (privileged groups) |
| `-GroupScope` | String | Filter by Group Scope. Valid values: `DomainLocal`, `Global`, `Universal` |
| `-GroupCategory` | String | Filter by Group Category. Valid values: `Security`, `Distribution` |
| `-ShowMembers` | Switch | Resolves and returns all group members (requires -Identity) |
| `-ShowOwner` | Switch | Include Owner and OwnerSID properties on returned objects |
| `-Raw` | Switch | Return raw DirectoryEntry objects without processing |
| `-Domain` | String | Target domain (FQDN) |
| `-Server` | String | Specific Domain Controller to query |
| `-Credential` | PSCredential | PSCredential object for authentication |

### Examples

```powershell
# Get specific group
Get-DomainGroup -Identity "Domain Admins"

# Get group by SID
Get-DomainGroup -Identity "S-1-5-21-*-512"

# Get all privileged groups
Get-DomainGroup -AdminCount

# Get global security groups
Get-DomainGroup -GroupScope Global -GroupCategory Security

# Get universal groups
Get-DomainGroup -GroupScope Universal

# Get distribution groups
Get-DomainGroup -GroupCategory Distribution

# Get group members
Get-DomainGroup -Identity "Domain Admins" -ShowMembers

# Get groups with specific text in description
Get-DomainGroup -LDAPFilter "(description=*admin*)"

# Get security groups only
Get-DomainGroup -GroupCategory Security
```

### Output Properties

Common properties returned:

- `name` - Group name
- `sAMAccountName` - Pre-Windows 2000 name
- `distinguishedName` - Full DN path
- `objectSid` - Group SID
- `member` - Direct members
- `memberOf` - Parent groups
- `groupType` - Group type flags
- `adminCount` - Privileged group indicator

---

## Get-DomainGPO

Retrieves Group Policy Objects with advanced analysis capabilities.

> **Note:** By default, attributes are returned in human-readable, converted format (e.g., timestamps as `DateTime`, UAC as flag names, SIDs resolved). Use `-Raw` to get the original LDAP values without conversion.

### Syntax

```powershell
Get-DomainGPO
    [-Identity <String>]
    [-LDAPFilter <String>]
    [-SearchBase <String>]
    [-Properties <String[]>]
    [-AppliedToOU <String>]
    [-Enabled]
    [-Disabled]
    [-ShowLinkedOU]
    [-ShowDangerousSettings]
    [-ShowPermissions]
    [-Raw]
    [-Domain <String>]
    [-Server <String>]
    [-Credential <PSCredential>]
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-Identity` | String | GPO identity (displayName, DN, or GUID) |
| `-LDAPFilter` | String | Custom LDAP filter for special queries |
| `-SearchBase` | String | Alternative SearchBase (DN) |
| `-Properties` | String[] | Array of attribute names to return |
| `-AppliedToOU` | String | Get GPOs linked to a specific OU (DN format) |
| `-Enabled` | Switch | Only enabled GPOs (flags=0, all settings active) |
| `-Disabled` | Switch | Only fully disabled GPOs (flags=3, both Computer and User settings disabled) |
| `-ShowLinkedOU` | Switch | Include OUs where the GPO is linked |
| `-ShowDangerousSettings` | Switch | Analyze GPO for dangerous settings (scheduled tasks, scripts, registry, etc.) |
| `-ShowPermissions` | Switch | Include GPO permissions (who can edit) |
| `-Raw` | Switch | Return raw DirectoryEntry objects without processing |
| `-Domain` | String | Target domain (FQDN) |
| `-Server` | String | Specific Domain Controller to query |
| `-Credential` | PSCredential | PSCredential object for authentication |

### Examples

```powershell
# Get all GPOs
Get-DomainGPO

# Get specific GPO by name
Get-DomainGPO -Identity "Default Domain Policy"

# Get GPO by GUID
Get-DomainGPO -Identity "{6AC1786C-016F-11D2-945F-00C04fB984F9}"

# Get GPOs with linked OUs
Get-DomainGPO -ShowLinkedOU

# Get GPOs linked to specific OU
Get-DomainGPO -AppliedToOU "OU=Servers,DC=contoso,DC=com"

# Analyze GPOs for dangerous settings
Get-DomainGPO -ShowDangerousSettings

# Get GPO permissions (who can edit)
Get-DomainGPO -Identity "Default Domain Policy" -ShowPermissions

# Get enabled GPOs only
Get-DomainGPO -Enabled

# Get GPOs with specific text in name
Get-DomainGPO -LDAPFilter "(displayName=*Security*)"

# Full GPO analysis
Get-DomainGPO -ShowLinkedOU -ShowDangerousSettings -ShowPermissions
```

### Dangerous Settings Detection

When using `-ShowDangerousSettings`, the function analyzes GPOs for:

- **Scheduled Tasks**: Immediate tasks, logon/logoff scripts
- **Startup Scripts**: Machine/User startup scripts
- **Registry Settings**: AutoRun entries, service modifications
- **Group Membership**: Local admin modifications
- **Security Options**: LAPS, password policies
- **File Deployments**: MSI packages, file copies
- **Service Configuration**: Service accounts, startup types

### Output Properties

Common properties returned:

- `displayName` - GPO display name
- `name` - GPO GUID
- `distinguishedName` - Full DN path
- `gPCFileSysPath` - SYSVOL path
- `whenCreated` - Creation date
- `whenChanged` - Last modified date
- `LinkedOUs` - OUs where linked (with -ShowLinkedOU)
- `DangerousSettings` - Security issues found (with -ShowDangerousSettings)
- `Permissions` - Edit permissions (with -ShowPermissions)

---

## Get-DomainObject

Generic function to retrieve any AD object. This is the base function used by all other Get-Domain* functions.

> **Note:** By default, attributes are returned in human-readable, converted format (e.g., timestamps as `DateTime`, UAC as flag names, SIDs resolved). Use `-Raw` to get the original LDAP values without conversion.

### Syntax

```powershell
Get-DomainObject
    [-Identity <String>]
    [-LDAPFilter <String>]
    [-SearchBase <String>]
    [-Properties <String[]>]
    [-ObjectClass <String>]
    [-Scope <String>]
    [-IsEnabled]
    [-IsDisabled]
    [-PasswordNeverExpires]
    [-PasswordNotRequired]
    [-PasswordMustChange]
    [-TrustedForDelegation]
    [-TrustedToAuthForDelegation]
    [-NotDelegated]
    [-HasSPN]
    [-AdminCount]
    [-LockedOut]
    [-SmartcardRequired]
    [-AccountExpired]
    [-AccountNeverExpires]
    [-PreauthNotRequired]
    [-DESOnly]
    [-ReversibleEncryption]
    [-ShowOwner]
    [-Raw]
    [-ResultLimit <Int>]
    [-Domain <String>]
    [-Server <String>]
    [-Credential <PSCredential>]
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-Identity` | String | sAMAccountName, DistinguishedName, SID, ObjectGUID, or DOMAIN\name. Wildcards supported. |
| `-ObjectClass` | String | Filter by specific object class (e.g., "user", "computer", "group", "organizationalUnit") |
| `-LDAPFilter` | String | Custom LDAP filter for special queries |
| `-Properties` | String[] | Array of attribute names to return |
| `-SearchBase` | String | Alternative SearchBase (DN). Default: Domain DN |
| `-Scope` | String | Search scope: Subtree (default), OneLevel, or Base |
| `-IsEnabled` | Switch | Return only enabled accounts (ACCOUNTDISABLE flag NOT set) |
| `-IsDisabled` | Switch | Return only disabled accounts (ACCOUNTDISABLE flag set) |
| `-PasswordNeverExpires` | Switch | Return only accounts with PASSWORD_NEVER_EXPIRES flag set |
| `-PasswordNotRequired` | Switch | Return only accounts with PASSWORD_NOT_REQUIRED flag set |
| `-PasswordMustChange` | Switch | Return only accounts where pwdLastSet=0 |
| `-TrustedForDelegation` | Switch | Return only accounts with TRUSTED_FOR_DELEGATION flag set |
| `-TrustedToAuthForDelegation` | Switch | Return only accounts with TRUSTED_TO_AUTH_FOR_DELEGATION flag set |
| `-NotDelegated` | Switch | Return only accounts with NOT_DELEGATED flag set |
| `-HasSPN` | Switch | Return only accounts with servicePrincipalName attribute set |
| `-AdminCount` | Switch | Return only accounts with adminCount=1 |
| `-LockedOut` | Switch | Return only locked out accounts (lockoutTime > 0) |
| `-SmartcardRequired` | Switch | Return only accounts with SMARTCARD_REQUIRED flag set |
| `-AccountExpired` | Switch | Return only accounts where accountExpires is in the past |
| `-AccountNeverExpires` | Switch | Return only accounts where accountExpires is 0 or never set |
| `-PreauthNotRequired` | Switch | Return only accounts with DONT_REQ_PREAUTH flag set (AS-REP Roastable) |
| `-DESOnly` | Switch | Return only accounts with USE_DES_KEY_ONLY flag set |
| `-ReversibleEncryption` | Switch | Return only accounts with ENCRYPTED_TEXT_PWD_ALLOWED flag set |
| `-ShowOwner` | Switch | Include Owner and OwnerSID properties on returned objects |
| `-Raw` | Switch | Return raw LDAP values without conversions |
| `-ResultLimit` | Int | Limit the number of results returned. Default: 0 (unlimited) |
| `-Domain` | String | Target domain (FQDN) |
| `-Server` | String | Specific Domain Controller to query |
| `-Credential` | PSCredential | PSCredential object for authentication |

### Examples

```powershell
# Get domain root object
Get-DomainObject -Identity "DC=contoso,DC=com"

# Get any object by SID
Get-DomainObject -Identity "S-1-5-21-1234567890-1234567890-1234567890-500"

# Get objects by object class
Get-DomainObject -LDAPFilter "(objectClass=organizationalUnit)"

# Get all OUs
Get-DomainObject -ObjectClass organizationalUnit

# Get configuration objects
Get-DomainObject -SearchBase "CN=Configuration,DC=contoso,DC=com"

# Get schema objects
Get-DomainObject -SearchBase "CN=Schema,CN=Configuration,DC=contoso,DC=com" -LDAPFilter "(lDAPDisplayName=servicePrincipalName)"

# Get enabled accounts with SPN
Get-DomainObject -HasSPN -IsEnabled

# Get accounts with weak delegation settings
Get-DomainObject -TrustedForDelegation

# Get accounts needing preauth (AS-REP Roastable)
Get-DomainObject -PreauthNotRequired
```

---

## Get-ObjectACL

Retrieves Access Control Lists for AD objects.

### Syntax

```powershell
Get-ObjectACL
    [-Identity <String>]
    [-DistinguishedName <String>]
    [-Trustee <String[]>]
    [-ExcludeTrustee <String[]>]
    [-Rights <String[]>]
    [-ExtendedRight <String[]>]
    [-DangerousOnly]
    [-WriteOnly]
    [-ExtendedRightsOnly]
    [-ExplicitOnly]
    [-AllowOnly]
    [-DenyOnly]
    [-IncludeObjectInfo]
    [-NoResolveGUIDs]
    [-NoResolveSIDs]
    [-Domain <String>]
    [-Server <String>]
    [-Credential <PSCredential>]
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-Identity` | String | Object identity (sAMAccountName, DN, SID). Default parameter set. |
| `-DistinguishedName` | String | DN of object to query (alternative to -Identity) |
| `-Trustee` | String[] | Filter ACEs to only show specific trustees (by name or SID) |
| `-ExcludeTrustee` | String[] | Exclude specific trustees from results |
| `-Rights` | String[] | Filter by specific AD rights. ValidateSet: GenericAll, GenericRead, GenericWrite, GenericExecute, CreateChild, DeleteChild, ListChildren, Self, ReadProperty, WriteProperty, DeleteTree, ListObject, ExtendedRight, Delete, ReadControl, WriteDacl, WriteOwner, Synchronize |
| `-ExtendedRight` | String[] | Filter by specific extended rights (e.g. "User-Force-Change-Password") |
| `-DangerousOnly` | Switch | Return only dangerous ACEs (GenericAll, WriteDacl, WriteOwner, etc.) |
| `-WriteOnly` | Switch | Return only write-related ACEs |
| `-ExtendedRightsOnly` | Switch | Return only extended right ACEs |
| `-ExplicitOnly` | Switch | Exclude inherited ACEs, show only explicit ones |
| `-AllowOnly` | Switch | Return only Allow ACEs (exclude Deny) |
| `-DenyOnly` | Switch | Return only Deny ACEs (exclude Allow) |
| `-IncludeObjectInfo` | Switch | Include target object information in output |
| `-NoResolveGUIDs` | Switch | Do not resolve GUIDs to names (faster) |
| `-NoResolveSIDs` | Switch | Do not resolve SIDs to names (faster) |
| `-Domain` | String | Target domain (FQDN) |
| `-Server` | String | Specific Domain Controller to query |
| `-Credential` | PSCredential | PSCredential object for authentication |

### Examples

```powershell
# Get ACL for domain root
Get-ObjectACL -Identity "DC=contoso,DC=com"

# Get dangerous ACLs only
Get-ObjectACL -DistinguishedName "DC=contoso,DC=com" -DangerousOnly

# Get ACL for specific user
Get-ObjectACL -Identity "administrator"

# Get only write permissions on an OU
Get-ObjectACL -DistinguishedName "OU=Admins,DC=contoso,DC=com" -WriteOnly

# Filter by specific trustee
Get-ObjectACL -Identity "Domain Admins" -Trustee "S-1-5-21-*-512"

# Get explicit (non-inherited) ACEs only
Get-ObjectACL -Identity "administrator" -ExplicitOnly -AllowOnly

# Fast query without GUID/SID resolution
Get-ObjectACL -Identity "DC=contoso,DC=com" -NoResolveGUIDs -NoResolveSIDs
```

---

## Get-CertificateTemplate

Retrieves certificate templates from ADCS.

> **Note:** By default, attributes are returned in human-readable, converted format (e.g., timestamps as `DateTime`, UAC as flag names, SIDs resolved). Use `-Raw` to get the original LDAP values without conversion.

### Syntax

```powershell
Get-CertificateTemplate
    [-Identity <String>]
    [-LDAPFilter <String>]
    [-Properties <String[]>]
    [-SearchBase <String>]
    [-ShowAll]
    [-EnrolleeSuppliesSubject]
    [-NoSecurityExtension]
    [-ClientAuthentication]
    [-ExportableKey]
    [-NoManagerApproval]
    [-EnrollmentAllowed]
    [-Export]
    [-ExportPath <String>]
    [-Raw]
    [-Domain <String>]
    [-Server <String>]
    [-Credential <PSCredential>]
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-Identity` | String | Template name or OID |
| `-LDAPFilter` | String | Custom LDAP filter for special queries |
| `-Properties` | String[] | Array of attribute names to return |
| `-SearchBase` | String | Alternative SearchBase (DN) |
| `-ShowAll` | Switch | Show all templates including disabled ones |
| `-EnrolleeSuppliesSubject` | Switch | Filter for templates where enrollee supplies subject name (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) |
| `-NoSecurityExtension` | Switch | Filter for templates without szOID_NTDS_CA_SECURITY_EXT (ESC9/ESC10) |
| `-ClientAuthentication` | Switch | Filter for templates with Client Authentication or Smartcard Logon EKU |
| `-ExportableKey` | Switch | Filter for templates allowing private key export |
| `-NoManagerApproval` | Switch | Filter for templates not requiring CA manager approval |
| `-EnrollmentAllowed` | Switch | Filter for templates where enrollment is enabled (autoenrollment or manual) |
| `-Export` | Switch | Export template settings as raw LDAP values (for backup/restore) |
| `-ExportPath` | String | Output path for exported template settings |
| `-Raw` | Switch | Return raw LDAP values without conversion |
| `-Domain` | String | Target domain (FQDN) |
| `-Server` | String | Specific Domain Controller to query |
| `-Credential` | PSCredential | PSCredential object for authentication |

### Examples

```powershell
# Get all certificate templates
Get-CertificateTemplate

# Get specific template
Get-CertificateTemplate -Identity "User"

# Get templates where enrollee supplies subject (ESC1 indicator)
Get-CertificateTemplate -EnrolleeSuppliesSubject -ClientAuthentication

# Get templates without security extension (ESC9/ESC10 indicator)
Get-CertificateTemplate -NoSecurityExtension

# Get templates allowing enrollment with exportable key
Get-CertificateTemplate -EnrollmentAllowed -ExportableKey

# Export template for backup
Get-CertificateTemplate -Identity "VulnTemplate" -Export -ExportPath "C:\backup\"
```

### Output Properties

- `name` - Template name
- `displayName` - Display name
- `msPKI-Certificate-Name-Flag` - Name flags
- `msPKI-Enrollment-Flag` - Enrollment flags
- `pKIExtendedKeyUsage` - EKU OIDs
- `msPKI-Certificate-Application-Policy` - Application policies
- `nTSecurityDescriptor` - ACL (who can enroll)

---

## LDAP Filter Reference

### Common Filters

| Purpose | Filter |
|---------|--------|
| All users | `(objectCategory=person)` |
| All computers | `(objectCategory=computer)` |
| All groups | `(objectCategory=group)` |
| Enabled accounts | `(!(userAccountControl:1.2.840.113556.1.4.803:=2))` |
| Disabled accounts | `(userAccountControl:1.2.840.113556.1.4.803:=2)` |
| Has SPN | `(servicePrincipalName=*)` |
| No pre-auth | `(userAccountControl:1.2.840.113556.1.4.803:=4194304)` |
| Unconstrained delegation | `(userAccountControl:1.2.840.113556.1.4.803:=524288)` |
| Domain Controllers | `(userAccountControl:1.2.840.113556.1.4.803:=8192)` |
| Password never expires | `(userAccountControl:1.2.840.113556.1.4.803:=65536)` |
| AdminCount=1 | `(adminCount=1)` |
| Locked out | `(lockoutTime>=1)` |
| Smartcard required | `(userAccountControl:1.2.840.113556.1.4.803:=262144)` |

### UserAccountControl Flags

| Flag | Value | Description |
|------|-------|-------------|
| ACCOUNTDISABLE | 2 | Account is disabled |
| PASSWD_NOTREQD | 32 | Password not required |
| NORMAL_ACCOUNT | 512 | Default account type |
| DONT_EXPIRE_PASSWORD | 65536 | Password never expires |
| SMARTCARD_REQUIRED | 262144 | Smartcard required for logon |
| TRUSTED_FOR_DELEGATION | 524288 | Unconstrained delegation |
| NOT_DELEGATED | 1048576 | Cannot be delegated |
| USE_DES_KEY_ONLY | 2097152 | DES encryption only |
| DONT_REQ_PREAUTH | 4194304 | No Kerberos preauthentication |
| TRUSTED_TO_AUTH_FOR_DELEGATION | 16777216 | Protocol transition (S4U2Self) |

### Combining Filters

```powershell
# Users with SPN (Kerberoastable)
Get-DomainUser -LDAPFilter "(&(objectCategory=person)(servicePrincipalName=*))"

# Enabled users not in Protected Users
Get-DomainUser -LDAPFilter "(&(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(memberOf=CN=Protected Users,CN=Users,DC=contoso,DC=com)))"

# Computers with LAPS (Legacy or Windows LAPS)
Get-DomainComputer -LDAPFilter "(|(ms-Mcs-AdmPwdExpirationTime=*)(msLAPS-PasswordExpirationTime=*))"
```

---

## Navigation

- [Previous: BloodHound-Collector](05-BloodHound-Collector.md)
- [Next: Set- & New-Modules](07-Set-Modules.md)
- [Back to Home](00-Home.md)