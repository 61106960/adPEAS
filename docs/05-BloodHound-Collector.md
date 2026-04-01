# BloodHound Collector

Export Active Directory data in BloodHound Community Edition (CE) compatible format.

---

## Overview

The `Invoke-adPEASCollector` function collects AD data and exports it as BloodHound CE compatible JSON files. This enables attack path analysis in BloodHound without requiring SharpHound.

**Key Features:**

- Pure PowerShell implementation (no external dependencies)
- BloodHound CE v6 JSON format
- DCOnly collection method (LDAP-only, NO SMB/RPC to member hosts)
- Full ACL edge support (Owns, GenericAll, WriteDacl, DCSync, etc.)
- Automatic ZIP compression

---

## Quick Start

```powershell
# 1. Connect to domain
Connect-adPEAS -Domain "contoso.com" -UseWindowsAuth

# 2. Collect data
Invoke-adPEASCollector

# 3. Import ZIP into BloodHound CE
```

Output: `<timestamp>_CONTOSO.COM_BloodHound.zip`

---

## Syntax

```powershell
Invoke-adPEASCollector
    [-OutputPath <String>]
    [-CollectionMethod <String>]
    [-NoZip]
    [-PrettyPrint]
    [-Domain <String>]
    [-Server <String>]
    [-Credential <PSCredential>]
```

---

## Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-OutputPath` | Output file or directory path | Current directory |
| `-CollectionMethod` | Collection method (see below) | `DCOnly` |
| `-NoZip` | Output raw JSON files instead of ZIP | `$false` |
| `-PrettyPrint` | Format JSON with indentation | `$false` |
| `-Domain` | Target domain FQDN | Session domain |
| `-Server` | Specific Domain Controller | Session DC |
| `-Credential` | Alternative credentials | Session credentials |

---

## Collection Methods

| Method | Description | Collects |
|--------|-------------|----------|
| `DCOnly` | Full LDAP-based collection (default) | Users, Groups, Computers, Domains, OUs, Containers, GPOs, ADCS objects, ACLs |
| `ObjectProps` | Object properties only | Users, Groups, Computers (no ACLs, no ADCS) |
| `ACL` | Objects with ACL focus | Users, Groups, Computers, OUs, GPOs, ADCS objects + ACLs |
| `Trusts` | Domain trusts only | Domains |
| `Container` | Container structure only | OUs, Containers, GPOs (no ACLs) |
| `CertServices` | ADCS objects only | CertTemplates, EnterpriseCAs, RootCAs, AIACAs, NTAuthStores, IssuancePolicies + ACLs |

**Note:** The `DCOnly` method matches SharpHound's `--collectionmethods DCOnly` which collects all LDAP-accessible data without contacting member hosts. This is the most complete collection method available in adPEAS.

---

## Examples

### Basic Collection

```powershell
# Collect to current directory
Invoke-adPEASCollector

# Specify output directory
Invoke-adPEASCollector -OutputPath "C:\BloodHound\"

# Specify full output path
Invoke-adPEASCollector -OutputPath "C:\BloodHound\domain_data.zip"
```

### Output Options

```powershell
# Raw JSON files (no ZIP)
Invoke-adPEASCollector -NoZip -OutputPath "C:\BloodHound\json\"

# Pretty-printed JSON (for debugging)
Invoke-adPEASCollector -PrettyPrint -NoZip
```

### With Credentials

```powershell
# Using session (recommended)
Connect-adPEAS -Domain "contoso.com" -Credential (Get-Credential)
Invoke-adPEASCollector

# Inline credentials
Invoke-adPEASCollector -Domain "contoso.com" -Credential (Get-Credential)
```

### Specific Collection Method

```powershell
# Full collection (default)
Invoke-adPEASCollector -CollectionMethod DCOnly

# Only object properties (faster, no ACLs)
Invoke-adPEASCollector -CollectionMethod ObjectProps

# Only ACLs
Invoke-adPEASCollector -CollectionMethod ACL

# Only domain trusts
Invoke-adPEASCollector -CollectionMethod Trusts

# Only ADCS objects (CAs, templates, policies)
Invoke-adPEASCollector -CollectionMethod CertServices
```

---

## Output Files

The collector generates the following JSON files:

| File | Contents |
|------|----------|
| `*_users.json` | User accounts with properties, SPNs, delegation |
| `*_groups.json` | Groups with membership |
| `*_computers.json` | Computer accounts with OS, delegation |
| `*_domains.json` | Domain information, trusts, functional level |
| `*_ous.json` | Organizational Units with GPO links |
| `*_containers.json` | Container objects |
| `*_gpos.json` | Group Policy Objects |
| `*_certtemplates.json` | Certificate templates with enrollment permissions and flags |
| `*_enterprisecas.json` | Enterprise CAs with enabled templates and hosting computer |
| `*_rootcas.json` | Trusted root CAs from Configuration NC |
| `*_aiacas.json` | Authority Information Access CAs |
| `*_ntauthstores.json` | NTAuth certificate store (trusted for domain auth) |
| `*_issuancepolicies.json` | Issuance policies with OID-to-group links (ESC13) |

### JSON Format

All files follow BloodHound CE v6 format:

```json
{
    "meta": {
        "methods": 1601,
        "type": "users",
        "count": 73,
        "version": 6
    },
    "data": [
        {
            "ObjectIdentifier": "S-1-5-21-...-1234",
            "Properties": {
                "name": "ADMIN@CONTOSO.COM",
                "domain": "CONTOSO.COM",
                "enabled": true,
                ...
            },
            "Aces": [
                {
                    "PrincipalSID": "S-1-5-21-...-512",
                    "PrincipalType": "Group",
                    "RightName": "Owns",
                    "IsInherited": false
                }
            ],
            ...
        }
    ]
}
```

---

## Collected ACL Edges

The collector extracts all BloodHound-compatible ACL edges:

### Ownership Edges

| Edge | Description |
|------|-------------|
| `Owns` | Object owner (implicit GenericAll) |

### Permission Edges

| Edge | Description |
|------|-------------|
| `GenericAll` | Full control |
| `GenericWrite` | Write all properties |
| `WriteDacl` | Modify permissions |
| `WriteOwner` | Take ownership |

### Property-Specific Edges

| Edge | Description |
|------|-------------|
| `WriteSPN` | Write servicePrincipalName (targeted Kerberoasting) |
| `AddKeyCredentialLink` | Shadow Credentials attack |
| `AddAllowedToAct` | Resource-Based Constrained Delegation |
| `AddMember` | Modify group membership |
| `WriteGPLink` | Link GPOs to OU/Domain |

### Extended Rights Edges

| Edge | Description |
|------|-------------|
| `AllExtendedRights` | All extended rights |
| `ForceChangePassword` | Reset user password |
| `GetChanges` | DCSync (replication) |
| `GetChangesAll` | DCSync with secrets |
| `GetChangesInFilteredSet` | DCSync filtered |

### Read Edges

| Edge | Description |
|------|-------------|
| `ReadLAPSPassword` | Read LAPS password |
| `ReadGMSAPassword` | Read gMSA password |

### Group Edges

| Edge | Description |
|------|-------------|
| `AddSelf` | Add self to group |

### ADCS Edges

| Edge | Description |
|------|-------------|
| `Enroll` | Certificate enrollment permission |
| `AutoEnroll` | Certificate auto-enrollment permission |
| `ManageCA` | CA administrator right |
| `ManageCertificates` | CA officer right (approve/deny requests) |
| `WritePKIEnrollmentFlag` | Write msPKI-Enrollment-Flag (template modification) |
| `WritePKINameFlag` | Write msPKI-Certificate-Name-Flag (template modification) |

---

## Filtered Principals

The following principals are filtered from ACL output (matching SharpHound behavior):

| SID | Principal | Reason |
|-----|-----------|--------|
| `S-1-5-18` | SYSTEM | Not user-controllable |
| `S-1-3-0` | Creator Owner | Placeholder, not actionable |
| `S-1-5-10` | Self | Placeholder, not actionable |

---

## Comparison with SharpHound

| Feature | adPEAS Collector | SharpHound |
|---------|------------------|------------|
| Language | PowerShell | C# |
| Dependencies | None | .NET Framework |
| Collection Methods | DCOnly, ACL, ObjectProps, Trusts, Container, CertServices | All, DCOnly, Session, etc. |
| Local Admin Enum | No | Yes (with Session) |
| Session Enum | No | Yes |
| ACL Collection | Yes | Yes |
| ADCS Collection | Yes (CertTemplates, CAs, NTAuth, IssuancePolicies) | Yes |
| Trust Enum | Yes | Yes |
| Output Format | BH CE v6 JSON | BH CE v6 JSON |

**When to use adPEAS Collector:**
- Pure PowerShell environment
- No SharpHound available
- Quick DCOnly collection
- Integrated with adPEAS workflow

**When to use SharpHound:**
- Need session enumeration
- Need local admin enumeration
- Need computer-based collection
- Need native BloodHound collection

---

## Navigation

- [Previous: Security-Checks](04-Security-Checks.md)
- [Next: Core-Functions](06-Core-Functions.md)
- [Back to Home](00-Home.md)