# Frequently Asked Questions

Common questions about adPEAS v2.

---

## General Questions

### What is adPEAS?

adPEAS (Active Directory Privilege Escalation Awesome Scripts) is a PowerShell tool for identifying security misconfigurations in Active Directory environments. It is designed for authorized penetration testing and security auditing.

---

### How is adPEAS different from other common AD tools?

| Feature | adPEAS v2 | PowerView | ADModule |
|---------|-----------|-----------|----------|
| External Dependencies | None | None | RSAT Required |
| Standalone File | Yes | Yes | No |
| Kerberos Auth Methods | All (OPtH, PtK, PKINIT, etc.) | Limited | Limited |
| Security Checks | 41+ | Enumeration only | None |
| OPSEC Mode | Yes | No | No |
| Output Formatting | Colored + Reports | Raw | Raw |

---

### Is adPEAS a replacement for BloodHound?

No. adPEAS and BloodHound serve different purposes:

- **adPEAS**: Real-time security assessment with actionable findings
- **BloodHound**: Attack path visualization and graph analysis

They complement each other well. Use adPEAS for quick vulnerability assessment and BloodHound for comprehensive attack path analysis.

---

### What PowerShell version is required?

Windows PowerShell 5.1 or higher. PowerShell Core (6+) is not fully supported due to .NET Framework dependencies.

---

### Does adPEAS require RSAT or ActiveDirectory module?

No. adPEAS uses only built-in .NET Framework classes (`System.DirectoryServices.Protocols`). No external modules are required.

---

### Can I run adPEAS from a non-domain-joined machine?

Yes. Use credentials or other authentication methods:

```powershell
Connect-adPEAS -Domain "contoso.com" -Username "john.doe" -Password "pass"
```

You may need to configure DNS or specify the DC directly:

```powershell
Connect-adPEAS -Domain "contoso.com" -Server "10.0.0.10" -DnsServer "10.0.0.1" -Username "john.doe" -Password "pass"
```

---

### Can I use adPEAS through a SOCKS proxy or tunnel?

adPEAS does not have built-in SOCKS support, but works perfectly through **local port forwards** (chisel, ligolo-ng, SSH, socat). Use `-Server "127.0.0.1"` with `-ForceSimpleBind` for the most reliable setup:

```powershell
Connect-adPEAS -Domain "contoso.com" -Server "127.0.0.1" -Username "john.doe" -Password "P@ssw0rd" -ForceSimpleBind
```

For slow tunnel connections, increase the LDAP timeout with `-TimeoutSeconds`:

```powershell
Connect-adPEAS -Domain "contoso.com" -Server "127.0.0.1" -Username "john.doe" -Password "P@ssw0rd" -ForceSimpleBind -TimeoutSeconds 120
```

See [Troubleshooting: Pivoting and Tunneling](11-Troubleshooting.md#pivoting-and-tunneling) for detailed setup guides.

---

## Authentication Questions

### Which authentication method should I use?

| Scenario | Recommended Method |
|----------|-------------------|
| Domain-joined machine | `-UseWindowsAuth` |
| Known credentials | `-Credential` or `-Username -Password` |
| Compromised hash | `-NTHash` or `-AES256Key` |
| Stolen certificate (Kerberos available) | `-Certificate` (PKINIT) |
| Stolen certificate (port 88 blocked) | `-Certificate -ForcePassTheCert` (Schannel) |
| Ticket from other tool | `-Kirbi` or `-Ccache` |

---

### Why does adPEAS attempt Kerberos first?

Kerberos authentication:
- Does not expose password to the DC (unlike SimpleBind)
- Works with hashes and keys (no plaintext needed)
- Is the native Windows authentication protocol

If Kerberos fails (port 88 blocked, etc.), adPEAS automatically falls back to NTLM Impersonation (which supports LDAP signing). If NTLM Impersonation also fails, it falls back to SimpleBind. Note: This tiered fallback only applies to password-based authentication. Hash/key-based methods (NT Hash, AES keys) require Kerberos and have no fallback.

---

### How do I use SimpleBind (skip Kerberos)?

```powershell
Connect-adPEAS -Domain "contoso.com" -Username "john.doe" -Password "pass" -ForceSimpleBind
```

---

### How do I use NTLM without modifying Kerberos tickets?

Use `-ForceNTLM` for NTLM Impersonation (similar to `runas /netonly`):

```powershell
Connect-adPEAS -Domain "contoso.com" -Username "john.doe" -Password "pass" -ForceNTLM
```

This keeps your existing Kerberos tickets intact and uses NTLM for network authentication.

---

### Can I use adPEAS with Pass-the-Hash?

Yes. Use the `-NTHash` parameter:

```powershell
# Example with NT-Hash
Connect-adPEAS -Domain "contoso.com" -Username "john.doe" -NTHash "32ED87BDB5FDC5E9CBA88547376818D4"
```

---

### Can I use adPEAS with certificates (PKINIT)?

Yes. Use the `-Certificate` parameter:

```powershell
Connect-adPEAS -Domain "contoso.com" -Certificate "user.pfx" -CertificatePassword "pass"
```

---

### Can I use a certificate when Kerberos (port 88) is blocked?

Yes. Use `-ForcePassTheCert` to authenticate via Schannel (TLS client certificate) instead of PKINIT:

```powershell
Connect-adPEAS -Domain "contoso.com" -Certificate "user.pfx" -ForcePassTheCert
```

This only needs port 636 (LDAPS). The certificate must be CA-issued (Shadow Credentials certificates don't work with Schannel). See [Authentication Methods: Pass-the-Cert](03-Authentication-Methods.md#pass-the-cert-schannel) for details.

---

## Security Check Questions

### What does OPSEC mode do?

OPSEC mode skips checks that generate active traffic or request tickets:

- **Kerberoasting** - Requests TGS tickets for service accounts
- **AS-REP Roasting** - Requests AS-REP without pre-authentication
- **BloodHound Collection** - Generates many LDAP queries across the domain

All other enumeration continues normally. OPSEC mode is recommended when stealth is critical.

```powershell
Invoke-adPEAS -Domain "contoso.com" -UseWindowsAuth -OPSEC
```

---

### Can I run only specific checks?

Yes. Use the `-Module` parameter:

```powershell
# Single module
Invoke-adPEAS -Module ADCS

# Multiple modules
Invoke-adPEAS -Module Domain,Accounts,Creds
```

Or run individual check functions:

```powershell
Connect-adPEAS -Domain "contoso.com" -UseWindowsAuth
Get-KerberoastableAccounts
Get-ADCSVulnerabilities
```

---

### Which ADCS ESC variants does adPEAS detect?

The ADCS module checks for:

- ESC1: Enrollee-supplied SAN + client authentication
- ESC2: Any purpose EKU
- ESC3: Enrollment agent template abuse
- ESC4: Vulnerable template ACLs
- ESC8: Web enrollment detection (HTTP/HTTPS + NTLM/EPA configuration)
- ESC9: No security extension + client auth
- ESC13: Issuance policy linked to AD group
- ESC15: Schema v1 + enrollee-supplied subject (CVE-2024-49019)

**Not implemented**: ESC6 (requires registry access via RPC, not LDAP), ESC7 (requires DCOM/RPC to CA, not LDAP)

```powershell
Get-ADCSVulnerabilities
```

---

## Output Questions

### How do I save results to a file?

```powershell
# Default: Both formats (creates .txt and .html)
Invoke-adPEAS -Domain "contoso.com" -UseWindowsAuth -Outputfile .\report

# Text report only
Invoke-adPEAS -Domain "contoso.com" -UseWindowsAuth -Outputfile .\report -Format Text

# HTML report only
Invoke-adPEAS -Domain "contoso.com" -UseWindowsAuth -Outputfile .\report -Format HTML
```

The file extension (.txt or .html) is added automatically based on the format.

---

### Why don't colors show in my terminal?

Legacy cmd.exe doesn't support ANSI escape codes. Use:

- Windows Terminal (recommended)
- ConEmu
- PowerShell ISE (limited support)

Or output to file instead.

---

### What do the symbols mean?

| Symbol | Meaning |
|--------|---------|
| `[?]` | Section header, information |
| `[!]` | Critical finding, vulnerability |
| `[+]` | Interesting finding for investigation |
| `[*]` | General note, information |
| `[#]` | Secure configuration |

---

### Can I run adPEAS against multiple domains?

Yes, but sequentially:

```powershell
# Domain 1
Connect-adPEAS -Domain "contoso.com" -UseWindowsAuth
Invoke-adPEAS -Outputfile .\contoso -Format All
Disconnect-adPEAS

# Domain 2
Connect-adPEAS -Domain "fabrikam.com" -UseWindowsAuth
Invoke-adPEAS -Outputfile .\fabrikam -Format All
Disconnect-adPEAS
```

---

## Version Questions

### Which release version should I download?

| Version | Use Case |
|---------|----------|
| `adPEAS.ps1` | Development, debugging, learning |
| `adPEAS_min.ps1` | Regular use |
| `adPEAS_ultra.ps1` | Size-constrained environments |
| `adPEAS_obf.ps1` | Smallest size, obfuscated transfer |

---

### How do I update adPEAS?

1. Download the new release
2. Replace the .ps1 file
3. Re-import

```powershell
Remove-Module adPEAS -ErrorAction SilentlyContinue
Import-Module .\adPEAS.ps1
```

---

## Legal Questions

### Is using adPEAS legal?

adPEAS is a security tool. Like all security tools, it is legal to use when:

- You own the target systems, or
- You have written authorization from the owner

Unauthorized use against systems you don't own or have permission to test is illegal.

---

### Do I need written authorization?

For professional engagements, yes. Always get written authorization (scope document, rules of engagement) before testing.

---

## Navigation

- [Previous: Troubleshooting](11-Troubleshooting.md)
- [Back to: Home](00-Home.md)