# adPEAS v2 - Active Directory Privilege Escalation Awesome Scripts

![adPEAS Logo](../images/adPEAS_large.jpg)

Welcome to the adPEAS v2 documentation. This documentation provides comprehensive information about using adPEAS for authorized Active Directory security assessments.

---

## What is adPEAS?

adPEAS (Active Directory Privilege Escalation Awesome Scripts) is a PowerShell-based security assessment tool designed to identify misconfigurations, vulnerabilities, and privilege escalation paths in Active Directory environments.

### Key Features

- **Zero External Dependencies**: Uses only built-in .NET Framework classes (System.DirectoryServices.Protocols)
- **No RSAT Required**: Works without Active Directory PowerShell module or Remote Server Administration Tools
- **Standalone Deployment**: Single .ps1 file for easy transfer to target systems
- **Multiple Authentication Methods**: Supports credentials, certificates (PKINIT & Pass-the-Cert/Schannel), NT-Hash, AES keys, and Kerberos tickets
- **Kerberos-First Authentication**: Attempts Kerberos authentication by default with automatic fallback
- **Comprehensive Security Checks**: 41+ security checks across 9 categories
- **BloodHound CE Export**: Built-in collector for attack path analysis in BloodHound Community Edition
- **OPSEC Mode**: Optional stealth mode that skips active testing (Kerberoast/ASREPRoast/BloodHound)

### Use Cases

- Penetration Testing (with authorization)
- Security Auditing
- Red Team Assessments

---

## Quick Links

| Topic | Description |
|-------|-------------|
| [Installation](01-Installation.md) | Download and setup instructions |
| [Quick-Start](02-Quick-Start.md) | Get started in 5 minutes |
| [Authentication-Methods](03-Authentication-Methods.md) | All supported authentication options |
| [Security-Checks](04-Security-Checks.md) | Complete reference of all security checks |
| [BloodHound-Collector](05-BloodHound-Collector.md) | Export data for BloodHound CE attack path analysis |
| [Core-Functions](06-Core-Functions.md) | LDAP query and data retrieval functions |
| [Set- & New-Modules](07-Set-Modules.md) | AD modification functions (⚠️ Authorized use only) |
| [Helper-Functions](08-Helper-Functions.md) | Utility functions reference |
| [Architecture](09-Architecture.md) | Technical architecture overview |
| [Risk-Scoring-System](10-Risk-Scoring-System.md) | Finding severity and risk score calculation |
| [Troubleshooting](11-Troubleshooting.md) | Common issues and solutions |
| [FAQ](12-FAQ.md) | Frequently asked questions |

---

## Version Information

- **Current Version**: 2.0.0
- **PowerShell Version**: 5.1+ required
- **Platform**: Windows (tested on Windows 10/11, Server 2016-2025)

---

## Release Versions

adPEAS is distributed in four versions:

| Version    | File               | Description                 |
| ---------- | ------------------ | --------------------------- |
| Readable   | `adPEAS.ps1`       | Full version with comments  |
| Minimized  | `adPEAS_min.ps1`   | Comments removed            |
| Ultra      | `adPEAS_ultra.ps1` | Fully compressed            |
| Obfuscated | `adPEAS_obf.ps1`   | GZip + XOR + Base64 encoded |

---

## Legal Notice

**IMPORTANT**: adPEAS is intended for authorized security testing only.

- Always obtain written authorization before testing
- Never use against systems you do not own or have permission to test
- The authors are not responsible for misuse of this tool
- Comply with all applicable laws and regulations

---

## Credits

- **Author**: Alexander Sturz (@_61106960_)

---

## Navigation

- [Next: Installation](01-Installation.md)
