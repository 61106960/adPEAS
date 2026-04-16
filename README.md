# adPEAS v2 — Active Directory Privilege Escalation Awesome Scripts

<p align="center">
  <img src="images/adPEAS_large.jpg" alt="adPEAS Logo" width="800">
</p>

<p align="center">
  <strong>Comprehensive Active Directory security assessment — zero dependencies, single file, ready to go.</strong>
</p>

---

## What is adPEAS?

adPEAS is a PowerShell-based security assessment tool that identifies misconfigurations, vulnerabilities, and privilege escalation paths in Active Directory environments. It is designed for penetration testers, security auditors, and red teams who need a reliable, self-contained tool that works on any Windows system — no RSAT, no ActiveDirectory module, no third-party dependencies.

**adPEAS v2** is a complete rewrite of adPEAS v1. It replaces the legacy `DirectoryEntry`/`DirectorySearcher` approach with a unified `System.DirectoryServices.Protocols.LdapConnection` architecture and adds native Kerberos authentication, advanced reporting, and offensive operations — all in pure PowerShell.

### What's New in v2

- **Native Kerberos stack** — AS-REQ/AS-REP, TGS-REQ/TGS-REP, Pass-the-Ticket, PKINIT, all in pure PowerShell
- **Multiple auth methods** — Password, NT-Hash (OPtH), AES keys (PtK), Certificates (PKINIT & Pass-the-Cert/Schannel), Windows integrated
- **40+ security checks** across 9 categories with severity scoring
- **Interactive HTML reports** with search, filtering, risk scores, and tooltips
- **JSON export** for offline report conversion, incremental scanning, and scan comparison
- **BloodHound CE collector** — built-in data collection for attack path analysis
- **Offensive operations** — Kerberoasting, AS-REP Roasting, Golden/Silver/Diamond Tickets, RBCD abuse, Shadow Credentials, and more
- **Session-based workflow** — connect once, run multiple checks interactively
- **Tab-completion** — autocomplete AD object names for interactive exploration

> **New to adPEAS?** Check the [Quick-Start Guide](docs/02-Quick-Start.md) or read the [blog series on blog.sekurity.de](https://blog.sekurity.de/blog/adpeas-v2-introduction) for a deep dive into architecture, authentication, and internals.

---

## Features at a Glance

| Category | Highlights |
|----------|-----------|
| **Authentication** | Credentials, PKINIT, Pass-the-Cert, NT-Hash, AES keys, Windows auth, Kerberos-first with automatic fallback |
| **Security Checks** | Domain config, Kerberoast, ASREPRoast, ACLs, DCSync, delegation, ADCS (ESC1-ESC15), GPO abuse, LAPS, outdated systems |
| **Reporting** | Console (color-coded), plain text, interactive HTML, JSON export |
| **Offensive Ops** | Kerberoasting, AS-REP Roasting, Golden/Silver/Diamond Tickets, RBCD, Shadow Credentials, Pass-the-Ticket |
| **BloodHound** | Built-in BloodHound CE collector (ZIP export) |
| **OPSEC Mode** | Skip active testing (Kerberoast, ASREPRoast, BloodHound) |
| **Deployment** | Single `.ps1` file, no RSAT, no external modules, works offline and air-gapped |

---

## Requirements

- **OS**: Windows 10/11, Windows Server 2016/2019/2022/2025
- **PowerShell**: 5.1+ (Windows PowerShell)
- **.NET Framework**: 4.5+ (included in Windows)
- **Network**: LDAP (389), LDAPS (636), Kerberos (88), SMB (445)

No ActiveDirectory module, RSAT, or external PowerShell modules required.

---

## Download

### Release Versions

| File | Size | Use Case |
|------|------|----------|
| `adPEAS.ps1` | ~4.5 MB | Development, debugging, code review |
| `adPEAS_min.ps1` | ~3-4 MB | Regular use with smaller footprint |
| `adPEAS_ultra.ps1` | ~3 MB | Minimal size, no comments |
| `adPEAS_obf.ps1` | <1 MB | Smallest size, obfuscated for transfer |

All four versions are functionally identical. Choose based on your deployment scenario.

```powershell
# Clone the repository
git clone https://github.com/61106960/adPEAS.git
cd adPEAS
```

### Building from Source

The `main` branch contains only source files (`src/`). Release builds are attached to each [GitHub Release](https://github.com/61106960/adPEAS/releases). If you want to build from the latest source, use the included build script:

```powershell
git clone https://github.com/61106960/adPEAS.git
cd adPEAS
.\Build-Release.ps1
```

This produces all four variants (`adPEAS.ps1`, `adPEAS_min.ps1`, `adPEAS_ultra.ps1`, `adPEAS_obf.ps1`) in the repository root. Requires Windows PowerShell 5.1 and no additional dependencies.

---

## Quick Start

```powershell
# Option 1: Import as module (recommended)
Import-Module .\adPEAS.ps1

# Option 2: Dot-sourcing
. .\adPEAS.ps1

# Option 3: Read and execute in memory
Get-Content -Raw .\adPEAS.ps1 | Invoke-Expression

# Option 4: Load directly from GitHub into memory (no file on disk)
Invoke-Expression (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/61106960/adPEAS/main/adPEAS_obf.ps1" -UseBasicParsing).Content
```

### One-Liner (v1 Compatible)

```powershell
# Domain-joined machine (current user)
Invoke-adPEAS -Domain "contoso.com" -UseWindowsAuth

# With credentials
Invoke-adPEAS -Domain "contoso.com" -Username "john.doe" -Password "P@ssw0rd!"

# OPSEC mode (skip Kerberoast, ASREPRoast, BloodHound)
Invoke-adPEAS -Domain "contoso.com" -UseWindowsAuth -OPSEC
```

### Session-Based (v2 Style)

```powershell
# Connect once
Connect-adPEAS -Domain "contoso.com" -UseWindowsAuth

# Run full scan
Invoke-adPEAS

# Or run individual checks
Get-KerberoastableAccounts
Get-ADCSVulnerabilities
Get-DangerousACLs

# Disconnect when done
Disconnect-adPEAS
```

### Authentication Methods

```powershell
# Credentials
Connect-adPEAS -Domain "contoso.com" -Credential (Get-Credential)

# Overpass-the-Hash (NT-Hash)
Connect-adPEAS -Domain "contoso.com" -Username "admin" -NTHash "32ED87BDB5FDC5E9CBA88547376818D4"

# Pass-the-Key (AES256)
Connect-adPEAS -Domain "contoso.com" -Username "admin" -AES256Key "4a3b2c1d5e6f..."

# PKINIT (Certificate)
Connect-adPEAS -Domain "contoso.com" -Certificate "user.pfx"

# Pass-the-Cert / Schannel (LDAPS, no Kerberos)
Connect-adPEAS -Domain "contoso.com" -Certificate "user.pfx" -PassTheCert

# LDAPS
Connect-adPEAS -Domain "contoso.com" -UseWindowsAuth -UseLDAPS
```

### Output & Reporting

```powershell
# All formats (default) — creates .txt, .html, and .json
Invoke-adPEAS -Domain "contoso.com" -UseWindowsAuth -Outputfile .\report

# HTML only
Invoke-adPEAS -Domain "contoso.com" -UseWindowsAuth -Outputfile .\report -Format HTML

# Offline report conversion from JSON
Convert-adPEASReport -InputJson ".\report.json" -OutputPath ".\new_report"

# Compare two scans (diff report)
Compare-adPEASReport -Baseline ".\scan_q1.json" -Current ".\scan_q2.json" -OutputPath ".\diff"
```

---

## Security Check Modules

| Module | Description |
|--------|-------------|
| `Domain` | Domain configuration, trusts, password policy, LDAP signing, SMB signing |
| `Creds` | Kerberoast, ASREPRoast, credential exposure in SYSVOL |
| `Rights` | ACLs, DCSync, password reset rights, dangerous OU permissions |
| `Delegation` | Unconstrained, constrained, resource-based constrained delegation |
| `ADCS` | Certificate templates, ESC1–ESC15 vulnerabilities |
| `Accounts` | Privileged accounts, protected users, service accounts, SID history |
| `GPO` | GPO permissions, local group membership via GPO |
| `Computer` | LAPS, outdated systems, infrastructure servers |
| `Application` | Exchange, SCCM, SCOM infrastructure |
| `Bloodhound` | BloodHound CE data collection |

Run specific modules:

```powershell
Invoke-adPEAS -Domain "contoso.com" -UseWindowsAuth -Module Domain,Creds,ADCS
```

---

## Documentation

Full documentation is available in the [docs/](docs/) directory:

| Document                                                | Topic                             |
| ------------------------------------------------------- | --------------------------------- |
| [Installation](docs/01-Installation.md)                 | Download, setup, execution policy |
| [Quick-Start](docs/02-Quick-Start.md)                   | Get started in 5 minutes          |
| [Authentication](docs/03-Authentication-Methods.md)     | All authentication options        |
| [Security Checks](docs/04-Security-Checks.md)           | Complete check reference          |
| [BloodHound Collector](docs/05-BloodHound-Collector.md) | BloodHound CE export              |
| [Core Functions](docs/06-Core-Functions.md)             | LDAP query functions              |
| [Set- & New-Modules](docs/07-Set-Modules.md)            | AD modification functions         |
| [Helper Functions](docs/08-Helper-Functions.md)         | Utility functions                 |
| [Architecture](docs/09-Architecture.md)                 | Technical architecture            |
| [Risk Scoring](docs/10-Risk-Scoring-System.md)          | Severity and risk scores          |
| [Troubleshooting](docs/11-Troubleshooting.md)           | Common issues and solutions       |
| [FAQ](docs/12-FAQ.md)                                   | Frequently asked questions        |

### Blog Series

A detailed blog series covering adPEAS v2 internals is published at [blog.sekurity.de](https://blog.sekurity.de/blog/adpeas-v2-introduction).

---

## License

adPEAS is **source-available**. Internal security assessments of your own organization are free. Commercial use (consulting, MSP, paid engagements) requires a commercial license.

See [LICENSE](license/LICENSE.md) for full terms, [COMMERCIAL_AGREEMENT](license/COMMERCIAL_AGREEMENT.md) for the commercial agreement, and [PRICING](license/PRICING.md) for licensing options.

- **Licensing Inquiries:** license@sekurity.gmbh
- **Technical Support:** support@sekurity.gmbh

---

## Legal Notice

adPEAS is intended for **authorized security testing only**. Always obtain written authorization before testing. Never use against systems you do not own or have permission to test. The authors are not responsible for misuse of this tool. Comply with all applicable laws and regulations.

---

## Author

**Alexander Sturz** — [SEKurity GmbH](https://sekurity.de)

- GitHub: [@61106960](https://github.com/61106960)
- Blog: [blog.sekurity.de](https://blog.sekurity.de)
