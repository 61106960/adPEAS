# Quick Start Guide

Get started with adPEAS v2 in under 5 minutes.

---

## Basic Usage

### Step 1: Load adPEAS

```powershell
Import-Module .\adPEAS.ps1
```

### Step 2: Run a Full Scan

```powershell
# From a domain-joined machine (uses current user)
Invoke-adPEAS -Domain "contoso.com" -UseWindowsAuth

# With credentials
Invoke-adPEAS -Domain "contoso.com" -Credential (Get-Credential)

# With username and password
Invoke-adPEAS -Domain "contoso.com" -Username "john.doe" -Password "P@ssw0rd!"
```

That's it! adPEAS will enumerate the domain and display findings.

---

## Two Usage Styles

adPEAS v2 supports two usage patterns:

### Style 1: One-Liner (adPEAS v1 Compatible)

Connect and scan in a single command:

```powershell
Invoke-adPEAS -Domain "contoso.com" -UseWindowsAuth
```

### Style 2: Session-Based (v2 Style)

Establish a session first, then run multiple operations:

```powershell
# Step 1: Connect
Connect-adPEAS -Domain "contoso.com" -UseWindowsAuth

# Step 2: Run full scan
Invoke-adPEAS

# Step 3: Run individual checks as needed
Get-KerberoastableAccounts
Get-DomainTrusts
Get-PrivilegedGroupMembers

# Step 4: Disconnect when done
Disconnect-adPEAS
```

The session-based approach is recommended for interactive assessments.

### Style 2b: Session-Based with Tab-Completion

For interactive exploration, enable tab-completion for quick object lookup:

```powershell
# Connect with tab-completion cache
Connect-adPEAS -Domain "contoso.com" -UseWindowsAuth -BuildCompletionCache

# Now use TAB to autocomplete object names:
Get-DomainUser -Identity adm[TAB]        # → "administrator"
Get-DomainGroup -Identity Domain[TAB]    # → "Domain Admins", "Domain Users", ...
Get-DomainGPO -Identity Def[TAB]         # → "Default Domain Policy"
```

See [Helper-Functions](08-Helper-Functions.md#tab-completion) for more details.

---

## Common Scenarios

### Scenario 1: Domain-Joined Machine

```powershell
# Uses current Windows credentials
Import-Module .\adPEAS.ps1
Invoke-adPEAS -Domain "contoso.com" -UseWindowsAuth
```

### Scenario 2: Non-Domain-Joined Machine

```powershell
# Specify credentials explicitly
Import-Module .\adPEAS.ps1
$cred = Get-Credential  # Enter domain\username and password
Invoke-adPEAS -Domain "contoso.com" -Credential $cred
```

### Scenario 3: Specific Domain Controller

```powershell
# Target a specific DC
Invoke-adPEAS -Domain "contoso.com" -Server "dc01.contoso.com" -Username "john.doe" -Password "P@ssw0rd!"
```

### Scenario 4: LDAPS (Encrypted)

```powershell
# Force LDAPS connection
Invoke-adPEAS -Domain "contoso.com" -UseWindowsAuth -UseLDAPS
```

### Scenario 5: OPSEC Mode (Stealth)

```powershell
# Skip Kerberoast, ASREPRoast, and BloodHound collection
Invoke-adPEAS -Domain "contoso.com" -UseWindowsAuth -OPSEC
```

OPSEC mode skips:
- Kerberoasting (TGS ticket requests)
- AS-REP Roasting (AS-REQ without pre-auth)
- BloodHound collection (many LDAP queries)

### Scenario 5b: Include Privileged Accounts

```powershell
# Include privileged accounts (Domain Admins, etc.) in permission checks
Invoke-adPEAS -Domain "contoso.com" -UseWindowsAuth -IncludePrivileged
```

By default, adPEAS filters out expected privileged accounts (Domain Admins, Enterprise Admins, etc.) from permission findings to focus on actual misconfigurations. Use `-IncludePrivileged` to see ALL accounts with dangerous permissions:
- Privileged accounts are shown in yellow (expected)
- Non-privileged accounts are shown in red (findings)

### Scenario 6: Write Output to File

```powershell
# Default: All formats - creates adPEAS_out.txt, adPEAS_out.html and adPEAS_out.json
Invoke-adPEAS -Domain "contoso.com" -UseWindowsAuth -Outputfile .\adPEAS_out

# Text output only - creates adPEAS_out.txt
Invoke-adPEAS -Domain "contoso.com" -UseWindowsAuth -Outputfile .\adPEAS_out -Format Text

# HTML output only - creates adPEAS_out.html
Invoke-adPEAS -Domain "contoso.com" -UseWindowsAuth -Outputfile .\adPEAS_out -Format HTML

# Text output without colors (plain text for editors)
Invoke-adPEAS -Domain "contoso.com" -UseWindowsAuth -Outputfile .\adPEAS_out -Format Text -NoColor

# Console output without colors
Invoke-adPEAS -Domain "contoso.com" -UseWindowsAuth -NoColor
```

**Output Formats:**

| Format | Description |
|--------|-------------|
| `All` (default) | Creates .txt, .html and .json files |
| `Text` | Plain text file with ANSI colors (viewable with `cat` or `Get-Content`) |
| `HTML` | Interactive HTML report with filtering, search, and tooltips |
| `JSON` | Machine-readable JSON export for offline conversion and report comparison |
**Note:** The file extension is added automatically based on the format. Just provide the base filename without extension.

### Scenario 7: Verbose Logging to File (Troubleshooting)

```powershell
# Enable verbose logging to file for detailed troubleshooting
# -VerboseLogging automatically enables -Verbose for console output
Invoke-adPEAS -Domain "contoso.com" -UseWindowsAuth -Outputfile .\report -VerboseLogging

# This writes timestamped verbose messages to the output text file:
# 2026-01-14 18:42:15 [Verbose] [Get-DomainUser] Querying users...
# 2026-01-14 18:42:16 [Verbose] [Get-DomainComputer] Found 50 computers
```

**Requirements:**
- `-Outputfile` must be specified (VerboseLogging requires a text file destination)
- `-VerboseLogging` writes verbose messages to the output file AND automatically enables `-Verbose` for console output

**Use Case:** When you need to analyze what adPEAS is doing internally, or when reporting issues.

### Scenario 8: Incremental Scanning with OutputAppend

```powershell
# Run modules separately and merge into a single report
Connect-adPEAS -Domain "contoso.com" -UseWindowsAuth

# First module - creates report files + JSON cache
Invoke-adPEAS -Module Domain -Outputfile .\audit

# Additional modules - findings are merged into existing report
Invoke-adPEAS -Module Creds,Rights -Outputfile .\audit -OutputAppend

# Even more modules later
Invoke-adPEAS -Module ADCS,Delegation -Outputfile .\audit -OutputAppend
```

**How it works:**
- Every run with `-Outputfile` creates up to 3 files: `audit.txt`, `audit.html`, and `audit.json`
- With `-OutputAppend`, new findings are merged with existing ones from the JSON file
- The HTML report is regenerated with all combined findings
- Text report is appended (new findings added at the end)
- Without `-OutputAppend`, existing reports are overwritten (default behavior)

**JSON Export:**

adPEAS automatically saves all findings to a JSON file (`<basename>.json`) alongside the report files. This enables:
- Incremental scanning with `-OutputAppend` (merge findings across runs)
- Post-processing and analysis of scan results in external tools
- Machine-readable export of all findings with full AD object data

### Scenario 9: Offline Report Conversion

Regenerate reports from a previous JSON export — without an active LDAP connection:

```powershell
Import-Module .\adPEAS.ps1

# Convert JSON to all formats (HTML + Text + re-exported JSON)
Convert-adPEASReport -InputJson ".\audit.json" -OutputPath ".\new_report"

# Only HTML report
Convert-adPEASReport -InputJson ".\audit.json" -OutputPath ".\new_report" -Format HTML

# Only Text report (plain text without ANSI colors)
Convert-adPEASReport -InputJson ".\audit.json" -OutputPath ".\new_report" -Format Text -NoColor

# Re-export JSON with current adPEAS version metadata
Convert-adPEASReport -InputJson ".\audit.json" -OutputPath ".\new_report" -Format JSON

# With license for branded reports
Convert-adPEASReport -InputJson ".\audit.json" -OutputPath ".\new_report" -License ".\license.json"
```

**Use cases:**
- Regenerate reports with a newer adPEAS version (updated finding definitions, scoring, templates)
- Create reports offline from previously collected scan data
- Convert between output formats (e.g., JSON-only scan to HTML report)

### Scenario 10: Comparing Two Scans (Diff Report)

Compare findings across two scans to track remediation progress:

```powershell
Import-Module .\adPEAS.ps1

# Compare baseline scan with current scan
Compare-adPEASReport -Baseline ".\scan_q1.json" -Current ".\scan_q2.json"

# Save diff report to file
Compare-adPEASReport -Baseline ".\scan_jan.json" -Current ".\scan_apr.json" -OutputPath ".\diff_report"
```

**The diff report shows:**
- **New findings** (in current but not in baseline) — potential new vulnerabilities
- **Remediated findings** (in baseline but not in current) — fixed issues
- **Changed findings** (severity or value changed between scans)
- **Summary statistics** with counts per category

### Scenario 11: BloodHound Data Collection

```powershell
# Collect data for BloodHound CE attack path analysis
Connect-adPEAS -Domain "contoso.com" -UseWindowsAuth
Invoke-adPEASCollector

# Output: <timestamp>_CONTOSO.COM_BloodHound.zip
# Import the ZIP into BloodHound CE
```

See [BloodHound-Collector](05-BloodHound-Collector.md) for detailed documentation.

---

## Running Specific Modules

Run only specific security check categories:

```powershell
# Single module
Invoke-adPEAS -Domain "contoso.com" -UseWindowsAuth -Module Domain

# Multiple modules
Invoke-adPEAS -Domain "contoso.com" -UseWindowsAuth -Module Domain,Accounts,ADCS
```

Available modules (ordered by severity/impact):

| Module        | Description                                           |
| ------------- | ----------------------------------------------------- |
| `Domain`      | Domain configuration, trusts, password policy         |
| `Creds`       | Kerberoast, ASREPRoast, credential exposure           |
| `Rights`      | ACLs, DCSync, password reset rights                   |
| `Delegation`  | Unconstrained, constrained, RBCD delegation           |
| `ADCS`        | Certificate templates, ESC vulnerabilities            |
| `Accounts`    | Privileged accounts, protected users, inactive admins |
| `GPO`         | GPO permissions, local group membership               |
| `Computer`    | LAPS, outdated systems, infrastructure servers        |
| `Application` | Exchange, SCCM, SCOM infrastructure                   |
| `Bloodhound`  | BloodHound CE collector                               |

---

## Individual Check Functions

Run specific checks without the full scan:

```powershell
# First establish a session
Connect-adPEAS -Domain "contoso.com" -UseWindowsAuth

# Then run individual checks
Get-KerberoastableAccounts     # Find Kerberoastable accounts
Get-ASREPRoastableAccounts     # Find AS-REP roastable accounts
Get-UnconstrainedDelegation    # Find unconstrained delegation
Get-ConstrainedDelegation      # Find constrained delegation
Get-DomainTrusts               # Enumerate domain trusts
Get-PrivilegedGroupMembers     # List privileged group members
Get-DangerousACLs              # Find dangerous ACLs on domain root
Get-ADCSVulnerabilities        # Find ADCS misconfigurations
Get-...
```

---

## Reading the Output

adPEAS uses color-coded output:

| Symbol | Color         | Meaning                            |
| ------ | ------------- | ---------------------------------- |
| `[?]`  | Blue          | Section header / Information       |
| `[!]`  | Red           | Finding / Vulnerability            |
| `[+]`  | Yellow        | Interesting hint for investigation |
| `[*]`  | Green         | General note / Information         |
| `[#]`  | Red on Yellow | Secure configuration               |

Example output:

```
[?] Analyzing Kerberoastable Accounts
[!] Found 3 Kerberoastable service accounts
    sAMAccountName: svc_backup
    servicePrincipalName: MSSQLSvc/db01.contoso.com:1433
    ...
[+] Account has weak encryption (RC4)
```

---

## Session Information

View current session details:

```powershell
# Show session info
Get-adPEASSession

# Test connection health
Get-adPEASSession -TestConnection
```

---

## Cleaning Up

End your session when finished:

```powershell
Disconnect-adPEAS
```

---

## Next Steps

- [Authentication-Methods](03-Authentication-Methods.md) - Learn about all authentication options
- [Security-Checks](04-Security-Checks.md) - Detailed reference for all checks
- [Core-Functions](06-Core-Functions.md) - Use individual query functions

---

## Navigation

- [Previous: Installation](01-Installation.md)
- [Next: Authentication-Methods](03-Authentication-Methods.md)
- [Back to Home](00-Home.md)