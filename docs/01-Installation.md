# Installation

This guide covers the installation and setup of adPEAS v2.

---

## Requirements

### System Requirements

- **Operating System**: Windows 10/11, Windows Server 2016/2019/2022/2025
- **PowerShell Version**: 5.1 or higher (Windows PowerShell)
- **.NET Framework**: 4.5+ (included in Windows)

### Network Requirements

- TCP port 389 (LDAP) or 636 (LDAPS) to Domain Controller
- TCP port 88 (Kerberos) for Kerberos authentication
- TCP port 445 (SMB/CIFS) for SYSVOL/NETLOGON access (GPO analysis, credential scanning)
- TCP port 80 (HTTP) and 443 (HTTPS) to ADCS and Exchange
- TCP port 3268 (GC) or 3269 (GC over SSL) - optional, for cross-domain/forest SID resolution
- DNS resolution to target domain

### No External Dependencies

adPEAS does **not** require:

- Active Directory PowerShell module
- RSAT (Remote Server Administration Tools)
- PowerView or other third-party modules
- Domain-joined system (works from non-domain-joined machines)

---

## Download

### Option 1: GitHub Releases (Recommended)

Download the latest version from the [GitHub Releases](https://github.com/61106960/adPEAS) page.

### Option 2: Clone Repository

```powershell
git clone https://github.com/61106960/adPEAS.git
cd adPEAS
```

### Option 3: Direct Download

```powershell
# Download readable version
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/61106960/adPEAS/main/adPEAS.ps1" -OutFile "adPEAS.ps1"

# Or download obfuscated version (smaller)
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/61106960/adPEAS/main/adPEAS_obf.ps1" -OutFile "adPEAS_obf.ps1"
```

---

## File Versions

Choose the version that best fits your needs:

| File | Size | Use Case |
|------|------|----------|
| `adPEAS.ps1` | ~4.5 MB | Development, debugging, code review |
| `adPEAS_min.ps1` | ~3-4 MB | Regular use with smaller footprint |
| `adPEAS_ultra.ps1` | ~3 MB | Minimal size, no comments |
| `adPEAS_obf.ps1` | <1 MB | Smallest size, obfuscated for transfer |

---

## Loading adPEAS

### adPEAS.ps1, adPEAS_min.ps1, adPEAS_ultra.ps1, adPEAS_obf.ps1

```powershell
# Import the module
Import-Module .\adPEAS.ps1

# Verify it's loaded
Get-Command Invoke-adPEAS
```


---

## Execution Policy

If you encounter execution policy restrictions:

### Option 1: Bypass for Current Session

```powershell
powershell -ExecutionPolicy Bypass
# Then inside the new session:
Import-Module .\adPEAS.ps1
```

### Option 2: Set Policy for Current User

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Option 3: Unblock Downloaded File

```powershell
Unblock-File -Path .\adPEAS.ps1
```

---

## Verifying Installation

After loading adPEAS, verify that the main functions are available:

```powershell
# List all adPEAS functions
Get-Command -Module adPEAS

# Or check specific functions
Get-Command Invoke-adPEAS
Get-Command Connect-adPEAS
Get-Command Get-DomainUser
```

Expected output should include functions like:

- `Invoke-adPEAS` - Main execution function
- `Connect-adPEAS` - Authentication function
- `Get-DomainUser` - User enumeration
- `Get-DomainComputer` - Computer enumeration
- `Get-DomainGroup` - Group enumeration
- And many more...

---

## Building from Source

The `main` branch contains only source files (`src/`). Pre-built release files are attached to each [GitHub Release](https://github.com/61106960/adPEAS/releases). To build from the latest source yourself, use the included build script:

```powershell
git clone https://github.com/61106960/adPEAS.git
cd adPEAS
.\Build-Release.ps1
```

This produces all four variants in the repository root:

| File | Description |
|------|-------------|
| `adPEAS.ps1` | Readable version with comments |
| `adPEAS_min.ps1` | Minimized, no comments |
| `adPEAS_ultra.ps1` | Ultra-compressed, no comments |
| `adPEAS_obf.ps1` | Obfuscated (GZip + XOR + Base64) |

Requires Windows PowerShell 5.1 and no additional dependencies.

---

## Licensing

adPEAS uses an RSA-SHA256 signature-based license system. A valid license replaces the default disclaimer in console output and HTML reports with a personalized message ("Licensed to {Licensee} - Valid until {ValidUntil}"). All features remain fully available regardless of license status.

### Build-time Embedding

The recommended approach is to embed the license during the build process. This produces standalone `.ps1` files that already contain the license - no additional parameters needed at runtime.

```powershell
.\Build-Release.ps1 -License .\license.json
```

The build output confirms the embedding:

```
[Build]   - Embedding license from: .\license.json
[Build]     Licensee: Acme GmbH
[Build]     Valid until: 2027-06-30
```

All four output variants (`adPEAS.ps1`, `adPEAS_min.ps1`, `adPEAS_ultra.ps1`, `adPEAS_obf.ps1`) will contain the embedded license.

### Runtime License

If you are using a build without embedded license, you can provide the license file at runtime. There are two options:

**Option 1: Two-step workflow (Connect + Invoke separately)**

```powershell
Connect-adPEAS -Domain "contoso.com" -UseWindowsAuth -License .\license.json
Invoke-adPEAS
```

**Option 2: Single command**

```powershell
Invoke-adPEAS -Domain "contoso.com" -UseWindowsAuth -License .\license.json
```

Both options load the license from the specified file path and apply it to the current session.

### License Priority

When multiple license sources are available, the following priority applies:

| Priority | Source | Description |
|----------|--------|-------------|
| 1 (highest) | `-License` parameter on `Invoke-adPEAS` | Runtime override |
| 2 | `-License` parameter on `Connect-adPEAS` | Stored in session |
| 3 (lowest) | Build-time embedded license | Compiled into the script |

### License File Format

A license file is a JSON file with three fields:

```json
{
  "Licensee": "Company Name",
  "ValidUntil": "2027-06-30",
  "Signature": "Base64-encoded RSA-SHA256 signature"
}
```

License files are issued by the adPEAS author. The signature is verified against a public key embedded in the tool.

### License Terms and Pricing

For complete licensing details, see the documents in the [`license/`](../license/) directory:

| Document | Description |
|----------|-------------|
| [LICENSE.md](../license/LICENSE.md) | License terms (permitted use, commercial use, restrictions) |
| [COMMERCIAL_AGREEMENT.md](../license/COMMERCIAL_AGREEMENT.md) | Commercial license agreement |
| [PRICING.md](../license/PRICING.md) | License types and pricing |

**In short**: Internal security assessments of your own organization are free. Consultants, MSPs, and service providers using adPEAS in customer environments or paid engagements require a commercial license. All commercial licenses include e-mail support and updates for the duration of the license term.

---

## Updating adPEAS

To update to a newer version:

1. Close any PowerShell sessions using adPEAS
2. Replace the .ps1 file with the new version
3. Re-import the module

```powershell
# Remove old module from memory
Remove-Module adPEAS -ErrorAction SilentlyContinue

# Import new version
Import-Module .\adPEAS.ps1
```

---

## Troubleshooting Installation

### Module Not Loading

**Symptom**: `Import-Module` fails or functions are not available

**Solutions**:

1. Check PowerShell version: `$PSVersionTable.PSVersion`
2. Verify file integrity (not corrupted during download)
3. Try dot-sourcing: `. .\adPEAS.ps1`

### Execution Policy Error

**Symptom**: "cannot be loaded because running scripts is disabled"

**Solution**: Use one of the execution policy bypass methods above

### File Not Found

**Symptom**: "cannot find path" error

**Solution**: Use full path or navigate to the correct directory

```powershell
# Use full path
Import-Module C:\Tools\adPEAS.ps1

# Or navigate first
cd C:\Tools
Import-Module .\adPEAS.ps1
```

---

## Navigation

- [Previous: Home](00-Home.md)
- [Next: Quick-Start](02-Quick-Start.md)
- [Back to Home](00-Home.md)