# Helper Functions Reference

Reference documentation for some adPEAS v2 utility and helper functions.

---

## Overview

Helper functions provide supporting functionality for core operations and security checks.

| Category | Functions |
|----------|-----------|
| [Session Management](#session-management) | Connect-adPEAS, Disconnect-adPEAS, Get-adPEASSession, Ensure-LDAPConnection |
| [Logging](#logging) | Write-Log |
| [Tab-Completion](#tab-completion) | Build-CompletionCache, Clear-CompletionCache, Get-CompletionCacheStats |
| [Kerberos Authentication](#kerberos-authentication) | Invoke-KerberosAuth, Request-ServiceTicket, Import-KerberosTicket, Invoke-UnPACTheHash |
| [Password Hash Derivation](#password-hash-derivation) | Get-Hash |
| [SID and ACL Utilities](#sid-and-acl-utilities) | ConvertFrom-SID, ConvertTo-SID, ConvertTo-LDAPSIDHex, Test-IsPrivileged, Get-ObjectOwner |
| [Credential Decryption](#credential-decryption) | ConvertFrom-GPPPassword, ConvertFrom-VBE |
| [Testing Functions](#testing-functions) | Invoke-Kerberoast, Invoke-ASREPRoast |
| [ADCS Certificate Enrollment](#adcs-certificate-enrollment) | Request-ADCSCertificate |
| [Network Utilities](#network-utilities) | Invoke-SMBAccess, Resolve-adPEASName |

---

## Session Management

### Connect-adPEAS

Establishes an authenticated LDAP connection to Active Directory.

```powershell
# Windows Authentication
Connect-adPEAS -Domain "contoso.com" -UseWindowsAuth

# With credentials
Connect-adPEAS -Domain "contoso.com" -Credential (Get-Credential)

# With username and password
Connect-adPEAS -Domain "contoso.com" -Username "admin" -Password "pass"

# With certificate (PKINIT)
Connect-adPEAS -Domain "contoso.com" -Certificate "user.pfx" -CertificatePassword "pass"

# With certificate (Pass-the-Cert/Schannel - no Kerberos needed)
Connect-adPEAS -Domain "contoso.com" -Certificate "user.pfx" -ForcePassTheCert

# With NT hash
Connect-adPEAS -Domain "contoso.com" -Username "admin" -NTHash "32ED87BDB5FDC5E9CBA88547376818D4"

# Use SimpleBind (skip Kerberos)
Connect-adPEAS -Domain "contoso.com" -Username "admin" -Password "pass" -ForceSimpleBind

# Use NTLM Impersonation (keeps existing Kerberos tickets)
Connect-adPEAS -Domain "contoso.com" -Username "admin" -Password "pass" -ForceNTLM
```

See [Authentication-Methods](03-Authentication-Methods.md) for complete details.

---

### Disconnect-adPEAS

Closes the LDAP connection and clears session data.

```powershell
Disconnect-adPEAS
```

**Effects**:
- Disposes LdapConnection
- Disposes Global Catalog connection (`$Script:GCConnection`), if established
- Clears `$Script:LdapConnection`
- Clears `$Script:LDAPContext`
- Clears SID resolution cache

---

### Get-adPEASSession

Displays current session information and tests connection health.

```powershell
# Show session info
Get-adPEASSession

# Test connection is working
Get-adPEASSession -TestConnection

# Quiet mode (returns boolean)
$healthy = Get-adPEASSession -TestConnection -Quiet
```

**Output**:
- Domain name
- Domain Controller
- Authentication method
- Authenticated user
- NT-Hash (if recovered via UnPAC-the-Hash after PKINIT authentication)
- Connection protocol (LDAP/LDAPS)

---

### Build-CompletionCache

Manually builds or refreshes the tab-completion cache.

```powershell
# Build cache for all object types
Build-CompletionCache

# Build cache for specific types only
Build-CompletionCache -ObjectTypes @('Users', 'Groups')

# Available types: Users, Computers, Groups, GPOs, All (default)
```

**Note**: Requires an active LDAP connection (`Connect-adPEAS` must be called first).

---

### Clear-CompletionCache

Clears all cached completion data.

```powershell
Clear-CompletionCache
```

**Use Case**: When switching domains or when cache becomes stale.

---

### Get-CompletionCacheStats

Returns statistics about the current completion cache.

```powershell
Get-CompletionCacheStats
```

**Output**:
```powershell
Users       : 523
Computers   : 87
Groups      : 142
GPOs        : 31
Total       : 783
CacheExists : True
```

---

### Cache Details

**What's cached**:

| Object Type | Cached Attribute | Example |
|-------------|------------------|---------|
| Users | sAMAccountName | `administrator`, `john.doe` |
| Computers | sAMAccountName (without $) | `DC01`, `WS001` |
| Groups | sAMAccountName | `Domain Admins`, `IT-Support` |
| GPOs | displayName | `Default Domain Policy` |

**Important Notes**:
- Cache is stored in memory only - cleared when PowerShell session ends
- Cache is NOT automatically updated - run `Build-CompletionCache` to refresh
- Maximum 50 suggestions are shown per TAB press
- Names with spaces are automatically quoted
- Large domains (>10,000 objects) may take a few seconds to cache

---

## Kerberos Authentication

### Invoke-KerberosAuth

Performs Kerberos AS-REQ/AS-REP to obtain a TGT.

```powershell
# Password-based
$tgt = Invoke-KerberosAuth -UserName "admin" -Domain "contoso.com" -Password "P@ss"

# Overpass-the-Hash
$tgt = Invoke-KerberosAuth -UserName "admin" -Domain "contoso.com" -NTHash "32ED87BDB5FDC5E9CBA88547376818D4"

# Pass-the-Key (AES256) - key is user+domain specific, get from Mimikatz sekurlsa::ekeys
$tgt = Invoke-KerberosAuth -UserName "admin" -Domain "contoso.com" -AES256Key "YOUR_64_HEX_CHAR_KEY"

# PKINIT (Certificate)
$tgt = Invoke-KerberosAuth -UserName "admin" -Domain "contoso.com" -Certificate "user.pfx"

# Save TGT to file
$tgt = Invoke-KerberosAuth -UserName "admin" -Domain "contoso.com" -Password "P@ss" -OutputKirbi "admin.kirbi"

# Get only the Base64 ticket (for easy copy-paste to other tools)
$ticketB64 = Invoke-KerberosAuth -UserName "admin" -Domain "contoso.com" -NTHash "32ED87..." -OutputTicketOnly
```

**Parameters**:

| Parameter | Type | Description |
|-----------|------|-------------|
| `-UserName` | String | sAMAccountName of the user |
| `-Domain` | String | Target domain FQDN |
| `-DomainController` | String | Specific KDC server (optional) |
| `-Credential` | PSCredential | PSCredential object |
| `-Password` | String | Plaintext password |
| `-NTHash` | String | 32-char hex NT hash (Overpass-the-Hash) |
| `-AES256Key` | String | 64-char hex AES256 key (Pass-the-Key) |
| `-AES128Key` | String | 32-char hex AES128 key (Pass-the-Key) |
| `-Certificate` | String/X509Certificate2 | PFX file path, Base64-encoded certificate, or X509Certificate2 object (PKINIT) |
| `-CertificatePassword` | String | PFX password (default: empty) |
| `-PreferredEType` | Int | 18=AES256, 17=AES128, 23=RC4 |
| `-OutputKirbi` | String | Path to save TGT as .kirbi file |
| `-OutputTicketOnly` | Switch | Return Base64 KRB-CRED (kirbi) for direct use |
| `-NoPAC` | Switch | Request TGT without PAC |

**Return Object** (default):
```powershell
@{
    Success        = $true
    Method         = "Password (AES256)"
    UserName       = "admin"
    Domain         = "CONTOSO.COM"
    EncryptionType = 18
    Ticket         = "base64..."      # TGT (raw)
    SessionKey     = "base64..."      # Session key
    TicketBytes    = [byte[]]         # Raw ticket
    SessionKeyBytes = [byte[]]        # Raw key
}
```

**Return Value** (with `-OutputTicketOnly`):
```powershell
# Returns KRB-CRED (kirbi format) as Base64 - includes session key!
# Can be directly used with Connect-adPEAS -Kirbi or Rubeus ptt
"doIKxjCCCsKgAwIBBaEDAgEWooIK..."
```

**Usage Example** (with `-OutputTicketOnly`):
```powershell
# Get TGT and directly use for connection
$kirbi = Invoke-KerberosAuth -UserName "admin" -Domain "contoso.com" -NTHash "32ED87..." -OutputTicketOnly
Connect-adPEAS -Domain "contoso.com" -Kirbi $kirbi

# Get ticket directly into clipboard
Invoke-KerberosAuth -UserName "admin" -Domain "contoso.com" -Password "pass" -OutputTicketOnly | Set-Clipboard

# Use with Rubeus
$ticket = Invoke-KerberosAuth -UserName "admin" -Domain "contoso.com" -AES256Key "4a3b2c1d..." -OutputTicketOnly
# Rubeus.exe ptt /ticket:$ticket
```

---

### Request-ServiceTicket

Requests a TGS (service ticket) using an existing TGT.

```powershell
# Get TGT first
$tgt = Invoke-KerberosAuth -UserName "admin" -Domain "contoso.com" -Password "pass"

# Request LDAP service ticket
$tgs = Request-ServiceTicket -TGT $tgt.TicketBytes `
    -SessionKey $tgt.SessionKeyBytes `
    -SessionKeyType $tgt.EncryptionType `
    -ServicePrincipalName "ldap/dc01.contoso.com" `
    -Domain "contoso.com" `
    -DomainController "dc01.contoso.com" `
    -UserName "admin"
```

**Return Object**:
```powershell
@{
    Success       = $true
    ServiceName   = "ldap/dc01.contoso.com"
    Ticket        = "base64..."
    SessionKey    = "base64..."
    TicketBytes   = [byte[]]
}
```

---

### Import-KerberosTicket

Imports a Kerberos ticket into the Windows session (Pass-the-Ticket).

```powershell
# Import TGT from bytes
Import-KerberosTicket -TicketBytes $tgt.TicketBytes `
    -SessionKey $tgt.SessionKeyBytes `
    -SessionKeyType $tgt.EncryptionType

# Import from .kirbi file
Import-KerberosTicket -Kirbi "admin.kirbi"

# Import from Base64
Import-KerberosTicket -TicketBase64 "doIFxjCC..."
```

**Requirements**: No administrator rights required (uses LsaConnectUntrusted).

---

## Password Hash Derivation

### Get-Hash

Derives common password hashes and Kerberos encryption keys from a plaintext password. Returns hex strings ready for copy/paste into tools like adPEAS, Rubeus, Mimikatz, or Hashcat.

```powershell
# Password only — RC4 + MD5/SHA hashes
Get-Hash -Password "P@ssw0rd"

# With user — adds DCC/DCC2
Get-Hash -Password "P@ssw0rd" -UserName "admin"

# Full — all hashes including AES Kerberos keys
Get-Hash -Password "P@ssw0rd" -Domain "contoso.com" -UserName "admin"
```

**Output** (full):
```
UserName : admin
Domain   : CONTOSO.COM
Password : P@ssw0rd
RC4      : E19CCF75EE54E06B06A5907AF13CEF42
AES128   : 8D7B15C4652FEDACC8CFAB8F49347A8B
AES256   : 72D552D91EA1A464381E0B63E074510E83944C0456747B5DC4171C88254AEEC6
DCC      : B27B6F1A2EFC3D...
DCC2     : 2139D292C27FE1...
MD5      : 202CB962AC5907...
SHA1     : 40BD001563085F...
SHA256   : A665A459204224...
SHA512   : 3C9909AFEC2535...
```

**Parameters**:

| Parameter | Type | Description |
|-----------|------|-------------|
| `-Password` | String | Plaintext password (required) |
| `-Domain` | String | Domain FQDN (optional, needed for AES keys) |
| `-UserName` | String | sAMAccountName (optional, needed for AES keys and DCC/DCC2) |

**Hash Formats**:

| Hash | Algorithm | Requires | Context |
|------|-----------|----------|---------|
| RC4 (NT-Hash) | MD4(UTF-16LE(password)) | Password only | NTLM auth, Pass-the-Hash |
| AES128 | PBKDF2-SHA1 + DK (RFC 3962) | Domain + UserName | Kerberos etype 17 |
| AES256 | PBKDF2-SHA1 + DK (RFC 3962) | Domain + UserName | Kerberos etype 18 |
| DCC | MD4(NT-Hash \|\| UTF-16LE(lowercase(user))) | UserName | mscache v1 (pre-Vista) |
| DCC2 | PBKDF2-HMAC-SHA1(DCC, user, 10240) | UserName | mscachev2 (Vista+) |
| MD5 | MD5(UTF-8(password)) | Password only | Legacy systems |
| SHA1 | SHA1(UTF-8(password)) | Password only | Various systems |
| SHA256 | SHA256(UTF-8(password)) | Password only | Modern systems |
| SHA512 | SHA512(UTF-8(password)) | Password only | Modern systems |

**Usage with Connect-adPEAS**:

```powershell
$h = Get-Hash -Password "P@ssw0rd" -Domain "contoso.com" -UserName "admin"

# Overpass-the-Hash
Connect-adPEAS -Domain "contoso.com" -Username "admin" -NTHash $h.RC4

# Pass-the-Key
Connect-adPEAS -Domain "contoso.com" -Username "admin" -AES256Key $h.AES256
```

**Note**: RC4, MD5, SHA1, SHA256, SHA512 are domain-independent — same password always produces the same hash. AES and DCC/DCC2 include the username (and domain for AES) in the salt.

---

## SID and ACL Utilities

### ConvertFrom-SID

Converts a SID to a friendly name (DOMAIN\Username).

```powershell
# Convert single SID
$name = ConvertFrom-SID -SID "S-1-5-21-123456789-123456789-123456789-500"
# Returns: CONTOSO\Administrator

# Well-known SIDs are resolved locally
$name = ConvertFrom-SID -SID "S-1-5-18"
# Returns: NT AUTHORITY\SYSTEM
```

**Features**:
- Caches resolved SIDs for performance
- Handles well-known SIDs without LDAP queries
- Automatically uses the Global Catalog (port 3268/3269) to resolve SIDs from foreign domains in the forest. The GC connection is created on demand via `Get-GCConnection` and cached in `$Script:GCConnection` for the session
- Falls back to a RID-based format (e.g., `FOREIGN\DomainAdmins (RID:512)`) if the GC connection is unavailable
- Returns original SID if resolution fails

---

### ConvertTo-LDAPSIDHex

Converts a SID string to LDAP binary hex format for queries.

```powershell
$sidHex = ConvertTo-LDAPSIDHex -SIDString "S-1-5-21-123456789-123456789-123456789-500"
# Returns: \01\05\00\00\00\00\00\05\15\00\00\00...

# Use in LDAP filter
$user = Get-DomainObject -LDAPFilter "(objectSid=$sidHex)"
```

---

### Test-IsPrivileged

Determines the security category of an identity in Active Directory. Returns a detailed PSCustomObject with classification information.

```powershell
# Check by SID - returns detailed result
$result = Test-IsPrivileged -Identity "S-1-5-21-...-512"
$result.Category      # "Privileged"
$result.IsPrivileged  # $true
$result.Reason        # "Privileged group (RID suffix -512)"

# Check Operator group
$result = Test-IsPrivileged -Identity "S-1-5-32-548"
$result.Category      # "Operator"
$result.IsPrivileged  # $false (Operators not privileged by default)

# Include Operators as privileged
$result = Test-IsPrivileged -Identity "S-1-5-32-548" -IncludeOperators
$result.IsPrivileged  # $true

# Check Exchange service group
$result = Test-IsPrivileged -Identity "Organization Management"
$result.Category      # "ExchangeService"
$result.IsPrivileged  # $false (by-design permissions, not considered privileged)
```

**Parameters**:

| Parameter | Description |
|-----------|-------------|
| `-Identity` | SID, DN, AD Object, or sAMAccountName to check |
| `-IncludeOperators` | Treat Operator category as Privileged |
| `-NoCache` | Bypass result cache |

**Return Object** (always PSCustomObject):

| Property | Type | Description |
|----------|------|-------------|
| `IsPrivileged` | Boolean/Null | `$true`/`$false`/`$null` (affected by IncludeOperators) |
| `Category` | String | Privileged, Operator, ExchangeService, BroadGroup, Standard, Unknown |
| `Reason` | String | Why identity was classified this way |
| `MatchedSID` | String | The SID that matched (or `$null`) |
| `MatchedGroup` | String | Group name if matched via membership (or `$null`) |
| `Identity` | Object | Original identity input |

**Categories**:

| Category | IsPrivileged (default) | Examples |
|----------|------------------------|----------|
| Privileged | `$true` | Domain Admins, Enterprise Admins, SYSTEM, Administrators |
| Operator | `$false` | Account/Server/Backup/Print Operators |
| ExchangeService | `$false` | Organization Management, Exchange Servers (by-design permissions) |
| BroadGroup | `$false` | Domain Users, Authenticated Users, Everyone |
| Standard | `$false` | Regular users and groups |
| Unknown | `$null` | Could not resolve identity |

**Reason Values**:
- `"Privileged identity (static SID)"` - Well-known privileged SID
- `"Privileged group (RID suffix -512)"` - Domain-relative privileged group
- `"Operator group (static SID)"` - Direct Operator group SID
- `"Member of privileged group"` - Nested in privileged group
- `"sIDHistory contains privileged SID (SID History Injection risk)"` - CRITICAL: Privileged via sIDHistory
- And more...

**SID History Injection Detection**:

Test-IsPrivileged automatically detects SID History Injection attacks by checking if the identity's sIDHistory attribute contains privileged SIDs:

```powershell
$result = Test-IsPrivileged -Identity "suspicious_user"
if ($result.Reason -like "*sIDHistory*") {
    # CRITICAL: This account has privileged SIDs in sIDHistory!
    # Possible SID History Injection attack
}
```

---

### Get-ObjectOwner

Retrieves the owner of an AD object.

```powershell
$owner = Get-ObjectOwner -DistinguishedName "CN=Computer01,CN=Computers,DC=contoso,DC=com"
```

**Returns**:
```powershell
@{
    OwnerSID  = "S-1-5-21-..."
    OwnerName = "CONTOSO\Domain Admins"
}
```

---

## Credential Decryption

### ConvertFrom-GPPPassword

Decrypts Group Policy Preferences (GPP) passwords.

```powershell
# Decrypt GPP cpassword
$clearText = ConvertFrom-GPPPassword -EncryptedPassword "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
```

**Background**: GPP passwords use a published AES key and can always be decrypted.

**Use Case**: Found in SYSVOL XML files (Groups.xml, Drives.xml, etc.)

---

### ConvertFrom-VBE

Decodes VBScript Encoded (.vbe) scripts.

```powershell
# Decode from encoded string
$script = ConvertFrom-VBE -EncodedScript "#@~^AAAA..."

# Decode from file content
$vbeContent = Get-Content "logon.vbe" -Raw
$script = ConvertFrom-VBE -EncodedScript $vbeContent
```

**Parameter**: `-EncodedScript` (String, mandatory, accepts pipeline input) - The VBE-encoded content to decode.

**Use Case**: Logon scripts may be encoded and contain credentials.

---

## Testing Functions

### Invoke-Kerberoast

Unified Kerberoasting module that automatically selects the appropriate method based on authentication context.

**Two Kerberoasting methods (automatically selected):**
- **Windows API**: Uses existing Windows ticket cache (Kerberos/SSPI auth)
- **In-Memory**: Own Kerberos stack (SimpleBind auth or explicit credentials)

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `InputObject` | PSCustomObject | Pipeline input from Get-DomainUser |
| `SAMAccountName` | String | Target user's sAMAccountName |
| `SPN` | String | Target Service Principal Name |
| `Domain` | String | Target domain |
| `Server` | String | Domain Controller to use |
| `Credential` | PSCredential | Credentials for in-memory method |
| `Username` | String | Username for in-memory method |
| `Password` | String | Password for in-memory method |
| `CleanupTickets` | Switch | Remove TGS ticket from cache after extraction (Windows API only) |

**Usage Examples:**

```powershell
# Pipeline from Get-DomainUser (recommended)
Get-DomainUser -SPN -Enabled | Invoke-Kerberoast

# By SAMAccountName (looks up SPN automatically)
Invoke-Kerberoast -SAMAccountName "svc_sql"

# By SPN directly (looks up username automatically)
Invoke-Kerberoast -SPN "MSSQLSvc/db01.contoso.com:1433"

# Both parameters (fastest - no lookups needed)
Invoke-Kerberoast -SAMAccountName "svc_sql" -SPN "MSSQLSvc/db01.contoso.com:1433"

# With explicit credentials (forces in-memory method)
Invoke-Kerberoast -SAMAccountName "svc_sql" -Credential (Get-Credential)
```

**Return Object:**
```powershell
[PSCustomObject]@{
    Success          = $true/$false
    SAMAccountName   = "svc_sql"
    SPN              = "MSSQLSvc/db01.contoso.com:1433"
    Hash             = "$krb5tgs$23$*svc_sql$CONTOSO.COM$MSSQLSvc/db01...*"
    EncryptionType   = 23
    EncryptionTypeName = "RC4-HMAC"
    HashcatMode      = 13100
    Method           = "WindowsAPI" / "InMemory"
    Error            = $null / "Error message"
}
```

**Output**: Hashcat-compatible hash (mode 13100 for RC4, 19700 for AES)

---

### Invoke-ASREPRoast

Sends AS-REQ without pre-authentication to extract the AS-REP hash for offline cracking. Uses raw Kerberos protocol (TCP/UDP port 88) to communicate directly with the KDC.

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `SAMAccountName` | String | Target user's sAMAccountName (required) |
| `Domain` | String | Target domain FQDN (optional, uses session domain) |
| `DomainController` | String | Specific DC to query (optional, uses session DC or auto-discovered) |

**Usage Examples:**

```powershell
# With active session (recommended) — Domain/DC from Connect-adPEAS
$result = Invoke-ASREPRoast -SAMAccountName "vulnuser"

# Explicit domain
$result = Invoke-ASREPRoast -SAMAccountName "vulnuser" -Domain "contoso.com"

# With specific Domain Controller
$result = Invoke-ASREPRoast -SAMAccountName "vulnuser" -Domain "contoso.com" -DomainController "dc01.contoso.com"

# Check result
if ($result.Success) {
    $result.Hash          # Hashcat/John compatible hash
    $result.Severity      # "CRITICAL" (RC4), "HIGH" (AES128), "MEDIUM" (AES256)
}
```

**Return Object:**
```powershell
[PSCustomObject]@{
    SAMAccountName     = "vulnuser"
    Success            = $true/$false
    EncryptionType     = 23                  # 23=RC4, 17=AES128, 18=AES256
    EncryptionTypeName = "RC4-HMAC"
    Severity           = "CRITICAL"          # Based on encryption type
    Description        = "Very fast to crack"
    Hash               = "$krb5asrep$23$vulnuser@CONTOSO.COM:checksum$encrypted"
    Error              = $null / "Error message"
}
```

**Output**: Hashcat-compatible hash (mode 18200 for RC4, mode 19600 for AES)

---

## ADCS Certificate Enrollment

### Request-ADCSCertificate

Requests a certificate from an ADCS Certificate Authority with automatic submission method detection and fallback.

**Submission Methods** (automatic fallback):
1. **HTTPS Web Enrollment** (`/certsrv/`) - Primary method
2. **HTTP Web Enrollment** (`/certsrv/`) - Fallback if HTTPS unavailable
3. **ICertRequest COM/RPC** (DCOM) - Fallback if Web Enrollment disabled/blocked

```powershell
# ESC1 - Impersonate another user
Request-ADCSCertificate -TemplateName "VulnTemplate" -Impersonate "administrator"

# ESC4 - Modify template temporarily, then request
Request-ADCSCertificate -TemplateName "WebServer" -ModifyTemplate -Impersonate "administrator"

# Specify CA manually
Request-ADCSCertificate -CAServer "ca01.contoso.com" -TemplateName "User" -Subject "CN=John"

# Custom SANs
Request-ADCSCertificate -TemplateName "User" -Subject "CN=Admin" -UPN "admin@contoso.com"
Request-ADCSCertificate -TemplateName "Computer" -Subject "CN=SRV01" -DNS "srv01.contoso.com"

# PFX without password (for scripting)
Request-ADCSCertificate -TemplateName "User" -Subject "CN=Test" -NoPassword

# With explicit credentials
Request-ADCSCertificate -TemplateName "User" -Credential (Get-Credential)
```

**Parameters**:
- `-CAServer` - CA FQDN (auto-discovered if omitted and session exists)
- `-TemplateName` - Certificate template name (required)
- `-Impersonate` - Convenience parameter: sets Subject + appropriate SAN automatically
- `-Subject` - Certificate subject (CN= prefix added if missing)
- `-UPN` - UPN for SAN (e.g., `admin@contoso.com`)
- `-DNS` - DNS name for SAN (e.g., `srv01.contoso.com`)
- `-ModifyTemplate` - ESC4: Backup → Modify → Request → Restore
- `-NoPassword` - Export PFX without password
- `-UseHTTP` - Force HTTP (skip HTTPS)
- `-OutputPath` - Custom PFX path
- `-PassThru` - Return result object for scripting

**Return** (with `-PassThru`):
```powershell
[PSCustomObject]@{
    Success       = $true
    PFXPath       = ".\administrator_20260222_125500.pfx"
    PFXPassword   = "K8#mP2@xL9!nQ4$wR7"
    CAServer      = "ca01.contoso.com"
    TemplateName  = "VulnTemplate"
    RequestID     = 142
}
```

**COM/RPC Fallback Details**:
- Automatically activated when Web Enrollment fails with connection/network errors
- Uses `ICertRequest` COM interface via DCOM (port 135 + dynamic)
- Returns certificate immediately (no separate retrieval needed)
- Requires same permissions as Web Enrollment (Enroll rights on template)

**Edge Cases**:
- Web Enrollment disabled → COM/RPC used automatically
- Firewall blocks HTTP/HTTPS → COM/RPC tried (if DCOM allowed)
- Only HTTP available → Automatic fallback from HTTPS to HTTP
- No manual intervention needed - best method selected automatically

---

## LAPS Utilities

### Get-LAPSGPOConfig

Parses LAPS Legacy configuration from GPO Registry.pol files. Queries all GPOs and checks their SYSVOL paths for LAPS AdminAccountName settings.

```powershell
# Use session DC (default)
$config = Get-LAPSGPOConfig

# Specify Domain Controller
$config = Get-LAPSGPOConfig -DomainController "dc01.contoso.com"
```

**Parameter**: `-DomainController` (String, optional) - Domain Controller to use for SYSVOL access.

**Returns**: Hashtable with GPO display name as key and configured AdminAccountName as value.

---

### Get-OUPermissions

Analyzes permissions on an Organizational Unit.

```powershell
$perms = Get-OUPermissions -DistinguishedName "OU=Admins,DC=contoso,DC=com"

# Check for specific permission type
$perms = Get-OUPermissions -DistinguishedName "OU=Admins,DC=contoso,DC=com" -CheckType "LAPS"
```

**Check Types** (ValidateSet):
- `All` - All permission checks (default)
- `GenericAll` - Full Control rights
- `GenericWrite` - Generic Write (includes WriteProperty on all attributes)
- `WriteDacl` - Modify permissions (effectively full control)
- `WriteOwner` - Take ownership (effectively full control)
- `PasswordReset` - Password reset rights (Extended Right)
- `AccountControl` - userAccountControl / User-Account-Restrictions modification
- `GroupMembership` - Group membership modification (member attribute)
- `SPNModification` - SPN modification (servicePrincipalName, Validated-SPN)
- `DNSHostName` - DNS hostname modification (dNSHostName, Validated-DNS-Host-Name)
- `ScriptPath` - Logon script path modification (scriptPath)
- `Delegation` - Delegation attribute modification (msDS-AllowedToDelegateTo, msDS-AllowedToActOnBehalfOfOtherIdentity)
- `LAPS` - LAPS password read (Legacy ms-Mcs-AdmPwd + Windows LAPS attributes)
- `ObjectCreation` - CreateChild rights (User, Computer, Group, OU creation)
- `GPOLinking` - GPO link modification (gPLink attribute on OUs)

---

## GPO Utilities

### Get-GPOLinkage

Queries LDAP for all objects with `gPLink` attribute and returns a hashtable mapping GPO GUIDs to their linked locations. Takes no parameters - uses the active LDAP session.

```powershell
# Get all GPO linkage information
$linkage = Get-GPOLinkage
$linkage["{6AC1786C-016F-11D2-945F-00C04fB984F9}"]  # Returns array of OUs where this GPO is linked
```

**Returns**: Hashtable with GPO GUID (uppercase, with braces) as key and array of linked location objects as value.

---

## Navigation

- [Previous: Set- & New-Modules](07-Set-Modules.md)
- [Next: Architecture](09-Architecture.md)
- [Back to Home](00-Home.md)