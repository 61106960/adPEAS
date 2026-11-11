# Authentication Methods

adPEAS v2 supports multiple authentication methods for maximum flexibility in penetration testing scenarios.

---

## Overview

| Method               | Parameter                          | Kerberos  | Fallback               |
| -------------------- | ---------------------------------- | --------- | ---------------------- |
| Windows Auth         | `-UseWindowsAuth`                  | SSPI      | N/A (Windows handles)  |
| PSCredential         | `-Credential`                      | Yes       | NTLM → SimpleBind      |
| Username/Password    | `-Username` `-Password`            | Yes       | NTLM → SimpleBind      |
| NTLM bind            | `-ForceNTLM`                       | No        | No (NTLM only)         |
| NT-Hash (OPtH)       | `-Username` `-NTHash`              | Yes       | No (requires Kerberos) |
| AES256 Key (PtK)     | `-Username` `-AES256Key`           | Yes       | No (requires Kerberos) |
| AES128 Key (PtK)     | `-Username` `-AES128Key`           | Yes       | No (requires Kerberos) |
| Certificate (PKINIT) | `-Certificate`                     | Yes       | No (requires Kerberos) |
| Pass-the-Cert (PtC)  | `-Certificate` `-ForcePassTheCert` | No        | No (Schannel only)     |
| Kirbi Ticket         | `-Kirbi`                           | Yes (PTT) | No (requires Kerberos) |
| Ccache Ticket        | `-Ccache`                          | Yes (PTT) | No (requires Kerberos) |
**Note**: Kerberos PTT (Pass-the-Ticket) uses `LsaConnectUntrusted` and does NOT require admin privileges.

---

## Kerberos-First Architecture

adPEAS v2 attempts Kerberos authentication by default for all methods. The authentication flow is:

```
1. Obtain TGT (AS-REQ/AS-REP)
   - For password auth: Try ETypes in order (AES256 → AES128 → RC4)
   - For hash/key auth: Use fixed EType based on key type
2. Request LDAP and CIFS service tickets (TGS-REQ/TGS-REP), offering AES256, AES128, RC4 in that order
3. Import tickets into Windows session (Pass-the-Ticket)
4. Connect to LDAP and CIFS - after a pass-the-ticket the bind uses the Kerberos package alone (never Negotiate), so it does not silently fall back to NTLM with your own Windows logon
5. If Kerberos fails -> Tiered fallback, for password logins only (unless disabled)
```

### Encryption Type (EType) Fallback

For **password-based authentication**, adPEAS automatically tries multiple encryption types if the KDC returns `KDC_ERR_ETYPE_NOSUPP` (error 14):

```
AES256-CTS-HMAC-SHA1-96 (etype 18) - Most secure, tried first
        ↓ fails (ETYPE_NOSUPP)
AES128-CTS-HMAC-SHA1-96 (etype 17) - Fallback
        ↓ fails (ETYPE_NOSUPP)
RC4-HMAC (etype 23) - Legacy compatibility
```

**Note:** For hash/key-based authentication (NT-Hash, AES256Key, AES128Key), the encryption type is fixed by the key type and cannot be changed.

### Salt Discovery via PA-ETYPE-INFO2

The Kerberos salt for AES key derivation is `UPPERCASE(REALM) + username` (RFC 3962). The **username part is case-sensitive** and must match exactly how AD stores the account name.

adPEAS follows the standard Kerberos protocol to obtain the correct salt:

```
1. Send AS-REQ without pre-authentication
        ↓
2. KDC responds with KDC_ERR_PREAUTH_REQUIRED (error 25)
   + PA-ETYPE-INFO2 in e-data containing the correct salt
        ↓
3. Extract salt from PA-ETYPE-INFO2 (e.g., "CONTOSO.COMAdministrator")
        ↓
4. Derive AES key using the KDC-provided salt
        ↓
5. Send AS-REQ with correct pre-authentication
```

This means you can enter `administrator` (lowercase) and adPEAS will automatically use the correct salt (`Administrator`) provided by the KDC.

**Note:** This applies to **password-based AES authentication** (etype 17 and 18). For NT-Hash (RC4-HMAC) no salt is used, and for pre-computed AES keys the salt is already baked into the key.

### Tiered Fallback System

The fallback is only for a **password** login (`-Username`/`-Password` or `-Credential`). A hash, key, certificate or ticket login has no fallback - it stops at its own method. When a password-based Kerberos attempt fails (e.g., port 88 blocked, DNS issues), adPEAS falls back:

```
Kerberos PTT (Primary)
        ↓ fails
NTLM bind (1st Fallback)
   - Explicit NTLM on the LDAP connection (AuthType Ntlm), not a logon impersonation
   - Supports LDAP signing
   - No cleartext credentials over network
        ↓ fails (e.g., NTLM disabled)
SimpleBind (Final Fallback)
   - Direct LDAP bind with credentials
   - Refused if "LDAP Server Signing Requirements = Require signing" (adPEAS then auto-upgrades to LDAPS)
```

Some KDC errors end the chain immediately with **no** fallback (wrong password, unknown user, disabled/locked account, expired password, wrong realm), unless it is a cross-domain login; `ETYPE_NOSUPP` does fall back. With `-UseLDAPS`, a TLS handshake or certificate failure also ends the chain.

**Why NTLM before SimpleBind?**
- The NTLM bind supports LDAP signing (required in hardened environments)
- No cleartext credentials transmitted over the network
- SimpleBind is refused when LDAP signing is required

### Control Flags

| Flag                    | Effect                                                    |
| ----------------------- | --------------------------------------------------------- |
| `-ForceSimpleBind`      | Force SimpleBind, skip Kerberos AND NTLM                  |
| `-ForceNTLM`            | Force an explicit NTLM bind (password credentials only)   |
| `-ForceKerberos`        | Force Kerberos, fail if unavailable (no fallback)         |
| `-ForcePassTheCert`     | Force Schannel (TLS client certificate) instead of PKINIT |

The three `-Force*` switches are mutually exclusive. `-ForceNTLM` exists only in the password parameter sets. `-ForceSimpleBind` and `-ForceKerberos` have no effect with `-UseWindowsAuth`, and `-ForceKerberos` has none with `-ForcePassTheCert` (adPEAS warns in those cases). `-NTHash`/`-AES*Key` combined with `-ForceSimpleBind` fails - SimpleBind needs a password.


---

## Windows Authentication

Uses the current Windows user context via SSPI (Security Support Provider Interface).

```powershell
Connect-adPEAS -Domain "contoso.com" -UseWindowsAuth
```

`-Domain` is optional with `-UseWindowsAuth`; without it the current domain is used.

**Requirements**:
- Domain-joined machine, or
- Valid Kerberos ticket in session (e.g., from `runas /netonly`)

**Best for**:
- Domain-joined workstations
- After `runas /netonly` with domain credentials

---

## PSCredential Object

Standard PowerShell credential object.

```powershell
# Interactive prompt
$cred = Get-Credential
Connect-adPEAS -Domain "contoso.com" -Credential $cred

# Programmatic
$securePass = ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force
$cred = New-Object PSCredential("CONTOSO\john.doe", $securePass)
Connect-adPEAS -Domain "contoso.com" -Credential $cred
```

**Authentication Flow**:
1. Kerberos: TGT request with password-derived key (AES256 default)
2. Fallback 1: NTLM bind (supports LDAP signing)
3. Fallback 2: LDAP SimpleBind with credentials

---

## Username and Password

Convenience method accepting plain text password.

```powershell
Connect-adPEAS -Domain "contoso.com" -Username "john.doe" -Password "P@ssw0rd!"

# Password can also be SecureString
$securePass = Read-Host "Password" -AsSecureString
Connect-adPEAS -Domain "contoso.com" -Username "john.doe" -Password $securePass
```

**Username Formats**:
- `username` (domain from -Domain parameter)
- `DOMAIN\username`
- `username@domain.com`

---

## NTLM Bind (`-ForceNTLM`)

Binds the LDAP connection with NTLM directly - `AuthType Ntlm` (Sicily) plus the supplied credential. Nothing is impersonated: there is no `LogonUser()`/`ImpersonateLoggedOnUser()` and no `runas /netonly`. The Windows logon's Kerberos tickets are left untouched because adPEAS never changes the ticket cache for this path. SMB access in this mode uses `New-PSDrive -Credential`, and `Get-adPEASSession` shows the method as `NTLM (LDAP)` or `NTLM (LDAPS)`.

```powershell
# With Username/Password
Connect-adPEAS -Domain "contoso.com" -Username "john.doe" -Password "P@ssw0rd!" -ForceNTLM

# With PSCredential
$cred = Get-Credential
Connect-adPEAS -Domain "contoso.com" -Credential $cred -ForceNTLM
```

**Key Advantages**:
- Does NOT touch the Kerberos ticket cache; the Windows logon's tickets remain intact
- Uses NTLM Challenge/Response for the LDAP bind
- Supports LDAP Signing (unlike SimpleBind)
- Works without LDAPS

**Best for**:
- Machines where you want to keep the current Windows Kerberos tickets
- Environments where SimpleBind is restricted but NTLM is allowed
- Quick credential testing

**Limitations**:
- Not Kerberos (NTLM only); some environments disable NTLM
- Password credentials only (`-Username`/`-Password` or `-Credential`) - no hash, key or ticket
- The `-ForceNTLM` parameter exists only in the password parameter sets

---

## NT-Hash (Overpass-the-Hash)

Authenticate using an NT hash without knowing the password.

```powershell
Connect-adPEAS -Domain "contoso.com" -Username "john.doe" -NTHash "32ED87BDB5FDC5E9CBA88547376818D4"
```

**Hash Format**: 32 hexadecimal characters (NTLM hash)

**Example Hash Origin**:
The example hash `32ED87BDB5FDC5E9CBA88547376818D4` is a generic placeholder.
- Calculation: `MD4(UTF16-LE(password))` = NT-Hash (16 bytes / 32 hex chars)

**Technical Details**:
- Uses RC4-HMAC (etype 23) for Kerberos AS-REQ
- NT hash serves directly as the encryption key
- No fallback: requires Kerberos (port 88 must be reachable)

**Obtaining NT Hashes**:
- Mimikatz: `sekurlsa::logonpasswords`
- secretsdump.py: `secretsdump.py domain/user@dc`
- LSASS dump analysis

---

## AES256 Key (Pass-the-Key)

Authenticate using AES256 Kerberos key.

```powershell
Connect-adPEAS -Domain "contoso.com" -Username "john.doe" -AES256Key "YOUR_64_HEX_CHAR_AES256_KEY_HERE"
```

**Key Format**: 64 hexadecimal characters (32 bytes)

**Example**: For user `admin` with password `mimikatz` in domain `CONTOSO.COM`:
```
AES256: 9f0d9e5b8a4c3e2d1f0e8b7a6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d
```
Note: AES keys are user-specific (salt = `CONTOSO.COMadmin`). Your actual key will differ.

**Technical Details**:
- Uses AES256-CTS-HMAC-SHA1-96 (etype 18)
- Derived via PBKDF2-SHA1 with 4096 iterations + DK function
- Salt: `UPPERCASE(REALM) + username`
- More secure than RC4 (no NTLM hash exposure)
- No fallback: requires Kerberos (port 88 must be reachable)

**Obtaining AES Keys**:
- Mimikatz: `sekurlsa::ekeys`
- secretsdump.py with `-just-dc-user`

---

## AES128 Key (Pass-the-Key)

Authenticate using AES128 Kerberos key.

```powershell
Connect-adPEAS -Domain "contoso.com" -Username "john.doe" -AES128Key "YOUR_32_HEX_CHAR_AES128_KEY_HERE"
```

**Key Format**: 32 hexadecimal characters (16 bytes)

**Example**: For user `admin` with password `mimikatz` in domain `CONTOSO.COM`:
```
AES128: 8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d
```
Note: AES keys are user-specific. Your actual key will differ.

**Technical Details**:
- Uses AES128-CTS-HMAC-SHA1-96 (etype 17)
- Same derivation as AES256, different key length
- Less common than AES256

---

## Certificate (PKINIT)

Authenticate using X.509 certificate via PKINIT protocol.

```powershell
# With password-protected PFX
Connect-adPEAS -Domain "contoso.com" -Certificate "C:\certs\user.pfx" -CertificatePassword "pfxpass"

# With unprotected PFX (no password)
Connect-adPEAS -Domain "contoso.com" -Certificate "C:\certs\user.pfx"

# Base64-encoded PFX data
$pfxBase64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes("user.pfx"))
Connect-adPEAS -Domain "contoso.com" -Certificate $pfxBase64 -CertificatePassword "pfxpass"
```

**Certificate Requirements**:
- PKCS#12 format (.pfx or .p12)
- Contains private key
- Valid for Smart Card Logon or Client Authentication
- An identity in the Subject Alternative Name: a UPN SAN maps to that account, a DNS SAN maps to the computer account `host$`, and the Subject CN is the last resort. If the certificate carries several identities, pick one with `-Username <name>`.

**No Fallback**: PKINIT requires Kerberos and cannot fall back to SimpleBind. If the DC lacks PKINIT support (KDC error 62), use `-ForcePassTheCert` to authenticate the certificate over Schannel/LDAPS instead.

**Errors adPEAS prints**: `Certificate load failed` (with password / private-key hints), KDC 77 (EKU must be Smart Card Logon or Client Authentication), KDC 62 (certificate not trusted / DC lacks PKINIT), KDC 66 (certificate does not match the principal), KDC 72 (certificate revoked).

### UnPAC-the-Hash (Automatic NT Hash Recovery)

When authenticating via PKINIT, the KDC can include the user's NT hash in the PAC (`PAC_CREDENTIAL_INFO`, Type 2). adPEAS automatically performs **UnPAC-the-Hash** after successful PKINIT authentication:

1. Sends a **U2U (User-to-User) TGS-REQ** to itself (`enc-tkt-in-skey`)
2. Decrypts the returned service ticket using the TGT session key
3. Extracts `PAC_CREDENTIAL_INFO` from the PAC
4. Decrypts the credential data using the AS-REP Reply Key (DH-derived, KeyUsage 16)
5. Parses `NTLM_SUPPLEMENTAL_CREDENTIAL` to recover the NT hash

The recovered NT hash is displayed in `Get-adPEASSession` right after "Authenticated as:":

```
Authenticated as:                            administrator@CONTOSO.COM
NT-Hash:                                     9ec9d30b8b69ecbbada1d3110f354f8d
Authentication Method:                       Kerberos (TGT/TGS)
```

**Note:** This only works with PKINIT authentication. For password/hash/key-based authentication, the KDC does not include `PAC_CREDENTIAL_INFO` because the client already possesses a symmetric key.

**Use Case:** After obtaining a certificate (via ADCS attacks or Shadow Credentials), recover the NT hash for Pass-the-Hash or offline use without needing to crack anything.

### Certificate Sources

PKINIT certificates can come from two sources:

| Source | Description | How to Obtain |
|--------|-------------|---------------|
| **ADCS** | Certificates from AD Certificate Services | ESC1-ESC11 attacks, Certipy, legitimate enrollment |
| **Shadow Credentials** | Self-signed certificates via msDS-KeyCredentialLink | `Set-DomainUser -AddShadowCredential` |

**Shadow Credentials Example**:

Shadow Credentials allow PKINIT authentication without a CA. If you have write access to an account's `msDS-KeyCredentialLink` attribute, you can add a public key and use the corresponding private key for PKINIT.

**Prerequisite:** Domain Functional Level **2016 or higher**. The `msDS-KeyCredentialLink` attribute only exists from DFL 2016 onwards. Shadow Credentials are not available in domains with DFL 2012 R2 or lower.

```powershell
# Step 1: Add Shadow Credential to target account (requires write access to msDS-KeyCredentialLink)
$result = Set-DomainUser -Identity "admin" -AddShadowCredential -PassThru

# $result contains:
#   .PFXPath     = "C:\admin_20260115_103000.pfx"
#   .PFXPassword = "aB3cD4eF5gH6iJ7kL8m9"
#   .DeviceID    = "a1b2c3d4-..."

# Step 2: Use the generated certificate for PKINIT authentication
Connect-adPEAS -Domain "contoso.com" -Certificate $result.PFXPath -CertificatePassword $result.PFXPassword

# Step 3 (optional): Cleanup
Set-DomainUser -Identity "admin" -ClearShadowCredentials -DeviceID $result.DeviceID
```

**Key Differences**:

| Aspect | ADCS Certificates | Shadow Credentials |
|--------|------------------|-------------------|
| Requires CA | Yes | No |
| CA Logs | Yes (Event 4886/4887) | No |
| Domain Functional Level | Any | 2016+ required |
| Detection | CA audit logs | Event 5136 (attribute modified) |
| Prerequisite | Enrollment permission on template | Write access to msDS-KeyCredentialLink |
| Certificate Validity | Defined by template | Self-defined (default: 1 year) |

See [Set-Modules](07-Set-Modules.md#set-domainuser) for full Shadow Credentials documentation.

---

## Pass-the-Cert (Schannel)

Authenticate using a TLS client certificate directly via LDAPS, bypassing Kerberos entirely.

```powershell
# With PFX file
Connect-adPEAS -Domain "contoso.com" -Certificate "user.pfx" -ForcePassTheCert

# With password-protected PFX
Connect-adPEAS -Domain "contoso.com" -Certificate "user.pfx" -CertificatePassword "pass" -ForcePassTheCert

# With specific DC
Connect-adPEAS -Domain "contoso.com" -Server "dc01.contoso.com" -Certificate "user.pfx" -ForcePassTheCert
```

**How It Works**:
- The certificate is presented during the TLS handshake to LDAPS (port 636)
- The Domain Controller maps the certificate to an AD account via Schannel Certificate Mapping
- No Kerberos involved - no TGT, no TGS, no PTT
- LDAPS is automatically enabled (Schannel requires TLS)

**Advantages over PKINIT**:

| Aspect | PKINIT | Pass-the-Cert (Schannel) |
|--------|--------|--------------------------|
| Protocol | Kerberos (port 88) | LDAPS (port 636) |
| Port 88 required | Yes | No |
| Admin rights for PTT | No (LsaConnectUntrusted) | No (no PTT needed) |
| Smart Card Logon EKU | Required | Not required |
| LDAP Channel Binding | N/A | Immune (TLS provides it) |
| LDAP Signing | N/A | Immune (TLS provides it) |

**Certificate Requirements**:
- PKCS#12 format (.pfx or .p12) with private key
- Must be issued by the domain's CA (ADCS) with UPN/DNS SAN mapping
- Shadow Credentials certificates do NOT work (they use Key Credential Link mapping, not Schannel Certificate Mapping)

**Best for**:
- Port 88 blocked (SOCKS proxy, SSH tunnel, firewall)
- Certificates without Smart Card Logon EKU (e.g., from ESC8 relay)
- Environments with LDAP Signing/Channel Binding requirements

---

## Kirbi Ticket File

Import a Kerberos ticket from a .kirbi file.

```powershell
# From file path
Connect-adPEAS -Domain "contoso.com" -Kirbi "C:\tickets\JohnDoe.kirbi"

# From Base64 data
Connect-adPEAS -Domain "contoso.com" -Kirbi "doIFxjCC..."
```

**Ticket Sources**:
- Rubeus: `Rubeus.exe dump /nowrap`
- Mimikatz: `kerberos::list /export`
- adPEAS: `Invoke-KerberosAuth -OutputKirbi ticket.kirbi`

**Requirements**:
- Valid TGT or service ticket
- Ticket must not be expired
- No administrator rights required (uses LsaConnectUntrusted)

---

## Ccache Ticket File

Import a Kerberos ticket from a ccache file (MIT Kerberos format).

```powershell
# From file path
Connect-adPEAS -Domain "contoso.com" -Ccache "C:\tickets\krb5cc_JohnDoe"

# From Base64 data
Connect-adPEAS -Domain "contoso.com" -Ccache "BQQADAAd..."
```

**Ticket Sources**:
- Linux KRB5CCNAME environment variable
- impacket tools output
- getTGT.py, getST.py

**Use Cases**:
- Cross-platform ticket reuse
- Tickets obtained on Linux, used on Windows

**Requirements**:
- Valid TGT or service ticket
- Ticket must not be expired
- No administrator rights required (uses LsaConnectUntrusted)

---

## Connection Options

### LDAPS (Encrypted Connection)

```powershell
Connect-adPEAS -Domain "contoso.com" -UseWindowsAuth -UseLDAPS
```

Force encrypted LDAP connection (port 636). Server-certificate validation is governed by `-IgnoreSSLErrors`, which **defaults to `$true`** - validation is off unless you pass `-IgnoreSSLErrors:$false`. `-UseLDAPS` has no fallback to plain LDAP.

### Specific Domain Controller

```powershell
Connect-adPEAS -Domain "contoso.com" -Server "dc01.contoso.com" -UseWindowsAuth
```

Target a specific DC instead of auto-discovery.

### Custom DNS Server

```powershell
Connect-adPEAS -Domain "contoso.com" -UseWindowsAuth -DnsServer "10.0.0.1"
```

Use custom DNS for name resolution (useful for non-domain-joined systems). `-DnsServer` steers **adPEAS's own** lookups only; once Kerberos tickets are imported, Windows still resolves the DC and domain through the system DNS when it uses the ticket. If that resolves wrongly (a VPN, a second adapter), the Kerberos bind fails with LDAP 82 - add `-PatchHostsFile` (needs admin, works together with `-DnsServer`) so Windows can match the DC's SPN, or fix the system DNS.

---

## Authentication Examples by Scenario

### Scenario: Compromised User Account

```powershell
# You have username and password
Connect-adPEAS -Domain "contoso.com" -Username "jsmith" -Password "Summer2024!"
```

### Scenario: Dumped NT Hash

```powershell
# You have NTLM hash from SAM/LSASS
Connect-adPEAS -Domain "contoso.com" -Username "admin" -NTHash "32ED87BDB5FDC5E9CBA88547376818D4"
```

### Scenario: Stolen Certificate (ESC1)

```powershell
# You obtained a certificate through ESC1 attack
Connect-adPEAS -Domain "contoso.com" -Certificate "stolen.pfx" -CertificatePassword "pass"
```

### Scenario: Ticket from Linux Attack Box

```powershell
# Transfer ccache from Linux
Connect-adPEAS -Domain "contoso.com" -Ccache "krb5cc_0"
```

### Scenario: Port 88 Blocked with Certificate

```powershell
# Use Pass-the-Cert (Schannel) when Kerberos is unavailable but you have a certificate
Connect-adPEAS -Domain "contoso.com" -Certificate "user.pfx" -ForcePassTheCert
```

### Scenario: Port 88 Blocked (No Kerberos)

```powershell
# Use SimpleBind when Kerberos is unavailable
Connect-adPEAS -Domain "contoso.com" -Username "john.doe" -Password "pass" -ForceSimpleBind
```

### Scenario: Keep Existing Kerberos Tickets

```powershell
# Use an NTLM bind to avoid touching the Windows Kerberos ticket cache
Connect-adPEAS -Domain "contoso.com" -Username "john.doe" -Password "pass" -ForceNTLM
```

### Scenario: Cross-Domain Login

```powershell
# NetBIOS prefix differing from the target -> NTLM/SimpleBind (Kerberos is skipped,
# the KDC cannot be discovered), reported as "Cross-domain authentication (NetBIOS)"
Connect-adPEAS -Domain "contoso.com" -Username "OTHERDOM\user" -Password "pass"

# An FQDN prefix or a UPN realm lets the TGT be fetched from the user's realm KDC
Connect-adPEAS -Domain "contoso.com" -Username "user@otherdom.example" -Password "pass"
```

adPEAS does not chase cross-realm referrals; the error message lists the fixes (OS DNS that resolves both realms, an account in the target domain, or a password instead of a hash). A hash or key login, and `-ForceKerberos`, need an FQDN/UPN - they fail with a NetBIOS prefix.

### Scenario: Kerberos Required (Security Policy)

```powershell
# Fail if Kerberos doesn't work (don't expose credentials via SimpleBind)
Connect-adPEAS -Domain "contoso.com" -Username "john.doe" -Password "pass" -ForceKerberos
```

---

## Session Management

### View Current Session

```powershell
Get-adPEASSession
```

Shows:
- Connected domain
- Domain Controller
- Authentication method
- Protocol (LDAP/LDAPS)
- Authenticated user and its User SID
- for a Kerberos session: the TGT encryption type, validity, clock skew and TGT status
- NT-Hash (if recovered via UnPAC-the-Hash after PKINIT authentication)
- under Windows auth, when the logon session's network credentials belong to another account (after `runas /netonly` or an outside pass-the-ticket): a `Local Identity:` row and `Identity Mismatch: DETECTED`

### Test Connection

```powershell
Get-adPEASSession -TestConnection
```

Verifies the connection is still working.

### End Session

```powershell
Disconnect-adPEAS
```

Closes the LDAP connection and clears session data.

---

## Navigation

- [Previous: Quick-Start](02-Quick-Start.md)
- [Next: Security-Checks](04-Security-Checks.md)
- [Back to Home](00-Home.md)