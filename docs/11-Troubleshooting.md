# Troubleshooting

Common issues and solutions for adPEAS v2.

---

## Connection Issues

### Error: "Connection failed: Server unreachable" / "Domain not found or unreachable"

**Symptoms** (the text adPEAS prints):
- `Connection failed: Server unreachable` with `Port 389 (LDAP) unreachable on <server>` (or port 636 with `-UseLDAPS`)
- `Domain not found or unreachable` with `Could not discover a Domain Controller for '<domain>' - DNS resolution failed. Use -Server ...`
- a connection that hangs until the timeout

**Causes and Solutions**:

1. **Network connectivity**
   ```powershell
   # Test connectivity
   Test-NetConnection -ComputerName dc01.contoso.com -Port 389
   Test-NetConnection -ComputerName dc01.contoso.com -Port 636
   ```

2. **DNS resolution**
   ```powershell
   # Test DNS
   Resolve-DnsName contoso.com
   Resolve-DnsName dc01.contoso.com

   # Use custom DNS server
   Connect-adPEAS -Domain "contoso.com" -DnsServer "10.0.0.1" -UseWindowsAuth
   ```

3. **Firewall blocking LDAP**
   - Ensure TCP 389 (LDAP) or 636 (LDAPS) is open
   - Ensure TCP 88 (Kerberos) is open for Kerberos auth
   - Optionally, TCP 3268 (GC) or 3269 (GC over SSL) for cross-domain SID resolution

4. **Specify DC directly**
   ```powershell
   Connect-adPEAS -Domain "contoso.com" -Server "dc01.contoso.com" -UseWindowsAuth
   ```

---

### Error: "Authentication failed: Invalid credentials"

**Symptoms** (the text adPEAS prints):
- `Authentication failed: Invalid credentials` with `Reason: Wrong username or password.`
- for a Kerberos login, a `Reason:` line naming the KDC error - e.g. `Wrong password, hash, or key.` (KDC 24) or `User not found in the domain.` (KDC 6)

**Solutions**:

1. **Verify credentials**
   ```powershell
   # Test credentials interactively
   $cred = Get-Credential
   Connect-adPEAS -Domain "contoso.com" -Credential $cred
   ```

2. **Check username format**
   ```powershell
   # Try different formats
   Connect-adPEAS -Domain "contoso.com" -Username "CONTOSO\john.doe" -Password "pass"
   Connect-adPEAS -Domain "contoso.com" -Username "john.doe@contoso.com" -Password "pass"
   Connect-adPEAS -Domain "contoso.com" -Username "john.doe" -Password "pass"
   ```

3. **Account locked or disabled**
   - Check if the account is locked out
   - Check if the account is disabled

---

### Error: "Kerberos ticket not usable" / "Kerberos authentication failed"

**What the messages mean** (adPEAS does not print raw `KRB5KDC_*` strings):

- A **KDC error** (wrong password, unknown user, expired or disabled account, wrong realm) is reported as `Authentication failed: Invalid credentials` with a `Reason:` line - see the section above.
- `Kerberos authentication failed` is the title only for a failure **without** a KDC error code, i.e. a client-side problem such as LDAP error 82 (the ticket could not be used).
- After a pass-the-ticket, a bind that the DC rejects is reported as `Kerberos ticket not usable`, with its reason; for LDAP 82 the hint points at the system DNS or a VPN.

**Fallback is not automatic.** Only a password login (`-Username`/`-Password` or `-Credential`) can fall back to NTLM then SimpleBind, and even then some KDC errors end the chain straight away (wrong password, unknown user, disabled/locked account, expired password, wrong realm) unless it is a cross-domain login. A hash, key, certificate or ticket login has **no** fallback. `ETYPE_NOSUPP` (the DC offers no supported encryption type) does fall back; with `-UseLDAPS`, a TLS handshake or certificate failure also ends the chain.

**Solutions**:

1. **Port 88 blocked - use SimpleBind or an NTLM bind** (password logins only)
   ```powershell
   # Skip Kerberos, use a direct LDAP SimpleBind
   Connect-adPEAS -Domain "contoso.com" -Username "john.doe" -Password "pass" -ForceSimpleBind

   # Or an explicit NTLM bind (does not touch the Windows Kerberos ticket cache)
   Connect-adPEAS -Domain "contoso.com" -Username "john.doe" -Password "pass" -ForceNTLM
   ```

2. **Windows cannot reach the DC's SPN after a pass-the-ticket** (LDAP 82)
   - `-DnsServer` only steers adPEAS's own lookups; Windows still resolves the DC through the system DNS when it uses the ticket
   - add `-PatchHostsFile` (needs admin) so Windows can match the `ldap/<DC>` SPN, or fix the system DNS

3. **Time synchronization issue**
   - Kerberos requires time within 5 minutes of the DC
   - Check the system clock

4. **Principal not found**
   - Verify the username exists in the domain and the domain name has no typo

---

## Pivoting and Tunneling

### Using adPEAS Through a Network Tunnel

adPEAS does not include a built-in SOCKS proxy or tunneling client. The underlying .NET `LdapConnection` class does not support proxy connections, and implementing a full SOCKS stack would add significant complexity for something that dedicated tools already handle well.

Instead, use **local port forwarding** with your preferred tunneling tool. adPEAS connects to whatever `-Server` address you provide — including `localhost` or any local IP that your tunnel exposes.

---

### Recommended Setup

**Architecture:**

```
┌──────────┐    Tunnel     ┌─────────────┐    Internal    ┌──────────┐
│ Attacker │ ◄════════════►│ Pivot Host  │ ──────────────►│   DC     │
│ Machine  │  (chisel,     │ (internal)  │   Port 389/636 │ Port 389 │
│          │   ligolo,     │             │   Port 88      │ Port 88  │
│          │   socat)      │             │                │          │
└──────────┘               └─────────────┘                └──────────┘
     │
     │ adPEAS connects to localhost / tunnel IP
     ▼
  Connect-adPEAS -Server "127.0.0.1" ...
```

**Step 1: Establish the tunnel** (examples for common tools)

```bash
# Chisel (reverse tunnel)
# On pivot host:
chisel server -p 8080 --reverse
# On attacker:
chisel client pivot-host:8080 R:389:dc01.contoso.com:389 R:88:dc01.contoso.com:88

# Ligolo-ng
# Ligolo creates a full tunnel interface — no individual port forwards needed
# All ports are accessible via the tunnel interface IP

# SSH port forward
ssh -L 389:dc01.contoso.com:389 -L 88:dc01.contoso.com:88 user@pivot-host

# Socat (simple TCP relay on pivot host)
socat TCP-LISTEN:389,fork TCP:dc01.contoso.com:389 &
socat TCP-LISTEN:88,fork TCP:dc01.contoso.com:88 &
```

**Step 2: Connect adPEAS through the tunnel**

```powershell
# SimpleBind through tunnel (most reliable)
Connect-adPEAS -Domain "contoso.com" -Server "127.0.0.1" -Username "john.doe" -Password "P@ssw0rd" -ForceSimpleBind

# With LDAPS (if tunnel forwards port 636)
Connect-adPEAS -Domain "contoso.com" -Server "127.0.0.1" -Username "john.doe" -Password "P@ssw0rd" -UseLDAPS -IgnoreSSLErrors -ForceSimpleBind

# Pass-the-Cert through tunnel (if you have a certificate, only needs port 636)
Connect-adPEAS -Domain "contoso.com" -Server "127.0.0.1" -Certificate "user.pfx" -ForcePassTheCert

# Ligolo-ng tunnel interface (full network tunnel)
Connect-adPEAS -Domain "contoso.com" -Server "10.10.10.10" -DnsServer "10.10.10.10" -Username "john.doe" -Password "P@ssw0rd"
```

> **If the domain enforces LDAP server signing**, a SimpleBind on port 389 is refused (LDAP error 8). adPEAS reports `LDAP signing required - the simple bind was refused on port 389, auto-upgrading to LDAPS` and retries over LDAPS, so the tunnel must also forward port 636 for `-ForceSimpleBind` to work there.

---

### Why Use ForceSimpleBind Over a Tunnel?

**Kerberos authentication is problematic over tunnels** for several reasons:

| Issue | Explanation |
|-------|-------------|
| **SPN mismatch** | Kerberos service tickets are bound to the target hostname (e.g., `ldap/dc01.contoso.com`). When connecting to `127.0.0.1`, the SPN doesn't match, causing `LDAP_LOCAL_ERROR` (error 82). |
| **DNS resolution** | Kerberos relies on DNS to find the KDC. Over a tunnel, DNS may not resolve correctly. |
| **Port 88 required** | Kerberos needs a separate TCP connection to port 88 on the KDC — your tunnel must forward this port too. |
| **PTT session isolation** | Pass-the-Ticket injects into the Windows LSA session. If the tunnel changes the network path, the ticket may not be usable for the LDAP connection. |

**Recommendation:** Use `-ForceSimpleBind` when working through port-forward tunnels. For full network tunnels (ligolo-ng with tunnel interface), Kerberos may work if DNS resolves correctly.

---

### Required Ports

Ensure your tunnel forwards the necessary ports:

| Port | Protocol | Required For | Mandatory? |
|------|----------|-------------|------------|
| 389  | TCP | LDAP | Yes (or 636) |
| 636  | TCP | LDAPS | Alternative to 389 |
| 88   | TCP | Kerberos | Only if using Kerberos auth |
| 3268 | TCP | Global Catalog (LDAP) | Optional — cross-domain/forest SID resolution |
| 3269 | TCP | Global Catalog (LDAPS) | Optional — cross-domain/forest SID resolution (SSL) |
| 445  | TCP | SMB/CIFS | For every check that reads SYSVOL or NETLOGON - all the GPO checks, credential exposure, LDAP/SMB-signing, domain info, authentication policy silos and add-computer rights (~14 checks), and the opt-in share hunt |
| 53   | UDP | DNS | Optional — names `Get-NetworkMap` does not find in the AD-integrated zones (none under `-OPSEC`) |

**Minimum for enumeration:** Port 389 (LDAP) + SimpleBind credentials.

---

### Troubleshooting Tunnel Connections

**Symptom: "Kerberos ticket not usable" (LDAP error 82) after Kerberos TGT+TGS**

The Kerberos ticket was obtained successfully, but Windows did not use it for the LDAP bind. After a pass-the-ticket adPEAS binds with the Kerberos package alone, so the bind fails on your host and nothing else is sent - under Negotiate, Windows would fall back to NTLM with the credentials of your own Windows logon and send them to the target's domain controller. Over a tunnel this typically means the SPN in the service ticket doesn't match the connection target.

Without a tunnel, check the system DNS: Windows looks up the domain controller and the domain through it. A VPN or a second network adapter with its own DNS server can answer those lookups instead of the target's DNS - disconnect it, or set the adapter metrics so the target's DNS server is asked first. For a **password** login without `-ForceKerberos`, adPEAS then continues with NTLM using the account you supplied; a hash, key, certificate or ticket login has no such fallback and stops here.

```powershell
# Fix: Skip Kerberos, use SimpleBind
Connect-adPEAS -Domain "contoso.com" -Server "127.0.0.1" -Username "john.doe" -Password "P@ssw0rd" -ForceSimpleBind
```

**Symptom: Connection timeout**

The tunnel is not forwarding the required port.

```powershell
# Test if tunnel is working
Test-NetConnection -ComputerName 127.0.0.1 -Port 389
```

**Symptom: "Server unavailable" or no results**

DNS may not resolve the domain name through the tunnel.

```powershell
# Specify DC IP directly and use DnsServer parameter
Connect-adPEAS -Domain "contoso.com" -Server "127.0.0.1" -DnsServer "127.0.0.1" -Username "john.doe" -Password "P@ssw0rd" -ForceSimpleBind
```

**Symptom: LDAPS certificate validation error**

The certificate is issued for the DC hostname, not for `127.0.0.1` or `localhost`. `-IgnoreSSLErrors` already defaults to `$true`, so validation is off unless you turned it back on with `-IgnoreSSLErrors:$false`; passing the bare switch keeps it off.

```powershell
# Certificate validation is off by default; pass the switch explicitly to be sure
Connect-adPEAS -Domain "contoso.com" -Server "127.0.0.1" -UseLDAPS -IgnoreSSLErrors -Username "john.doe" -Password "P@ssw0rd" -ForceSimpleBind
```

### Slow Connections / Timeouts

**Symptom: `The operation was aborted because the client side timeout limit was exceeded`**

High-latency connections (SOCKS tunnels, VPN, multi-hop pivots) can cause LDAP queries to exceed the default 30-second timeout, especially for complex operations like ACL analysis.

**Solution: Increase the timeout**

```powershell
# Increase timeout to 120 seconds (recommended for tunneled connections).
# -ForceSimpleBind and the auth parameters belong on Connect-adPEAS, not
# Invoke-adPEAS: connect once, then run Invoke-adPEAS against the session.
Connect-adPEAS -Domain "contoso.com" -Server "127.0.0.1" -Username "john.doe" -Password "P@ssw0rd" -ForceSimpleBind -TimeoutSeconds 120
Invoke-adPEAS

# Maximum: 600 seconds (10 minutes) for extremely slow connections
Connect-adPEAS -Domain "contoso.com" -TimeoutSeconds 600 -Username "john.doe" -Password "P@ssw0rd" -ForceSimpleBind
```

**Additional tips for slow connections:**
- Run only specific modules: `-Module Domain,Accounts` (skip heavy ACL checks)
- Use OPSEC mode: `-OPSEC` (fewer queries)
- Rights checks (ACLs) are the most timeout-prone — consider running specific modules with `-Module Domain,Accounts,Creds` instead

---

## Authentication Method Issues

### NT Hash Authentication Not Working

**Symptoms** (the text adPEAS prints):
- `Invalid NT-Hash format: Expected 32 hex chars, got N` - the format is validated before anything is sent
- for a DC that offers no supported encryption type (`ETYPE_NOSUPP`): with an NT hash the reason names RC4 being disabled; with an AES key it says the account has no AES key
- authentication fails completely - hash-based auth has no fallback

**Solutions**:

1. **Verify hash format** - must be 32 hex characters (adPEAS checks this itself and prints the message above)

2. **RC4 disabled in domain**
   - If RC4 is disabled, NT hash auth will fail
   - Use AES256 key instead
   ```powershell
   Connect-adPEAS -Domain "contoso.com" -Username "john.doe" -AES256Key "..."
   ```

3. **PTT fails due to security policy**
   - adPEAS uses `LsaConnectUntrusted` - admin rights are NOT required
   - In rare cases, restrictive security policies may block LSA access
   - NT Hash/AES key auth has no fallback - Kerberos (port 88) must be reachable
   - For password-based auth, use `-ForceSimpleBind` as a workaround

---

### Certificate (PKINIT) Authentication Not Working

**Symptoms** (the text adPEAS prints):
- `Certificate load failed`, with hints about the password and the private key
- a KDC error naming the cause: 77 (the EKU must be Smart Card Logon or Client Authentication), 62 (`Client certificate not trusted by KDC ... DC lacks PKINIT support`), 66 (the certificate does not match the principal), 72 (certificate revoked)

**Solutions**:

1. **Verify certificate requirements**
   - Must contain the private key, and have Smart Card Logon or Client Auth EKU
   - The identity is taken from the SAN UPN; a DNS SAN maps to the computer account `host$`, and the Subject CN is the last resort. If the certificate carries several identities, pick one with `-Username <name>`

2. **Check certificate password**
   ```powershell
   # Verify PFX is readable
   $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new("user.pfx", "password")
   $cert.Subject
   ```

3. **DC has no PKINIT support (KDC 62)**
   - Use `-ForcePassTheCert` to authenticate the certificate over Schannel/LDAPS instead of PKINIT

4. **Certificate expired or revoked**
   - Check the certificate validity dates and whether the CA has revoked it

---

### Kirbi/Ccache Import Not Working

**Symptoms** (the text adPEAS prints):
- `Invalid ticket file format` - the file could not be parsed (only ccache v3/v4 is accepted)
- `Ticket import failed (Pass-the-Ticket)`; for NTSTATUS `0xC000009A` the detail is `PTT requires domain-joined machine or elevated privileges`
- `Ticket is EXPIRED` (a warning) for a ticket past its lifetime
- since 2.10.0, a ticket that imports but the DC will not accept is reported as `Kerberos ticket not usable` - there is no fallback

**Solutions**:

1. **Restrictive LSA policy**
   - adPEAS uses `LsaConnectUntrusted` which does NOT require admin rights
   - In rare cases, restrictive security policies may block LSA access; NTSTATUS `0xC000009A` points to a non-domain-joined host or missing elevation
   - Try running from a different session or machine

2. **Ticket expired**
   - Check ticket expiration time and request a new ticket

3. **Wrong ticket type**
   - Ensure it's a TGT (krbtgt service) or a service ticket for LDAP

---

## Query Issues

### Error: "Access denied" on specific objects

**Symptoms**:
- Some objects return, others don't
- "Insufficient access rights"

**Cause**: The authenticated account lacks read permissions.

**Solutions**:

1. **Use account with more privileges**
   ```powershell
   Connect-adPEAS -Domain "contoso.com" -Credential (Get-Credential)
   # Enter an account with more access
   ```

2. **This is expected behavior**
   - Some objects are protected (e.g., AdminSDHolder)
   - Document what couldn't be read

---

### Error: "The search filter is invalid"

**Symptoms**:
- LDAP filter syntax error
- Empty results unexpectedly

**Solutions**:

1. **Check filter syntax**
   ```powershell
   # Correct: parentheses balanced
   Get-DomainUser -LDAPFilter "(sAMAccountName=admin)"

   # Wrong: missing parenthesis
   Get-DomainUser -LDAPFilter "(sAMAccountName=admin"
   ```

2. **Escape special characters**
   ```powershell
   # Characters to escape: * ( ) \ NUL
   # Use \2a for *, \28 for (, \29 for ), \5c for \
   Get-DomainUser -LDAPFilter "(description=*\2a*)"
   ```

---

### No Results Returned

**Symptoms**:
- Query returns $null or empty array
- Expected objects not found

**Solutions**:

1. **Verify object exists**
   ```powershell
   Get-DomainUser -Identity "username"
   ```

2. **Check search base**
   ```powershell
   # Might be searching wrong OU
   Get-DomainUser -SearchBase "DC=contoso,DC=com"
   ```

3. **Verify connection**
   ```powershell
   Get-adPEASSession -TestConnection
   ```

---

## Performance Issues

### Queries Taking Too Long

**Symptoms**:
- Timeouts
- Slow response

**Solutions**:

1. **Target specific DC**
   ```powershell
   Connect-adPEAS -Domain "contoso.com" -Server "dc01.contoso.com" -UseWindowsAuth
   ```

2. **Limit result set**
   ```powershell
   # Add more specific filter
   Get-DomainUser -LDAPFilter "(&(objectCategory=person)(adminCount=1))"
   ```

3. **Check network latency**
   ```powershell
   Test-Connection dc01.contoso.com
   ```

---

## Output Issues

### Colors Not Displaying

**Symptoms**:
- ANSI codes showing as text
- No color output

**Solutions**:

1. **Use Windows Terminal or ConEmu**
   - Legacy cmd.exe doesn't support ANSI
   - Windows Terminal has full support

2. **Enable VirtualTerminal**
   ```powershell
   # In Windows 10+
   Set-ItemProperty HKCU:\Console VirtualTerminalLevel -Type DWORD 1
   ```

3. **Output to file instead**
   ```powershell
   Invoke-adPEAS -Outputfile .\report
   ```

---

### File Output Not Created

**Symptoms**:
- No file created
- "Cannot write to file" error

**Solutions**:

1. **Check path exists**
   ```powershell
   # Use existing directory
   Invoke-adPEAS -Outputfile "C:\existing\path\report"
   ```

2. **Check write permissions**
   - Ensure you can write to the target directory
   - Try different location

3. **Close file if open**
   - If file is open in another program, writing fails

---

### Functions Not Available After Loading adPEAS

**Symptoms**:
- Logo displays correctly
- `Invoke-adPEAS` not recognized

**Cause**: Script was executed instead of dot-sourced

**Solution**:
- Use dot-sourcing to load adPEAS: `. .\adPEAS.ps1`
- Do NOT run `.\adPEAS.ps1` directly (functions stay in script scope)
- After dot-sourcing, `Invoke-adPEAS`, `Connect-adPEAS` and other functions are available

---

## Diagnostic Commands

### Check PowerShell Version

```powershell
$PSVersionTable.PSVersion
# Requires 5.1 or higher
```

### Check .NET Framework Version

```powershell
[System.Environment]::Version
# or
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" | Select-Object Version
```

### Test Network Connectivity

```powershell
# Test LDAP
Test-NetConnection -ComputerName dc01.contoso.com -Port 389

# Test LDAPS
Test-NetConnection -ComputerName dc01.contoso.com -Port 636

# Test Kerberos
Test-NetConnection -ComputerName dc01.contoso.com -Port 88
```

### Verify DNS Resolution

```powershell
Resolve-DnsName contoso.com
Resolve-DnsName _ldap._tcp.contoso.com -Type SRV
```

### Check Current Session

```powershell
Get-adPEASSession
Get-adPEASSession -TestConnection
```

### Enable Verbose Output

```powershell
# Display verbose messages in console
$VerbosePreference = "Continue"
Connect-adPEAS -Domain "contoso.com" -UseWindowsAuth -Verbose
```

### Enable Verbose Logging to File

For detailed troubleshooting, write verbose messages to a file with timestamps:

```powershell
# Write verbose messages to output file (timestamped)
# -VerboseLogging automatically enables -Verbose for console output
Invoke-adPEAS -Domain "contoso.com" -UseWindowsAuth -Outputfile .\debug_report -VerboseLogging

# Output text file contains timestamped entries like:
# 2026-01-14 18:42:15 [Verbose] [Get-DomainUser] Querying users...
# 2026-01-14 18:42:16 [Verbose] [Invoke-LDAPSearch] Filter: (objectClass=user)
```

**Parameters:**
- `-Outputfile` - Required: Path to output file (text format needed for logging)
- `-VerboseLogging` - Writes verbose log messages to the output file AND automatically enables `-Verbose` for console output

**Note:** `-VerboseLogging` without `-Outputfile` will show a warning. Verbose messages will still appear in the console, but file logging is skipped.

---

## Getting Help

If you cannot resolve an issue:

1. **Enable verbose mode** and capture the output
2. **Check if the issue is reproducible** with minimal parameters
3. **Open an issue** on GitHub with:
   - PowerShell version
   - Windows version
   - Error message
   - Steps to reproduce

---

## Navigation

- [Previous: Risk-Scoring-System](10-Risk-Scoring-System.md)
- [Next: FAQ](12-FAQ.md)
- [Back to Home](00-Home.md)