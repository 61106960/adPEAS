# Troubleshooting

Common issues and solutions for adPEAS v2.

---

## Connection Issues

### Error: "Cannot connect to Domain Controller"

**Symptoms**:
- Connection timeout
- "The server is not operational"
- "The RPC server is unavailable"

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

### Error: "The user name or password is incorrect"

**Symptoms**:
- Authentication failure
- "Logon failure: unknown user name or bad password"

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

### Error: "Kerberos authentication failed"

**Symptoms**:
- "KRB5KDC_ERR_PREAUTH_FAILED"
- "KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN"
- Kerberos port 88 timeout

**Solutions**:

1. **Port 88 blocked - Use SimpleBind or NTLM**
   ```powershell
   # Skip Kerberos, use direct LDAP bind
   Connect-adPEAS -Domain "contoso.com" -Username "john.doe" -Password "pass" -ForceSimpleBind

   # Or use NTLM impersonation (keeps existing Kerberos tickets)
   Connect-adPEAS -Domain "contoso.com" -Username "john.doe" -Password "pass" -ForceNTLM
   ```

2. **DNS cannot resolve DC**
   ```powershell
   # Use custom DNS
   Connect-adPEAS -Domain "contoso.com" -DnsServer "10.0.0.1" -Username "john.doe" -Password "pass"
   ```

3. **Time synchronization issue**
   - Kerberos requires time within 5 minutes of DC
   - Check system clock

4. **Principal not found**
   - Verify username exists in domain
   - Check for typos in domain name

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
| 445  | TCP | SMB/CIFS | Only for SMB checks (`Get-SMBSigningStatus`) |

**Minimum for enumeration:** Port 389 (LDAP) + SimpleBind credentials.

---

### Troubleshooting Tunnel Connections

**Symptom: `LDAP_LOCAL_ERROR` (Error 82) after Kerberos TGT+TGS**

The Kerberos ticket was obtained successfully, but the LDAP bind with Negotiate auth failed locally. This typically means the SPN in the service ticket doesn't match the connection target.

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

The certificate is issued for the DC hostname, not for `127.0.0.1` or `localhost`.

```powershell
# Ignore certificate hostname mismatch
Connect-adPEAS -Domain "contoso.com" -Server "127.0.0.1" -UseLDAPS -IgnoreSSLErrors -Username "john.doe" -Password "P@ssw0rd" -ForceSimpleBind
```

### Slow Connections / Timeouts

**Symptom: `The operation was aborted because the client side timeout limit was exceeded`**

High-latency connections (SOCKS tunnels, VPN, multi-hop pivots) can cause LDAP queries to exceed the default 30-second timeout, especially for complex operations like ACL analysis.

**Solution: Increase the timeout**

```powershell
# Increase timeout to 120 seconds (recommended for tunneled connections)
Invoke-adPEAS -Domain "contoso.com" -Server "127.0.0.1" -Username "john.doe" -Password "P@ssw0rd" -ForceSimpleBind -TimeoutSeconds 120

# Or with Connect-adPEAS directly
Connect-adPEAS -Domain "contoso.com" -Server "127.0.0.1" -Username "john.doe" -Password "P@ssw0rd" -ForceSimpleBind -TimeoutSeconds 120

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

**Symptoms**:
- "Overpass-the-Hash failed"
- Authentication fails completely (no fallback for hash-based auth)

**Solutions**:

1. **Verify hash format**
   ```powershell
   # Must be 32 hex characters
   $hash = "32ED87BDB5FDC5E9CBA88547376818D4"
   if ($hash.Length -ne 32) { Write-Error "Invalid hash length" }
   ```

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

**Symptoms**:
- "PKINIT authentication failed"
- "Certificate not valid for logon"

**Solutions**:

1. **Verify certificate requirements**
   - Must contain private key
   - Must have Smart Card Logon or Client Auth EKU
   - Must have UPN or other identity in SAN

2. **Check certificate password**
   ```powershell
   # Verify PFX is readable
   $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new("user.pfx", "password")
   $cert.Subject
   ```

3. **Certificate expired or revoked**
   - Check certificate validity dates
   - Check if CA has revoked the certificate

---

### Kirbi/Ccache Import Not Working

**Symptoms**:
- "Failed to import ticket"
- "Access denied"

**Solutions**:

1. **Restrictive LSA policy**
   - adPEAS uses `LsaConnectUntrusted` which does NOT require admin rights
   - In rare cases, restrictive security policies may block LSA access
   - Try running from a different session or machine

2. **Ticket expired**
   - Check ticket expiration time
   - Request a new ticket

3. **Wrong ticket type**
   - Ensure it's a TGT (krbtgt service)
   - Or a service ticket for LDAP

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