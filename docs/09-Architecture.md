# Architecture

Technical architecture overview of adPEAS v2.

---

## Design Principles

### 1. Zero External Dependencies

adPEAS uses only built-in .NET Framework classes:

- `System.DirectoryServices.Protocols.LdapConnection` - Unified LDAP operations (queries and modifications)
- `System.DirectoryServices.Protocols.SearchRequest` - LDAP search operations
- `System.DirectoryServices.Protocols.ModifyRequest` - LDAP modify operations (Set-DomainObject)
- `System.DirectoryServices.ActiveDirectorySecurity` - ACL parsing and modification
- `System.Security.Principal` - SID handling
- `System.Security.Cryptography` - Kerberos crypto
- `System.Net` - Network operations

**Note**: adPEAS v2 uses a **unified LdapConnection architecture**. All LDAP operations (queries, schema lookups, modifications) use `System.DirectoryServices.Protocols.LdapConnection` instead of the older `DirectoryEntry`/`DirectorySearcher` pattern. This provides:
- Better LDAPS support (native SSL/TLS handling)
- Consistent behavior across all operations
- Support for Configuration and Schema partition queries
- Unified authentication handling

### 2. Standalone Deployment

The final product is a single .ps1 file:

- All modules combined during build
- No external files or dependencies
- Easy to transfer and execute
- Works on any Windows system with PowerShell 5.1+

### 3. Auth-Agnostic Architecture

Authentication is handled once at connection time. All subsequent operations are independent of the authentication method used.

### 4. Layered Design

Clear separation between data retrieval, security analysis, and output formatting.

---

## Module Architecture

```
+-------------------------------------------------------+
|                      adPEAS.ps1 (Main)                |
|                    Orchestration Layer                |
+---------------------------+---------------------------+
                            |
        +-------------------+-------------------+
        |                   |                   |
+-------v-------+   +-------v-------+   +-------v-------+
|    Helpers    |   |     Core      |   |    Checks     |
+---------------+   +---------------+   +---------------+
| Convert*      |<--| Get-Domain*   |<--| Security      |
| Ensure*       |   | Invoke-LDAP*  |   | Analyses      |
| Test-*        |   | Connect-*     |   | Findings      |
| Kerberos*     |   | Set-Domain*   |   |               |
+-------+-------+   +-------+-------+   +-------+-------+
        |                   |                   |
        +-------------------+-------------------+
                            |
                    +-------v-------+
                    |   Reporting   |
                    +---------------+
                    | Text Export   |
                    | Console Out   |
                    +---------------+
```

---

## Data Flow

```
1. User Input (Parameters)
         |
         v
2. Authentication (Connect-adPEAS)
         |
         v
3. LDAP Connection ($Script:LdapConnection)
         |
         v
4. Data Caching ($Script:LDAPContext)
         |
         v
5. Check Execution (Check Modules)
         |
         v
6. Finding Generation
         |
         v
7. Output Formatting (Show-* functions)
         |
         v
8. Report (Console/File)
```

---

## Module Hierarchy

### Call Hierarchy

```
Check Module
    |
    +-> Get-DomainUser / Get-DomainGroup / Get-DomainComputer / Get-DomainGPO
    |       |
    |       +-> Get-DomainObject
    |               |
    |               +-> Invoke-LDAPSearch
    |                       |
    |                       +-> $Script:LdapConnection (LdapConnection)
    |
    +-> Get-ObjectACL (ACL analysis checks)
    +-> Get-CertificateTemplate / Get-CertificateAuthority (ADCS checks)
```

### Rules

1. **Check Modules**: Call Get-Domain* functions, Get-ObjectACL, Get-CertificateTemplate, and Get-CertificateAuthority
2. **Get-Domain Functions**: Only call Get-DomainObject
3. **Get-DomainObject**: Only calls Invoke-LDAPSearch
4. **Invoke-LDAPSearch**: Only uses `$Script:LdapConnection`
5. **Set-DomainObject**: Uses `ModifyRequest` via `$Script:LdapConnection`

---

## Session Management

### Session Variables

| Variable | Type | Purpose |
|----------|------|---------|
| `$Script:LdapConnection` | LdapConnection | Used for ALL LDAP operations (queries and modifications) |
| `$Script:LDAPContext` | Hashtable | Session metadata (domain, server, auth info) |
| `$Script:LDAPCredential` | PSCredential | Stored credentials |
| `$Script:SIDResolutionCache` | Hashtable | SID to name cache |

### Unified LdapConnection Architecture

All LDAP operations flow through `$Script:LdapConnection`:

```
+-------------------------------------------------------+
|                    Connect-LDAP                       |
|                Creates LdapConnection                 |
+---------------------------+---------------------------+
                            |
                            v
+-------------------------------------------------------+
|           $Script:LdapConnection                      |
|        (System.DirectoryServices.Protocols)           |
+---------------------------+---------------------------+
                            |
        +-------------------+-------------------+
        |                   |                   |
        v                   v                   v
+---------------+   +---------------+   +---------------+
| SearchRequest |   | ModifyRequest |   |  Anonymous    |
| (Queries)     |   | (Set-*)       |   |  Bind Test    |
+---------------+   +---------------+   +---------------+
```

**Global Catalog Connection**: `Connect-LDAP -AsGlobalCatalog` creates a secondary connection to the Global Catalog (port 3268 for LDAP, 3269 for LDAPS). This is used internally by `ConvertFrom-SID` to resolve SIDs from foreign domains in the forest. The GC connection is cached in `$Script:GCConnection` and cleaned up by `Disconnect-adPEAS`. If the GC is unreachable, SID resolution falls back to a RID-based format.

### LDAPContext Structure

```powershell
$Script:LDAPContext = @{
    Domain              = "contoso.com"
    DomainDN            = "DC=contoso,DC=com"
    Server              = "dc01.contoso.com"
    Protocol            = "LDAP"           # or "LDAPS"
    Port                = 389              # or 636
    AuthMethod          = "Kerberos"       # or "NTLM Impersonation", "SimpleBind", "WindowsSSPI"
    KerberosUsed        = $true
    AuthenticatedUser   = "CONTOSO\john.doe"
    SchemaNamingContext = "CN=Schema,CN=Configuration,DC=contoso,DC=com"
    ConfigurationNamingContext = "CN=Configuration,DC=contoso,DC=com"
    DomainSID           = "S-1-5-21-..."
    AnonymousAccessEnabled = $false        # Security check result
}
```

---

## Authentication Flow

### Kerberos-First Design

```
+-------------------+
| Connect-adPEAS    |
| (Entry Point)     |
+---------+---------+
          |
          v
+-------------------+      Success      +-------------------+
| Invoke-Kerberos   |------------------>| Import-Kerberos   |
| Auth (TGT)        |                   | Ticket (PTT)      |
+---------+---------+                   +---------+---------+
          |                                       |
          | Failure                               v
          v                             +-------------------+
+-------------------+                   | Connect-LDAP      |
| NTLM              |                   | (Kerberos auth)   |
| Impersonation     |                   +---------+---------+
| (Fallback 1)      |                             |
+---------+---------+                             |
          |                                       |
          | Failure                               |
          v                                       |
+-------------------+                             |
| SimpleBind        |                             |
| (Fallback 2)      |                             |
+---------+---------+                             |
          |                                       |
          +-------------------+-------------------+
                              |
                              v
                    +-------------------+
                    | $Script:LDAP      |
                    | Connection        |
                    +-------------------+
```

### Authentication Methods

| Method | Kerberos Attempt | Fallback |
|--------|-----------------|----------|
| Windows Auth | SSPI (automatic) | N/A |
| PSCredential | TGT + TGS + PTT | NTLM Impersonation -> SimpleBind |
| Username/Password | TGT + TGS + PTT | NTLM Impersonation -> SimpleBind |
| NT Hash | TGT (RC4) + TGS + PTT | None |
| AES256 Key | TGT (AES256) + TGS + PTT | None |
| AES128 Key | TGT (AES128) + TGS + PTT | None |
| Certificate | PKINIT + TGS + PTT | None |
| Kirbi | PTT | None |
| Ccache | PTT | None |

---

## Output Architecture

### Unified RenderModel Pipeline

adPEAS uses a unified rendering pipeline where a single data model drives both Console and HTML output:

```
+----------------------------------------------------------+
|                    Check Module                          |
|           Returns structured finding objects             |
+---------------------------+------------------------------+
                            |
                            v
+----------------------------------------------------------+
|              Get-RenderModel (Model Builder)             |
|    - Object type detection (User/Computer/GPO/Cert)      |
|    - Attribute ordering and classification               |
|    - Delegates to AttributeTransformers per attribute    |
|    - Returns: { Primary, Extended, PostObject } model    |
+---------------------------+------------------------------+
                            |
              +-------------+-------------+
              |                           |
              v                           v
+---------------------------+  +---------------------------+
| Render-ConsoleObject      |  | Render-HtmlObject         |
| - ANSI color codes        |  | - HTML table rows         |
| - Prefix ([!],[+],etc.)   |  | - Severity CSS classes    |
| - Multivalue alignment    |  | - Tooltip integration     |
| - AlignAt column layout   |  | - Collapsible sections    |
+---------------------------+  +---------------------------+
              |                           |
              v                           v
+---------------------------+  +---------------------------+
| Write-adPEASOutput        |  | Export-HTMLReport         |
| - Console + Text file     |  | - Full HTML report        |
+---------------------------+  +---------------------------+
```

**Key components:**

| Component | File | Purpose |
|-----------|------|---------|
| `Get-RenderModel` | `Get-RenderModel.ps1` | Builds a renderer-agnostic data model from AD objects |
| `AttributeTransformers` | `AttributeTransformers.ps1` | Per-attribute transform functions (memberOf, UAC, SPN, etc.) |
| `Get-AttributeSeverity` | `AttributeTransformers.ps1` | Classifies attribute values by security relevance |
| `Render-ConsoleObject` | `Render-ConsoleObject.ps1` | Renders the model to colored console output |
| `Render-HtmlObject` | `Render-HtmlObject.ps1` | Renders the model to HTML table rows with tooltips |
| `Write-adPEASOutput` | `Write-adPEASOutput.ps1` | Low-level output (ANSI codes, file writing, prefixes) |

**RenderModel structure:**

```powershell
@{
    Primary = @(           # Always-visible attributes (severity != Standard)
        @{ Name; RowType; OverallSeverity; Values = @(
            @{ Display; Severity; FindingId; RawValue; Metadata }
        )}
    )
    Extended = @(          # Collapsible attributes (severity == Standard)
        # Same structure as Primary
    )
    PostObject = @(        # Post-object lines (e.g., activityStatus)
        @{ Text; Severity }
    )
}
```

### Semantic Output Functions

Check modules use semantic wrapper functions that delegate to the RenderModel pipeline:

```powershell
# Display AD object with all properties
Show-Object $user
# Internally: Get-RenderModel -> Render-ConsoleObject + Render-HtmlObject

# Display finding text
Show-Line "Finding text" -Class Finding
# Internally: Write-adPEASOutput with appropriate formatting

# Section headers
Show-Header "Analyzing Security"
# Internally: Write-adPEASOutput with Header class

# Sub-section headers
Show-SubHeader "Searching for accounts..."
# Internally: Write-adPEASOutput with SubInfo class
```

**Available Functions** (defined in `adPEAS-Messages.ps1`):
- `Show-Header` - Main section headers with decorative lines
- `Show-SubHeader` - Sub-section headers
- `Show-Line` - Single line output with optional styling
- `Show-KeyValue` - Key-value pairs with alignment
- `Show-Object` - AD object output via RenderModel pipeline
- `Show-Logo` - adPEAS logo display

---

## Check Module Pattern

All check modules follow a consistent pattern:

```powershell
function Get-SecurityCheck {
    [CmdletBinding()]
    param(
        [string]$Domain,
        [string]$Server,
        [PSCredential]$Credential
    )

    begin {
        Write-Verbose "[Get-SecurityCheck] Starting check"
    }

    process {
        # 1. Ensure connection
        if (-not (Ensure-LDAPConnection @PSBoundParameters)) {
            return
        }

        # 2. Display section header
        Show-SubHeader "Analyzing security configuration..."

        # 3. Query data using Get-Domain* functions
        $data = Get-DomainUser -LDAPFilter "(condition=*)" @PSBoundParameters

        # 4. Analyze and output findings
        foreach ($item in $data) {
            if ($item.IsVulnerable) {
                Show-Object $item
            }
        }

        # 5. Summary message
        if ($findings.Count -eq 0) {
            Show-Line "No issues found" -Class Note
        }
    }

    end {
        Write-Verbose "[Get-SecurityCheck] Check completed"
    }
}
```

---

## Security Considerations

### OPSEC Mode

When `-OPSEC` is specified:
- Kerberoasting is skipped (no TGS requests)
- AS-REP Roasting is skipped (no AS-REQ without pre-auth)
- BloodHound collection is skipped (generates many LDAP queries)
- Only passive enumeration is performed

### Credential Handling

- Credentials stored only in `$Script:LDAPCredential`
- Cleared on Disconnect-adPEAS
- Never written to disk
- Never logged in verbose output

### SID-Based Checks

All identity checks use SIDs, not names:
- Language-independent (works in any locale)
- Reliable (names can be duplicated)
- Faster (no name resolution needed for well-known SIDs)

---

## Performance Optimizations

### Caching

| Cache            | Purpose                         |
| ---------------- | ------------------------------- |
| SID Resolution   | Avoid repeated LDAP lookups     |
| LAPS Schema      | Check schema once per session   |
| Group Membership | Recursive membership resolution |

### LDAP Query Optimization

- Server-side filtering (LDAP filters, not client-side Where-Object)
- Paged results for large result sets via `PageResultRequestControl`
- Attribute selection for targeted queries (internal use only)
- Unified `LdapConnection` for both LDAP and LDAPS
- Configurable timeouts (Operation timeout, Send timeout)
- Support for all partitions (Domain, Configuration, Schema) via `-SearchBase`

---

## Error Handling

### Two-Level Approach

**Critical Errors** (script stops):
- LDAP connection failure
- Authentication failure
- No DC reachable

**Non-Critical Errors** (continue):
- Single object query failure
- Permission denied on specific object
- Timeout on single query

### Error Display

```powershell
try {
    # Operation
} catch {
    Write-Log "[FunctionName] Error: $_" -Level Error
}
```

---

## Navigation

- [Previous: Helper-Functions](08-Helper-Functions.md)
- [Next: Risk-Scoring-System](10-Risk-Scoring-System.md)
- [Back to Home](00-Home.md)