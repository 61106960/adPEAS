# Changelog

All notable changes to adPEAS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

---

## [2.0.4] - 2026-05-19

### Added

- **Resizable name column in HTML report** — drag the column divider per
  object card to widen/narrow the attribute-name column (Excel-style),
  e.g. for screenshots. Transient only, resets to default on reload.

### Changed

- **GPO/object attribute reordering in HTML report** now uses a dedicated
  drag handle (small grip at the left of each row) instead of making the
  whole row draggable, so row text stays selectable.

### Fixed

- **Umlauts garbled in GPO local group / scheduled task findings** — GPP
  `Groups.xml` / `ScheduledTasks.xml` are UTF-8, but were read with the
  ANSI code page (Windows PowerShell 5.1 default without BOM), mojibaking
  names such as "Domänen-Benutzer" → "DomÃ¤nen-Benutzer"
- **Inactive accounts shown as active** when the AD object had no
  `lastLogonTimestamp` (very old / never-used accounts, e.g. stale
  computers found via SPN) — activity status now falls back to
  `pwdLastSet` / `whenCreated`
- **HTML report card text could not be selected or copied** — finding and
  object card content is now freely selectable; selecting text no longer
  expands/collapses the card

---

## [2.0.3] - 2026-05-07

### Fixed

- **Crash on second `Invoke-adPEAS` call** — `op_Subtraction` error when
  running `Invoke-adPEAS` a second time in the same session.
  `Connect-adPEAS` cleared `$Script:StartTime` on reconnect, breaking the
  end-of-scan duration calculation
- **`-OPSEC` mode still listed Bloodhound** in the module overview
  (`Executing Modules: ..., Bloodhound`) even though collection was
  correctly skipped — confusing for users who couldn't tell at a glance
  whether BloodHound had run
- **GPO Local Group card** title showed "Local Group" placeholder instead
  of the actual group name
- **LDAP "Not Configured"** signing/channel-binding values were shown as
  Hint instead of Finding in GPO analysis
- **SMB Signing DC-only configuration** was shown as Hint even when
  server signing is Required — member servers fall back to OS defaults,
  so this should be a Finding
- **Certificate template ACL** was tagged as Primary finding even when
  the current low-privileged user had no write rights — now Primary only
  when actually exploitable by the running identity
- **`Connect-adPEAS` cache cleanup** on reconnect was incomplete — stale
  cached state from the previous session could leak into the new one

---

## [2.0.2] - 2026-04-16

### Added

- **Certificate template ACL** display in ADCS report — shows who has
  write/modify rights on each template (relevant for ESC4 context)

### Fixed

- **BloodHound CE v6.2 compatibility** — major collector overhaul to fix
  import errors:
  - Replace `LocalAdmins/RemoteDesktopUsers/DcomUsers/PSRemoteUsers` with
    `LocalGroups/UserRights/DumpSMSAPassword` (SharpHound v2.12 format)
  - `CARegistryData` moved to top-level field (was causing Neo4j Map{} errors)
  - `IsWebClientRunning` and `SmbInfo` correctly set to `null` in DCOnly mode
  - `serviceprincipalnames` guard against empty LDAP hashtable (`@{}`)
  - `HasSIDHistory` now a TypedPrincipal array instead of bool
  - `IssuancePolicy.GroupLink` now a TypedPrincipal instead of raw string
  - ADCS flags (`enrollmentflag`, `certificatenameflag`, `flags`) converted
    to strings as required by BH CE v6.2
  - ~50 missing Properties and top-level fields added across all 13 object
    types (users, groups, computers, domain, OUs, containers, GPOs, cert
    templates, enterprise CAs, root CAs, AIA CAs, NTAuth stores, issuance
    policies)
  - JSON output now compact by default; `PrettyPrint` opt-in
  - Missing helper functions `Convert-CAFlagToString`,
    `Convert-CertNameFlagToString`, `Convert-EnrollFlagToString` added
    (absence caused runtime crash on Enterprise CA collection)
  - `$sidHistoryTyped` now correctly built as TypedPrincipal array
    (was undefined — `HasSIDHistory` was always `null`)
  - Null-reference crashes on trust objects, OUs, and containers fixed
- **NTAuth Certificate / AIA CA** showed "Unknown" as name in PKI Trust
  Infrastructure card — now correctly resolves CN from Subject DN
- **BloodHound collection crash** on OUs/containers without `objectGuid`
- **Top Priority Action** click in HTML report now scrolls to card header

---

## [2.0.1] - 2026-04-16

### Added

- **GPO link order priority** — SMB signing and LDAP configuration checks now
  show which GPO is effectively applied (`IsEffectiveSetting`) based on GPO
  link order precedence (DC OU beats Domain-level)
- **HTML diff report** in `Compare-adPEASReport` for visual scan comparison
- **PublishedOn** property on certificate templates

### Changed

- **scriptPath** display for user accounts now shows with conditional severity

### Fixed

- GPO local group membership check not reporting findings
- Add-Computer severity now correctly distinguishes restricted scope
  (Administrators only → secure) from broad scope (Authenticated Users,
  Everyone → finding)

---

## [2.0.0] - 2026-04-02

Initial release of adPEAS v2 — a complete rewrite of adPEAS v1.

### Added

- **Unified LdapConnection architecture** replacing legacy DirectoryEntry/DirectorySearcher
- **Native Kerberos stack** — AS-REQ/AS-REP, TGS-REQ/TGS-REP, Pass-the-Ticket, all in pure PowerShell
- **Authentication methods** — Password, NT-Hash (OPtH), AES keys (PtK), PKINIT, Pass-the-Cert/Schannel, Windows integrated auth
- **Kerberos-first authentication** with automatic fallback to NTLM Impersonation and SimpleBind
- **UnPAC-the-Hash** — automatic NT-Hash recovery after PKINIT authentication
- **41+ security checks** across 9 categories (Domain, Creds, Rights, Delegation, ADCS, Accounts, GPO, Computer, Application)
- **ADCS vulnerability detection** — ESC1 through ESC15
- **Severity scoring system** with Critical/High/Medium/Low/Info levels and risk scores
- **Interactive HTML reports** with search, filtering, sorting, dark/light theme, and tooltips
- **JSON export** for machine-readable output, offline report conversion, and scan comparison
- **Report comparison** (`Compare-adPEASReport`) — diff two scans to track remediation progress
- **Offline report conversion** (`Convert-adPEASReport`) — regenerate reports from JSON without LDAP connection
- **Incremental scanning** with `-OutputAppend` to merge findings across multiple runs
- **BloodHound CE collector** — built-in data collection for attack path analysis
- **Offensive operations** — Kerberoasting, AS-REP Roasting, Golden/Silver/Diamond Tickets, RBCD abuse, Shadow Credentials, GPO abuse
- **Session-based workflow** — connect once, run multiple checks interactively
- **Tab-completion** for AD object names (`-BuildCompletionCache`)
- **OPSEC mode** — skip active testing (Kerberoast, ASREPRoast, BloodHound)
- **Verbose logging** to file for troubleshooting (`-VerboseLogging`)
- **LDAP timeout configuration** (`-TimeoutSeconds`) for slow connections (SOCKS, VPN)
- **RSA-SHA256 license system** with build-time embedding and runtime override
- **Four release variants** — readable, minimized, ultra-compressed, and obfuscated

### Changed

- Zero external dependencies — no RSAT, no ActiveDirectory module, no PowerView
- All LDAP operations use `System.DirectoryServices.Protocols.LdapConnection`
- Modular source structure (`src/modules/`) compiled into single standalone `.ps1` file
- SID-based identity checks for language-independent operation

### Removed

- PowerView dependency
- DirectoryEntry/DirectorySearcher usage
