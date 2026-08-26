# Changelog

All notable changes to adPEAS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

---

## [Unreleased]

## [2.3.2] - 2026-08-26

### Added

- **AD CS ESC3 second condition (enrollment-agent target templates) is now
  detected.** adPEAS flagged the template that *issues* an enrollment-agent
  certificate (ESC3 condition 1), but not the template that *requires* an agent
  co-signature and is the actual on-behalf-of target. A template with
  `msPKI-RA-Signature >= 1`, the Certificate Request Agent policy in
  `msPKI-RA-Application-Policies`, and client authentication is now reported as
  `ESC3-TARGET`. Severity reflects whether an agent certificate is obtainable in
  the domain. The RA attributes are now loaded and shown on the template.

### Changed

- **A required enrollment-agent signature no longer suppresses ESC findings
  outright.** A template gated by `msPKI-RA-Signature` is a barrier, not a fix.
  ESC1/2/9/13/15 on such templates are now reported with damped severity (unless
  the agent certificate is freely obtainable, or the template is also
  ESC4-writable) rather than hidden entirely.

### Fixed

- **Objects whose DN contains `(`, `)` or an escaped comma silently vanished
  from all output.** A distinguished name such as `CN=Doe\, Jane (Contractor),...`
  was interpolated raw into LDAP filters, where the parentheses are read as
  filter grammar and produce an invalid filter — the DC returned an error and no
  object. Every DN placed into a filter is now RFC 4515 escaped (`Get-DomainObject`,
  `Set-DomainObject`, `Get-DomainGPO`, certificate templates, privileged group
  membership, shadow-credential reads, GPO linking).
- **The same DNs broke identity resolution before the query even ran.** The
  cross-domain parser split `DOMAIN\user` on any backslash, so an RFC 4514
  escaped comma was misread as a domain separator. Distinguished names are now
  excluded from `DOMAIN\user` parsing.
- **The NetBIOS domain name was misdetected when it differs from the DNS label.**
  adPEAS derived it from the first DNS label instead of the true NetBIOS name. It
  is now resolved authoritatively from the Partitions crossRef at connect time
  and reused everywhere, fixing both the reported domain name and false
  cross-domain detection for local `DOMAIN\user` identities.
- **`InsufficientAccessRights` write errors gave misleading advice.** Every
  denied LDAP write (`0x2098`) suggested the "Create Computer Objects" OU
  permission, even for attribute writes like shadow credentials or RBCD. The
  message is now operation-specific and names the actual permission required.
- **Site subnets were not vertically aligned.** `Get-DomainInformation` rendered
  a site's subnets as one long comma-separated line that wrapped out of column
  alignment; they now print one per line like the other multi-value fields.

## [2.3.1] - 2026-07-28

### Fixed

- **Release artifacts could not be loaded by Windows PowerShell 5.1.** The
  standalone builds of v2.3.0 (`adPEAS.ps1`, `adPEAS_min.ps1`,
  `adPEAS_ultra.ps1`) aborted with four parser errors on the target runtime;
  only `adPEAS_obf.ps1` was unaffected, because its loader stub is pure ASCII
  and the payload travels as Base64. `Build-Release.ps1` used encoding defaults
  that differ between PowerShell versions: `Out-File -Encoding UTF8` writes a
  BOM in Windows PowerShell 5.1 but not in PowerShell 7+, and `Get-Content`
  without `-Encoding` falls back to the system ANSI code page in 5.1 for files
  that carry no BOM. A build produced under PowerShell 7 was therefore decoded
  as ANSI by 5.1, where an em dash inside a string literal became three
  characters — one of them a quotation mark that PowerShell treats as a string
  delimiter, which ended the string early and aborted parsing. The build now
  reads and writes UTF-8 explicitly so both PowerShell versions produce
  identical output, and the sources are pure ASCII so the defect cannot be
  reintroduced. **Users on PowerShell 5.1 must download the v2.3.1 artifacts —
  the v2.3.0 ones do not run.**

- **`msDS-ManagedPasswordId` was displayed as a meaningless constant.** The
  MS-GKDI KEY_ID blob of a gMSA was rendered from its first 16 bytes, which hold
  only Version, the `KDSK` magic, Flags and the L0 index — identical for every
  gMSA and carrying no account-specific information. The Root Key Identifier
  GUID lives at offset 24. The attribute now shows
  `RootKeyId: <guid>, L0/L1/L2: <n>/<n>/<n>`, so gMSAs derived from the same KDS
  root key can be correlated. This value is unrelated to the 64-character
  "GMSA ID" reported by tools such as NetExec — that one is an HMAC-SHA256 over
  the account and domain name, used to name the LSA secret on a member host.

## [2.3.0] - 2026-07-22

### Added

- **`Get-GPORegistrySettings` — new GPO check** that flags security-relevant
  registry values deployed via Group Policy which, *when actively set*, enable an
  attack (credential theft, lateral movement, privilege escalation, defense evasion).
  Only positively-set values are reported — absence of a hardening value is never
  flagged, because GPO/SYSVOL parsing cannot distinguish "not configured in this GPO"
  from "secure". Both delivery mechanisms are parsed from SYSVOL: Administrative
  Templates (`Registry.pol`, PReg binary format) **and** Group Policy Preferences
  (`Registry.xml`). The dangerous-value catalogue is centralised in
  `adPEAS-RegistryKeys.ps1` (`$Script:DangerousRegistryKeys`) and covers, among others:
  the Zerologon/OneLogon `VulnerableChannelAllowList` (Critical), `AlwaysInstallElevated`
  (Critical, only when **both** HKLM and HKCU are set), WDigest cleartext caching,
  `LocalAccountTokenFilterPolicy`/`EnableLUA` (remote pass-the-hash), RDP Restricted
  Admin, Point and Print (PrintNightmare), WSUS-over-HTTP, weak LM/NTLMv1, plus
  explicitly disabled defenses (Defender, LSA Protection, Credential Guard, SMB signing).
  Each finding is mapped to the affected OUs / domain-wide scope via GPO links and ships
  with an HTML report card and hover tooltip. Scope is GPO-deployed values only — values
  set locally on a host are out of scope by design (no Remote Registry; consistent with
  the LDAP+SMB, no-RSAT model). Inspired by OneLogon (https://github.com/rub-softsec/onelogon).

### Fixed

- **Silent fallback to a stale session when an explicit `-Credential` bind
  failed.** `Connect-LDAP` does not throw on a failed bind — it displays the
  reason (e.g. LDAP 49 invalid credentials) and returns `$null`, leaving any
  pre-existing session in `$Script:LDAPContext`/`$Script:LdapConnection` intact.
  `Ensure-LDAPConnection` discarded that return value (`| Out-Null`) and then
  reported *"Successfully connected"* using the stale context, so a command run
  with wrong/mistyped credentials (e.g. `Set-DomainUser -Credential …`) silently
  proceeded under the **previous** identity instead of failing. It now checks the
  `Connect-LDAP` return value and returns `$false` on failure, so the caller aborts
  with the real authentication error instead of operating as the wrong principal.

- **Consistent web endpoint reporting for ADCS/Exchange probes.** When a web
  endpoint probe ran against a reachable, active server but did not succeed (e.g.
  a CA's web enrollment endpoint blocked during a VPN scan), it silently produced
  no output — indistinguishable from "the service exposes no web endpoint". A
  central `Show-WebEndpointUnreachable` (`Core/adPEAS-Messages`) now emits a
  uniform Note for both ADCS and Exchange; inactivity-skipped servers stay silent.
  Additionally, HTTP/HTTPS availability is now tracked per endpoint
  (`AvailableHttp`/`AvailableHttps`) in `Invoke-HTTPRequest`, so HTTPS-only
  endpoints (ADCS CEP/CES, Exchange EWS/MAPI/RPC/PowerShell/ActiveSync) are no
  longer dropped from the endpoint list; global transport flags are derived
  additively so HTTP-only, HTTPS-only and mixed cases all render correctly.

- **Actionable error messages for directory write operations.** When a write
  (`New-DomainComputer`/`User`/`Group`/`GPO`, `Set-Domain*`, RBCD and Shadow
  Credential operations) is rejected by a Domain Controller — common after AD
  hardening — the LDAP `SendRequest` throws a `DirectoryOperationException` that
  PowerShell wraps, so the tester previously saw only the generic
  *"The server cannot handle directory requests."* with no LDAP result code and no
  AD sub-error. A new `Resolve-LDAPWriteError` decoder (`adPEAS-ErrorCodes.ps1`)
  unwraps the exception chain, extracts the LDAP `ResultCode` and the server-side
  extended sub-error (the 8-hex-digit prefix, e.g. `0000216D` =
  MachineAccountQuota exhausted/`0`, `00002098` = insufficient access rights), and
  emits a *"Likely cause: …"* hint. Falls back to the raw message when the failure
  is not a directory write, so no information is ever lost. `-PassThru` result
  objects now also carry `ResultCode`/`ResultName`.

- **`lockoutDuration` nonsensical value in the password policy check.** When a
  domain sets the account lockout duration to "until an administrator unlocks"
  (AD stores this as the `Int64.MinValue` / `0x8000000000000000` "never" sentinel),
  `Get-DomainPasswordPolicy` divided the sentinel instead of recognising it and
  printed `lockoutDuration: 15372286728.0913 minutes`. It now applies the same
  `Int64.MinValue` guard that `maxPwdAge` already had, to both `lockoutDuration`
  (→ *"Forever (manual unlock)"*) and `lockoutObservationWindow`. Normal values are
  unchanged. (Root cause is a latent mislabelling of the interval attributes as
  FileTime attributes in `Invoke-LDAPSearch`, left in place because the BloodHound
  collector deliberately relies on the raw passthrough.)

## [2.2.0] - 2026-06-21

### Added

- **`Get-GPOUserRightsAssignment` — new Rights check** that parses the
  `[Privilege Rights]` section of `GptTmpl.inf` in every GPO and flags sensitive
  Windows user rights assigned to non-privileged principals. Two tiers: privilege-
  escalation/credential privileges (SeDebug, SeBackup, SeRestore, SeTakeOwnership,
  SeImpersonate, SeAssignPrimaryToken, SeCreateToken, SeTcb, SeLoadDriver,
  SeEnableDelegation, SeSyncAgent, SeManageVolume, SeSecurity, SeRelabel,
  SeTrustedCredManAccess) → Finding; logon rights (RDP/service/batch/interactive,
  change system time, shutdown) → Hint. Rights granted to broad principals (Everyone,
  Authenticated Users, Domain Users) are escalated to Finding. Each finding is mapped to
  the affected OUs / domain-wide scope via GPO links; privileged principals, built-in
  operator groups and well-known service/builtin default holders are hidden unless
  `-IncludePrivileged`. Closes the gap vs. dedicated GPO parsers — adPEAS previously only
  detected `SeMachineAccountPrivilege` (via Get-AddComputerRights).

- **`Set-DomainGPO` — Backup/Revert for GPO modifications**, aligned to the
  `Set-CertificateTemplate -Export`/`-Import` idiom (operator-driven, no automatic
  backup — "the tester must know what they're doing"):
  - **`-Export <path>`** snapshots the full restorable GPO state to one JSON: AD
    attributes (`gPCMachineExtensionNames`, `gPCUserExtensionNames`, `versionNumber`,
    `nTSecurityDescriptor` as SDDL) plus a recursive base64 copy of the entire SYSVOL tree.
  - **`-Import <path>`** restores the GPO server-side: rewrites SYSVOL to the snapshot,
    deletes files injected after the backup, restores the extension attributes and
    version, and warns on security-descriptor drift.
  - **Surgical reverse switches** to remove a single injected payload by name without a
    JSON: `-RemoveScheduledTask`, `-RemoveLocalGroupMember`, `-RemoveService`,
    `-RemoveDeployedFile`, `-RemoveFirewallRule`, `-RemoveStartupScript`,
    `-RemoveLogonScript`. Each strips the corresponding Client-Side-Extension from the AD
    extension list when the last payload of that type is gone and bumps the GPO version.
  - Note: restores the GPO **definition** (server-side); effects a GPP already applied on
    clients are not auto-reverted (roadmap: `-ClientRevert`).

- **`Get-BitLockerRecoveryKeyAccess` — new Creds check** that lists the
  BitLocker recovery keys the current user can read from AD. BitLocker
  recovery information is escrowed as `msFVE-RecoveryInformation` child
  objects below each computer (not as a computer attribute); the check
  runs a single domain-wide, server-side filtered subtree query
  `(&(objectClass=msFVE-RecoveryInformation)(msFVE-RecoveryPassword=*))`.
  The presence filter is ACL-gated, so only readable keys are returned —
  no per-computer enumeration. A schema/feasibility check short-circuits
  (and is cached for the session) so domains without BitLocker escrow skip
  the query entirely. The owning computer name is derived from the parent
  DN without extra LDAP queries, and recovery/volume GUIDs are decoded for
  display. Reported as a *Hint* (yellow) since read access is often a
  legitimate recovery/helpdesk capability, with full HTML report card and
  hover tooltip.

### Fixed

- **HTML report card titles** — object cards whose title template referenced a
  custom property placeholder rendered it literally. The "GPO User Right" card
  showed `GPO User Right: {userRightName}` instead of the resolved right name
  (e.g. *Manage auditing and security log*). `Get-ObjectTypeTitle` now resolves
  any remaining `{propertyName}` placeholder from the matching object property,
  which also fixes the BitLocker Recovery Key card's `{ComputerName}` placeholder.

---

## [2.1.0] - 2026-06-06

### Added

- **`Request-ADCSCertificate` — ESC3 (enrollment agent)** via
  `-OnBehalfOf` / `-PFX` / `-PFXPassword`: enroll-on-behalf-of another
  user using an enrollment-agent certificate (PKCS#7 SignedData).
- **`Request-ADCSCertificate` — ESC13 / ESC15 (EKUwu)** via
  `-ApplicationPolicies` (raw OIDs or friendly names), injected through
  the `szOID_APPLICATION_CERT_POLICIES` extension.
- **`Request-ADCSCertificate` — retrieve pending requests** via
  `-RetrieveID` / `-KeyFile`; the private key is persisted when a request
  goes pending so it can be completed later.
- **`Request-ADCSCertificate` — new request controls**: `-SID` (with LDAP
  auto-resolution) / `-NoSID`, `-Method Auto/Web/COM`, `-CAName`, and
  `-Port` for a custom certsrv Web Enrollment port.

### Changed

- **Diamond Ticket now "recuts" from the genuine PAC** instead of
  rebuilding a synthetic one. It preserves the real identity/session
  fields, `PrimaryGroupId` and `UserAccountControl` from the base TGT and
  only appends the requested group(s), removing the synthetic fingerprints
  (default group set 512/513/518/519/520) that are a known IOC. Diamond
  without `-GroupRIDs` now injects only Domain Admins (512). Golden/Silver
  output is byte-identical to before.
- **`Invoke-TicketForge -PTT`** now warns when Windows cannot locate a KDC
  for the ticket's realm (host not joined, no `_kerberos._tcp.<realm>` SRV
  record), so `SEC_E_NO_LOGON_SERVERS` is not mistaken for an invalid
  ticket. Suggests an NRPT rule / ksetup mapping as the fix.

### Fixed

- **`New-DomainComputer` failed to create accounts via
  MachineAccountQuota** — the LDAP AddRequest set `dNSHostName` and
  `userPrincipalName` at creation time, which AD validated-writes reject
  ("A value in the request is invalid") for unprivileged MAQ creators,
  aborting the whole creation. These are now set best-effort after
  creation, so the account is always created.
- **`Request-ADCSCertificate` (COM/RPC) leaked a Base64 string** instead
  of decoding the issued certificate (now X509 / PKCS#7-aware), and the
  COM/RPC fallback is now reachable when `/certsrv/` web enrollment is
  absent.
- **Requester SID dropped from the issued certificate** — the SID is now
  also embedded in the SAN as a URL
  (`tag:microsoft.com,2022-09-14:sid:`) in addition to the NTDS CA
  Security Extension, so it survives CAs that strip the requester-supplied
  extension (matches Certipy).

---

## [2.0.5] - 2026-05-27

### Fixed

- **`Get-DomainUser` / `Get-Domain*` silently dropped attributes** (e.g.
  `objectSid`, `displayName`, `userPrincipalName`, `accountExpires`)
- **`terminalServer` / `userParameters` shown as raw byte arrays** — both
  are now decoded to readable text (TS per-user settings and Per-User CAL
  tracking token respectively)
- **`protocolSettings` (Exchange) shown as cryptic `§`-separated strings**
  — now rendered as `<Protocol>: enabled/disabled` per entry, dropping the
  per-user encoding/use-defaults flags that are noise for security review
- **ADCS certificate templates not rendered to console** — templates were
  collected but their attribute conversion never reached `Show-Object`
- **Certificate Authority common name shown under generic `displayName`
  label** — CA-specific name field now used
- **Groups falsely flagged as `INACTIVE`** — the activity check applied
  the user-only `lastLogonTimestamp` heuristic unconditionally; groups
  never log on, so they always tripped the heuristic
- **GPO findings with empty `LinkedOUs` rendered blank** — now shown
  explicitly as `Not linked`
- **Overpass-the-Hash (RC4) failed with AS-REP decryption error**
- **Relative file paths resolved against the process directory** instead
  of the current PowerShell location (`$PWD`)

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
