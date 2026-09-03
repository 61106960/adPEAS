# Changelog

All notable changes to adPEAS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

---

## [Unreleased]

### Added

- **`Get-GPOPointAndPrint` - new GPO check for Point and Print printer driver policies.**
  Installing a printer driver runs code as SYSTEM, so Point and Print decides who may
  execute code on every machine in a GPO's scope. The check reports the complete
  configuration of each GPO that deploys one and derives the verdict from the
  combination of values rather than from any single value, because no single value
  settles the question:
  `RestrictDriverInstallationToAdministrators` blocks the install unless it is
  explicitly `0`, and only then do `NoWarningNoElevationOnInstall=1` and
  `UpdatePromptSettings=2` make the install silent. That combination is
  PrintNightmare-style privilege escalation and is reported as Critical.
  Also reported: where drivers may come from (Package Point and Print, its approved
  server list, the legacy trusted-server and forest restrictions), the remote spooler
  RPC endpoint (`RegisterSpoolerRemoteRpcEndPoint`), queue-specific files
  (`CopyFilesPolicy`, CVE-2021-36958), driver download over HTTP
  (`DisableWebPnPDownload`, `DisableHTTPPrinting`), and the Security Option
  "Devices: Prevent users from installing printer drivers" read from `GptTmpl.inf`.
  Settings are collected from Administrative Templates (`Registry.pol`), Group Policy
  Preferences (`Registry.xml`) and `GptTmpl.inf`, and every entry lists the OUs,
  domains and sites its GPO is linked to.

### Fixed

Found while building the unit test suites, each reproduced before it was changed.

- **A `userParameters` blob with exactly one Terminal Services setting was reported as a
  single letter.** `ConvertFrom-TSProperties` returned its lines with a plain `return`,
  which unrolls a one-element array to a bare string. `Invoke-LDAPSearch` tests
  `.Count -eq 1` - which is also true for a string - and then takes `[0]`, so the
  attribute value became `T`. `ConvertFrom-TSClientLicense` returned the same shape and
  is fixed alongside, though it always emits at least two lines and never hit it.
- **`RECONNECT_SAME` led the `CtxCfgFlags1` flag list instead of closing it.** Its mask
  was written as `0x80000000`, and PowerShell reads a hex literal that fills the sign bit
  as a negative `Int32`. The `-band` still matched, because both sides widen to `Int64`
  and the low 32 bits agree, but the key sorted below every other flag in a list the code
  documents as ascending.
- **The DES key from `Primary:Kerberos` was never read.** `supplementalCredentials` holds
  the Kerberos keys in two properties with two different layouts:
  `Primary:Kerberos-Newer-Keys` is a `KERB_STORED_CREDENTIAL_NEW` with a 24-byte header
  and 24-byte entries, `Primary:Kerberos` a `KERB_STORED_CREDENTIAL` with 16 and 20
  (MS-SAMR 2.2.10.4/2.2.10.5/2.2.10.7). The fallback that reads the second one used the
  first one's layout, which put every field eight bytes past where it lives - `KeyType`
  landed on `KeyLength`, the test for DES-CBC-MD5 never matched, and the fallback
  returned nothing. Silently: a key that is not found looks exactly like a key that is
  not there.
- **An entry declaring a zero-length key produced two bytes of the blob as if they were
  key material.** The key was sliced with `$Data[$offset..($offset + $length - 1)]`, and
  a length of zero makes that range count backwards - PowerShell reads `5..4` as
  `@(5, 4)`. The bounds check in front of it cannot catch that, because `offset + 0` is
  always inside the blob. Both parsers now share one extractor that copies the bytes
  instead of slicing.
- **A single empty property discarded the credentials next to it.** A property value of
  zero length was stored as `$null`, the first consumer that touched it threw, and the
  outer `catch` reported the whole `supplementalCredentials` attribute as unparseable -
  so the AES keys beside it were lost as well.
- **`WDigestHashes` was not always an array.** It came back as a bare string when exactly
  one of the 29 slots was set and as `$null` when the blob was too short, though the
  documented output is an array; indexing the string yields characters.
  `ConvertFrom-SupplementalCredentials` also refused an empty or null blob at the
  parameter binder, ahead of its own guard for exactly that case.
- **`Invoke-Kerberoast` left the caller's credential in session state.** The splat table
  it builds in `begin{}` carries the `PSCredential` and was never torn down, so it
  outlived `Disconnect-adPEAS`. It is cleared in `Clear-SessionState` now, along with the
  two other run-state variables that were missing there.
- **gMSA passwords were never extracted at all in the built artifact.**
  `ConvertFrom-ManagedPassword` called `Get-NTHashFromPassword -Password`, naming the
  parameter of a second function of that name defined in the same file. `Kerberos-Crypto.ps1`
  defines the same name with a `-PlainPassword` parameter and is concatenated later in the
  build, so its definition won: the call failed to bind, the outer `catch` swallowed the
  error, and the function returned `$null`. Every group managed service account password
  in a real scan produced nothing. The duplicate definition is removed.
- **The NT hash of a gMSA password was computed from a mangled string.** The hash was taken
  from the decoded password rather than from the bytes in the blob. A gMSA password is 256
  bytes of randomness read as 128 UTF-16 code units, so about one unit in 32 falls in the
  surrogate range and almost none of them pair up - with 128 units, roughly 98 percent of
  real passwords contain at least one. Decoding those to a .NET string turns every unpaired
  surrogate into `U+FFFD`, and a hash of the round-tripped string is not the account's NT
  hash. It is now computed over the exact bytes, which is also what removed the need for
  the duplicate hash function. The plaintext is still returned for display and is still
  lossy for those passwords, which is unavoidable in a string and is why the hash may not
  be derived from it.
- **A Shadow Credential's device id was reported as a byte-reversed hex string.**
  `ConvertFrom-KeyCredentialLink` sliced each LTV entry out of the blob with a range
  index, which returns `Object[]` rather than `byte[]`. `BitConverter` coerces that, so
  the timestamps came out right, but the GUID constructor does not: the DeviceId entry
  threw, its catch fell back to a hex dump, and a device that is
  `a1b2c3d4-1111-2222-3333-444455556666` was printed as
  `d4c3b2a1111122223333444455556666`. The display string exists precisely so an operator
  can pass that value to `-RemoveDeviceID`, and the reversed form matches no device, so
  the removal quietly does nothing. `Invoke-ShadowCredentialOperation` parses the same
  structure and already cast correctly; the shared helper now does the same, using
  `Array::Copy` rather than a slice, and a plain assignment rather than one out of an
  if-expression - the latter enumerates the result and would undo an explicit cast.
  The structure comment also claimed a two-byte entry identifier; MS-ADTS 2.2.20 defines
  one byte, which is what the code has always read.
- **A disabled GPO link was reported as an active one, and enforcement was never seen.**
  A `gPLink` entry holds the GPO GUID and its option digit at opposite ends of a
  distinguished name - `[LDAP://cn={GUID},cn=policies,cn=system,DC=...;2]`.
  `Get-GPOLinkage` searched for both with one pattern that required the `;2` to follow the
  closing brace directly, so it never matched, the options fell back to `0`, and every
  link came back as `Enabled` with `IsEnforced` false. Five checks - LDAP configuration,
  SMB signing, GPO permissions, add-computer rights and user rights assignment - filter on
  `LinkStatus -ne 'Disabled'` before they report, so a policy whose link an administrator
  had switched off was still reported as applying; and enforcement, which decides
  precedence between containers, was invisible. Link order was wrong for the same reason,
  because a disabled link was counted as one that applies. Each entry is now parsed as a
  unit.
- **A recovered GPP password could be a password nobody has.** `ConvertFrom-GPPPassword`
  decrypted with `PaddingMode::Zeros`, which leaves PKCS7 padding in the output, and then
  cleaned that up by filtering the decoded characters down to `U+0020-U+007E` and
  `U+0080-U+00FF` on the assumption that "GPP passwords are ASCII-safe". They are not: a
  euro sign, a tab, or any Cyrillic, Greek or CJK character was dropped without a word,
  so `P@ss<euro>w0rd` was reported as `P@ssw0rd`. This is the one output an operator
  authenticates with, and a quietly wrong credential costs a failed logon against an
  account that may be monitored. The padding is now removed on the bytes - PKCS7 by its
  length marker, zero padding in UTF-16 code units, because every ASCII character already
  ends in a zero byte - and the decoded string is returned unfiltered. Round-tripped
  against both padding schemes, which GPP files carry both of. The example in the
  function's own documentation was also wrong and now states what it actually returns.
- **One finding without a timestamp cost the reader the whole imported report.**
  `Import-FindingsFromCache` parsed the timestamp of every finding with an unguarded
  `[datetime]::Parse`, which throws on a missing value. The findings it reads come from a
  JSON file written by some other run of adPEAS - an older version, a partial export, a
  hand edit - so a single entry missing that field ended the import for all of them. The
  timestamp is informational here; the scan date the report shows comes from the cache
  metadata. It is now read the same way `Compare-adPEASReport` already reads the export
  date: guarded, and with the invariant culture, since the export writes the round-trip
  format and must not be read through the reader's local settings.
- **The worst password policy was the one the risk scoring could not read.**
  `Build-ScoringContext` pulls the minimum password length, the maximum password age and
  the account lockout threshold back out of the strings `Get-DomainPasswordPolicy`
  formatted for display, by matching the first run of digits. For the value zero that
  check renders the word "Disabled" - or "Disabled (Never expires)" - which carries no
  digits at all, so the field stayed unset and the scoring above it read "unknown"
  instead of "off". Zero is the dangerous setting in all three: no minimum length,
  passwords that never expire, and no lockout at all, which is the precondition password
  spraying needs. A new `ConvertTo-PolicyNumber` maps the word back to the number.
- **A report converted from a JSON export could end with an exception.**
  `Convert-adPEASReport` reads findings back out of a JSON file rather than from the
  running scan, so a file written by an older version - or edited by hand - can be missing
  the `Category` property. Three grouping loops guarded on `Category -ne 'Unknown'`, which
  is true for a missing value, and two of them then called `.ToLower()` on it. The result
  was not a wrong line in the report but a crash that ended the whole conversion. A
  finding without a category has no check context, which is what "Unknown" already meant,
  and it is now skipped the same way.
- **A directory object could inject script into the generated HTML report.** The report
  embeds three JSON documents as JavaScript literals inside a `<script>` block, and one of
  them - the scoring context - is built from the scan findings, so it carries group names
  and distinguished names out of the audited directory. Windows PowerShell escapes the
  less-than sign as a `\u` sequence in `ConvertTo-Json` output precisely so that embedded
  JSON cannot close the
  surrounding tag, and `Repair-JsonUnicodeEscapes` converted every such escape back to a
  raw character on the premise that they "display literally in HTML". They do not: a
  JavaScript parser reads these documents and `\uXXXX` is an ordinary escape there, so the
  un-escaping changed nothing a script sees and everything the HTML parser sees. An object
  named `CN=</script><img src=x onerror=...>` ended the script block in the report a
  consultant hands to a customer. The function is replaced by `Protect-JsonForScriptBlock`,
  which escapes in that direction instead and is idempotent across both PowerShell
  versions. It also removes a second transformation that collapsed four backslashes to two
  in the raw JSON, which is one escape level and silently turned every UNC path in a
  tooltip from `\\server\share` into `\server\share`.
- **A long attribute name ended an object's console output with an exception.** The Secure
  class is the one branch that computes its padding by hand instead of using `PadRight`,
  and PowerShell throws on a negative repeat count rather than returning an empty string.
  An attribute whose display name was longer than the alignment column therefore aborted
  the rest of the object. Guarded in all four places that pad this way.
- **A creation date without a trailing `Z` was read as the year 1601.** A generalized time
  is 14 plain digits when the `Z` is absent, which `[long]::TryParse` accepts, so
  `ConvertTo-ActivityDate` parsed it as a FileTime and returned a date four centuries off
  without failing. `Add-ActivityStatus` dates never-logged-on accounts by `whenCreated`,
  so a brand new account was aged past every threshold and flagged as long abandoned -
  the exact false positive the guard there exists to prevent.
- **Access control entries silently disappeared when scanning a domain from outside it.**
  Four places read a DACL through the `.Access` property of `ActiveDirectorySecurity`.
  That property asks for the rules as `NTAccount`, so the scanning host has to resolve
  every SID to an account name - and it drops the entries it cannot resolve, without an
  error. Against a domain the host is not joined to, which is how this tool is normally
  used, that is every domain principal in the descriptor: the DACL came back holding the
  built-in identities alone, or empty, and no check above could tell an empty ACL from an
  unreadable one. `ConvertFrom-SecurityDescriptor` feeds `Get-ObjectACL`,
  `Invoke-LDAPSearch` and `Get-OUPermissions`, so this reached every ACL-based check; the
  other three sites were the AdminSDHolder analysis in `Get-PrivilegedGroupMembers`, the
  enrollment detection in `Get-CertificateTemplate` that ESC1, ESC2 and ESC3 depend on,
  and the RBCD parsing in the collector. All four now ask for
  `SecurityIdentifier`, which needs no name resolution and cannot drop anything, and
  resolve the display name through `ConvertFrom-SID` as CLAUDE.md requires.
- **A Domain Admin who was also a Backup Operator was reported as unprivileged.**
  `Test-IsPrivileged` is the identity gate nine checks use to decide whether a principal
  holding a dangerous right is already privileged. It tested Operator membership before
  privileged membership, and the first match won, so the lesser of two memberships
  decided the verdict. The same inversion applied to `sIDHistory`, where the check
  returned on the first entry that matched anything and so depended on the order the
  directory happened to return the attribute in. The highest privilege an identity holds
  now decides, in both places.
- **`Test-IsPrivileged` did nothing useful when used from the pipeline.** A value arriving
  through the pipeline is wrapped in a `PSObject`, and `-is [PSCustomObject]` is true for
  that wrapper whatever it holds. The AD-object branch was tested first, so every piped
  SID string fell into it, found no `objectSid`, and came back as `Unknown` - the
  `ValueFromPipeline` the function advertises silently did nothing.
- **A user principal name never resolved to a SID.** The UPN branch of `ConvertTo-SID`
  built its LDAP filter and then fell through to the shared result handling without ever
  running the query, so it returned `$null` and wrote that to the negative cache. UPN is
  a documented input format.
- **A distinguished name with a comma or parentheses in its RDN resolved to nothing.**
  `ConvertTo-SID` escaped DNs with a chain of `-replace` calls, but a `-replace`
  replacement string does not process backslash escapes: `'\\5c'` produced a literal
  double backslash and `'\\28'` a backslash followed by `\28`. Every escape was malformed,
  so `CN=Doe\, Jane (Contractor),...` built an invalid filter and matched nothing without
  an error. It now uses `Escape-LDAPFilterDN`, which also knows that a DN out of AD is
  already RFC 4514 escaped. The sAMAccountName and UPN filters in the same function are
  escaped as well, so an account name holding `(`, `)` or `*` can no longer close the
  filter early or turn an exact lookup into a wildcard search.
- **A delegation inherited from the Certificate Templates container was invisible.** The
  three AD CS access-control checks asked the descriptor for explicit ACEs only, so an
  ESC4 or ESC5 grant authored on the parent container never produced a finding, although
  it is exactly as exploitable as one written on the template. Every other read path in
  adPEAS already reads inherited ACEs.
- **An AD CS enrollment principal could be judged against another principal's SID.** The
  name list and the SID list are paired by index, but a SID was appended only when the ACE
  carried one, so a single principal without a SID shifted every later entry. That can
  rate an unprivileged group as privileged and silently suppress ESC1, ESC2 and ESC3 for
  the whole template.
- **One failing query in `Get-InfrastructureServers` ended the whole check.** All six
  sections shared a single try/catch, so an unreadable Exchange group took MSSQL, SCCM,
  SCOM and Entra ID Connect down with it and the report showed nothing for them, which
  reads exactly like a domain that has none of those. Each section now handles its own
  errors and says when its result is unknown rather than empty.
- **A password that could not be read was reported as readable.** `Get-LAPSCredentialAccess`
  and `Get-BitLockerRecoveryKeyAccess` trusted the ACL-gated presence filter and never
  looked at the value that came back, so an object returned without its secret was
  announced as a readable credential. The LAPS check reports Finding, the most severe
  verdict the tool has. Both checks now report only the entries that actually carry a
  value, and say separately how many secrets exist that the account may not read.
- **The Norwegian and Esperanto spellings of "password" were never matched.** The pattern
  `passw\S*` was documented as covering "passord" and "pasvorto", which it cannot: neither
  word contains "w". A Norwegian description with a real password in it was invisible, and
  the Norwegian terms in the exclusion list were unreachable for the same reason, so
  Norwegian policy prose was reported as a credential mention. One shared token now covers
  every spelling.
- **A credential mention in the description hid an assignment in the info attribute.** The
  first match ended the scan of the whole account, so an account was filed as a yellow
  mention while an explicit password one attribute away went unread. Both attributes are
  now read and the stronger hit decides.
- **An empty Exchange group was reported as having one member.** `@($null)` is a
  one-element array holding `$null`, so a group with no `member` attribute announced
  "Found 1 member(s)", looped once over a null DN, and could never reach its own
  "has no members (unusual)" branch. Affected Exchange Trusted Subsystem, Exchange
  Windows Permissions and Organization Management.
- **A disabled account lockout was rated one step below a short password.** A
  `lockoutThreshold` of 0 means an attacker may guess without limit against every account
  in the domain, which is the precondition password spraying needs. It now rates with the
  critical weaknesses instead of as a hint.
- **A within-forest trust was told its disabled SID filtering was a security risk.**
  Inside a single forest that is how trusts work. The trigger that was meant to suppress
  the finding only set the colour: a severity-only trigger contributes no finding id, so
  the general trigger still supplied the tooltip. The same applied to trust transitivity.
- **The NetBIOS domain name was thrown away when the domain object could not be read.**
  It is resolved from the crossRef at connect time and needs no domain object, but was
  only read inside that query's success branch, so a permissions problem turned a known
  value into "(not found)".
- **SCOM service accounts and security groups were introduced by the server help text.**
  Both sections announced themselves with the SCOM server object type although
  `SCOMServiceAccount` and `SCOMGroup` carry their own section titles and explanations.
- **The SCCM and SCOM checks never reported a single server.** Both looped with
  `foreach ($server in ...)` while declaring a `[string]$Server` parameter. PowerShell
  keeps that type constraint on the loop variable, so every directory object was coerced
  to its string form: in SCCM `distinguishedName` came back empty and the dedup guard
  never fired, in SCOM `dNSHostName` came back null and the duplicate comparison ran
  `$null -notin $null`, which is false. Both checks always printed "no servers found".
  This is the collision CLAUDE.md warns about.
- **Read-only domain controllers were missing from the infrastructure inventory.**
  `Get-InfrastructureServers` filtered on `SERVER_TRUST_ACCOUNT` alone, but an RODC
  computer account carries `WORKSTATION_TRUST_ACCOUNT` plus `PARTIAL_SECRETS_ACCOUNT` and
  `primaryGroupID` 521. An RODC holds credentials and is a domain controller.
- **A current Windows Server was indistinguishable from a network printer.** The
  end-of-support dates for Windows Server 2019 and 2022 sat in a comment above the
  lifecycle table instead of in it, so both came back as "no lifecycle data" - the same
  answer the table gives for a Linux member or an appliance. They are now rows with the
  dates that were already written down beside them. Windows 11 and Windows Server 2025
  have no single published end date and are carried in a separate supported-without-date
  list rather than being given an invented one. `Get-OutdatedComputers` now closes with a
  count of the machines whose operating system it could not judge, so a clean result says
  how much of the estate it actually covers.
- **`Get-OutdatedComputers -InactiveDays` did nothing.** The parameter was declared,
  defaulted and documented, but never reached `Test-AccountActivity`. Passing it now works
  because `Test-AccountActivity` no longer turns an explicit window into an implicit
  "inactive only" filter when the caller asked for `-IncludeDetails`, which is a request to
  annotate every object rather than to filter.
- **The entire gMSA password-access analysis never ran.** In
  `Get-ManagedServiceAccountSecurity` the security descriptor was assigned from an
  if-expression, which routes the value through the output stream and enumerates it, so a
  `[byte[]]` arrived as `[Object[]]` and the `-is [byte[]]` guard on the next line was
  always false. Every domain was told its gMSA password access was properly restricted to
  privileged accounts, however many broad groups could actually read the passwords.
- **Every resource-based constrained delegation could disappear.** The decoder in
  `Invoke-LDAPSearch` read the `.Access` property, which is an extended type member
  registered by `Microsoft.PowerShell.Security`. Where that module is not loaded the
  expression is `$null` with no error and every RBCD target came back as
  "[SD present, no Allow ACEs]". It now uses `GetAccessRules`, and an unresolvable trustee
  keeps its SID instead of becoming an empty entry that nulls the whole attribute.
- **A domain without AD CS produced a phantom vulnerable certificate template.**
  `@($null)` is a one-element array holding `$null`, which the query-error filter kept, so
  the empty guard never fired and an all-null placeholder was analysed as a real template.
  With no extended key usage it read as Any Purpose plus Client Authentication.
- **A template enrollable through an All-Extended-Rights ACE was missed.**
  `ConvertFrom-SecurityDescriptor` spelled out a right name only for an ACE carrying an
  object type, so an ACE granting every extended right - Certificate-Enrollment included -
  stayed the bare word `ExtendedRight` and no consumer recognised it.
- **Windows LAPS read delegations were never detected.** `Get-OUPermissions` looks the
  `msLAPS-*` schemaIDGUIDs up in `$Script:PropertyGUIDs`, which held only the two legacy
  LAPS entries. Every comparison ran against `$null` and could never match, so a delegated
  read on a Windows LAPS password attribute produced no finding at all and only the
  "All Properties" fallback caught such a delegation. The static GUIDs were already present
  in the same file, in `$Script:ReadPropertyAliases`.
- **Anonymous LDAP binding was reported as restricted when it was allowed.**
  `Get-LDAPConfiguration` matched the `RestrictAnonymous` value name with `.*?=`, which also
  matched `RestrictAnonymousSAM`. In the usual DC baseline ordering the check read the SAM
  value instead. All three value names are now anchored.
- **Scheduled tasks running as a named privileged account were never rated privileged.**
  `Get-GPOScheduledTasks` called `ConvertTo-SID -Name`, but the function declares
  `-Identity`. The binding error was swallowed by the surrounding `catch`, so only a
  `runAs` already given as a raw SID reached the privilege check.
- **A failed SMB access was reported as a clean domain.** `Get-GPOUserRightsAssignment`
  had no branch for "SYSVOL answers but this scan could not read it" and fell through to
  its Secure message. Same for a failed AdminSDHolder read in `Get-PrivilegedGroupMembers`
  and for an aborted `Get-DangerousACLs` run, which produced no output at all.
- **A reported credential line was used as a wildcard pattern.** The duplicate suppression
  in `Get-CredentialExposure` compared with `-like "*$reported*"`, so a password containing
  `*` or `?` silently swallowed unrelated credentials found later in the same file.
- **The domain scan ignored PowerShell scripts.** `Get-CredentialExposure` scanned `.ps1`
  and `.psm1` in custom-path mode but not in SYSVOL, where logon scripts commonly are
  PowerShell today.
- **A quoted script path was mangled.** `Get-GPOScriptPaths` tested for an absolute path
  without stripping surrounding quotes, so a quoted path was rewritten as if relative and
  its language detection fell through to Unknown.
- **A privileged user with a comma in their name was skipped.** `Get-PasswordResetRights`
  derived the parent container with `^CN=[^,]+,(.+)$`, which splits on the escaped comma in
  a name such as `Doe\, Jane` and produced a DN that does not exist.
- **Restricted Groups entries keyed by group name were dropped.** Both
  `__Members` and `__Memberof` variants required the GptTmpl.inf `*` SID prefix, which is a
  detection gap on localized domains. Names are now resolved to a SID so every downstream
  comparison stays SID based.
- **The severity of a GPO scheduled task and of a GPO registry setting never reached the
  report.** Both checks computed a per-row severity and discarded it immediately before
  output, so a SYSTEM task on a UNC path rendered exactly like a benign one and a Critical
  AlwaysInstallElevated was announced in yellow. Rows now carry their class, the reason is
  a visible attribute, and results are ordered most severe first.
- **A GPO ACE granting only delete rights was reported without a label**, rendering as
  `CONTOSO\helpdesk ()`.
- **Domain Users kept a blanket read finding that Authenticated Users and Everyone were
  exempt from.** The OU identity gate consulted only the static well-known SID list, not
  the domain-relative RID list Domain Users belongs to.
- **The LAPS check over-detected.** `Get-OUPermissions` tested GenericAll with a bitwise
  overlap against a composite mask, so almost any harmless Allow right came back as an
  "All Properties includes LAPS" finding.
- **A machine account quota of 0 depended on an accident.** `Get-AddComputerRights` used a
  truthiness test that only worked because LDAP returns attribute values as strings.
- Smaller corrections: the SMB failure message in `Get-CredentialExposure` was printed
  twice; pattern hits in custom-path mode were tagged with the wrong object type; two
  tier-2 credential patterns were unreachable behind a more generic one; a scheduled task
  without a name attribute was reported as `Properties`; the membership path in
  `Get-PrivilegedGroupMembers` used a stray `?` as its separator; broad SIDs were compared
  with a substring regex instead of equality; and `Get-DangerousOUPermissions` claimed
  "no dangerous OU permissions detected" when the domain had returned no OUs at all.

### Changed

- **Point and Print is no longer reported by `Get-GPORegistrySettings`.** Its two
  entries flagged `NoWarningNoElevationOnInstall=1` and
  `RestrictDriverInstallationToAdministrators=0` independently, each as High. Since the
  August 2021 update the first is inert on its own, which made a very common pre-2021
  legacy GPO a false positive, while the genuinely exploitable combination of both was
  under-rated and split across two findings. Both values are now evaluated together by
  `Get-GPOPointAndPrint`. A prompt suppression that is currently blocked by the default
  is reported as a latent risk instead of a vulnerability, and approved-server
  restrictions are reported as the driver source but never allowed to downgrade an
  exploitable configuration - a suppressed elevation prompt overrides them.
- **Group Policy Preferences `Registry.xml` parsing moved to a shared helper**
  (`Parse-RegistryXml`), alongside the existing `Parse-PRegRecords`, so both GPO
  registry checks read the same two delivery mechanisms through the same parsers.

## [2.4.1] - 2026-08-28

### Added

- **LAPS configuration deployed via Group Policy is now analyzed and reported.**
  `Get-LAPSConfiguration` shows, per GPO and for both LAPS generations, the managed
  account name, password complexity, length, passphrase length and maximum age, and
  for Windows LAPS additionally the backup target, AD password encryption and the
  principal allowed to decrypt. These settings are readable from SYSVOL without any
  LAPS password permission, so they disclose the managed local administrator account
  and reveal misconfigurations before a single computer object is touched. Every
  entry lists the OUs, domains and sites its GPO is linked to.
  New findings: AD password encryption disabled (the password is stored in cleartext
  in `msLAPS-Password`), backup target disabled or set to Microsoft Entra ID only
  (nothing is escrowed to this Active Directory), password expiration protection
  disabled, weak password complexity, and LAPS settings in a GPO that is linked
  nowhere. The GPO analysis now also runs when the LAPS schema is absent - a GPO
  configuring LAPS without the schema extension is a critical misconfiguration that
  was previously invisible.
- **`Test-RemoteAdminAccess` accepts `-Username` and `-Password`** as an alternative
  to `-Credential`. `-Password` takes a plaintext string or a SecureString and allows
  an empty string. A bare username is resolved against the connected domain, because
  SMB and WMI would otherwise treat it as a local account on the target.
- **Windows LAPS plaintext passwords now expose `msLAPS-Account` and `msLAPS-Updated`.**
  The JSON in `msLAPS-Password` was parsed but only the password was kept, so the
  managed account name was dropped for plaintext LAPS while the encrypted path
  reported it.

### Fixed

- **A blank line in a multi-line attribute value silently dropped the whole object
  from the output.** An AD free-text field (`description`, `info`) containing a blank
  line or a trailing newline aborted rendering; the calling check caught the error as
  a generic warning, so the object was counted in the summary but never displayed.
  Affected every check. Values with CRLF line endings also no longer keep a stray
  carriage return in the display.
- **The LAPS GPO scan found nothing when the client could not reach the SYSVOL DFS
  path.** The scan built its path from `gPCFileSysPath` (the domain DFS namespace),
  while SMB authenticates against the domain controller hostname - a different target.
  The mismatch failed silently with an empty result and no error.
- **The Windows LAPS policy registry root was wrong**, so Windows LAPS GPO settings
  were never found. The correct GPO root is
  `Software\Microsoft\Windows\CurrentVersion\Policies\LAPS`.
- **`Registry.pol` was searched as text instead of parsed as the binary format it is.**
  The Type/Size fields contain embedded nulls that break a "read to the next null
  terminator" match, so the LAPS account name was never extracted correctly.

### Changed

- **Fewer SMB round-trips when scanning SYSVOL.** `Get-LDAPConfiguration`,
  `Get-SMBSigningStatus`, `Get-AddComputerRights` and `Get-GPOUserRightsAssignment`
  probed a constructed `GptTmpl.inf` path per GPO - one round-trip each for a file
  most GPOs do not have. They now use the shared cached SYSVOL listing, which is also
  what the LAPS GPO scan uses, so a single SYSVOL walk serves all GPO checks.
- **`Get-LAPSConfiguration` reports in a more logical order:** schema detection, then
  the GPO configuration, then deployment coverage.

## [2.4.0] - 2026-08-27

### Added

- **Server-side password-age and inactivity filters on `Get-DomainUser` and
  `Get-DomainComputer`.** Three new parameters build the LDAP filter directly
  instead of pulling all objects and filtering client-side: `-PasswordAgeDays <N>`
  (password last set at least N days ago), `-InactiveDays <N>` (logged in once but
  not within N days; never-logged-in accounts are excluded), and `-NeverLoggedIn`.
  Implemented centrally in `Get-DomainObject`.

### Fixed

- **HTML report generation aborted when a finding value contained a `$` followed by
  digits.** Template placeholders were substituted with `-replace`, whose replacement
  engine reads `$<n>` as a capture-group reference; a long digit run overflowed with
  "Capture group numbers must be less than or equal to Int32.MaxValue" and killed the
  whole report. All placeholder substitutions now use literal `.Replace()` (main report
  and comparison report).
- **BloodHound collector crashed with "cannot call a method on a null-valued
  expression" during OU/container collection.** After a disconnect/reconnect,
  `Clear-SessionState` reset the DN caches to an empty hashtable (which the lazy build
  guard treats as "already built") and left a sibling cache `$null`, so collection ran
  on a half-built cache. Caches are now reset to `$null`, the build guard requires both
  caches, and the consumers null-guard the lookup.
- **BloodHound collection failures now report their origin without `-Verbose`.** A
  failure previously showed only a generic message; the failing function and line are
  now surfaced.
- **Misleading Kerberos error for `KDC_ERR_ETYPE_NOSUPP` (etype 14).** The message
  always suggested using `-AES256Key`, even when an AES key was already used. It is now
  aware of the authentication method: with an AES key it points at a missing AES key on
  the account; with an NT hash it points at RC4 being disabled.
- **Cross-realm Kerberos failures are now explained precisely.** Authenticating as a
  user from a different realm than the target (over a trust) failed with a generic
  "ticket not usable" error. adPEAS does not chase cross-realm referrals; the message
  now says so and lists the fixes (OS DNS resolving both realms, an account in the
  target domain, or a plaintext password for NTLM).
- **`sIDHistory` display printed each SID twice** (e.g. `<SID> (FOREIGN) (<SID>)`). A
  SID is now shown once, resolved to a name only when a real name is available. The
  verbose "(SID History Injection risk!)" suffix was removed from the label (it is
  explained in the HTML tooltip).

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
