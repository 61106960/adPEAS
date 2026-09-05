# Changelog

All notable changes to adPEAS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

---

## [Unreleased]

### Added

- **Constrained delegation now says whether the target is a Domain Controller.** The check
  listed the accounts and left the delegation targets for the reader to judge, while the
  finding text told that reader to look for exactly what the check could have determined
  itself. Targets are now matched against the domain's Domain Controllers and an account
  that reaches one is called out separately, as `CONSTRAINED_DELEGATION_TO_DC`.

  **Matched on the host, never on the service class.** Restricting the service class is
  not a control: S4U2Proxy returns a ticket encrypted with the target host's account key,
  and every SPN registered to that account shares that key, so a ticket obtained for
  `time/DC01` can be rewritten to `ldap/DC01` and will decrypt. Delegation to any SPN on a
  Domain Controller is therefore worth as much to an attacker as delegation to LDAP, and
  the guidance that said otherwise was corrected in the same pass (see Fixed).

  If the Domain Controllers cannot be enumerated the check says so rather than reporting
  no DC target, which would read as a clean result.

- **Accounts carrying protocol transition without any delegation target are reported.**
  `TRUSTED_TO_AUTH_FOR_DELEGATION` with an empty `msDS-AllowedToDelegateTo` was invisible:
  the check filters on the presence of that attribute, which these accounts do not have.
  A second, server-side filtered query picks them up as
  `CONSTRAINED_DELEGATION_TRANSITION_NO_TARGET`. The flag alone still buys a forwardable
  S4U2Self ticket for any user against the account's own services, and set on its own it
  is more often a leftover or an attacker's groundwork than anything intended.

- **`Get-DomainComputer -DomainController`.** What counts as a Domain Controller is now
  defined once in the data layer instead of being spelled out per check.

- **A roastable account that holds privileged rights is called out separately.** Every
  kerberoastable or AS-REP roastable account hands out a hash to crack offline, but on a
  privileged one cracking it is a domain compromise rather than the compromise of a
  service - and both used to be reported alike. Both checks now consult `Test-IsPrivileged`
  per account (nested membership, cached per SID) and mark the account as
  `ROASTABLE_PRIVILEGED_ACCOUNT`. Operators count: an Account Operator can reset most
  passwords in the domain, which makes its own worth as much to whoever cracks it.

- **ESC10 is detected where it is deployed by Group Policy.** Both halves of ESC10 live in
  the registry of the domain controllers rather than on a template or a CA, which is why
  they belong to `Get-GPORegistrySettings` and not to the AD CS checks:

  | | value | why it is ESC10 |
  |---|---|---|
  | `Kdc\StrongCertificateBindingEnforcement` | `0` | the KDC skips the certificate's SID extension even when it is present, so every certificate maps by UPN alone |
  | `Schannel\CertificateMappingMethods` | bit `0x4` | UPN-based mapping for everything that authenticates through Schannel - LDAPS and any other TLS client-auth endpoint |

  The second needed a new `BitSet` match type: `CertificateMappingMethods` is a flag field
  (`0x1` subject/issuer, `0x2` issuer, `0x4` UPN, `0x8` subject), and an equality test would
  have missed every combination that carries the bit next to another one - which is how the
  value is normally written.

  Value `1` for the KDC is deliberately not reported. It is weaker than full enforcement and
  KB5014754 calls it transitional, but a certificate that carries a SID extension is still
  validated, so it is not the ESC10 primitive - and it is the value Windows shipped as the
  default.

  **This sees a value only where Group Policy deploys it.** A value set locally on a domain
  controller is invisible from the directory, and the finding says so rather than implying
  the domain is clean.
- **`Get-WeakCertificateMapping` - new AD CS check for ESC14, explicit certificate
  mappings.** `altSecurityIdentities` maps a certificate to an account directly, overriding
  the SID extension the CA writes into it. Active Directory accepts six formats and
  Microsoft classifies three as weak (KB5014754), because each names something an attacker
  can put into a certificate of their own:

  | | strong | | weak |
  |---|---|---|---|
  | issuer + serial | `X509:<I>…<SR>…` | issuer + subject | `X509:<I>…<S>…` |
  | key identifier | `X509:<SKI>…` | subject only | `X509:<S>…` |
  | public key hash | `X509:<SHA1-PUKEY>…` | e-mail address | `X509:<RFC822>…` |

  The check reports two different problems: principals that already carry a weak mapping -
  anyone able to enrol for a certificate with a matching subject or e-mail authenticates as
  them, and on a template where the enrollee supplies the subject that is one request - and
  privileged principals whose `altSecurityIdentities` a non-privileged trustee may write,
  which is ESC14 as originally described: the mapping being added rather than found.

  Write access is examined for privileged principals only. Mapping a certificate onto an
  account is an escalation when the account is worth reaching, and a domain-wide ACL sweep
  over every user would cost a great deal to answer a question that matters for a few.
  `altSecurityIdentities` is also added to the GUID table, so an ACE on it is named rather
  than shown as a bare GUID wherever ACLs appear.
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

### Changed

- **Security descriptors are read in one query instead of one per object.**
  `Get-ObjectACL` reads exactly one object per call, so a check that needs the ACLs of many
  paid one LDAP round trip for each - a domain with 400 group policies paid 400 of them for
  data a single search returns. `Get-ObjectACL` now accepts a descriptor the caller already
  holds, so the caller asks once with `-Raw` and hands the bytes over per object. Everything
  after the read is the same code, so the analysis and its results are unchanged.

  `Get-GPOPermissions` prefetches every GPO descriptor in one query, and
  `Get-ADCSVulnerabilities` does the same for certificate templates, which it used to read a
  second time each because `Get-ADCSTemplate` returns the converted form and the ESC4
  analysis needs the raw bytes. Both keep the per-object read as a fallback, so a failed
  prefetch costs speed rather than findings.

  `Get-ProtectedUsersStatus` no longer re-reads the direct members of every Tier-0 group:
  the recursive `LDAP_MATCHING_RULE_IN_CHAIN` query above it already returns them, so only
  a member that query did not cover is looked up - in a normal domain, none.
- **An output path is no longer truncated at a dot that was never a file extension.**
  `-Outputfile` and `-OutputPath` are documented as taking a path without an extension,
  and one is dropped as a courtesy if the caller types it anyway, so that
  `-Outputfile report.html` does not produce `report.html.html`. The courtesy applied to
  anything `Path.HasExtension` recognised - which in a tool whose reports are usually
  named after the audited domain is the common case, not the exotic one. `.com`, `.local`
  and `.de` are indistinguishable from an extension, so `-Outputfile scan_contoso.com`
  silently wrote `scan_contoso.html`, and `scan_v1.2` became `scan_v1`.

  Only the three extensions adPEAS itself appends - `.html`, `.txt`, `.json`, in any
  casing - are dropped now. **This changes file names:** a caller who passes a base path
  ending in something dot-like now gets the file they asked for
  (`scan_contoso.com.html`), where before they got a shortened one. Scripts that hard-code
  the previously produced path need updating.

  The rule lived in three hand-written copies (`adPEAS.ps1`, `Convert-adPEASReport`,
  `Compare-adPEASReport`) and is now one function, `Get-adPEASOutputBasePath`.
- **LDAP attribute conversion moved out of `Invoke-LDAPSearch` into its own function,
  `ConvertFrom-LDAPAttribute`.** Every attribute of every object adPEAS reads passes
  through this conversion, and all 45 checks see only its output, never the raw value -
  yet it had no test coverage at all, because there was no way to reach it: exercising it
  meant calling `Invoke-LDAPSearch`, which needs a real
  `System.DirectoryServices.Protocols.SearchResponse`, and `SearchResultEntry` has no
  public constructor. It was 1422 lines inline in the result loop, 68 % of the file, 57
  conversion branches in three groups (13 multi-value, 18 `byte[]`, 26 string) and 153
  `Add-Member` calls. `Invoke-LDAPSearch.ps1` goes from 2087 to 449 lines; the call site
  is 12. The three `Convert-*` helpers the conversion uses moved with it - they were
  declared *inside* `Invoke-LDAPSearch`'s process block and were reachable from the
  conversion only through PowerShell's dynamic scoping, which works when
  `Invoke-LDAPSearch` is the caller and nowhere else. No behaviour change: the block was
  moved with two mechanical rewrites (`Add-Member` calls became assignments into the
  returned dictionary, the `continue` that ended each multi-value branch became a
  `return`), and equivalence was verified rather than assumed - the original block was
  lifted out of the previous commit, wrapped, and run against the extracted function over
  100 cases covering every branch, comparing canonically serialised output. New suite
  `LDAPAttributeConversion.Tests.ps1` (46 tests) now pins the conversion directly, and
  the RBCD decoding test calls the real function instead of lifting an AST fragment.
- **The two attribute-name lists the conversion consults for every value are built once
  instead of per attribute.** `$FileTimeAttributes` (14 entries) and
  `$GeneralizedTimeAttributes` sat inside the conversion branch, so they were rebuilt for
  every attribute of every object - a scan of 10.000 objects with 30 attributes each
  allocated both arrays 300.000 times for nothing. They are now script-level HashSets
  built at load time. Also removed: an unreachable branch that would have rendered the
  five domain policy intervals as "42 days" / "30 minutes". All five are listed among the
  FileTime attributes, so that branch claimed them first, `[DateTime]::FromFileTime`
  throws on a negative duration, and the raw interval falls through - which is what
  `Get-DomainPasswordPolicy` already documents and converts itself. Removed rather than
  made reachable, because reviving it would change the value of `maxPwdAge`, `minPwdAge`,
  `lockoutDuration`, `lockOutObservationWindow` and `forceLogoff` for every consumer.
  No behaviour change in either case, verified against the pre-refactor code.
- **The domain policy interval arithmetic is now one function,
  `ConvertFrom-ADInterval`.** The five interval attributes are stored as negative
  100-nanosecond deltas and reach a consumer as the raw interval string - deliberately,
  because the BloodHound export needs the raw number. Converting them is therefore each
  consumer's job, and two of them did the same three steps (absolute value, divide by a
  ticks-per-unit constant, catch the `Int64.MinValue` "never" sentinel) in four places
  each: 77 lines between `Get-DomainPasswordPolicy` and the collector's
  `Convert-ADIntervalToString`. Both now call the shared helper, which returns a
  `TimeSpan` - or `TimeSpan.Zero` when the attribute is 0, or `$null` for the sentinel;
  three states the callers act on differently, and collapsing two of them would turn "no
  lockout duration configured" into "locked forever". Formatting stays with the caller,
  because the report wants whole days and the export wants "42 days". No behaviour
  change: the password policy suite passes unchanged, its fixtures included. New suite
  `ADInterval.Tests.ps1` (43 tests) covers the helper and, for the first time,
  `Convert-ADIntervalToString` - the export formatter whose failure mode is silent, since
  anything it cannot read comes out as "Forever", which reads as a domain whose passwords
  never expire.
- **The sidebar derives its category filter through the same function as the sections, and
  encodes names the way the rest of the report does.** Clicking a category in the sidebar
  calls `filterByCategory('<slug>')`, and the script then shows the sections whose
  `data-category` matches - two separately written derivations of the same string, so a
  filter click finding anything at all rested on them staying identical. `Build-NavigationHtml`
  now calls `ConvertTo-CategorySlug`, the function the sections already use. It also
  encoded the category name with `[System.Net.WebUtility]::HtmlEncode` while everything
  else in the file uses the report's own `ConvertTo-HtmlEncode`; WebUtility escapes
  non-ASCII too, so a localized category name appeared as "Dom&#228;nen" in the sidebar
  and with the umlaut itself in its own section title, in the same UTF-8 document. And the
  sidebar took the findings as a second parameter that it never read - dropped, along with
  the pass over all findings the caller made to build it.
- **A finding card reports its section the way a reader sees it, and an untagged object
  card names a computer the same way a tagged one does.** Two small inconsistencies in the
  per-card content, both found while putting the first tests around it. The `section` field
  the report's "top actions" list displays was chosen by a guard that tested `CheckTitle`
  and then returned `Category`, so a card whose first finding named no check fell through
  to the lowercase id slug and the list showed "Accounts" and "accounts" next to each
  other - the list's own DOM fallback reads the section title, which is capitalised. And
  `Get-ObjectCardTitle` stripped the trailing `$` from a computer account name on the
  tagged path but not on the `[UNTAGGED]` one, so the same computer read differently
  depending on whether its check had declared an object type.
- **The HTML report is grouped into cards once instead of three times.** A report is built
  from one ordered list of findings by walking it and cutting it into cards at each
  SubHeader. That walk existed three times - in `Get-CardBasedCounts` (the numbers at the
  top and in the sidebar), in `Build-ScoringContext` (the `findingCards` array the
  JavaScript scoring reads) and in `Build-FindingSectionsHtml` (the cards a reader sees) -
  and the three did not agree on where a card ends. The counting walk ignored `Header`
  entirely, so content sitting between a header and the next subheader was added to the
  previous section's card: counted in the summary, rendered nowhere. The metadata walk
  closed a card on `Header` unconditionally while the rendering walk did so only inside an
  open section, so a group that never got a section produced a scoring entry but no card -
  and since a card looks up `findingCards[N]` by its own index, every card after that
  point read the next card's score and remediation text. Not reachable from a normal scan,
  where output always starts with a header, but reachable through `Convert-adPEASReport`,
  which reads findings back out of a JSON export. All three now consume
  `Get-FindingCardGroups`, so the alignment is structural rather than coincidental; the
  summary no longer counts items that are not rendered, and a section is emitted only when
  it actually holds a card.
- **`Secure` now outranks `Hint` everywhere in the HTML report - the summary counts, the
  card badge and the scoring metadata.** The ranking existed three times in
  `Export-HTMLReport.ps1`, as three near-identical loops: `Get-GroupSeverity` (feeds the
  counters at the top), `Build-FindingCardHtml` (the badge a reader sees) and
  `Build-FindingCardMetadata` (the severity the JavaScript scoring reads). All three
  ranked `Hint` above `Secure`, a documented divergence from the central ranking
  (`adPEAS-Types.ps1`'s `$Script:SeverityPriority` and `Get-RenderModel.ps1`'s
  `Get-MaxSeverityFromValues`, both `Finding > Secure > Hint > Note`), left as an
  intentional difference pending a decision. Decided: unify on the central ranking, so a
  section that is otherwise confirmed secure is not downgraded by a mere Hint elsewhere
  in it. The first attempt changed only `Get-GroupSeverity` and claimed to have changed
  the badge - it had not, and the result was worse than before: a group holding both a
  Secure and a Hint was *counted* as Secure while the card below it still rendered a
  Hint badge and scored as hint. All three now call `Get-GroupSeverity`, which derives
  its table from `$Script:SeverityPriority` instead of restating it, so there is one
  answer to "how severe is this group" rather than three. Visible effect: for a group
  holding both, the badge, the counter and the score all read Secure.
- **HTML report risk score: the account tier classification now matches the identity
  gate every check already uses.** `Build-ScoringContext` (the report's risk-scoring
  layer) classified an account's highest privileged group membership with its own
  inline regex, independently of `Test-IsPrivileged` (the identity gate every check
  module already uses to decide "is this account already known to be privileged").
  The two had drifted apart - not a documented decision, unlike the severity ordering
  above - and Group Policy Creator Owners (-520) and Key Admins/Enterprise Key Admins
  (-526/-527), each a direct path to domain takeover that adPEAS itself implements the
  full attack chain for (GPO -> SYSTEM code execution; `msDS-KeyCredentialLink` ->
  Shadow Credentials -> PKINIT -> UnPAC-the-Hash), scored only `tier2` instead of the
  `tier0` the identity gate already considered them. Decided: `Build-ScoringContext`
  now classifies every group through `Test-IsPrivileged` (the same central
  `$Script:PrivilegedRIDSuffixes`/`$Script:OperatorRIDSuffixes` tables in
  `adPEAS-SIDs.ps1`) instead of its own copy. Visibly raises the risk score of any
  account whose only privileged membership is one of those two groups, and correctly
  distinguishes the well-known BUILTIN Operator groups (Account/Server/Backup
  Operators, real SID `S-1-5-32-nnn`) from a same-looking but nonexistent
  domain-relative SID, which the old string-suffix regex could not tell apart.
- **Console attribute-column alignment is now computed in one place.** Every renderer
  aligns the value of an attribute line to a fixed column, but `Secure` (the only
  severity class with a background colour) could not use `.PadRight()` like every other
  class: colouring a `PadRight`-ed string tints the padding spaces too, so `Secure`
  computed its padding by hand instead - copy-pasted across four call sites in
  `Write-adPEASAttribute` (`Write-adPEASOutput.ps1`) and the multi-value row renderer
  (`Render-ConsoleObject.ps1`), each console and file output. Found while building the
  unit test suites: a name longer than the alignment column made the hand-rolled
  version throw (`' ' * negative`), already fixed with `[Math]::Max(0, ...)`; the
  duplication itself was left as a documented, unresolved design question. Decided: a
  new shared helper, `Get-adPEASAttributeAlignment -Name -Width`, returns the name, the
  padding spaces, and the two already joined as separate parts, so every caller builds
  on the same computation - the ones that colour name and padding together use the
  joined form, `Secure` uses the two parts separately. Internal refactoring only, no
  visible behaviour change.

### Fixed

Found while building the unit test suites, each reproduced before it was changed.

- **Policy wording in a description hid the password written next to it.** In
  `Get-PasswordInDescription` the exclusion list ran before the high-confidence patterns
  and skipped the whole attribute on a match. Since people write both in one sentence -
  "Passwort muss geaendert werden. Passwort = Winter2024!", "Password complexity required;
  password: Herbst2024" - the credential went unreported, silently. Measured against five
  realistic descriptions carrying an actual assignment, three were lost. The exclusions
  now only downgrade a bare mention, which is what the comment above them always claimed
  they did. The one exception is a separate, narrower list for masked and bracketed values
  (`Password: ********`): those describe the value rather than the sentence, so they still
  silence the attribute outright.

- **`Get-UnixPasswordAccounts` only looked at user objects.** The five password attributes
  are not confined to one object class, and the check asked `Get-DomainUser`, whose filter
  adds `(&(objectCategory=person)(objectClass=user)(!(objectClass=computer)))`. A
  Unix-integrated host with `unixUserPassword` on its computer account holds the same
  leaked credential and was invisible. It now asks `Get-DomainObject`.

- **`Get-UnixPasswordAccounts` printed the credential as decimal bytes.** `userPassword`,
  `unixUserPassword`, `msSFU30Password`, `sambaNTPassword` and `sambaLMPassword` are octet
  strings, so they arrive as `byte[]` and reached the report unconverted - a password came
  out as `83 111 109 109 101 114 50 48 50 52 33`. Showing what these attributes hold is the
  entire purpose of the check. They are now decoded as text, which covers cleartext, a
  crypt(3) hash and the hex form of an NT or LM hash alike; a value that is not printable
  text is rendered as hex rather than pushed through a decoder that would substitute the
  undecodable bytes and leave a hash no longer matching itself. Multi-valued attributes
  keep every value.

- **Every server with protocol transition was listed as a Domain Controller.** The DC
  query in `Get-InfrastructureServers` matched `userAccountControl` bit `16777216`, meant
  as `PARTIAL_SECRETS_ACCOUNT` to catch read-only DCs. `PARTIAL_SECRETS_ACCOUNT` is
  `67108864`; `16777216` is `TRUSTED_TO_AUTH_FOR_DELEGATION`. Any account configured for
  constrained delegation with protocol transition therefore appeared in the Domain
  Controller inventory. The filter moved into `Get-DomainComputer -DomainController` and
  now uses the right constant.

- **The advice on constrained delegation was wrong about what protects a Domain
  Controller.** Four finding definitions, the check's help text and the documentation all
  suggested that the danger lay in delegating to particular services - "ensure target
  services don't include sensitive services like LDAP on DCs". That reads as though
  `time/DC01` were safe. It is not: all SPNs registered to one host account share a single
  key, so a service ticket issued for one of them can be rewritten to another. Every text
  now says what actually holds - do not delegate to a Domain Controller at all - and the
  new detection matches accordingly.

- **The template loaders threw instead of falling back to the current directory.** Both
  `Get-HTMLTemplate` and `Get-DiffHTMLTemplate` look for their template files relative to
  `$PSScriptRoot`, then to the invocation path, then to the current location. The second
  step was written as `Split-Path -Parent $MyInvocation.MyCommand.Path`, which throws on a
  null argument rather than returning nothing - so a function defined in memory instead of
  dot-sourced from a file died there, and the third step was unreachable. Both now check
  the path before splitting it.
- **Three gaps in the AD CS checks, found by auditing them against the published ESC
  preconditions.**
  - **A template whose only authentication EKU is PKINIT was invisible.** The four OIDs the
    ESC1 precondition names are Client Authentication (`1.3.6.1.5.5.7.3.2`), Smart Card
    Logon (`1.3.6.1.4.1.311.20.2.2`), PKINIT Client Authentication (`1.3.6.1.5.2.3.4`) and
    Any Purpose (`2.5.29.37.0`). All but PKINIT were matched, so a template carrying it
    alone authenticated in the domain while adPEAS reported nothing. Every
    enrollment-driven check keys off this flag, so ESC1, ESC2, ESC3-TARGET and ESC9 were
    all blind to it.
  - **Manager approval never damped a finding.** `PEND_ALL_REQUESTS` holds every request
    until a certificate manager releases it. It was computed and displayed but never
    consulted, so ESC1/2/3/9/13/15 were reported at full severity on templates where no
    certificate can be issued without a person in the loop. It now damps the severity
    exactly as a required enrollment agent co-signature does - and, like that one, does not
    damp on a template that is also ESC4-vulnerable, because write access lets an attacker
    clear the flag before enrolling.
  - **ESC5 did not look at the AIA and CDP containers.** Both are named in the precondition
    alongside `CN=NTAuthCertificates`: write access to AIA publishes an attacker's own CA
    into the chain, write access to CDP decides where revocation is looked up. Neither was
    in the list, so the check could report the PKI containers as properly restricted
    without having read either ACL.
- **The certificate templates a CA publishes are listed one per line.** They were joined
  into a single comma-separated run, which on a CA publishing a dozen templates is the
  hardest form to read one name out of. The renderer already lays a multi-valued attribute
  out one value per line, the way `memberOf` and `WebEnrollmentEndpoints` appear on the
  same card; the list is now passed through as the list it is. Order is left as the
  directory returns it.
- **A user right assigned to nobody was reported as held by the next line of the file.**
  `GptTmpl.inf` writes rights out even when no principal holds them -
  `SeCreateTokenPrivilege =` with nothing after the `=` - and every default Domain
  Controllers Policy is full of them. The parser matched the `=` with `\s*`, which also
  matches a line break, so the capture ran on and took the whole following line as the
  principal list:

  ```
  [!] userRight:   SeCreateTokenPrivilege
      principals:  SeDebugPrivilege = *S-1-5-32-544
  ```

  Three dangerous rights were raised that way against values that are lines of the file,
  on every domain controller policy scanned. `Get-AddComputerRights` read
  `SeMachineAccountPrivilege` with the same construct and had the same defect.

  Both now match only horizontal whitespace around the `=` and stop the value at the line.
  A right assigned to nobody keeps no principal, so `Get-GPOUserRightsAssignment` raises
  no finding for it - a right nobody holds is not a dangerous assignment - while
  `Get-AddComputerRights` still lists the GPO, with an empty account list, because setting
  the right to nobody is a configuration worth seeing.
- **The BloodHound collector named its archive without saying where it put it.** The
  completion line printed `Split-Path -Leaf` of the output path - the file name alone -
  while the scan summary reports the text, HTML and JSON files with their full paths. With
  `-Outputfile` the archive is written beside the reports rather than into the current
  directory, so the one line that named it was the one that did not say where to look. It
  now prints the full path like the others.

  The path is also resolved once, up front, so the archive is written and reported under
  the same name: .NET file APIs resolve a relative path against the process working
  directory, which is not necessarily PowerShell's current location, so a relative
  `-OutputPath` could have placed the archive somewhere other than where the caller was
  standing.
- **Every GPO was reported as "NOT LINKED", and linking a GPO would have destroyed the
  existing links on the target.** `Invoke-LDAPSearch` rewrote `gPLink` for readability
  before any caller saw it:

  ```
  stored      [LDAP://cn={31B2F340-...},cn=policies,cn=system,DC=contoso,DC=com;0]
  delivered   GPO {31B2F340-016D-11D2-945F-00C04FB984F9} [Enabled]
  ```

  That drops the GPO's distinguished name and the link option digit, and turns one string
  into an array. Nothing displays `gPLink` - it is in no attribute list of any report - so
  the readability reached no one, while three callers that need the attribute itself were
  parsing a rendering of it:

  - `Get-GPOLinkage` reads `[LDAP://<dn>;<options>]` per entry. While it searched for a
    bare `{GUID}` the mismatch stayed hidden, because the rendering still contains one -
    but the options always read as 0, which is why every link was reported Enabled and
    never enforced. Once that pattern was corrected to require the real form, it matched
    nothing at all and every GPO came out "NOT LINKED": the Default Domain Policy and
    Default Domain Controllers Policy included, which are linked in every domain there is.
  - `Invoke-adPEASCollector` parses the same form, so BloodHound received no GPO link
    edges.
  - `Set-DomainGPO -LinkTo` prepends its new entry to the current value and writes the
    result back with a Replace modification. Handed the rendering, it would have replaced
    every existing link on the target OU with unparseable text.

  `gPLink` is now passed through unchanged. Rendering belongs where something is displayed,
  not in the layer that reads the directory.
- **Dates were read and written through the host's calendar, which broke Kerberos outright
  on some regional formats.** A custom date format string (`'yyyy-MM-dd'`,
  `'yyyyMMddHHmmss'`) is rendered with the current culture's calendar, and `ParseExact`
  with a `$null` provider reads with it. Windows ships cultures whose default calendar is
  not Gregorian, and there the same instant is a different year:

  | | en-US / de-DE | th-TH | ar-SA | fa-IR |
  |---|---|---|---|---|
  | written | 2026-03-09 | 2569-03-09 | 1447-09-20 | 1404-12-18 |
  | read back | 2026-03-09 | 1483-03-09 | throws | throws |

  The severe case was the Kerberos stack. `New-ASN1GeneralizedTime` produces the
  KerberosTime that goes on the wire, including the PA-ENC-TS-ENC `patimestamp` and the
  Authenticator `ctime` - the two fields a KDC checks against its own clock. On such a
  host adPEAS sent `25690309140500Z`, which reads as 543 years of clock skew:
  pre-authentication failed, and `-NTHash`, `-AES256Key` and `-Certificate`, which have no
  fallback, failed outright. The matching read path turned a KDC's Gregorian reply into
  the year 1483, or threw. Also affected: the DC clock-skew figure, Windows end-of-life
  dates behind the outdated-computer check, password ages behind the scoring, certificate
  validity, and every date in the HTML and text reports; and a scheduled task deployed via
  `Set-DomainGPO` got a `StartBoundary` 543 years out.

  Dates now go through a new `Format-adPEASDate`, and the places a machine reads spell the
  invariant culture out inline. `.claude/Test-Project.ps1` fails the build on a new
  culture-dependent date site, which is how the second ASN.1 encoder and four further
  sites were found after the first sweep had already been made.
- **Both offline report commands announced a report they had not written.** In
  `Convert-adPEASReport`, the "HTML report saved to: ..." line is printed a second time at
  the very end with `-Format All`, so it does not scroll away behind the text replay. That
  repeat was guarded on the output path having been *computed*, not on the export having
  *succeeded* - and the path is assigned before the attempt. A failed HTML export therefore
  produced a warning followed by a success line naming a file that does not exist. It is
  now gated on the export.
  `Compare-adPEASReport` had the same outcome by a different route:
  `Export-DiffHtmlReport` warned and returned when the diff template could not be loaded
  instead of throwing, so the caller's `try/catch` never fired and the success line right
  after the call ran anyway. It now throws, the way `Export-HTMLReport` reports the same
  condition.
- **A report that could not be built destroyed the report from the previous run.** When
  `Get-HTMLTemplate` returned nothing, `Export-HTMLReport` called `Write-Error` and
  returned. `return` leaves `process{}` but `end{}` still runs, and `WriteAllText` with a
  null string truncates the file to zero bytes - so the output path was left holding an
  empty document where an earlier report may have been. `Write-Error` is non-terminating
  as well, so neither caller's `try/catch` fired: `adPEAS.ps1` went on to log "HTML report
  generated" and kept the path in its summary. It now throws, which is what both callers
  already expect and what `end{}` itself does when the write fails.
- **`Invoke-PasswordSpray -Auto`'s lockout protection never ran, and the console said the
  domain had no lockout policy while spraying every enabled account.** Auto mode's whole
  purpose is to read the lockout threshold, check each account's `badPwdCount` and leave
  out the accounts that are one failed attempt away from being locked. It read the policy
  through `Get-DomainPasswordPolicy`, which is a check module: it hands its policy object
  to `Show-Object` and returns nothing to a caller. The threshold was therefore always
  `$null` -> 0, the `badPwdCount` filter was skipped entirely, and the run continued into
  the "no lockout policy configured" branch - a message that reads like a property of the
  domain rather than a failed read. Verified by driving the check with a policy of
  threshold 5 and watching `$null` come back. The policy is now read off the domain
  object directly (which also stops a whole report section, fine-grained policy scan
  included, from being rendered into the middle of the spray output), the intervals go
  through `ConvertFrom-ADInterval`, and the two cases are now told apart: a domain that
  really has no lockout policy is sprayed in full and said so, while a policy that cannot
  be read **aborts the run** - the new `-Force` switch is the deliberate override.
- **Every early exit in `Invoke-PasswordSpray`'s `begin` block failed to stop the run.**
  `return` inside `begin{}` ends the block, not the function: `process{}` and `end{}` run
  on regardless. All eleven abort paths - no password given, both `-Password` and
  `-PasswordList`, no LDAP connection, no users found, no safe users left, and now the
  unreadable lockout policy - therefore fell through to the summary in `end{}`, which
  computes `($endTime - $startTime)` on a `$startTime` that was never assigned. The
  caller got its real error followed by an unrelated `op_Subtraction` one. The aborts now
  set a flag that `process{}` and `end{}` honour.

- **An ACE granting full control via the SDDL generic bit (`GA`, `0x10000000`) - the
  form `Invoke-RBCDOperation` itself writes, and the shape any real full-control grant
  in a DACL actually takes - was invisible to `Get-OUPermissions.ps1` (used by
  `Get-LAPSPermissions`, `Get-PasswordResetRights`, `Get-DangerousOUPermissions`) and to
  `Get-PrivilegedGroupMembers`'s AdminSDHolder check.** Both tested the raw
  `$ACE.ActiveDirectoryRights` with `-band [ActiveDirectoryRights]::X`, but the
  directory maps a generic bit (`GA`/`GR`/`GW`/`GX`) to its object-specific mask only at
  access-check time (MS-ADTS 5.1.3.2) - a stored ACE keeps the bit exactly as written,
  and `[ActiveDirectoryRights]::GenericAll` itself already **is** the mapped `0xF01FF`,
  not the raw `0x10000000` bit. A `-band` test against a GA-only ACE therefore failed
  every right it was asked about, not just `GenericAll` - the ACE was completely
  invisible to the check, not merely misclassified. `Get-DangerousACLs`,
  `Get-GPOPermissions` and `Get-AddComputerRights` were already unaffected: all three go
  through `Get-ObjectACL`, whose `.Rights`/`.RightsRaw` (and its own `-DangerousOnly`/
  `-Rights` filters) already apply this mapping via `ConvertTo-ADRightsList`. Fixed with
  two new central functions in `adPEAS-GUIDs.ps1` - `ConvertTo-ExpandedADRightsValue`
  (the generic-bit mapping, extracted out of `ConvertTo-ADRightsList` rather than
  duplicated) and `Test-ADRightsMask -Rights -Has` (the predicate every raw
  `$ACE.ActiveDirectoryRights` test now goes through) - so every consumer shares one
  mapping instead of re-implementing it. Verified end to end with real SDDL descriptors:
  a `(A;;GA;;;<sid>)` ACE now produces the identical set of findings as the equivalent
  `0xf01ff` hex mask in both affected modules.
- **`Compare-adPEASReport` (scan-diff / `-Baseline`/`-Current`) silently dropped findings
  when two of them shared the same identity key, keeping only the last one.** The two
  scans were matched through a single hashtable keyed by `Get-FindingIdentity`
  (`identity -> finding`), so a second finding under an already-used key overwrote the
  first with no warning - and that key is not guaranteed unique by design: an Object
  finding adPEAS could not identify at all falls back to the literal key `unknown`
  (shared by every such finding from the same check), and the `Line` finding
  number-normalisation (`"Found 5 accounts"`/`"Found 3 accounts"` -> the same identity,
  intentionally) could not tell a count from a digit inside an account name, so
  `Credential found for User 'svc01'` and `'svc02'` collided too. Redesigned rather than
  patched, since neither cause could be fixed by tightening the key alone: the
  `Line` normalisation now leaves digits inside a quoted span untouched (that is where
  adPEAS puts account/computer names), and the diff itself no longer assumes a key is
  unique - the new `Get-FindingSetDiff` buckets findings by identity instead of mapping
  to a single slot, matches identical findings within a bucket first regardless of scan
  order, then pairs whatever is left as changed, and only reports a real add/remove when
  a bucket's size actually differs between scans. Nothing is silently dropped any more,
  and `Added`/`Removed`/`Changed`/`UnchangedCount` now sum to exactly the number of
  findings compared on each side - previously they counted distinct identities, which
  under a collision was less than the actual finding count with no indication why.
- **`Get-ObjectTypeTitle` silently corrupted a report card's title whenever the
  underlying AD object's name contained a `$`.** The `{Name}`/`{Context}`/
  `{DisplayName}`/`{CAName}`/`{DN}` placeholder substitutions used PowerShell's
  `-replace` with the untrusted AD name as the *replacement* argument -
  `-replace`'s replacement text is a regex replacement pattern, not a literal string,
  so `$1` in a name is read as a backreference (resolving to nothing, and swallowing
  whatever followed it) and `$$` collapses to a single `$`. An ordinary AD computer
  account's trailing `$` was already safe (not a valid backreference shape), which is
  presumably why this went unnoticed, but any other `$`-containing name was not. This
  is `Export-HTMLReport.ps1`'s only source for a finding's card title, so the
  corruption reaches an actual report. Fixed with literal `.Replace()` - the exact
  treatment the function's own generic `{propertyName}` fallback loop, a few lines
  below, already uses for this same reason (with a comment naming it); the fix here
  is extending that same treatment to the five named placeholders above it, which had
  been missed.
- **`Get-CurrentUserTokenGroups` returned an empty list, every time, for any user whose
  `tokenGroups` held exactly one SID** (a lone-group account, or one in only its
  primary group) **- the gate `Get-LAPSCredentialAccess`'s optimized Windows LAPS path
  uses to decide whether the current user can locally decrypt a given computer's
  password.** `byte[]` is itself an array, so `$tokenGroupsAttr -is [array]` - meant to
  distinguish "one SID" from "several" - was `$true` either way; a lone SID's raw bytes
  fell into the "already a list" branch and were iterated byte by byte, none of which
  passed the inner `-is [byte[]]` check, so the account's only group membership was
  silently dropped. Fixed with `-is [byte[]]`, the check that actually distinguishes
  the two shapes. Two related defects surfaced fixing this:
  - The same function's four return statements had the `Object[]`-vs-`byte[]` defect
    documented below for the PAC module, in the shape it takes for a list of *strings*
    rather than bytes: a bare `return` of an *empty* SID list collapses to `$null`
    (not empty), and of a list with *exactly one* SID collapses to that bare string
    (not a one-item array) - "`return $lines` vs. `return ,$lines`", an already-named
    recurring pattern in this codebase's test notes. Fixed with a leading comma on all
    four.
  - This function's own call to `Invoke-LDAPSearch` is, uniquely among every call site
    in this codebase, a plain assignment rather than the `@(Invoke-LDAPSearch ...)`
    wrapping every other caller uses. A Base-scope self-lookup (what this function
    queries) always returns exactly one result, which `Invoke-LDAPSearch`'s own bare
    `return $OutputObjects` unrolls to that bare entry rather than a one-item array; a
    bare `PSCustomObject` has no synthetic `.Count`, so this function's own connection
    guard silently always read `$null -gt 0` as false and never got past it. **Fixed by
    adding the same `@(Invoke-LDAPSearch ...)` wrapping every other call site already
    uses - not by touching `Invoke-LDAPSearch` itself.** That was tried first and
    reverted: every one of `Invoke-LDAPSearch`'s ~40 other call sites relies on its
    return staying bare specifically *because* they wrap the call in `@(...)`, and `@()`
    around a call that emits its whole result as a single (comma-forced) pipeline
    object wraps that single object as the sole element of a *new* array instead of
    collecting its actual entries - `@(Invoke-LDAPSearch ...)[0]` would silently become
    the entire result set rather than the first row. `Invoke-LDAPSearch`'s bare return
    is therefore deliberate, not an instance of the wider defect below - see
    `LDAPSearchReturnContract.Tests.ps1` for the full account, including the general
    rule this leaves for future changes to any function fixed elsewhere in this pass:
    before comma-forcing a return, check whether any real caller wraps the *call site*
    in `@(...)` - if one does, it depends on the unroll, and the fix belongs at the
    caller instead.
- **`New-DiamondTicket`'s encryption-type mismatch error named the wrong (generic)
  cipher label.** `$etypeNames.ContainsKey($ticketEType)` was always `$false`:
  `$ticketEType` comes from `Read-ASN1Integer`, which returns `[int64]`, and
  `Hashtable.ContainsKey([int64]18)` never matches `[int32]`-keyed entries even for
  the same numeric value - a non-generic `Hashtable` compares by CLR type, not just
  value. An operator handed the wrong krbtgt key got "you need the krbtgt etype 18
  key" instead of "...the krbtgt AES256-CTS key". Purely cosmetic - the actual
  mismatch *detection* a few lines below (`-ne`, which does coerce numeric types) was
  already correct - but the entire point of the message is telling the operator which
  key to go get. The identical defect was already fixed at its other two occurrences
  in this codebase (`Invoke-Kerberoast.ps1`, both carrying a comment naming this exact
  cause); only this third occurrence had been missed. Fixed with the same `[int]` cast
  used at the other two sites.
- **The same `Object[]`-instead-of-`byte[]` return defect documented below for the PAC
  module (Golden/Silver/Diamond Ticket) also runs through the entire rest of the
  Kerberos stack: the ASN.1 DER encoder every AS-REQ/TGS-REQ/KRB-CRED byte stream is
  built from (`Kerberos-ASN1.ps1`), the crypto primitives that produce every
  NT-Hash/derived key/RC4-HMAC and AES-CTS ciphertext (`Kerberos-Crypto.ps1`), PKINIT's
  DH nonce/SHA-1/SHA-256/CMS-signature helpers, and one call site each in
  AS-REP-Roasting, Kerberoasting, ticket forging, and the main Kerberos auth flow.**
  Sweeping for the exact `return [byte[]](...)` shape already fixed in the PAC module
  found it in another 30 places across `Kerberos-ASN1.ps1` alone; chasing why a bare
  `return $variable` relay of an *already-correctly-typed* value still broke (it does -
  even a `[byte[]]`-typed parameter, a `New-Object byte[]`, or a `List[byte].ToArray()`
  unrolls to `Object[]` on a bare return, not just a fresh literal) turned up 9 more
  there, then the same pattern throughout `Kerberos-Crypto.ps1`, `Invoke-PKINITAuth-
  Native.ps1`, `Request-ADCSCertificate.ps1`, and one relay each in
  `Invoke-ASREPRoast.ps1`, `Invoke-Kerberoast.ps1`, `Invoke-TicketForge.ps1`, and
  `Invoke-KerberosAuth.ps1`. A further sweep for `return $variable[range]` - array
  slicing produces `Object[]` independent of the source array's element type, so it
  needed the leading comma *and* an explicit `[byte[]]` cast, unlike a plain variable
  relay - found 6 more in `Kerberos-Crypto.ps1` alone, including both ticket-decryption
  confounder-stripping functions (RC4-HMAC and AES-CTS) that every parsed AS-REP/TGS-REP
  goes through. A `return $a + $b` sweep found the mirror image: `Encrypt-RC4HMAC` and
  `Encrypt-AESCTS` - the functions that build every encrypted PA-DATA blob adPEAS
  actually sends to a KDC - had the same defect from the opposite direction, a fresh `+`
  concatenation returned bare. In total, about 70 return statements across 9 files.
  Confirmed via a live loopback UDP/TCP round-trip that this is inert for the one traced
  live-network path (`Invoke-ASREPRoast`'s raw `NetworkStream.Write`/`UdpClient.Send`
  calls both tolerate an `Object[]` argument through PowerShell's own
  single-applicable-overload coercion) - same latent-not-live risk as the PAC module: it
  only bites the first caller that hands a result to an overload-ambiguous .NET method
  instead of a typed parameter or an explicit cast. Fixed the same way throughout: a
  leading comma on every affected return, with an explicit `[byte[]]` cast added
  wherever the value is `Object[]` independent of the return statement itself (a fresh
  array literal, a `+` concatenation, or a range slice).
- **`New-ASN1Integer` threw `InvalidCastException` for any negative value** - its numeric
  encoding path unconditionally cast to `[uint64]` before checking the sign, and
  `[uint64](-138)` throws rather than wrapping. This is not a theoretical input:
  `Request-ServiceTicket.ps1`'s S4U2Self checksum construction calls
  `New-ASN1Integer -Value ([int32]-138)` (the well-known HMAC-MD5 checksum type KDCs use
  for S4U2Self), so every constrained-delegation/RBCD abuse path that reaches an
  S4U2Self request crashed before a single byte reached the wire. Fixed by routing
  negative values through `BigInteger`, which already returns the minimal
  two's-complement byte representation DER requires (verified against `-1`, `-127`,
  `-128`/`-129` at the one/two-byte boundary, `-138`, `-1000`, and a value outside
  `Int32`'s range).
- **`Get-NTHashFromPassword` explicitly supports a blank password
  (`[AllowEmptyString()]` on `-PlainPassword`, for `PASSWD_NOTREQD` accounts) but handed
  the resulting empty byte array to `Get-MD4Hash`, whose `-Data` parameter was
  `Mandatory` without `[AllowEmptyCollection()]` and rejected it outright.** Every
  NT-Hash computation for a blank-password account threw before any Kerberos code ran.
  Fixed by adding `[AllowEmptyCollection()]`; MD4's own padding already handles a
  zero-length message correctly (confirmed against the RFC 1320 empty-string vector).
- **Every structure builder in the PAC (Golden/Silver/Diamond Ticket) module returned
  `Object[]` where it documented, and its callers assumed, `byte[]`.** A bare
  `return [byte[]]$array` - even with the explicit cast right there - still hands the
  caller `Object[]`: PowerShell unrolls a fresh array element-by-element through the
  function's output stream and re-collects the pieces generically on the other side. All
  21 structure-building functions in `Kerberos-PAC.ps1` had this, including
  `ConvertTo-FlatByteArray`, whose own docstring states solving exactly this problem as
  its reason to exist ("PowerShell's += operator on arrays creates Object[] instead of
  byte[]. This function properly flattens ... into a single byte[]") - it wasn't, for any
  caller across a function boundary.
  Confirmed inert for every current caller: `Build-PAC` already defensively re-casts
  every builder call with `[byte[]](...)` (with a comment naming this exact problem), and
  everything one level up the call chain - `Complete-PACSignatures -PACData`,
  `Read-KerbValidationInfo -Data`, `New-EncTicketPart -PACData` - declares a
  `[byte[]]`-typed parameter, which PowerShell's parameter binder coerces correctly
  regardless of what it receives. The risk was latent, not live: it only bites a caller
  that passes the result straight into a .NET method with more than one applicable
  overload rather than into a typed PowerShell parameter or an explicit cast -
  `System.IO.BinaryWriter.Write` is exactly that shape, and is exactly what broke this
  session's own test fixture for a different file (`NTLM-HTTP.ps1`) two fixes ago. Fixed
  with a leading comma on each return statement, which stops the unrolling; three
  functions needed an explicit `[byte[]]` cast alongside the comma as well, because the
  value at the return statement was itself built fresh there (an array literal, or a `+`
  concatenation of two `byte[]` arrays - which independently produces `Object[]` before
  the return statement is even reached).
- **`LDAP_NO_SUCH_OBJECT` (error 32) was classified as an error by
  `ConvertFrom-LDAPError`/`Get-ExceptionErrorInfo`, but as the expected, non-error case by
  `ConvertFrom-HResult`'s equivalent entry (`0x80072030`) for the identical condition** -
  the two tables disagreed about the same LDAP result code. Confirmed to be inert today:
  the search path that matters (`Invoke-LDAPSearch`, "the SearchBase does not exist")
  decides this independently through `Test-LDAPErrorNotFound`'s own HResult check, and
  `Connect-LDAP.ps1`'s bind-time category switch maps both the old and the corrected
  category to the same outcome. Aligned so a future caller of the plain-integer path gets
  the same answer the HResult path already gives.
- **A zero-length AV_PAIR in an NTLM Type2 (Challenge) message was decoded as one bogus
  character instead of an empty string.** `Read-NTLMAvPairs`, part of the EPA/NTLM-relay
  detection stack, sliced a value with `$offset..($offset + $avLen - 1)`. For `$avLen`
  of `0` PowerShell reads that as the two-element descending range
  `@($offset, $offset - 1)`, not an empty one, so an empty `NbDomainName` or similar
  pulled in one stray byte from each side of the intended (empty) slice; at offset `0`
  the trailing `-1` means "last element of the array" in PowerShell, so the corruption
  could reach into unrelated bytes at the far end of the buffer. Guarded on
  `$avLen -gt 0` now. The empty-array branch of that guard needed a leading comma of its
  own: an `if`/`else` assignment routes each branch's output through the normal success
  stream, and an empty array written there unrolls to zero objects, so
  `else { [byte[]]@() }` assigned `$null` rather than an empty array and broke every
  string decode downstream on exactly the input the guard was meant to make safe.
  `Read-NTLMAvPairs`, `Read-NTLMType2Message` and `New-NTLMType3Message` also rejected
  `$null`/empty input at their parameter binders ahead of the guards their own bodies
  already had for it - `AllowEmptyCollection`/`AllowEmptyString`/`AllowNull` added so a
  computer's own explicit handling of that input is reachable.
- **`New-RandomEPAIdentifier`'s suffix characters were not drawn uniformly.** Same
  modulo-bias defect as `New-SafePassword` earlier in this list, for the same reason (256
  is not a multiple of the 36-character alphabet) - not a secret, so the bias itself risks
  nothing, but it would have been inconsistent to fix it in one file and leave the
  identical pattern in the next.
- **PKINIT certificate authentication found the wrong identity, or none at all, on
  German-locale Windows.** `Connect-adPEAS -Certificate` and `Get-CertificateInfo` both
  read which UPNs and DNS names a certificate's Subject Alternative Name carries from
  `X509Extension.Format($false)` and a regex over the English labels
  (`"Principal Name=..."`, `"DNS Name=..."`). `Format()` renders through the OS's
  installed crypt32 language resources, not through .NET's thread culture - confirmed by
  overriding `CurrentUICulture` and observing no change in the output - so on de-DE
  Windows it produces `"Prinzipalname="` and `"DNS-Name="` (the DNS label differs too,
  by more than word order). Neither regex ever matched. A certificate whose only SAN
  entry was a UPN reported zero identities: `Connect-adPEAS` fell back to authenticating
  as the CN, silently using the wrong principal, or failed outright if the CN did not
  resolve to an account, and `Get-CertificateInfo` printed no usage hint at all. Fixed
  by decoding the extension's raw DER bytes instead of its formatted text -
  `ConvertFrom-SubjectAlternativeName` (new, in `Kerberos-ASN1.ps1`, reusing the
  existing generic ASN.1 primitives) - which reads identically regardless of the host's
  language, since a DER `GeneralName` is a `CHOICE` keyed by a context tag, not by
  whatever label a formatter chooses to print. The otherName UPN case is filtered by its
  own type-id OID (`1.3.6.1.4.1.311.20.2.3`) rather than assumed, since a certificate can
  carry other otherName types.
  Two further defects in `Get-CertificateInfo` came out of the same investigation.
  A PKINIT-capable certificate with no SAN extension at all never reached its own CN
  fallback - it was nested one level too deep, inside the `if ($sanExt)` block it needed
  to run without. And a V2-only certificate template's OID was extracted from a
  `"Template=([0-9.]+)"` regex over the same kind of locale-dependent `Format($false)`
  string (`"Vorlage="` on de-DE), so `TemplateName` stayed empty for every V2-only
  template on a German-locale host; it is now read from the extension's own DER bytes
  (`CertificateTemplateInformation`'s first field is simply the template OID).
- **An ECDSA certificate's key size was reported as blank.** `X509Certificate2.PublicKey.Key`
  only ever resolves an RSA key on .NET Framework; for ECDSA it returns `$null` rather
  than throwing, so the surrounding `try`/`catch` never caught it and
  `Get-CertificateInfo` printed `"ECC ( bit)"`. Fixed by reading the key through
  `ECDsaCertificateExtensions.GetECDsaPublicKey()`, the API meant for this, alongside the
  existing RSA path.
- **A GPP `Registry.xml` with no byte order mark was decoded wrongly on Windows
  PowerShell 5.1.** `Parse-RegistryXml` read the file with `Get-Content` and no
  `-Encoding`, which falls back to the ANSI code page on 5.1 - the runtime adPEAS ships
  for - and to UTF-8 on PowerShell 7. A deployed path such as `C:\Geraete\setup.exe` with
  an umlaut came back with the umlaut split into two characters, so the value reported was
  not the value deployed. The file is loaded through `XmlDocument` now, which honours the
  encoding declared in the XML prolog on both hosts. Its `XmlResolver` is cleared as well,
  which changes nothing measurable - .NET already refused external entities and did not
  fetch external DTDs on either host - but states the intent for a file that comes off
  SYSVOL.
- **`REG_MULTI_SZ` from a `Registry.pol` was reported as one string with null characters
  in it.** Only the trailing nulls were trimmed, not the separators between the entries,
  so a server list reached the console and the report as `srv01<NUL>srv02<NUL>srv03`. The
  entries are joined with `, ` now. In the same parser, `REG_DWORD_BIG_ENDIAN` was read in
  the machine's byte order, turning a stored `1` into `16777216`.
- **A ticket or certificate file whose name contains square brackets could not be read.**
  `ConvertFrom-Base64OrFile` tested for the file with `Test-Path -Path`, which reads
  brackets as a wildcard character class, so `admin[1].kirbi` did not match itself and a
  valid ticket was reported as "neither a valid Base64 string nor an existing file path".
  The `Resolve-Path` one line further down already used `-LiteralPath`. Windows PowerShell
  5.1 also printed a raw "illegal character in path" error next to the returned result
  whenever the input held a character no path may contain; that is suppressed now, since
  the function answers through its result object.
- **`Export-adPEASFile` wrote text with a BOM on Windows PowerShell 5.1 and without one on
  PowerShell 7.** `Out-File -Encoding UTF8` means different things on the two hosts.
  `Request-ADCSCertificate` writes a JSON key file through that branch, and a BOM in front
  of a JSON document breaks a strict parser. Text now goes through
  `[IO.File]::WriteAllText` like the JSON branch, so both write UTF-8 without a BOM on
  either host. The directory and overwrite checks were switched to `-LiteralPath` for the
  same reason as above, and a filename that the sanitizer empties out entirely - `(temp)`,
  say - is now refused with that reason instead of silently targeting the parent
  directory.
- **`Search-Value` read square brackets in the search pattern as a wildcard character
  class.** Searching for `[Backup]` matched every value containing any one of `B`, `a`,
  `c`, `k`, `u` or `p` - nearly every object in a domain - with nothing in the output to
  say why, and an unbalanced bracket such as `svc[1` threw a `WildcardPatternException`
  once per property per object. Brackets are escaped now and mean themselves; `*` and `?`
  keep working, which is what "wildcard search" in the help refers to. `-Exact` and
  `-Regex` together, which used to let `-Exact` win silently, is now refused.
- **`Test-AccountActivity -IncludeDetails` dropped every object on a second pass.**
  `Add-Member` refuses to overwrite an existing member, so annotating the same object
  twice - chaining two calls, or handing the same objects to another check - wrote an
  error and emitted nothing at all, because `-PassThru` never ran. The annotation is
  written with `-Force` now, so a second pass refreshes it. The help for
  `-PasswordAgeDays` also claimed the threshold was exclusive while the code has always
  included a password exactly N days old.
- **One LAPS password in 256 lost its update timestamp.** Whether an
  `msLAPS-EncryptedPassword` blob carries the 16-byte header was decided by testing the
  first byte for `0x30`, the ASN.1 SEQUENCE tag. With a header present that byte is the
  low byte of the upper FILETIME DWORD, which advances roughly every seven minutes and is
  therefore effectively random - so one password update time in 256 was read as a
  headerless CMS blob. Those hosts reported no update time at all, and the CMS metadata
  scan ran across the header bytes as well. The header is now recognised by its own
  contents: a plausible FILETIME, or a size field that fits what follows it.
  `ConvertFrom-LAPSEncryptedPassword` also threw on an empty attribute value instead of
  returning `$null`, ahead of its own guard for exactly that case.
- **`New-SafePassword` did not draw uniformly from its alphabet.** A random byte was
  mapped with a plain modulo, and 256 is not a multiple of the alphabet size (81 with
  special characters, 62 without), so the first characters of the set came up about a
  quarter more often than the rest - measured over 200,000 draws. Replaced with rejection
  sampling. The documented character set also omitted `~`, which the generator has always
  used.
- **An ACE carrying a generic access right was displayed with an empty rights field.**
  An ACE may hold GENERIC_ALL (`0x10000000`), GENERIC_READ, GENERIC_WRITE or
  GENERIC_EXECUTE instead of the specific mask; the directory maps them at access-check
  time (MS-ADTS 5.1.3.2). None of those bits matches any member of the
  `ActiveDirectoryRights` enum - whose `GenericAll` is already the mapped `0x000F01FF` -
  so the decomposition produced no names and `-ShowACE` printed nothing at all in the
  Rights column. A resource-based constrained delegation descriptor is written exactly
  that way (`O:BAD:(A;;GA;;;<sid>)`), including by adPEAS's own `Invoke-RBCDOperation`,
  so the most permissive ACE there is came out blank. The mask is now mapped first.
- **A resolved extended right was glued onto the right beside it.** Replacing the generic
  `ExtendedRight` label filtered the list with `Where-Object` and appended with `+=`.
  When exactly one other right survived the filter, the result collapsed to a string and
  `+=` concatenated: an ACE with ReadProperty and ExtendedRight rendered as
  `ReadPropertyDS-Replication-Get-Changes`.
  Both defects existed in two copies, in `Get-ObjectACL` and in `ConvertTo-FormattedACE`.
  The decomposition now lives once, in `ConvertTo-ADRightsList`.
- **`ConvertTo-AccessRules` threw on an empty attribute value** instead of returning
  `$null`: an empty array unwraps to `$null`, and the line reporting the unexpected type
  called `GetType()` on it. It also answered `$null` for a valid descriptor that arrived
  as `Object[]` rather than `byte[]`, which is what a plain `return` of a byte array
  produces.
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
