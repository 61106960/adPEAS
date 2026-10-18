# Changelog

All notable changes to adPEAS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

---

## [Unreleased]

### Added

- **`Get-GPOScheduledTasks` reads who may write the UNC path a task running as SYSTEM or
  as a privileged account starts from.** **This is a new outgoing connection: adPEAS now
  connects over SMB, with the session's credentials, to the file servers such tasks
  name** - only to enabled computers of the domain, by the DNS name the directory records
  for them, or to the domain's own name. Addresses and hosts the domain does not know are
  never contacted, and `-OPSEC` (on the check and on `Invoke-adPEAS`) suppresses the
  connection entirely. An account beyond the expected administrators that can write the
  file or its folder makes the task a finding and is listed in the new
  `UNCPathPermissions` row; a path only privileged accounts can write is reported as a
  hint for a SYSTEM task and stays a finding for a privileged account. The share
  permissions are not read - Windows returns them to administrators of the file server
  only.

- **GPO findings say whether the policy reaches a domain controller.** A new
  `reachesDomainControllers` row beside `LinkedOUs` in the seven GPO checks names the
  link that puts a domain controller in the policy's scope - the Domain Controllers OU,
  an OU above a domain controller, the domain root or the domain controller's site - or
  says why none does. Domain controllers are found where their computer objects are, and
  a container that blocks inheritance stops every link above it that is not enforced.
  The row speaks of links and security filtering only; a WMI filter the policy names is
  shown in a row of its own. It is information and changes no severity.

- **Credentials found in SYSVOL say what their account is in the directory.** A new
  `accountInAD` row on every GPP password, AutoAdminLogon and `net use` credential says
  whether a domain account of that name exists, whether it is enabled, whether it is
  privileged and through which group, and whether its password was changed after the file
  was last written - which separates a password that may still work from one that is
  probably outdated. Names whose domain account is not the account they mean are named as
  what they are instead of being looked up: variables such as `%USERNAME%`, local and
  built-in accounts, names qualified with another domain or a computer, and every account
  in a `Groups.xml`, which sets local accounts on the computers. Without a directory
  session - a custom path scanned without `Connect-adPEAS` - the row is left out. It is
  information and changes no severity.

- **`Get-BitLockerRecoveryKeyAccess` says who else may read the recovery passwords.** The
  check answered for the account running the scan only, so a scan as an ordinary user
  ended with "No readable BitLocker recovery keys found" whatever a helpdesk group could
  read. A second section, *Delegated BitLocker Recovery Read*, now lists every principal
  holding a delegated read of `msFVE-RecoveryPassword` on the containers that hold
  computers - disabled ones included, since a recovery password stays valid for its disk -
  with the number of computers it reaches. The schema ships the attribute confidential and
  grants the recovery objects to Domain Admins and SYSTEM only, so a read takes
  `ReadProperty` and `ControlAccess` on the same objects; the two halves are combined per
  container, and the row says whether the read works today, is blocked by the confidential
  flag (a hint: live the moment the flag is cleared), or cannot be decided because the
  schema could not be read. Privileged principals are hidden unless `-IncludePrivileged`,
  which the check now takes and `Invoke-adPEAS` passes on. `Get-OUPermissions` has a new
  check type `BitLocker` for it; `Get-DangerousOUPermissions` leaves those rights to this
  check, as it does for LAPS and Credential Roaming.

- **`Get-ADCSVulnerabilities` judges the NTAuth store instead of only listing it.** Every
  issuer in `CN=NTAuthCertificates` may issue a certificate that logs on as any account.
  Each entry now carries an `EnterpriseCA` row - the Enterprise CA of this forest that
  holds the certificate, an earlier certificate of one that was renewed since, or none,
  which an Enterprise CA never leaves behind on its own: a third-party smart card CA, a
  standalone CA, or a removed one whose key may still exist. Such an entry, an expired
  one and one signed with SHA1 or MD5 is a hint, each kind is summed up in a line, and the
  section says when more than one CA is trusted. The Certificate Authorities are read
  once for this and the CA analysis; where they could not be read the row says Unknown.

- **`Get-PrivilegedGroupMembers` reads the DACL of the privileged groups AdminSDHolder does
  not protect.** It read the AdminSDHolder template, which SDProp writes onto the
  protected groups - and nothing read the groups SDProp leaves alone: DnsAdmins, Group
  Policy Creator Owners, Cert Publishers, the Exchange groups, and every group nested into
  a privileged group. A new section reports who may write their `member` attribute, use
  the Self-Membership validated write, change their DACL or owner, holds full control or
  owns them, with the same identity gate as the AdminSDHolder analysis. Which groups are
  unprotected is read from `adminCount`, not from a list - Microsoft counts Key Admins and
  Enterprise Key Admins among the protected groups. Account Operators control every
  unprotected group through the default security descriptor of the group class; that is
  said once, as a hint while Account Operators has members.

- **Who may write `msDS-KeyCredentialLink` is reported (Shadow Credentials).** No check
  asked it, although the card for a populated key credential said the ACL checks did.
  `Get-DangerousOUPermissions` now reports a delegated write of the attribute on an OU's
  users and computers; Key Admins and Enterprise Key Admins, which hold it by design for
  Windows Hello for Business, are rated as privileged and stay out of a default report.

- **AdminSDHolder is checked for the rights that take over the administrator accounts,
  and for its owner.** SDProp copies AdminSDHolder's descriptor onto every protected
  account as well as onto the protected groups, and the check asked only about full
  control and the member attribute. A write on `msDS-KeyCredentialLink`,
  `servicePrincipalName`, `altSecurityIdentities` or `userAccountControl`, the password
  reset right and "all extended rights" are now findings, each row saying what the right
  allows on every protected account, and a non-default owner of AdminSDHolder is named.
  The rows open a card of their own, which the member rows did not have. A trustee with
  several ACEs is reported once with all of its rights; the check used to keep the first
  ACE the descriptor returned, and the descriptor re-sorts them on load.

- **An account without Kerberos pre-authentication is said to make Kerberoasting possible
  without credentials.** Such an account lets anybody request service tickets in an
  AS-REQ, so with one of them every account with an SPN can be roasted by an attacker who
  holds no account at all. `Get-ASREPRoastableAccounts` names how many accounts that
  reaches, with a card of its own.

- **The Kerberos policy is read from the GPOs that set it.** `Get-DomainInformation` read
  the ticket lifetimes from the domain object, which does not carry them - so the row
  always said "Unknown" and the card for widened lifetimes could never appear. They now
  come from the `[Kerberos Policy]` section of the GPOs linked to the domain, per setting
  from the highest-ranked GPO that sets it, with the GPO named; the service ticket
  lifetime and the tolerated clock skew are shown beside them, a lifetime of 0 is said to
  never expire, and every widened value is named in the verdict.

- **Unconstrained delegation names the privileged accounts whose TGT those hosts
  receive.** A privileged user or managed service account that is neither marked
  "Account is sensitive and cannot be delegated" nor in Protected Users hands its TGT to
  a host with unconstrained delegation on every Kerberos logon to it.
  `Get-UnconstrainedDelegation` now lists those accounts after the hosts, as a finding
  with a card of its own, or says that every privileged account is protected - which
  still leaves a coerced domain controller's machine account, and the line says so.
  Protected Users counts from domain functional level Windows Server 2012 R2 on, the
  level at which it stops delegation.

- **Computer accounts with "Password Not Required" are reported.** `Get-PasswordNotRequired`
  asked for user accounts only. A computer account created ahead of its computer carries
  the flag until a computer joins the domain with it, and created as a "pre-Windows 2000
  computer" its password until then is the computer name in lowercase - a logon for
  anybody who can list the computer names. Enabled computer accounts with the flag that
  have never logged on are now a finding with a card of its own; one that has logged on
  is a hint.

- **New check `Get-ComputerPasswordAge`: active computers that do not rotate their machine
  account password.** A domain member and a Domain Controller change it every 30 days by
  default. An enabled computer that logged on within the last 30 days (`-ActiveDays`) but
  whose password is 90 days old or older (`-PasswordAgeDays`) has the change switched
  off - by policy, by a non-Windows join tool or as a clone - and its machine account key
  never ages out. Domain Controllers are a finding, since their key replicates the
  directory; other computers are a hint. It runs in the Computer module.

- **Computer accounts with the Domain Controller role that are not Domain Controllers are
  reported.** Whoever holds DS-Install-Replica on the domain object and may write a
  computer account's `userAccountControl` can set `SERVER_TRUST_ACCOUNT`, which moves the
  account's primary group to Domain Controllers and gives it their replication rights,
  without any server being promoted. `Get-InfrastructureServers` now also asks for
  computers whose primary group is Domain Controllers, compares every account with the
  role against the NTDS Settings objects in the configuration partition, and reports the
  ones without as a finding with a card of its own. Where the configuration partition
  cannot be read, it says so instead.

- **New check `Get-RODCPasswordReplication`: privileged passwords on read-only Domain
  Controllers.** For every enabled read-only Domain Controller it compares the allow list
  (`msDS-RevealOnDemandGroup`) and the deny list (`msDS-NeverRevealGroup`) with the token
  of every privileged account - recursive membership and the primary group, deny
  winning - and names the privileged accounts whose password the RODC may cache. It also
  names the privileged accounts whose secrets the RODC holds already
  (`msDS-RevealedUsers`), and a deny list that has lost the Denied RODC Password
  Replication Group. It runs in the Accounts module.

- **The Exchange Servers group is judged, and a role held through a group names its
  members.** `Get-ExchangeInfrastructure` read Exchange Servers only to find the servers;
  it now shows the group like the other Exchange service groups, so a member that is
  neither an Exchange server, a computer account, an Exchange group nor a privileged
  principal is a finding. Exchange Install Domain Servers, which setup puts into Exchange
  Servers from `CN=Microsoft Exchange System Objects`, counts as an Exchange group.
  `Get-ExchangeRBACAssignments` names the direct members of a group that holds one of the
  watched roles - for the role groups Exchange ships them on, such as Discovery
  Management with Mailbox Search, the membership is who actually holds the role.

- **SCCM-related groups name their members and report a broad group among them.**
  `Get-SCCMInfrastructure` counted the members of each group it finds by name and showed
  none of them. It now lists them - a foreign security principal by its resolved name -
  and asks once per group which of them is a broad group: Domain Users, Domain Computers,
  Authenticated Users or Everyone in such a group hands whatever SCCM access the group
  grants to every account they cover, a finding with a card of its own. What the group
  grants inside SCCM is not read; the site database records it, not Active Directory.

- **Passwords in registry values a GPO deploys are reported.** `Get-CredentialExposure`
  found the Winlogon password in a preference Registry.xml and nothing else a policy writes
  into the registry. It now reports every string value named like a password -
  `Password`, `ProxyPassword`, `ServiceAccountPassword`, `Pwd` - from Registry.xml and
  from the Administrative Template file Registry.pol, which no pass read for credentials,
  with hive, key, GPO and links and a card of its own. Numeric values such as
  `RequirePassword`, preference items switched off or deleting the value, and the
  Winlogon password, which keeps its own row, are left out.

- **New check `Get-CriticalObjectACLs`: control over the schema, the partitions container
  and the RID and infrastructure objects.** These four objects carry the schema, the
  naming contexts of the forest and two operations master roles, and no check read their
  ACLs. A principal outside Tier-0 - an operator group counts - that owns one of them,
  holds full control, write or DACL rights on it, holds the transfer right of the role it
  carries or all extended rights, or may write the RID pool of the RID Manager is a
  finding with a card of its own. It runs in the Rights module.

- **GPO links on sites and Block Inheritance on OUs are checked for who may set them.**
  `Get-CriticalObjectACLs` now also reads every site under `CN=Sites`: a principal outside
  Tier-0 that may write `gPLink` on a site can link a GPO that applies to every computer
  of the site, domain controllers included. The OU permission check reports a write on
  `gPOptions`, the other attribute the "Manage Group Policy links" delegation grants:
  whoever sets Block Inheritance on an OU switches off every non-enforced GPO linked
  above it, a security baseline at the domain included.

- **Explicit permissions on computer objects are reported.** `Get-NonDefaultComputerOwners`
  read the owner of every computer object and nothing else of its descriptor, so a
  write on `msDS-AllowedToActOnBehalfOfOtherIdentity` someone had put on a single
  computer - resource-based constrained delegation to it - went unreported, as did a
  shadow credential write, a password reset right or full control. It now lists, from the
  descriptors it already reads, every entry written on the object itself that gives a
  principal outside Tier-0 full control, a generic write, a write on every attribute or on
  the DACL, the right to take ownership, all extended rights (the LAPS password included),
  the password reset right, or a write on
  `msDS-AllowedToActOnBehalfOfOtherIdentity`, `msDS-KeyCredentialLink`,
  `servicePrincipalName` or `dNSHostName`. Inherited entries are left to the OU
  permission check, which reports them where the delegation is defined; the entries the
  computer class writes for its creator, the owner, SELF and the operators are not
  reported. `ConvertFrom-SecurityDescriptor` now carries `IsInherited`,
  `InheritedObjectType` and `PropagationFlags` on every ACE.

- **Who may take over a privileged account through its own DACL is reported.**
  `Get-PrivilegedGroupMembers` read the AdminSDHolder template and the DACL of the
  privileged groups it does not protect, but not the DACL of the privileged accounts: a
  password reset right on a DnsAdmins member, a key credential write on a managed service
  account in a privileged group or an OU delegation reaching an administrator whose
  account still inherits went unreported. A new step reads every privileged user and
  managed service account of the domain and reports, per principal and with the accounts
  it reaches, full control, a DACL or owner change, a write of every attribute, all
  extended rights, the password reset right, writes of `msDS-KeyCredentialLink`,
  `servicePrincipalName`, `altSecurityIdentities`, `userAccountControl`, `scriptPath` and
  `msDS-GroupMSAMembership`, and the owner - explicit and inherited entries, an inherited
  one marked as such. On an account AdminSDHolder protects, what the template grants is
  left to the AdminSDHolder step instead of being repeated per account. Account Operators,
  who control every unprotected account through the default security descriptor of the
  user class, are named once. New card `PRIVILEGED_ACCOUNT_ACL`.

- **`Get-GPOScriptPaths` reads who may write a script that runs from outside the policy
  store.** A script in NETLOGON, in SYSVOL outside a GPO folder or on a file share follows
  the NTFS permissions of that file, not the GPO's, and the check said only that they
  were not checked. It now reads them over SMB the way `Get-GPOScheduledTasks` reads the
  program of a task - from the domain's own name and enabled computers of the domain only,
  and not under the new `-OPSEC` switch, which `Invoke-adPEAS -OPSEC` passes on. A
  principal beyond the administrators that may write the script or its folder makes the
  script a finding in either context and is named in the new `scriptPathPermissions` row;
  a script in NETLOGON only administrators may change is a note, one on another server a
  hint, because that server's administrators decide what runs. A path that could not be
  read keeps its verdict and says why. The share permissions are not read.

- **New check `Get-LogonScriptPermissions`: logon scripts a principal beyond the
  administrators may change.** Windows runs the logon script an account's `scriptPath`
  names at every logon of that account, as that account, and nothing read who may change
  those scripts in NETLOGON. The check resolves the `scriptPath` of every enabled account,
  reads the NTFS permissions of each distinct script and of its folder over SMB with the
  same reader as the GPO checks, and reports a script a principal beyond the
  administrators may write - with the number of accounts that run it and the privileged
  ones among them by name. A local path is not read; `-OPSEC`, passed on by
  `Invoke-adPEAS -OPSEC`, reads nothing. It runs in the Accounts module.

- **The reach of a GPO takes its security filtering into account.** A computer applies a
  policy only if its token holds a principal granted the Apply Group Policy right on the
  policy object and none denied it; by default Authenticated Users hold it. The
  `reachesDomainControllers` row of the GPO checks and the `affectedComputerCount` of
  `Get-GPOPermissions` read the links alone, so a policy linked at the domain root but
  filtered to a group of file servers was said to reach the domain controllers and every
  computer. Both now read who may apply the policy - one query for every policy object
  per session - and judge each computer by its own SID, its primary group, the groups it
  is in (nested ones included, and the primary groups nested into a filter group), and
  Enterprise Domain Controllers for a domain controller. Such a policy now reads "No - by
  its link on ... it would, but only ... may apply it", and its computer count says the
  same in `affectedComputersNote`; a principal that cannot be read makes the answer
  Unknown and the count a lower bound. Where the filtering is not known, the links decide
  as before.

- **The signing checks and the computer count read the reach of a GPO the way the
  reachesDomainControllers row does.** The precedence contest of `Get-LDAPConfiguration`
  and `Get-SMBSigningStatus` filed a policy by the name of the OU it was linked to and
  left site links out; `affectedComputerCount` of `Get-GPOPermissions` took every computer
  below a link, every computer of the domain for a root link. Both now go by where the
  domain controllers actually are, their sites and the containers that block inheritance,
  with enforced links passing a block. A policy on the site of a domain controller takes
  part in the contest - it decides what no domain or OU policy configures, and everything
  when its link is enforced; a policy whose links a block keeps from the domain
  controllers says so ("applies below its links, but not on the domain controllers")
  instead of deciding their values; a policy linked above a domain controller moved out of
  the Domain Controllers OU competes for it. The count leaves out the computers below a
  block and says how many in `affectedComputersNote`. When the domain controllers cannot be
  read, the contest goes by the names as before.

- **`Get-LDAPConfiguration` reads three more characters of `dsHeuristics`.** Only
  character 7, anonymous LDAP, was evaluated. Now also: character 8, anonymous calls to
  the NSPI address book interface; character 16 (`dwAdminSDExMask`), which takes Account,
  Server, Print or Backup Operators and their members out of AdminSDHolder protection in
  every domain of the forest - the line names the groups; and character 21, which switches
  off the UPN, SPN or SPN alias uniqueness checks of the domain controllers - with the
  alias check off, a principal that may write SPNs can claim a server's service for an
  account it controls (CVE-2021-42282). Each is a finding with a card of its own; a
  character outside the values the specification defines is reported as unknown. The
  section is now *Checking the directory service heuristics*, and its row, which carried
  the GPO type with the card title "LDAP Configuration GPO:" and no name, has a type of its
  own, *Directory Service Heuristics*, with one decoded value per heuristic.

- **`Get-DomainTrusts` reads the Kerberos encryption types of each trust.** A referral
  ticket across a trust is encrypted with the trust key in a type that
  `msDS-SupportedEncryptionTypes` on the trust object allows; the attribute was read
  nowhere. A new `trustEncryptionTypes` row names the types, and a trust that allows no
  AES is a hint - including one without the attribute, which supports RC4 and no AES
  (KB4492348); Microsoft's 2026 change to AES by default covers accounts, not trusts
  (CVE-2026-20833). A line counts such trusts. The RC4 attribute bit keeps its meaning on
  a realm trust to MIT Kerberos without the attribute. The card *Trust Without AES for
  Kerberos* no longer claims offline cracking of an Active Directory trust key, whose
  password the domain controllers generate, nor that the trust has to be re-created: AES
  is switched on at the trust object.

- **`Get-DomainTrusts` shows the partner's domain SID and the age of the trust
  password.** `partnerDomainSID` comes from `securityIdentifier` on the trust object, which
  the data layer now decodes like `objectSid` instead of handing over bytes. On a trust the
  partner extends to this domain, `trustPasswordLastSet` says when the password of its
  interdomain trust account `<flatName>$` was last changed - one query for all of them.
  The trusting domain changes it about every 30 days; at 90 days or more the rotation has
  stopped, a trust key extracted before stays valid, and the trust is a hint with the new
  card *Trust Password No Longer Rotated* and a line that counts such trusts. A missing
  or unreadable account is said as such.

- **`Get-DomainPasswordPolicy` reads the password history and the five PSO settings it
  skipped.** `pwdHistoryLength` was not read: a history of 0 - a user can set the
  password a reset replaced at once - is now a moderate weakness with the card *Password
  History Disabled*, a value below Microsoft's default of 24 is said as such, and an
  unreadable one keeps the policy from reading as secure. Fine-grained policies now show
  `msDS-PasswordHistoryLength`, `-MaximumPasswordAge`, `-MinimumPasswordAge`,
  `-LockoutDuration` and `-LockoutObservationWindow` - all mandatory, none read before,
  so a policy that let the passwords of the admin group never expire was silent. The rows
  carry the names and texts of the domain policy, so its cards judge both.

- **`Get-DomainInformation` says what a deletion leaves behind in the forest.** Neither
  the tombstone lifetime nor the Active Directory Recycle Bin was read. `tombstoneLifetime`
  comes from `CN=Directory Service` - 60 days when the attribute is not set, at least 2
  (MS-ADTS 3.1.1.1.5.1); below the 180 days Microsoft sets in a new forest it is a hint,
  since a backup older than that can no longer be restored. `recycleBin` is read from
  `msDS-EnabledFeature` on the Partitions container: disabled at forest functional level
  2008 R2 or higher is a hint - a deleted object then keeps only a few attributes and
  comes back without its group memberships - and below that level it is said to be
  unavailable. With the Recycle Bin, `deletedObjectLifetime` shows how long a deleted
  object stays complete. Two new cards, *Active Directory Recycle Bin Not Enabled* and
  *Tombstone Lifetime Shorter Than 180 Days*.

- **`Get-DomainInformation` says which service replicates SYSVOL.** A new
  `sysvolReplication` row reads the FRS replica set and the DFSR replication group of
  SYSVOL under `CN=System` and the global migration state in `msDFSR-Flags`: *DFSR*,
  *FRS* for a domain never migrated, or *FRS and DFSR* with the state while a migration
  has not reached Eliminated. FRS is a hint with the card *SYSVOL Still Replicated by
  FRS*: it is deprecated, and no domain controller from Windows Server 1709 on can be
  added to such a domain (KB4025991).

- **`Get-GPORegistrySettings` reports Group Policies that weaken SMB.** Four rules with the
  paths and values Microsoft documents: the SMBv1 server enabled (`SMB1=1` under
  `LanmanServer\Parameters`), the SMBv1 client driver left loadable (`mrxsmb10` start type
  2 or 3 - 4 disables it), SMBv2 and SMBv3 disabled on the server (`SMB2=0`), and
  unencrypted access to shares that require encryption (`RejectUnencryptedAccess=0`).
  Each is a hint with a card of its own; a policy that turns SMBv1 off is the
  recommendation and is not reported. Signing stays with `Get-SMBSigningStatus`. A new
  test files every rule of the table under the card it names - and found that the
  Credential Guard rule for the runtime key never reached its card; it does now.

- **`Get-SIDHistoryInjection` says where a SID of another domain comes from.** Whether
  the source domain still exists was never checked. A new `sidHistorySource` row names it:
  a domain of this forest - read through the Global Catalog, since a domain has no trust
  object for its siblings - a domain this domain trusts, or neither. A line counts every
  account that carries sIDHistory from a domain that is neither, whether or not
  `-IncludeNonPrivileged` was given, with the card *SID History From a Domain Neither
  Trusted Nor in the Forest*: the leftover of a migration, still added to the token at
  every logon and honoured by every ACL that names it. When the Global Catalog or the
  trusts cannot be read, the row says unknown and nothing is counted.

- **The card for 'Account is sensitive and cannot be delegated' names the condition it
  depends on.** It promised protection from every delegation attack. Before the fix for
  CVE-2020-17049 ("Bronze Bit") a service with constrained delegation could alter a
  ticket that was not valid for delegation and the KDC accepted it, so neither the flag
  nor Protected Users stopped that path; Microsoft enforces the fix on every domain
  controller since the July 13, 2021 update. The patch level is not readable over LDAP,
  so the card says so and links Microsoft's deployment guidance.

- **The card for SeEnableDelegationPrivilege no longer claims it bypasses the sensitive
  flag.** It said the holder bypasses 'Account is sensitive and cannot be delegated' and
  recommended that very flag as a second layer. The flag does not depend on who
  configured the delegation; the card now names whom the holder can impersonate - every
  account neither marked sensitive nor in Protected Users.

- **`Get-ExchangeInfrastructure` reads ms-Exch-SMTP-Accept-Authentication-Flag on receive
  connectors.** The permission decides whether a session's mail is treated as
  authenticated, and only the Exchange server permission groups carry it by default.
  Granted to an anonymous principal it was not read - the connector came out as
  "Anonymous submission only - expected". It is now the verdict *Unauthenticated mail
  treated as authenticated*, a finding with a card of its own: such mail reaches
  distribution groups that accept internal senders only and loses its external marking.

- **`Get-PrivilegedGroupMembers` reports the ESX Admins group.** VMware ESXi joined to the
  domain makes every member of a domain group named ESX Admins a full administrator of the
  host, matched by name alone (CVE-2024-37085) - and an administrator of the hypervisor
  owns the virtual machines on it, domain controllers included. Where the group exists, its
  members are listed with the other privileged groups, with the card *Member of ESX
  Admins*, and who may change it is read in the group ACL step.

- **`Get-InfrastructureServers` asks whether a SQL Server service account is privileged.**
  The domain accounts an instance runs under were listed without judging them. A sysadmin
  on the instance runs operating system commands as that account through `xp_cmdshell`,
  and the host keeps its password among the LSA secrets - so an account privileged in the
  domain hands the domain to whoever controls the instance or its host. Privileged ones,
  operators included, are now a finding with the card *SQL Server Running Under a
  Privileged Domain Account*, naming the group that makes each one privileged; an account
  whose privileges cannot be evaluated is named as unknown rather than counted as clean.

- **`Get-GPORegistrySettings` reports DsrmAdminLogonBehavior = 2.** With that value the
  Directory Services Restore Mode account - a domain controller's local administrator, its
  password checked against no password policy - logs on while the directory runs, over the
  network with its hash alone; Microsoft recommends against it, and it is a known way to
  keep access after the domain passwords were reset. A policy that deploys it is a finding
  with the card *DSRM Administrator Logon Allowed at Any Time via GPO*. 0, the default, and
  1, Microsoft's suggestion for a single or isolated domain controller, are not reported.

- **`Get-LAPSConfiguration` says whose DSRM password Windows LAPS manages.** Domain
  controllers are rightly left out of the coverage figures, and the report then said
  nothing about the one account LAPS can manage on them: the Directory Services Restore
  Mode account, set at promotion and checked against no password policy. The coverage
  section now ends with what the domain controllers themselves show - read from
  `msLAPS-PasswordExpirationTime` on each DC, not from the policy: which of them carry no
  Windows LAPS expiration time, which carry one that passed more than 30 days ago, or that
  all of them are managed. Notes, with the card *DSRM Password Not Managed by Windows
  LAPS*.

- **A SYSVOL file that could not be read or parsed is a gap in the result, not an empty
  file.** Folders the scan account may not open were already reported; a file inside a
  readable folder that could not be read - denied, locked, gone - or was read and could
  not be parsed - a truncated `Registry.pol`, a `Groups.xml` that is not XML - left a log
  line and nothing else, and the checks concluded over it. Every reader now records such a
  file: the content cache, the `Registry.pol` and `Registry.xml` parsers, and the checks
  that read on their own. The coverage note before a "nothing found" conclusion names
  them - "N SYSVOL file(s) could not be read or parsed - the result below is incomplete",
  with each path and whether it could not be read or not be parsed - and keeps the
  conclusion from being green. Each check is told only about the files it reads: a
  `Groups.xml` nobody could parse says nothing about the registry settings. An empty file
  is not a gap.

- **`Get-UnixPasswordAccounts` judges every value of a multi-valued attribute on its
  own.** `userPassword` and `unixUserPassword` may hold more than one value, and the check
  cast them to one string: the values were joined with a space and judged as one. A
  salted `{SSHA}` hash with the password itself beside it read as a salted hash, and the
  cleartext went unreported; two salted hashes side by side matched no hash shape and
  read as cleartext. Each value now gets its own line - "userPassword (2 of 2): Cleartext
  ..." - and the account its loudest verdict.

- **`Get-PasswordInDescription` reads the link and the cloud extension attributes.**
  `wWWHomePage` and `url` are searched with the other free-text attributes, and a new
  pattern finds credentials in the userinfo part of a URL - `https://svc:Secret@host` - in
  any of them; a password in a query string was already an assignment. Only those count in
  a link: a homepage pointing at the password reset portal mentions the word and holds
  nothing, so the mention tier does not apply there. `msDS-cloudExtensionAttribute1-20`
  run in a query of their own beside `extensionAttribute1-15`, because either set can be
  missing from a schema that has the other, and a filter naming an undefined attribute
  fails as a whole. The card is titled *Credentials Found in a Free-Text Attribute*.
  `scriptPath`, `homeDirectory` and `profilePath` are read the same way as the links: a
  UNC path carries no credentials of its own, so only an assignment or a URL with
  credentials typed beside it counts, and a share named after the password team is not a
  mention.

- **`Get-CredentialExposure` reads the files a credential is written into besides
  scripts.** GPO comment files (`.cmtx`), application and deployment configuration
  (`.config`, `.json`, `.yml`, `.yaml`, `.psd1`) and exported registry files (`.reg` - an
  AutoAdminLogon export carries `DefaultPassword` in clear) and setup information files
  (`.inf`, a `sysprep.inf`'s `AdminPassword` among them) are searched like the scripts, in
  SYSVOL and in a custom path. `GptTmpl.inf` is skipped by name: every one with a password
  policy names `MinimumPasswordAge`, which would put a mention on each of them, and
  `Registry.pol` is parsed for password values on its own.

- **Windows answer files are read for their passwords.** An `unattend.xml`,
  `autounattend.xml` or any XML whose root is `unattend` carries the built-in
  administrator's password, local accounts', the automatic logon's and the domain join
  account's. Windows SIM can "hide" the first three, which Microsoft says is not
  encryption - Base64 of the password with the setting's name appended - so they are shown
  decoded; the domain join password cannot be hidden at all. Each is a finding with the card
  *Password in a Windows Answer File*, and the local accounts are named `.\name`, so they
  are not looked up as domain accounts of the same name.

- **`Get-GPOUserRightsAssignment` evaluates seven more user rights.** A GPO granting
  `SeCreateSymbolicLinkPrivilege`, `SeAuditPrivilege`, `SeSystemEnvironmentPrivilege`,
  `SeCreateGlobalPrivilege`, `SeProfileSingleProcessPrivilege`, `SeSystemProfilePrivilege`
  or `SeDelegateSessionUserImpersonatePrivilege` beyond the Windows default passed without
  a word. Each default is taken from the Default values table of its Microsoft page -
  `SeSystemProfilePrivilege` includes `NT SERVICE\WdiServiceHost`, as the page's text
  says - and all seven are hints with a card of their own. Microsoft publishes no default
  for `SeDelegateSessionUserImpersonatePrivilege`, so its holders are listed through the
  identity filter rather than compared against a guess.

- **GPO findings name the policy's WMI filter and its loopback processing mode.** Two new
  rows beside `reachesDomainControllers`, in the seven GPO checks: `wmiFilter` names the
  filter and its WQL queries - a policy applies only where the query returns a result, so
  a filter can narrow it to no machine at all - or says the filter is missing from the
  directory, in which case a client applies the policy. `loopbackProcessing` says whether
  the policy switches user Group Policy loopback processing on, in Merge or Replace mode,
  which makes the user settings of the policies reaching its computers apply to everyone
  who logs on to them. Each row appears only for a policy that has one, and says
  *Unknown* where it could not be read whether the policy has one. Both are information
  and change no severity.

- **`Get-GPOPermissions` tells a missing policy folder from an unreadable one, and names
  orphaned folders.** A policy whose folder in SYSVOL does not exist used to be listed
  among the folders that *could not be read*. It is now reported as what it is, together
  with policies whose folder holds no `gpt.ini`: a client opens the `gpt.ini` of every
  policy in its scope before it applies any, and Event 1058 says what a failure does -
  "Group Policy processing aborted". A linked policy in that state is a hint (*GPO Without
  Its Folder or gpt.ini in SYSVOL*), an unlinked one a note, and a policy whose links could
  not be resolved counts as linked. Folders in `SYSVOL\Policies` named for no policy object
  the scan account can read are listed as a note (*SYSVOL Folder Without a GPO*) - left
  over from a deleted policy, or a policy hidden from the account. A policy whose
  `gPCFileSysPath` points elsewhere is not expected to have the folder.

- **An unlinked GPO a broad group may change says it is one link away.** A policy that
  applies nowhere - nothing links it, or its links are disabled - showed "Not linked" and
  0 affected computers, which reads as harmless. Where a broad group such as Authenticated
  Users or Domain Users may change it - rewrite the directory object or write its SYSVOL
  folder; deleting it does not count - the new `oneLinkAway` row says that a single link
  applies whatever the policy then holds, and the card *Unlinked GPO a Broad Group May
  Change* explains who can place that link. Where the links could not be resolved, no
  such claim is made.

- **`Get-GPORegistrySettings` reports seven more settings that take back a Windows
  hardening.** Each is a hint with a card of its own, read from `Registry.pol`,
  `Registry.xml` or the Security Options in `GptTmpl.inf`:
  - `RpcAuthnLevelPrivacyEnabled=0` - the print spooler RPC privacy hardening of
    KB4599464 (CVE-2021-1678) switched off again
  - `SetProxyBehaviorForUpdateDetection=1` - the update scan may fall back to the user's
    proxy, which matters with an `http://` update server
  - `MaximumPasswordAge` above 30 days - machine account passwords change less often than
    the default Microsoft recommends
  - `RestrictNullSessAccess=0` - null sessions reach every share and named pipe their
    permissions admit, not only the ones listed (on the existing null session card)
  - `EnableScriptBlockLogging=0`, for Windows PowerShell and PowerShell 7, in either half
    of a policy - an explicit 0 also suppresses the script blocks PowerShell otherwise
    logs by itself as suspicious
  - `ConsentPromptBehaviorAdmin=0` - administrators elevate without a UAC prompt
  - Schannel `Enabled` other than 0 for SSL 3.0 or TLS 1.0, server or client role

- **Objects of the Configuration partition are found by their DN.** `Get-DomainObject`
  looked for an object asked for by its distinguished name under the domain DN, and the
  Configuration partition is a naming context of its own that such a search does not
  enter. Against a real domain the Directory Service object, the Partitions container,
  the schema and every site came back as not found: `Get-DomainInformation` reported the
  tombstone lifetime and the Recycle Bin as unknown, `Get-LDAPConfiguration` said
  dsHeuristics could not be read, and `Get-CriticalObjectACLs` could not read the ACLs of
  the schema, the partitions container and the sites - all objects every domain user may
  read. Such an object is now read by a base search on its own DN. A search under a base
  that does not exist returns nothing again instead of an error: the not-found test
  missed the shape `System.DirectoryServices.Protocols` throws it in.

- **The Restricted Admin card is a hint, as its row is.** The registry table lowered
  `DisableRestrictedAdmin=0` to a Medium hint, and the card's description says so, but the
  card and the trigger on its row stayed a finding: the console printed the row yellow and
  the HTML report counted a red finding scored 50 for the same line. Both are a hint now,
  scored 30 like the other hints of the table.

- **An SMB access made from inside another one no longer ends the connection of the
  first.** `Get-GPOScheduledTasks` reads who may write a task's UNC path while it reads
  SYSVOL, and that path can be on the very SYSVOL share it is reading. The inner access
  mounted the share a second time and removed it again, and for a drive mounted with
  credentials removing it cancels every connection to that share without a drive letter -
  the scan's own included, which then read on without the credentials it had mounted with.
  A call for a share an enclosing call already has mounted now runs on that mount, and a
  failure there no longer marks the share as unreachable for the rest of the session.

- **The anonymous LDAP row says what was measured.** In a fresh Windows PowerShell
  session the anonymous bind test never ran: it was the first code of the connection to
  create a `System.DirectoryServices.Protocols` type, the assembly was loaded only after
  it, and the error was read as a refused bind - so `Get-DomainInformation` printed
  "Refused - an anonymous bind was tried and could not read the domain object" for a bind
  nobody tried. The assembly is loaded before the test now, and a test the server never
  answered - a domain controller out of reach, a timeout, a connect error - is reported
  as "Not tested" with its reason instead of as refused. The finding pattern for an
  enabled anonymous bind is anchored, so the text of that reason cannot colour the row.

- **The Exchange permissions model no longer reads a class-scoped ACE as PrivExchange.**
  Exchange setup gives Exchange Trusted Subsystem full control on the domain object
  scoped to the `msExchDynamicDistributionList` class - the right to create and delete
  such lists. `Get-ExchangeInfrastructure` ignored the scope and reported "Shared
  permissions - Exchange Trusted Subsystem can rewrite the domain DACL (PrivExchange)" for
  an organization whose Exchange Windows Permissions ACEs are inherit-only. An
  object-specific ACE is no longer counted as a DACL rewrite of the domain object or of
  its descendants, which is how `Get-DangerousACLs` already read it.

- **Exchange configuration the account cannot read is no longer reported as absent.**
  Measured with a domain user against an Exchange SE organization: the organization and
  its servers are readable, its accepted domains, connectors, virtual directories, role
  assignments and hybrid configuration are not - and the checks said "No SMTP receive
  connectors found", "No Exchange role assignments found" and "this organization appears
  to be purely on-premises". Every organization has an accepted domain and several hundred
  role assignments, and a server that transports mail has receive connectors, so these
  results now say the configuration is not readable by this account and the answer is
  unknown. The organization card carries a new `ConfigurationVisibility` row when no
  accepted domain is readable.

- **An Exchange 2019 known only from the directory is reported as out of support.**
  Exchange writes its version into the `serialNumber` of its server object as
  "Version 15.2 (Build 31544.4)", and from Exchange 2013 on the build carries an offset
  of 30000 - that value is build 15.2.1544.4, Exchange 2019 CU14. Read as written, every
  Exchange 2019 build lay above the Exchange SE boundary of 2562, so the server inventory
  and the Exchange check classified it as Exchange SE, supported, wherever no HTTP probe
  supplied the build. The offset is removed now; the Exchange organization's server card
  names the product instead of printing the raw value, and the inventory shows the build
  Microsoft publishes.

- **Windows Server 2025 has its support end date.** Its lifecycle was unpublished when
  the table was written, so `Get-OutdatedComputers` counted every Windows Server 2025
  machine - the domain controllers of a current domain among them - as a system it
  cannot assess. Microsoft has published extended support to 2034-11-14, and these
  machines are reported as supported.

- **A masked value no longer hides the password next to it.** `Get-PasswordInDescription`
  skipped a whole attribute as soon as a masked or placeholder value appeared in it, before
  looking for an assignment - so "pwd: Sommer2024, old: password=****" was not reported.
  A masked value is now recognized at the value itself, and only keeps the mention beside
  it from becoming a hint. The descriptions the Allowed and Denied RODC Password
  Replication Groups ship with ("can have their passwords replicated") are no longer a
  hint in every scan.

- **A credential mention is a hint on every row, not a finding.** The trigger behind
  `CREDENTIAL_IN_DESCRIPTION` used one pattern for both tiers and coloured any description
  or info containing a password word red - the hint objects of `Get-PasswordInDescription`
  among them, and any description in the report that said "passwords". An assignment with
  a value is a finding, a mention is a hint, and a masked value is neither, as the check
  rates them.

- **The print spooler's restricted service SID is named and expected.** The Default Domain
  Controllers Policy a Windows Server 2025 domain is created with grants Generate security
  audits to `RESTRICTED SERVICES\PrintSpoolerService` (`S-1-5-99-...`), and
  `Get-GPOUserRightsAssignment` reported it in every such domain as an unresolvable holder
  beyond the Windows default. The SID resolves by name now, any other SID under the
  restricted services authority by its authority, and the user right accepts it on domain
  controllers without expecting it in a domain created earlier.

- **SeSecurityPrivilege granted by a GPO is a hint throughout.** The right was moved to
  the hint tier - it destroys the record of an intrusion rather than enabling one - but
  its card stayed a finding scored 65. `Get-GPOUserRightsAssignment` printed a yellow
  object with red rows, and the HTML report counted a finding, for Exchange Servers
  holding the right on the domain controllers as Exchange setup grants it. The card is a
  hint scored 35 now, and every right's card and rows follow the table's tier.

- **A domain controller's TRUSTED_FOR_DELEGATION is rendered as expected again.** The
  test for a domain controller reads SERVER_TRUST_ACCOUNT off the object's
  `userAccountControl`, and the renderer handed it the row's flags as a string instead of
  the object. Every domain controller therefore showed a red TRUSTED_FOR_DELEGATION with
  the unconstrained delegation card - whose first remediation clears the flag - in the
  server inventory and wherever else a domain controller was printed. It is a hint with
  the card written for domain controllers now.

- **Exchange's Deny ACEs on AdminSDHolder are no longer said to hide the template.**
  Exchange setup denies Exchange Servers and Exchange Trusted Subsystem writing
  userCertificate, altSecurityIdentities and servicePrincipalName on protected accounts -
  hardening against a compromised Exchange server - and `Get-PrivilegedGroupMembers`
  listed both groups as Deny trustees that "can hide the template from the people who
  audit it". Only a Deny that keeps someone from reading the template's DACL, or from
  reading or listing the object as a whole, is listed now.

- **Users and computers with a non-default owner are a hint throughout.** Their cards
  are hints and the Owner row had been aligned to them, but `Get-NonDefaultUserOwners` and
  `Get-NonDefaultComputerOwners` still announced and filed the objects as findings - a red
  heading and object over a yellow row, in front of a card rated a hint.

- **Dates in object rows are written as yyyy-MM-dd HH:mm:ss.** A date without a
  transformer of its own was turned into text by PowerShell's invariant culture, so
  `pwdLastSet` and `lastLogonTimestamp` of every object read "07/04/2025 10:20:55" in the
  console, the text report and the HTML report - the 7th of April to most readers, for the
  4th of July. They go through the same formatter as every other date in adPEAS now.

- **Who may write altSecurityIdentities is read the way the access check reads it.**
  `Get-WeakCertificateMapping` counted any ACE with GenericAll, GenericWrite, WriteDacl or
  WriteOwner as the write, whatever the ACE was scoped to, read inherit-only ACEs as if
  they applied to the account, and ignored Deny ACEs. Measured on an Exchange SE domain,
  that made Organization Management, Exchange Servers and Exchange Trusted Subsystem
  writers on the RID 500 account and on krbtgt: their GenericAll is scoped to the
  `msExchDynamicDistributionList` class, the Exchange Servers grant is inherit-only, and
  Exchange setup denies Exchange Trusted Subsystem the attribute explicitly. An ACE scoped
  to anything but the attribute or its property set no longer counts, inherit-only ACEs
  are skipped, and an explicit Deny of the write cancels a grant that reaches it as a write
  - not one that can rewrite the DACL. The same reading decided ESC14 findings for
  delegations outside Exchange.

- **The OU permission checks count what they analysed.** `Get-PasswordResetRights`
  counted a protected administrator once per privileged group it belongs to - measured,
  one account was "5 privileged account(s) have inheritance disabled" - and then said "No
  OUs with privileged users found to analyze" about an account that sits in an OU. It
  counts accounts now and says that no other privileged account was found.
  `Get-DangerousOUPermissions`, `Get-PasswordResetRights` and `Get-LAPSPermissions`
  analyse containers such as CN=Users alongside organizational units and called all of
  them OUs ("12 analyzed OU(s)" for 4 OUs and 8 containers); they name both counts now.

- **The BloodHound export carries the real account flags and timestamps.** Measured on an
  export from Windows PowerShell 5.1: every account was enabled - the disabled Guest,
  krbtgt and test accounts among them - no account had a password that never expires or
  was AS-REP roastable, both domain controllers had `isdc` and `unconstraineddelegation`
  false, `pwdproperties` was 0 for a domain requiring complexity, and every `lastlogon`,
  `lastlogontimestamp`, `pwdlastset` and `whencreated` was -1. userAccountControl and
  pwdProperties arrive decoded into flag names, which the collector read as 0, and
  `[DateTime]::UnixEpoch`, which the timestamp conversion subtracted, exists in PowerShell
  7 only. The flags are read from their names now and the epoch is built.

- **Role transfer and takeover rights reach the checks that look for them.**
  `Get-ObjectACL -DangerousOnly` kept an extended right only as "ExtendedRight" or by the
  pattern DS-Replication, Force-Change-Password or All-Extended-Rights - but the right
  arrives under its resolved name, so an ACE granting Change-PDC, a role transfer,
  Migrate-SID-History, Reanimate-Tombstones or DS-Install-Replica was dropped before
  `Get-DangerousACLs` and `Get-CriticalObjectACLs` saw it. Both checks look for exactly
  these names, and neither could report one. They pass the filter now.

- **A class-scoped GenericAll on an OU is no WriteDacl or WriteOwner.** The OU permission
  analysis behind `Get-DangerousOUPermissions` limited GenericAll and GenericWrite to ACEs
  that name no ObjectType, but read WriteDacl and WriteOwner out of any ACE's mask.
  Exchange setup grants Exchange Trusted Subsystem GenericAll scoped to the
  `msExchDynamicDistributionList` class, inherited by every OU and container - measured,
  it was listed as WriteDacl and WriteOwner on all of them. Such an ACE grants creating and
  deleting objects of that class, which is what remains reported.

- **Only a grant for computers lets `Get-AddComputerRights` call a trustee a computer
  creator.** GenericAll on CN=Computers counted whatever class the ACE was scoped to, so
  Exchange's GenericAll on the `msExchDynamicDistributionList` class made Exchange Trusted
  Subsystem and Organization Management computer creators. GenericAll now counts like
  CreateChild: for all classes or for the computer class.

- **AD CS permissions are read the way the access check reads them.** `Get-ADCSTemplate`
  took every GenericAll for an enrollment right and every Deny of one for a Deny of
  enrollment, whatever the ACE was scoped to, read inherit-only ACEs as if they applied to
  the template, and let an inherited Deny win over an Allow written on the template - which
  dropped a principal, and its ESC findings, from a template it can enrol from. ESC4, the
  check of the CA's AD object and ESC5 on the PKI containers read GenericAll, GenericWrite,
  WriteDacl and WriteOwner out of any ACE's mask and counted inherit-only ACEs as well. An
  object ACE grants its mask on the attribute or class its GUID names only: a scoped
  GenericAll now counts as enrollment for the two enrollment rights, as a write of the
  attribute it names - for ESC4 one of the six template attributes - and on a PKI
  container as creating objects of the class it names, which the row says. Inherit-only
  ACEs are skipped; the delegation wizard's full control of certificate templates is
  reported by ESC4 on each template it reaches, no longer as GenericAll on the container.
  An explicit ACE is evaluated before every inherited one, and the row of an inherited
  Deny says that an Allow on the template overrides it.

- **A session bound through Kerberos knows its own account.** Only a connection opened with
  explicit credentials - the NTLM and simple bind fallbacks - looked the bound account up.
  Every Kerberos session, which is Windows authentication and every password, NT hash, AES
  key, certificate or ticket logon, asked LDAP "Who Am I?", got `DOMAIN\name` and kept the
  name only: no DN, SID, sAMAccountName or UPN. `Get-LAPSCredentialAccess` could therefore
  not tell whether the scanning account is privileged and reported an administrator's
  expected LAPS read as a finding, and `Get-adPEASSession` showed no SID. The account is
  looked up now, and only when the name belongs to the connected domain. The lookup reads
  objectSid as bytes: the attribute indexer of a search result returns a string for a SID
  whose bytes happen to be valid UTF-8, and the SID was lost.

- **The token groups of the session are read at all.** `Get-CurrentUserTokenGroups`, the
  fast path of the encrypted-LAPS check that compares the decryptor a blob names against
  the scanning account's groups, had never returned a SID from a real domain. It read
  tokenGroups off the account's own object, and `Invoke-LDAPSearch` did not know the
  attribute as binary: a SID that happened to decode as UTF-8 arrived as a string and
  every other one byte by byte - measured, three SIDs came back as one string and 56 loose
  bytes. It needed the account's DN as well, which no Kerberos session had. It reads the
  token of the connection off the rootDSE now (MS-ADTS 3.1.1.3.2.41), which also holds the
  account's own SID and the well-known groups of the logon. `Invoke-LDAPSearch` returns the
  three tokenGroups attributes as one SID per value, and without `-Raw` as SID strings.

- **`Get-adPEASSession` writes the session start as yyyy-MM-dd HH:mm:ss.** It read
  "10/18/2026 14:55:10" - the one date in the summary that did not go through the common
  formatter. The duration counts every hour: a session of 26 hours read "02:00:00".

- **The built-in Administrator is a Tier-0 account to `Get-ProtectedUsersStatus` in its
  own right.** The Tier-0 list holds RID 500 among the groups, and the check asked for it
  as a group - "Group not found" in every scan - so the account counted only through the
  groups it belongs to, and not at all once it belongs to none. It is read as the account
  it is now.

- **A GPO permission scoped to one attribute is no control of the GPO.**
  `Get-GPOPermissions` held that an ObjectType narrows the attribute rights only, so an
  ACE granting GenericAll, WriteDacl, WriteOwner or Delete beside it was reported as that
  right over the whole GPO - a write of the WMI filter link as full control. An object ACE
  grants its mask on the attribute or class its GUID names and nowhere else (MS-ADTS
  5.1.3.3.3): a scoped GenericAll now counts as the write of that attribute, with the
  attribute named and judged by whether it carries the policy content, and an ACE scoped
  to a child class counts as nothing. A Deny takes a right only from what it covers: a Deny
  of one attribute no longer cancels a write of every property, and an inherited Deny
  nothing from an Allow written on the GPO.

- **The BloodHound export draws an edge only for a right that holds on the object.** The
  collector read GenericAll, GenericWrite, WriteDacl and WriteOwner out of any ACE's mask
  and counted inherit-only ACEs. Measured on an Exchange SE domain, Exchange setup's
  GenericAll scoped to its `msExchDynamicDistributionList` class made 228 GenericAll edges
  each for Exchange Trusted Subsystem and Organization Management - a path from either to
  every privileged account that no access check grants. Those rights now come only from
  an ACE that names no ObjectType; scoped, the ACE is read as the write of the attribute it
  names (full control of servicePrincipalName is a WriteSPN edge). Inherit-only ACEs make no
  edge, AddSelf needs the validated write of member, and a Deny in
  msDS-AllowedToActOnBehalfOfOtherIdentity is no AllowedToAct edge. The other way round,
  GENERIC_ALL written as the single generic bit - SDDL "GA", the form impacket and Certipy
  write - matched no mask and became no edge at all. The measured export went from 4157 to
  3343 ACE edges.

- **An inherited Deny no longer cancels a delegation written on the object.** The Deny
  netting behind the OU permission checks and the privileged-group and privileged-account
  ACL rows let a Deny inherited from a parent cancel an Allow on the object itself. The
  access check evaluates every explicit ACE first, so that delegation is access, and it is
  reported again.

- **`Get-SCCMInfrastructure` reports only a write that reaches the management points.** Any
  ACE on the System Management container whose mask held a write right counted, whatever
  it was scoped to and whether it applied to the container at all. The container inherits
  what Exchange setup grants on every container of the domain - measured on CN=System:
  Exchange Windows Permissions may create users, computers, groups, OUs and contacts, and
  Exchange Trusted Subsystem may write single attributes - so every domain running both
  products listed those groups as able to publish a management point. Inherit-only ACEs no
  longer count, and an ACE scoped to a class counts only when the class is not one adPEAS
  can name; the SCCM schema classes are not in its tables, so a management point stays
  reported, with the class named.

### Changed

- **Every object a check shows carries its severity into the JSON export and the report
  diff.** 109 places in 36 checks handed an object to the output without a class - among
  them every credential found in SYSVOL, every kerberoastable and AS-REP roastable
  account, every constrained delegation, every outdated computer and every dangerous ACL
  on the domain root. The console and the HTML card were unaffected, because they colour
  an object by its attributes, but the JSON export and `Compare-adPEASReport` filed all of
  them as `Standard`. Each object now has the class of the line that announces it -
  `Finding`, `Hint`, `Note` or `Secure` - and an unprotected Tier-0 account is a `Finding`
  even where the Protected Users coverage line above it is not. **The first
  `Compare-adPEASReport` run against a scan made with an earlier version therefore lists
  these objects once as a severity change (`Standard -> ...`).** That is the correction,
  not a change in the domain.

- **A populated `msDS-KeyCredentialLink` is information, not a Shadow Credentials
  finding.** Windows Hello for Business, FIDO2 keys and Entra hybrid join fill the
  attribute in normal operation; the card was a Finding with a base score of 60 and put
  that score on every such account. It is a note now, and its text says where the attack
  is reported: the write right on the attribute, which the ACL checks find. The row still
  lists each key with its source and, on a computer, how long after the account it
  appeared.

- **A GPO scheduled task that runs a local script or PowerShell as SYSTEM is a hint.** It
  was a finding with "check if script is modifiable" and "check command for injection
  vulnerabilities" - claims about permissions on the computers the directory does not
  show, and about an injection surface a static command line does not have. The rows say
  what was not checked. Risky directories and UNC paths, which the check can judge, stay
  findings.

- **A GPO linked to a site no longer claims to affect 0 computers.** Site membership
  follows the IP subnet a computer starts in, which the directory does not record per
  computer, so `Get-GPOPermissions` never counted a site's computers. Where a site is the
  only link the count reads "unknown"; beside OU links the number stands as a lower bound
  and a row next to it says so.

- **The domain password policy shows every `pwdProperties` flag.** Two of the six fed the
  verdict and the other four were never shown. Each flag that is set is now listed by
  name and meaning; three of them MS-SAMR calls reserved, and the row says so. Where a
  lockout threshold exists and `DOMAIN_LOCKOUT_ADMINS` is not set, a row says that the
  built-in Administrator is exempt from the lockout - the default, so it is information
  and changes no severity.

- **An unread lockout threshold or `pwdProperties` is no longer reported as disabled.**
  Both became 0 when the attribute did not arrive or could not be parsed, and 0 carries
  the hardest verdicts the password policy has: no account lockout, no complexity. The
  rows read "Unknown" now, as the minimum length and the maximum age already did, and
  count toward no weakness.

- **A password policy is not called secure over a value nobody read, and a Fine-Grained
  Password Policy nobody could read is not called weak.** With nothing weak among the
  values that were read, a domain policy whose minimum length, maximum age, complexity
  flags or lockout threshold did not arrive was a green "Found password policy:"; it is a
  note now. By default only Domain Admins may read a Password Settings Object, and every
  setting on it is a mandatory attribute - so a missing setting was not read, yet it
  printed "Disabled" and counted as a weakness, the precedence became 999 and the policy
  read as assigned to nobody. Those rows say "Unknown" now, a policy that could not be
  read in full is named as not assessed, and a value that does not parse no longer throws
  the whole section away. Where no policy comes back at all, the check says that only
  Domain Admins can read them by default instead of "No Fine-Grained Password Policies
  configured".

- **`Get-LAPSConfiguration` and `Get-OutdatedComputers` say when they could not finish.**
  Both wrote a failed query to the log only, so the section simply ended - a LAPS
  coverage figure that was never computed looked like a domain with nothing to report.
  They print "Error during check - ... could not be evaluated" now, as the other checks
  do.

- **`Get-GPORegistrySettings` reports AutoAdminLogon as Windows stores it.** The value is
  a String holding `1`, and the rule compared numbers only, so a GPO that switches on
  automatic logon the documented way was never reported. The rule reads the number out of
  the string now; the DWORD rules still ignore a string, because Windows does too.

- **`Get-CredentialExposure` reports every Winlogon password in a Registry.xml.** It kept
  one value of each name per file - the last - so a file that deploys two kiosk accounts
  reported one of them, and it looked only at files that also say `AutoAdminLogon`,
  although a GPO that deploys the user name and password while another GPO switches
  automatic logon on puts the password into SYSVOL all the same. Each `DefaultPassword`
  and `AltDefaultPassword` under the Winlogon key is now its own credential, with the user
  and domain name of its own set or collection.

- **Eight extended rights carried the GUID of another right, and six `Set-DomainObject`
  aliases wrote the wrong ACE.** The table that names an ACE's right had been written
  from memory; checked against MS-ADTS 5.1.3.2.1 now. `Migrate-SID-History` was the GUID
  of Update-Password-Not-Required-Bit, while the real right was filed as
  `Manage-Optional-Features` - so a Migrate-SID-History ACE on the domain object went
  unreported. `Send-As` was Send-To, Change-PDC was Change-Domain-Master,
  Change-Infrastructure-Master was Change-PDC, Change-Domain-Master was
  Do-Garbage-Collection, and `Recalculate-Hierarchy`, `Add-GUID` and
  `Validated-MS-DS-Behavior-Version` were wrong as well. **`Set-DomainObject -ExtendedRight`
  with `SendAs`, `MigrateSIDHistory`, `SIDHistory`, `SeizePDC`, `SeizeInfrastructure` or
  `SeizeDomainMaster` granted a different right than its name says**; each now writes the
  right it names.

- **`Get-DangerousACLs` reports only the role-transfer right that acts on the domain
  object.** Change-Rid-Master, Change-Infrastructure-Master, Change-Domain-Master and
  Change-Schema-Master apply to RID Manager$, CN=Infrastructure, CN=Partitions and the
  schema container, so an ACE for one of them on the domain object authorises nothing and
  was reported as a role-transfer right. Change-PDC is reported as before, and its card
  now speaks of the PDC emulator alone.

- **The card for write access to the domain root's GPO link no longer claims
  `gPOptions`.** The check reports `gPLink` only, and the card said "gPLink or gPOptions"
  and described blocked inheritance - which at the domain stops the site-linked policies
  alone and is not what the card is about.

- **A GPO script in NETLOGON is no longer said to be guarded by the GPO's permissions.**
  `Get-GPOScriptPaths` counted NETLOGON, and SYSVOL outside a GPO folder, as the policy
  store "where the GPO permissions decide who may change it". That folder's file
  permissions are no GPO's and are not read by the check. Such a script is now a hint when
  it runs as SYSTEM and a note when it runs as the user, says that its permissions were
  not checked, and carries the card for scripts outside the policy store.

- **SCCM and SCOM groups no longer carry the operator-group card.** Their member count
  shares its attribute name with the count on the Account, Backup, Print and Server
  Operators rows, and every SCCM or SCOM group with a member opened that write-up. The
  card now goes to the operator-group rows only.

- **A kerberoastable account without `msDS-SupportedEncryptionTypes` says so.** The
  attribute was simply missing from the row, and the card for it - the KDC then falls
  back to the domain default and RC4 stays available - fired only for a stored 0, which
  is not how the case occurs. The row now reads "Not configured" and carries that card.

- **The note about a gMSA that expires appears.** The account's `accountExpires` arrives
  as a date, and the check parsed it as a number, which a date never is - so a gMSA with
  an expiry date was never mentioned.

- **The trust account card no longer tells the reader to remove PASSWD_NOTREQD.** Windows
  sets the flag on every trust account, and the trust password is generated and rotated
  by the domain controllers; the card called that password possibly empty and named a
  `netdom` switch that does not exist. Its MITRE reference pointed at Kerberoasting.

- **`Get-AdminReversibleEncryption` describes what it checks.** It reports every account
  with reversible password encryption and names the privileged ones, while its help text
  and its report section still spoke of privileged accounts with `adminCount=1` only. A
  failed query now prints an error line instead of ending the section without a word.

- **Every check says when it could not finish.** In 35 checks - among them the
  Kerberoasting, AS-REP, delegation, trust, password policy, LDAP and SMB signing, GPO
  and ADCS checks - a failed query was written to the log only, so the section simply
  ended, which reads like a domain with nothing to report. Each prints "Error during check
  - ... could not be evaluated" now. In `Get-WeakCertificateMapping` a failed write-access
  analysis was followed by the green line "No non-privileged principal can write
  altSecurityIdentities on a privileged account"; it is an error line now, and the green
  line is printed only after an analysis that ran.

- **`Get-GPOLocalGroupMembership` recognises every broad group in a local group.** Its
  three parsers kept a private list of Everyone, Authenticated Users and Anonymous Logon
  plus Domain Users, so Domain Computers, Domain Guests, BUILTIN\Users, BUILTIN\Guests,
  Interactive and Network put into a local group by policy did not raise the assignment.
  They are recognised the way every other check recognises them now, and shown under
  their English names.

- **Two values of the BloodHound export came from the wrong place.** The domain's
  `dsheuristics` was read from the domain object, which never carries it, so every export
  said null; it is read from `CN=Directory Service` in the Configuration partition now.
  And the `ReadLAPSPassword` edge was keyed on the GUID of `msDS-ManagedPassword`, the gMSA
  password attribute: a LAPS read delegation produced no edge, and a right on a gMSA
  password produced a LAPS one. The edge now comes from control access on the LAPS
  password attributes.

- **More GUIDs that named another attribute, among them in commands the reader runs.**
  Checked against Microsoft's schema pages: `msPKIRoamingTimeStamp` carried a GUID that is
  not that attribute, so a delegated read of it was not recognised, and the
  `Set-DomainObject` read aliases `ReadUserPassword`, `ReadLMHash`, `ReadLMPwdHistory`,
  `ReadNTHash` and `ReadNTPwdHistory` named other attributes. Four cards had a wrong GUID
  in their remediation commands - **the dNSHostName card's last command granted SELF an
  unvalidated write on `displayName`**; it now checks that computers keep the validated
  write they hold by default. The scriptPath card filtered on a wrong GUID, the
  DNS-Host-Name-Attributes card offered the validated write as an extended right under a
  wrong GUID, and the encrypted-LAPS card now reads the attribute's GUID from the schema.

- **An OU delegation with `NoPropagateInherit` says how far it reaches.** Such an ACE
  stops one level down, at the direct children of the OU, and it read like a delegation
  on the whole subtree. Its rights now carry "(direct children only)", or "(this object
  and its direct children only)" where the ACE applies to the OU itself as well.

- **`Get-DomainComputer -LAPS` asks only for the LAPS attributes the schema defines.** The
  filter named both generations' expiration attributes, also in a domain whose schema
  has only Windows LAPS - every new installation. It is built from the schema answer
  the LAPS checks already share now, and asks for both only where that answer is
  missing. The fallback probe behind that answer asks each generation on its own, so a
  failing Legacy query can no longer hide Windows LAPS.

- **Exchange role assignments tell delegating from regular.** A delegating assignment
  does not give its holder the role, only the right to assign it, and Exchange setup
  creates one for Organization Management on practically every role. Counted as role
  holders, they made findings of every standard installation - ApplicationImpersonation,
  Unscoped Role Management and Mailbox Import Export on Organization Management. Those
  are shipped defaults now, and so is ApplicationImpersonation on Hygiene Management. A
  delegating assignment anywhere else is a finding on the card of the role it hands out.
  The distinction is bit 49 of `msExchRoleAssignmentFlags`, measured against
  `Get-ManagementRoleAssignment`; the "-Delegating" name suffix is cut at 64 characters.

- **The LDAP and SMB signing checks decide GPO precedence per setting.** Both elected one
  winning policy for the domain controllers and called every other policy overridden.
  But a policy that leaves a value unset does not override another policy's value for
  it: a Default Domain Policy that alone set channel binding to Never read as overridden
  by a Domain Controllers policy that only set LDAP signing - while its Never was what
  the domain controllers enforced. `EffectiveSetting` now names which of a policy's
  settings are in force and who overrides the rest, enforced links rank as Group Policy
  ranks them, and a new object below the policies shows what is in force on the domain
  controllers, value by value, with the policy each value comes from. It is coloured by
  its weakest value and says that it is read from the policies: a value can stay on a
  domain controller after its policy stops applying.

- **The Exchange permissions model is determined in child domains too.** Exchange creates
  its groups once, in the forest root domain, and grants them their rights on every other
  domain object. `Get-ExchangeInfrastructure` looked for Exchange Windows Permissions and
  Exchange Trusted Subsystem in the domain it scanned, found neither in a child domain,
  and reported the model as undeterminable - while the WriteDACL ACE that decides it was
  on the domain object. Where the groups are missing, the check now asks the Global
  Catalog for them in the forest root and says where it found them; the group cards say
  that the group lives in the forest root instead of "not found".

- **A child domain of a forest prepared with Active Directory split permissions no longer
  reads as shared permissions.** Setup creates `OU=Microsoft Exchange Protected Groups` in
  the forest root only and moves Exchange Windows Permissions into it, so the lookup in
  the scanned domain never found the OU there and the `ADSplitPermissions` row said "Not
  enabled - shared permissions model"; the forest root lookup asked only `OU=Microsoft
  Exchange Security Groups` and missed the moved group. Both OUs are asked now, and where
  the forest root keeps Exchange Windows Permissions answers the question. The row also
  no longer says "holds no ACEs" while the domain object still carries them - Setup
  removes them from a domain only when that domain is prepared again.

- **A Credential Roaming row that says `PrivilegedAccount: No` no longer carries the
  privileged-account card.** The card "The Affected Account Is Privileged" hangs off any
  value of `PrivilegedAccount`, because the check it was written for sets that attribute
  on privileged accounts only; `Get-CredentialRoaming` writes Yes or No on every row, so
  every account and delegated principal that is not privileged was shown red with the
  claim that it is. A `No` now carries no card. The delegation rows call their column
  `PrivilegedPrincipal`: a privileged holder of a delegated read is the expected case
  there, and the card describes an aggravation.

- **A Credential Roaming delegation judges control access per container.** The two
  halves of the confidential-attribute read were combined over the whole principal, so
  control access delegated on one container made a read on another, which the
  confidential flag blocks, look readable today. The row's verdict is the strongest of
  its containers as before, and a container whose verdict differs from it now says so
  (`blocked by the confidential flag`).

- **An account that is a Domain Admin through its primary group is privileged.**
  `Test-IsPrivileged` read group membership through `member` links only, and
  `primaryGroupID` leaves none - so an account whose primary group is Domain Admins, or a
  group nested into a privileged one, came back as an ordinary account.
  `Get-AdminPasswordNeverExpires` and `Get-InactiveAdminAccounts` select their candidates
  by `primaryGroupID` on purpose and then dropped exactly those accounts again, and the
  ACL checks reported such an account as an unprivileged holder of rights. The primary
  group and its nesting now count for the privileged and operator tiers; the default
  primary group, Domain Users, still makes no account a broad-group member. Domain
  controller accounts, whose primary group is Domain Controllers, are privileged now too.

- **An Exchange role assigned through a role assignment policy is judged on its own.**
  `Get-ExchangeRBACAssignments` set the resolved assignee only for directory principals
  and never cleared it, so a policy assignment inherited the object of the assignment
  before it - and with it that account's privilege verdict. A high-value role on a
  policy that followed an assignment to an administrator was reported as a hint about an
  "already privileged" assignee instead of as a finding.

- **An ACE that names an object class for inheritance is no longer ignored on the object
  that carries it.** The class in an ACE (`InheritedObjectType`) says which children may
  inherit it; whether it applies to the object itself is decided by the inherit-only flag
  alone - the access check reads the object type and skips inherit-only entries, nothing
  else (MS-DTYP). Five places took a class as "children only" and dropped the entry:
  the domain root ACL in `Get-DangerousACLs`, the AdminSDHolder template in
  `Get-PrivilegedGroupMembers`, `Get-CriticalObjectACLs`, the container check of
  `Get-AddComputerRights` and the GPO-link rights on an OU. An entry such as "this object
  and descendant user objects" is full control over the domain object - replication
  rights of that shape are DCSync - and on AdminSDHolder it is copied onto every
  protected account. The wizard's "descendant objects only" forms are inherit-only and
  stay out. AdminSDHolder entries that are inherit-only but name no class were counted,
  and are not any more: they reach neither the template nor the objects SDProp copies it
  onto.

- **The anonymous LDAP card describes `dsHeuristics`.** `Get-LDAPConfiguration` raises it
  from character 7 of `dsHeuristics` alone, but the card still said "The GPO does not
  restrict anonymous LDAP binding" and recommended 'Network access: Do not allow anonymous
  enumeration of SAM accounts and shares', an SMB null-session setting that has no effect
  on LDAP. It now says what the character allows, which ACLs decide what an anonymous
  client can read, and how to set the character back; its title is *Anonymous LDAP
  Operations Allowed*, and its risk is a finding like the line that raises it.

- **Operator groups that `dsHeuristics` takes out of AdminSDHolder protection are read
  in the group ACL step.** `Get-PrivilegedGroupMembers` reads the DACL of the privileged
  groups AdminSDHolder does not protect and measures that by `adminCount`. Character 16
  of `dsHeuristics` excludes Account, Server, Print or Backup Operators and their members
  from the protection - but the `adminCount=1` SDProp set before stays, so exactly the
  groups whose DACL nobody resets any more looked protected, and the right granted on
  them since went unread. The step now reads `dsHeuristics`, records through which
  privileged group each group was reached, and reads a group whose every path runs
  through an excluded operator group, whatever its `adminCount` says; a note names them.
  A group another protected group still covers stays out.

- **`msDS-SupportedEncryptionTypes` is decoded at the bits MS-KILE defines.** The Kerberos
  feature flags were read at 0x40-0x200 instead of 0x10000-0x80000, so the SHA-2 variants
  of AES (0x40, 0x80) were shown as "FAST-Supported" and "Compound-Identity-Supported",
  and a computer's 0x2001C lost its compound-identity flag. A value without any encryption
  type - only feature flags or the session-key bit - now reads "Not configured" beside
  them, which is what it means: the domain's default types apply. **The `-SK` bit no
  longer counts as AES**: it asks for AES session keys, and 0x24 - RC4 with AES session
  keys, Microsoft's recommendation for an account that has to keep RC4 - still encrypts
  the ticket with RC4. Counted as AES, such a kerberoastable account was neither "RC4
  without AES" on its card nor RC4-only in the report's scoring.

---

## [2.7.0] - 2026-10-08

### Added

- **Credential Roaming check.** Detects users whose DPAPI master keys
  (`msPKIDPAPIMasterKeys`) and private keys (`msPKIAccountCredentials`) are roamed into
  Active Directory, whether that material is readable by every authenticated user, and
  whether a delegated read is granted on the containers that hold it. Presence is tested
  with light attribute reads only - the key blobs themselves are never fetched - and the
  schema is consulted only once material has actually been found.

- **Per-TLS-version LDAPS handshake diagnostics.** When an LDAPS (port 636) handshake
  fails, adPEAS now probes each TLS version individually and classifies the result from
  the exception chain rather than from localized message text, separating a transport that
  was reset (a middlebox tearing the connection down) from a protocol the server declined
  to negotiate. The report says which it was instead of simply retrying and reporting a
  generic failure.

### Changed

- **Dormant Group Policies are named, not just counted.** Findings on GPOs that reach no
  machine - unlinked, or disabled - are held back from the main results and summarized
  separately. That held-back material is now listed one line per policy (display name on
  the left, GUID on adPEAS's standard column), rendered as object cards, and printed
  *before* the active findings rather than after. This is applied consistently across every
  GPO check: LDAP configuration, SMB signing, local group membership, registry settings,
  scheduled tasks, script paths, Point and Print, user-rights assignment and
  add-computer rights.

- **GPO findings name the policy they come from,** carrying a per-finding reach verdict and
  resolving the effective setting per directory partition.

- **Point and Print reports a count of hardened configurations** instead of printing a
  green line for each one.

- **A user-rights assignment lists only what a GPO grants,** not what it hardens; an
  assignment that only removes default holders is held back rather than shown as a finding.

- **ESC14 findings are dampened when no NTAuth issuer is published,** since the
  misconfiguration cannot be reached without one.

- **The console sub-header names the check function** it belongs to.

- **Container and OU completion ranks the container that bears the typed name first.**

### Fixed

- **GPO linkage is now three-valued:** an *unresolved* linkage is told apart from *linked
  nowhere*. An unresolved linkage had been read as "not linked", which silenced several
  checks completely and could report an unlinked GPO as the effective setting.

- **Machine-local and well-known SIDs are resolved locally.** Service-account authorities
  (S-1-5-80/82/83/84/90/94/96, hashed from a name) and other well-known SIDs that carry no
  directory object are answered without a directory or Global Catalog query, which would
  otherwise fail or leak connection state.

- **Four incorrect values in the user-rights default baseline** were corrected against the
  documented Windows defaults.

- **A failed LDAPS handshake no longer retries, misleads, or hides its reason.**

- **An auxiliary Global Catalog probe no longer emits errors, retries, or leaks connection
  state** when it fails.

## [2.6.0] - 2026-10-04

### Added

- **`Move-DomainObject` moves and renames any Active Directory object.** An object's OU
  membership is its position in the directory tree, carried by its `distinguishedName` -
  no attribute holds it, which is why `Set-DomainObject` cannot relocate an object and
  this is a function of its own, built on LDAP ModifyDN. Moving and renaming are the same
  operation, so `-DestinationOU` and `-NewName` are each optional and may be combined in a
  single request. It works on any object class, including an organizational unit with its
  whole subtree. The object's `objectGUID`, `objectSID`, group memberships and Kerberos
  principal survive the move unchanged; what changes is which GPOs apply and which
  delegated ACLs reach it - the required `Create Child` on the target OU is the same right
  the `Get-AddComputerRights` and `Get-GPOPermissions` checks already report. Moves are
  validated before the write for a cross-domain target, a destination inside the object's
  own subtree, a missing target container, a `systemFlags` move or rename block, and the
  no-op case, each of which the directory would otherwise report with an error that points
  away from the cause. A rename escapes the name per RFC 4514, so a value containing a
  comma, a leading `#` or a trailing space is handled correctly.

- **Tab completion for organizational-unit and container parameters.** `-SearchBase`
  (across the `Get-Domain*` functions, `Set-DomainObject`, `Invoke-LDAPSearch` and
  `Get-CertificateTemplate`), `-OrganizationalUnit` (the `New-Domain*` functions) and
  `-DestinationOU` (`Move-DomainObject`) now complete to the domain's OUs and top-level
  containers, built lazily on first use and cached for the session. The completion matches
  on any part of the name rather than only a leading prefix, since a distinguished name
  begins with `OU=` or `CN=` while what the operator knows is the OU name, and
  `-SearchBase` additionally offers the Configuration and Schema naming contexts for
  partition queries. `-Identity` completion is unchanged in behavior but now serves
  `Move-DomainObject` as well.

## [2.5.1] - 2026-09-17

### Added

- **Whether Exchange can reach the domain is now answered directly.** In the shared
  permissions model Exchange setup places a WriteDACL entry for an Exchange group on the
  domain object, and a member of that group can rewrite the domain's own access control
  list to grant itself the replication rights DCSync needs. The generic ACL check sees
  that entry and drops it: every group under `OU=Microsoft Exchange Security Groups` is
  classified as an expected trustee on the grounds that Exchange permissions are by
  design, and expected trustees are skipped without `-IncludePrivileged`. For this one
  entry that reasoning does not hold, because Microsoft documents narrowing it with the
  inherit-only flag and removing it outright with AD split permissions.

  The check separates the entries that apply to the domain object from the inherit-only
  ones that only reach child objects of a named class, so the line the verdict rests on is
  visible next to the ones that look similar and are harmless. It also reports which
  permissions model the forest was prepared with.

- **SMTP receive connectors are judged by what they grant an unauthenticated sender.**
  Every verdict comes from the connector's own security descriptor - which `ms-Exch-SMTP-*`
  extended rights it grants ANONYMOUS LOGON or Everyone - and separates an open relay from
  a connector that merely lets an anonymous session submit mail. A connector that also
  permits an internal sender address is called out on its own, because mail arriving from
  a colleague's address that nobody sent passes every trust indicator a mail client has.

  The right GUIDs are read from the forest's own Extended-Rights container rather than
  carried in a table, so a schema that names them differently cannot make an open relay
  report as clean. A connector whose descriptor could not be read says so instead of
  counting as clean.

- **A hybrid deployment with Exchange Online is reported.** On-premises Exchange and the
  cloud tenant share one service principal, so administrative access to an on-premises
  server reaches the tenant through it - which changes what every other Exchange finding
  in the report is worth. Detected from the coexistence relationship the Hybrid
  Configuration Wizard creates.

- **Exchange management role assignments are read, not just the role groups.** A role can
  be assigned straight to a single user, and such an assignment appears in no group
  membership at all - so checking Organization Management was never enough. The new check
  reports who holds Mailbox Import Export, ApplicationImpersonation, Role Management,
  Unscoped Role Management, Mailbox Search and Active Directory Permissions, and tells an
  assignment Exchange ships from one somebody made. ApplicationImpersonation alone is one
  account with read and send access to every mailbox in the organization.

- **MRSProxy joined the endpoint probe.** Extended Protection is configured per virtual
  directory, so a server that enforces it on the EWS root can still leave the replication
  service inside that directory open to an NTLM relay. It appears in the endpoint list
  with its own authentication methods and its own Extended Protection verdict.

### Changed

- **`msDS-KeyCredentialLink` says when a key was last used.** The parser always read the
  approximate last-logon timestamp and the display always discarded it, so what reached a
  report was the device ID and the creation time. A key planted by an attacker and a key
  a user authenticates with every morning look identical that way; the last use is what
  separates them. The line now reads
  `<DeviceID> | created <ts> | used <date|never>`, and the device ID keeps its full length
  because that is the value handed back to `-RemoveDeviceID`.

### Fixed

- **An ordinary access control entry no longer reports as a delegation right.** The
  extended-rights table mapped `4828cc14-1437-45bc-9b07-ad6f015e5f28` to
  `Allowed-To-Act-On-Behalf-Of-Other-Identity`. That GUID is the schema identifier of the
  `inetOrgPerson` class, and resource-based constrained delegation is not an extended
  right at all but a write to `msDS-AllowedToActOnBehalfOfOtherIdentity`. Because GUID
  resolution consults extended rights before schema classes, every entry inherited to
  `inetOrgPerson` objects - they sit in the default domain DACL, and in the entry
  Microsoft's Exchange guidance narrows - was labelled with a delegation right that was
  never granted.

- **Object classes an extended schema adds are named instead of printed as a GUID.** A
  static table can only hold the classes the base schema ships, so an Exchange-extended
  forest produced raw GUIDs in access control entries - and two entries that differed only
  in their target class rendered as the same repeated line. Unknown class GUIDs are now
  resolved from the forest's own schema, once per session; a schema that cannot be read
  yields the GUID rather than a guess.

---

## [2.5.0] - 2026-09-08

### Added

- **Who can write to the SCCM System Management container is now reported.** Configuration
  Manager publishes its sites and its management points in
  `CN=System Management,CN=System`, and a client configured for Active Directory site
  discovery trusts what it finds there. Whoever can write to the container can publish a
  management point of their own, and every client that picks it up takes its policy - and
  the software that policy deploys - from a server the attacker controls.

  The container is one of the few things around SCCM that is created by hand before setup
  runs, by an administrator following a docs page that says to grant the site server Full
  Control; what else was granted along the way is what this reads. The check found the
  container and printed its path, and stopped there.

  Reported as `SCCM_SYSTEM_MANAGEMENT_ACL`. The site servers the check discovered are
  excluded - Full Control is what they are supposed to have - and so are SYSTEM, BUILTIN\
  Administrators, Domain Admins and Enterprise Admins. A privileged principal that is not
  one of those, an Account Operator say, is reported rather than cleared: publishing a
  management point every client trusts is not something it could already do. An unreadable
  security descriptor says so instead of passing as a clean one.

- **A SCOM service account with privileged rights in the domain is called out.** SCOM makes
  its action and SDK accounts local administrator on every monitored server by design, and
  lets an operator run a task on any agent. Domain privileges on top of that turn a
  management server compromise into a domain compromise, and management servers are rarely
  administered as Tier 0. The check listed the accounts and judged none of them; it now
  consults `Test-IsPrivileged` per account, by SID, and reports the privileged ones as
  `SCOM_PRIVILEGED_SERVICE_ACCOUNT` with the membership that makes them privileged.

- **The validation now checks that a finding definition can actually appear in a report.** A
  definition carries the whole write-up a reader gets - impact, attack path, remediation,
  references - and reaches a report through a `Triggers` block, a `-FindingId` on a line, or
  an ObjectType's `PrimaryFindingId`. Nine of them have none of the three: analysis that was
  written and never wired up, and nothing in the validation would have said so. Reported as
  a warning next to the existing unused-ObjectType warning.

  The ObjectType scan in the same step also recognises the `ObjectType = '...'` form now, so
  a check that drives several sections from one table is not reported as leaving its types
  unused.

- **LAPS passwords that stopped rotating are reported.** Coverage counted a machine as
  protected the moment the LAPS expiration attribute existed, which says nothing about
  whether the password behind it ever changed. An expiration time in the past means the
  client did not rotate when it was due - the CSE is broken, the policy no longer reaches
  the machine, or the machine has been off - and the local administrator password is as old
  as the day rotation stopped. If it leaked once it is still valid, which is precisely what
  LAPS exists to prevent, and the coverage figure said the machine was fine.

  `LAPS_PASSWORD_NOT_ROTATED` reports it, judged on the later of the legacy and the Windows
  LAPS expiration attribute so a machine migrated between the two generations is not
  reported for the attribute it stopped using. A 30-day grace period keeps a machine that
  was merely switched off for a fortnight out of the result.

- **AD FS is found and named.** The inventory looked for Entra ID Connect and not for the
  federation service next to it. An AD FS server holds the key its token-signing
  certificate is protected by, and whoever obtains that key can mint a SAML token for any
  federated user - Golden SAML - which is authentication into the connected cloud tenant
  that no on-premises password reset and no MFA at the identity provider revokes.

  Detected the way AD FS actually records itself: the DKM container under
  `CN=ADFS,CN=Microsoft,CN=Program Data`, whose presence says the federation service exists
  in this domain, plus computers registering `adfssrv/`. Reported as `ADFS_DKM_CONTAINER`.

- **A computer whose owner is not its creator is called out separately.** Owner means
  implicit WriteDACL, and on a computer that is `msDS-AllowedToActOnBehalfOfOtherIdentity`
  or `msDS-KeyCredentialLink` and local SYSTEM on the machine. But a workstation joined by a
  helpdesk technician leaves that technician as owner, which is ordinary and in a real
  domain accounts for most of the list - so the finding that mattered was buried in the ones
  that did not.

  `mS-DS-CreatorSID` records who created the account. Ownership that changed afterwards did
  not happen by itself, and it is now reported as `COMPUTER_OWNERSHIP_REASSIGNED`, with the
  creator resolved and named. Where no creator is recorded the check says so rather than
  implying the two match.

- **Disabled computer accounts are included in the owner check.** Ownership survives the
  disable: the owner can re-enable the account, set its password and take it over. The path
  is one step longer, not closed. Disabled accounts are marked rather than dropped, so the
  reader can weigh them.

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

- **The JSON export survives a scan that does not finish.** A scan wrote its findings once,
  at the very end. An unhandled error, a closed window or a killed process took the whole
  JSON with it - and the HTML report with it, since both are generated from the same
  in-memory collection. Only the text report was written as it went. The export now runs
  after every module, and writes atomically: beside the target, then swapped into place
  with `File.Replace`. That matters precisely because it now runs ten times instead of
  once - truncating the target and then writing would have multiplied the window in which
  a crash leaves a half-written file, making the failure worse rather than better.

  A partial file says so. The cache header carries `Complete` and `CompletedModules`, and
  both `Convert-adPEASReport` and `Compare-adPEASReport` warn when they read one. The
  comparison is where it matters most: every finding from a module that never ran shows up
  as resolved, which is the one result a reader acts on. A file without the flag counts as
  complete, since back then the export only ever ran at the end.

  `-OutputAppend` now seeds the collection before the first check rather than after it. It
  reads the previous run's export from exactly the path the checkpoints write, so at its
  old position it would have found this run's own data there and silently dropped
  everything the previous run collected. Seeding first also means an interrupted append
  run keeps the history it started from.

- **`-ExcludeModule` runs everything but the named modules.** Skipping one module meant
  naming the other nine. `-ExcludeModule` takes the complement, and combines with
  `-Module` as "these, minus those" - deliberately not mutually exclusive, since that
  reading is unambiguous and lets a saved `-Module` list be trimmed for a single run.

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

### Fixed

Found while building the unit test suites, each reproduced before it was changed.

- **ESC5 findings now carry the ESC5 write-up.** The PKI container permission check worked
  and set `pkiContainersAffected` on every finding. `ESC5_PKI_CONTAINER_ACL` triggered on
  `Container` and `Rights`, two attribute names no check emits, so the definition could
  never fire and the findings attached to the generic `ACL_GENERICALL` and `ACL_WRITEDACL`
  texts instead. The reader was told somebody holds GenericAll on an object, where a text
  explaining that they can create an ESC1-vulnerable template from scratch, grant themselves
  enrollment on any template and poison the NTAuth store was sitting unused.

- **`StrongCertificateBindingEnforcement=1` deployed by Group Policy is reported.** Only 0
  was flagged, on the reasoning that 1 was the value Windows shipped as the default. It was,
  from May 2022 until the February 2025 update moved to full enforcement and made 2 the
  default. Compatibility mode validates the SID extension only when the certificate carries
  one - and a certificate without that extension is precisely what a template with
  CT_FLAG_NO_SECURITY_EXTENSION issues, which adPEAS already reports as ESC9. The value is
  therefore the second half of that attack's precondition, reported as
  `REGISTRY_ESC10_KDC_BINDING_COMPAT` at a lower severity than the 0 case.

- **ESC9 says what else has to be true.** The finding read "attacker can modify
  userPrincipalName and request certificate for any user", which also needs
  StrongCertificateBindingEnforcement to be 0 or 1 on the domain controllers. Where
  enforcement is 2 - the default since February 2025 - the template is a latent
  misconfiguration rather than a live path, and the text now says so and points at the
  registry findings that establish which it is.

- **An EKU OID no longer matches a longer OID that starts with it.** The template analysis
  tested `$ekuString -match '1\.3\.6\.1\.5\.5\.7\.3\.2'` against the joined EKU list.
  1.3.6.1.5.5.7.3.21 and .22 are the registered SSH client and server usages, and both were
  read as Client Authentication - the flag ESC1, ESC2, ESC3-TARGET and ESC9 all key off, so
  a template good for nothing but SSH was enough to raise one. `Test-EKUPresent` puts a
  digit-or-dot boundary on both sides, which leaves the parenthesised form
  "Client Authentication (1.3.6.1.5.5.7.3.2)" matching.

- **The reachability check reads a definition to its end.** The step added in the previous
  entry cut each definition at the first line that looked like a closing brace. Several
  definitions embed a whole remediation script in a here-string, and those scripts contain
  braces at exactly that indentation - so the scan ended mid-string and missed everything
  after it, including seven Triggers blocks. It now ends a definition where the next one
  begins. The corrected count is 216 of 231 definitions with a trigger and seven
  unreachable, not nine.

- **Both halves of the ESC14 check were deciding on a value that was never right.**
  `Get-WeakCertificateMapping` asked `[bool](Test-IsPrivileged -Identity $sid @connectionParams)`
  in two places. `Test-IsPrivileged` returns an object, and `[bool]` of any object is
  `$true`; the function also takes no connection parameters, so splatting Domain or Server
  into it threw and the surrounding catch turned that into "not privileged".

  Which way it was wrong depended only on how adPEAS had been invoked. Run against the
  current domain, every weak mapping was reported as sitting on a privileged principal, and
  in the second half every trustee looked privileged and was skipped - so the
  writable-altSecurityIdentities detection, the original ESC14, reported nothing at all.
  Run with -Domain or -Credential, no mapping was called privileged and no trustee was
  skipped, so SYSTEM and Domain Admins were listed as non-privileged writers.

  Neither showed up in the 306 AD CS tests, because none of them ran the check - only its
  classification helpers. It now has an end-to-end suite covering both halves.
- **The Exchange service groups are judged, not just listed.** Exchange Trusted Subsystem
  and Exchange Windows Permissions are supposed to hold Exchange servers and nothing else -
  Exchange Windows Permissions carries WriteDACL on the domain object in the shared
  permissions model, so an ordinary user in it can write itself a DCSync ACE, and Exchange
  Trusted Subsystem is a member of it. The check resolved every member with its own LDAP
  query and printed them all at Hint level, which answers "who is in this group" and never
  "who is in it that does not belong there".

  The judgement already existed: the member renderer runs `Get-ExchangeGroupMemberClass`,
  which clears Exchange servers, computer accounts, nested Exchange groups and privileged
  principals and flags the rest as `EXCHANGE_GROUP_LOW_PRIV_MEMBER`. It only runs on an
  object marked `_isExchangeGroup`, which three Rights checks set when an Exchange group
  turns up as the holder of a dangerous permission - and which the module whose subject
  these groups are did not. It now shows the group rather than its members one by one, so
  the classification runs and the query per member disappears with it.

- **An empty Exchange Windows Permissions group is reported.** Two of the three groups said
  "exists but has no members (unusual)"; this one had no such branch, so an empty group
  produced a section header and nothing after it - indistinguishable from not having been
  checked. All three now go through the same code.

- **`netbootserver` is no longer printed as a host name.** The attribute holds the
  distinguished name of the server object. It went into fields called `Name` and
  `PXEServer`, where it read as a name that resolves nowhere. The RDN is shown as the name
  and the DN stays beside it.

- **Two SCOM management servers without a DNS host name are both reported.** The
  deduplication compared `dNSHostName`, and two objects that both have none compare as the
  same machine, so the second was dropped. It keys on the distinguished name now, which
  every object has.

- **`MemberCount` is a number.** Both the SCCM and the SCOM group rows carried it as the
  string "3 member(s)", which the report cannot sort or compare - and which sorts 10 before
  2 when it tries.

- **`Set-DomainUser` and `Set-DomainComputer` could not read the userAccountControl they
  were about to change.** Every operation that flips a UAC bit - disable, enable, set or
  clear PASSWD_NOTREQD, PASSWD_CANT_CHANGE, DONT_REQ_PREAUTH, DONT_EXPIRE_PASSWORD,
  TRUSTED_FOR_DELEGATION and the rest, 32 places across the two functions - read the
  current mask with `[int]$Target.userAccountControl`.

  The attribute does not arrive as a number. `ConvertFrom-LDAPAttribute` replaces it with
  the decoded flag names before any caller sees it, and casting that array throws. The
  throw was caught by the surrounding handler and surfaced as the operation failing for
  some unrelated reason, so the functions worked against hand-built objects and failed
  against a real domain.

  The conversion now lives in one place, `ConvertTo-UACValue`, shared with
  `Test-AccountActivity`, which had the same defect in its other direction: it parsed the
  attribute numerically and fell back to a mask of zero, turning a disabled account into an
  enabled one. An unknown flag name is skipped rather than voiding the mask, so a future
  Windows flag next to ACCOUNTDISABLE cannot make an account look enabled.

- **The per-OU list of unprotected computers is capped.** `Get-LAPSConfiguration` joined
  every name in an OU into one field. A flat domain with thirty thousand machines in one OU
  put all thirty thousand names into a single string, in the console and again in the HTML
  report, and name twelve thousand says nothing name twelve did not. Fifty are named and
  the rest are counted; the exact number beside the row was always and stays exact.

- **`Test-AccountActivity` understands the userAccountControl it is actually handed.** It
  parsed the attribute as a number. Every object that came through `Invoke-LDAPSearch`
  carries it as the decoded flag names instead, because `ConvertFrom-LDAPAttribute` replaces
  the number with `@('WORKSTATION_TRUST_ACCOUNT', 'ACCOUNTDISABLE', ...)`. That form fell
  through to a mask of zero, so **a disabled account passed `-IsEnabled` and reported
  `IsEnabled = $true`**, and `PASSWD_NOTREQD` and `DONT_EXPIRE_PASSWORD` were never seen
  either.

  It stayed invisible wherever the LDAP query already filtered on the bit server-side, which
  is most callers. Where it did not - the infrastructure inventory, which asks for domain
  controllers and Exchange, MSSQL, SCCM and SCOM servers without an enabled filter and
  relies on this function for it - disabled machines were listed as live infrastructure.
  Both shapes are now read, and an unknown flag name is skipped rather than voiding the
  whole mask.

- **Domain controllers are out of the LAPS coverage figures.** A DC has no local SAM, so the
  built-in Administrator account LAPS manages everywhere else does not exist there. Legacy
  LAPS never touched a DC at all, and Windows LAPS reaches one only through the DSRM
  account, and only when `BackupDsrmPassword` is on. Counting them meant **every domain
  reported its own domain controllers as unprotected** and put `OU=Domain Controllers` in
  the list of exposed OUs - a finding no domain could ever clear.

  They are reported on their own terms instead, including whether a GPO configures DSRM
  password backup for them, which the LAPS GPO parser now reads. A failed lookup leaves them
  in the coverage figures and says so, rather than dropping real machines because one query
  did not answer.

- **Exchange is found in the Configuration partition, not by a group's membership.**
  Detection read the members of a group looked up by the literal string "Exchange Servers".
  That group is not a list of servers - Exchange puts service accounts in it too - it is
  not rename-proof, it cost one LDAP query per member, and it contradicted the function's
  own documentation, which promised SPN-based detection the code never did.
  Exchange records each of its servers as an `msExchExchangeServer` object under
  `CN=Services` in the Configuration partition; that list is authoritative and carries the
  build, which is what decides whether the server still receives patches. The SPN route,
  with domain controllers excluded, is the documented fallback.

- **`Get-InfrastructureServers` no longer loses one half of the AD FS evidence to the
  other.** The DKM container and the `adfssrv/` servers are independent findings, and a
  failing computer query used to discard a container that had already been found - the same
  reason each section already has its own error boundary, one level down.

- **The two Computer checks read their findings back in one query instead of one per
  finding.** `Get-OutdatedComputers` and `Get-NonDefaultComputerOwners` both work in two
  passes, and the second pass ran one LDAP round-trip per finding: a domain with three
  hundred end-of-life machines paid three hundred round-trips for data a handful of queries
  return. `ConvertTo-LDAPDNFilter` builds the batched filters, escaping every DN, so a name
  like `CN=Doe\, Jane (Contractor),...` cannot silently drop an object out of the report.

- **A trust's SID filtering verdict now reads the direction and the kind of trust, not one
  bit.** `Get-DomainTrusts` decided on `QUARANTINED_DOMAIN` alone: absent meant "SID
  filtering disabled". Three things decide it, and using only one produced a false positive
  on every correctly configured forest trust and on every trust pointing the other way,
  while missing the one attribute that really does weaken a forest trust.

  Direction. `trustDirection` 2 is outbound, which per MS-ADTS 6.1.6.7.12 means *this*
  domain trusts the partner and the partner's principals authenticate here. That is the
  direction the SID-history risk runs in. A purely inbound trust is the partner's exposure,
  not ours, and was being reported as ours.

  Which filter applies. An external trust carries `QUARANTINED_DOMAIN` by default and its
  absence means filtering was switched off - that part was right. A forest trust filters
  differently: it accepts SIDs from the trusted forest and rejects the rest, and normally
  carries no `QUARANTINED_DOMAIN` at all. Every healthy forest trust was therefore flagged.
  What actually weakens one is `TREAT_AS_EXTERNAL` (0x40), which downgrades it to external
  semantics so SIDs naming any domain of the trusted forest are honoured - and that flag
  was not looked at.

  Within-forest trusts were already excluded and still are: one forest is one security
  boundary. The verdict now goes out as `sidFiltering` on every trust, with `trustRisk` and
  a `Finding` severity only where the risk actually runs towards this domain, and a closing
  line that counts them.

- **LDAP channel binding is read from `Registry.pol`, not only from `GptTmpl.inf`.**
  `LDAPServerIntegrity` is a Security Option and lands in `GptTmpl.inf`, so the check found
  it. `LdapEnforceChannelBinding` has no Security Option UI at all - Group Policy carries it
  in `Registry.pol` - so a domain that enforces channel binding correctly was told every one
  of its domain controllers was potentially vulnerable. The false alarm was aimed precisely
  at the domains that had done the right thing. A GPO whose only LDAP setting lives in
  `Registry.pol` is now reported as well, instead of being read and dropped.

- **`Get-LDAPConfiguration` asks the data layer which computers are domain controllers.**
  It spelled out the `userAccountControl` bit filter itself. Now it uses
  `Get-DomainComputer -DomainController`, so the definition cannot drift from the rest of
  the checks.

- **A GPO linked to the Domain Controllers OU is recognised as reaching them.** Whether a
  GPO covers the domain controllers is now decided in one place,
  `Test-GPOCoversDomainControllers`, and two defects went with it. A link at or above the
  DC's own OU counts, not only a domain-wide link. And the ancestor test uses an ordinal
  `EndsWith` on an RDN boundary rather than `-like`: `-like` reads `[` and `]` as a
  character class, so an OU named `[Tier 0] Domain Controllers` - an ordinary tiering
  convention - matched nothing, and the GPO hardening LDAP on exactly those controllers was
  reported as not reaching them.

- **`Get-GPOUserRightsAssignment` was rebuilt around what Windows actually ships.** It used
  to decide by the identity of the holder: a right granted to a privileged SID, an operator
  group or a well-known service identity was hidden, everything else reported. That asked
  the wrong question and failed in both directions.

  It hid real findings. `Backup Operators` holding `SeDebugPrivilege` is not a Windows
  default and is a clean path to SYSTEM on every machine in scope - and it was suppressed,
  because the group is on the privileged list. It reported expected ones too, because which
  principals hold a right by default depends on the right and not on how privileged the
  holder looks.

  The check now compares. The `[Privilege Rights]` section is absolute, not additive: the
  principals a GPO lists become the complete set of holders on the machines it reaches. So
  the GPO's list and the documented default list describe the same thing, and the difference
  runs both ways - what the policy **adds** beyond the default is the escalation risk and
  the finding, what it **removes** is usually hardening and is reported as a note.

  Member computers and domain controllers have different defaults, so the comparison uses
  the ones for the machines the policy actually reaches: the Default Domain Controllers
  Policy is recognised by its GUID, a link at or below `OU=Domain Controllers` counts as
  well, and a policy reaching both is measured against the union.

  A right whose default set is not established is not guessed at. It falls back to the old
  identity filter and the finding says so, so the gap is visible rather than silently
  decided. `SeServiceLogonRight` is that case: what holds it depends on which products are
  installed.

  The defaults live in the new `adPEAS-UserRights.ps1`. They are the published Windows
  values, entered from documentation rather than measured against a live domain - a wrong
  row produces a false positive or a false negative, so they are worth a spot-check against
  real data. `-IncludePrivileged` survives as an alias of the new `-IncludeDefaults`.

- **No GPO check asked whether the policy it was reading actually applies.** A GPO carries
  two switches that decide that, and the five checks reading its settings consulted
  neither. The `flags` attribute disables half the policy or all of it, and
  `Get-DomainGPO` decodes it into `GPOStatus` - nothing read the result. The other is
  linkage: a GPO linked nowhere applies nowhere. A dangerous startup script in a policy
  whose computer configuration is switched off was reported exactly like one that runs on
  every boot.

  Findings now carry `GPONotEffective` naming the reason, and the half matters rather than
  just the switch: a user-side setting is unaffected by a disabled computer configuration.
  Nothing is suppressed - a disabled half is one click from being enabled, and the setting
  inside a forgotten policy is a cleanup candidate precisely because nobody looks at it. A
  linkage lookup that failed is reported as nothing rather than as "applies nowhere".

- **`Get-GPOScheduledTasks` could mistake an ordinary account for SYSTEM.** The SID tests
  are the reliable half and run first, but the name fallbacks behind them were unanchored:
  `LocalSystem` also matched an account called `svc-LocalSystemBackup`, and `\SYSTEM$`
  would take any domain account named SYSTEM for the machine account. Both would have
  filed a user task as running with full machine rights. All of them are anchored now.

- **The permission scans stopped at the organizational units.** `Get-DangerousOUPermissions`
  and the `-IncludeAllOUs` path of `Get-PasswordResetRights` asked for
  `(objectClass=organizationalUnit)` and nothing else. `CN=Users` and `CN=Computers` are
  containers, not organizational units, and in a great many domains that is where most
  accounts sit - everything nobody deliberately moved. A delegation granting GenericAll or
  password resets over `CN=Users` was invisible while the same delegation one OU further
  along was reported.

  The new `Get-PrincipalContainer` adds the containers directly under the domain root -
  one query, scoped to a single level, for the container class and for `builtinDomain`,
  which is what `CN=Builtin` is. The scope is deliberate: a subtree search would drag in
  the whole `CN=System` hierarchy and multiply the ACL reads that follow by the same
  factor. The default path of `Get-PasswordResetRights` was never affected, because it
  derives its scope from where the privileged accounts actually live.

- **`Get-AddComputerRights` looked at the wrong container, and only at explicit grants.**
  The container was assumed to be `CN=Computers`; after `redircmp` it is not, and the
  actual one is recorded in `wellKnownObjects` on the domain object, which is now read.
  `-ExplicitOnly` was dropped as well: a `CreateChild` grant inherited from the domain root
  lets its holder create computer accounts exactly as an explicit one does, and every such
  grant was discarded without a word.

- **`Get-LAPSPermissions` could not tell the two LAPS generations apart in its output.**
  The check works out per OU who reads the legacy attribute and who reads the Windows LAPS
  one, then reported every principal with the same flat label, `LAPS Password Read`. In a
  domain part way through the migration that is the difference between reading the password
  of the machines already moved and of the ones still on the legacy attribute. The label
  now names the generation, and a read on every property is reported as covering both.

- **Primary group membership was invisible everywhere.** An account whose `primaryGroupID`
  is `512` is a Domain Admin - the RID is in its token - but Active Directory does not
  write that relation into the group's `member` attribute, and the account carries no
  `memberOf` pointing back. `LDAP_MATCHING_RULE_IN_CHAIN` therefore cannot see it either.
  Setting the primary group is a known way to hold privilege out of sight of exactly the
  enumeration adPEAS performs, and `primaryGroupID` appeared in `src/` only to identify
  domain controllers - never as a membership relation.

  `Get-PrivilegedGroupMembers` now folds these accounts into the group they point at, with
  one query for all privileged groups rather than one per group, and labels them
  `(primary group)` rather than `(direct)`: the account is not in the member attribute, so
  it cannot be removed from the group and the fix is a different one.
  `Get-PrivilegedAccountFilter` gained the matching clauses, which costs no query at all -
  the RIDs are known and the attribute is indexed - so the three account checks that use
  it see these accounts too. `513` for a user and `515` for a computer are the defaults and
  are not privileged RIDs, so nothing ordinary matches.

- **`adminCount=1` was the definition of "privileged account", and it misses accounts.**
  Three checks - `Get-AdminReversibleEncryption`, `Get-AdminPasswordNeverExpires` and
  `Get-InactiveAdminAccounts` - drew their candidates from that attribute. AdminSDHolder
  sets it and never clears it, which two of the three already compensated for by verifying
  each candidate with `Test-IsPrivileged`. Nothing compensated for the other direction:
  AdminSDHolder protects a fixed list of groups, and adPEAS counts groups outside it as
  privileged - **Group Policy Creator Owners** (RID `-520`) above all, whose members can
  create and edit Group Policy and never receive `adminCount` at all. Propagation is also
  periodic, so an account added to Domain Admins within the last SDProp cycle is unmarked.

  The candidate set is now the union of membership in a privileged group, resolved through
  `LDAP_MATCHING_RULE_IN_CHAIN` so nested members count, and `adminCount=1`, which stays in
  as the catch-all for a group this build does not list. It is built once, in the new
  `Get-PrivilegedAccountFilter`, and cached for the session.

- **`Get-AdminReversibleEncryption` only looked at privileged accounts.** Reversible
  encryption means the cleartext password is recoverable from the domain controller, which
  is the same leaked credential on a service account as on an administrator - and whether
  anyone was told depended on the account's privilege rather than on its exposure. Every
  account carrying the flag is reported now, with the privileged ones marked as
  `PRIVILEGED_ACCOUNT_AFFECTED`. The domain-wide switch behind the same weakness is
  reported by `Get-DomainPasswordPolicy` and was never affected.

- **`Get-NonDefaultUserOwners` skipped disabled accounts.** Ownership carries WriteDacl
  implicitly, so whoever owns a disabled privileged account can grant itself the rights to
  enable it and set its password. The takeover path is the ownership; the account being
  disabled is a step in it rather than a reason to leave it out.

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

- **The minified and ultra-compressed builds shipped code the build itself had mangled.**
  The minimization was regexes over the whole assembled file, which cannot tell code from
  the string literals the file is full of - and the file carries 251 KB of embedded report
  CSS, JavaScript and HTML. Proven with two probes put into that CSS, a `#sidebar {` line
  and a `<# ... #>` comment: both survived into `adPEAS.ps1` and both were deleted from
  `adPEAS_min.ps1` and `adPEAS_ultra.ps1`. The readable build, the one anybody would test,
  stayed correct while the shipped variants did not. Rewriting leading four-space
  indentation to a tab did the same inside every here-string: the ASCII logo shipped
  misaligned in the ultra and obfuscated variants, and the embedded report template
  differed between artifacts by 16 KB.

  Comments are removed by token now and logging calls by AST node, neither of which can
  see into a string, and the line-based steps skip lines inside a multi-line string
  literal - 8 % of the file. The build then proves it, comparing the embedded assets in
  all three text variants against the files they came from. The artifacts came out
  *smaller* than before, because a token knows a trailing comment is one and `^#` did not.

  Embedded assets are located by an explicit `#region BUILD:EMBED` marker rather than by a
  regex matched against the wording of a doc comment. Rewording that comment broke the
  match, and for the report-diff template the build only warned - so every artifact
  shipped the development version, which looks for a `templates/` directory beside itself
  and returns nothing.

  Code signing had never worked either. On Windows PowerShell 5.1, the runtime this
  project targets, `Get-PfxCertificate` has no `-Password` parameter, so a
  password-protected PFX killed the build before a single file was touched. Under
  PowerShell 7 it did sign, then reported "0/4 files signed successfully" and exited 0,
  because it tested whether the signature verifies on the build machine rather than
  whether one had been written - a self-signed or internal-CA certificate returns
  `UnknownError` while writing a perfectly good signature. The result is read back off the
  file now, a signature the host cannot chain is reported as such, and a build asked to
  sign that did not now fails.

- **S4U delegation attacks reported a real success as a failure.** `Invoke-S4UCore` handed
  `Build-KRBCred` the session key as its Base64 display string where raw bytes are
  required. Every successful S4U2Proxy exchange, in every mode, ended in a
  type-conversion exception: the Kerberos exchange had already succeeded, and the tool
  reported the whole attack as failed with an error that said nothing about what actually
  happened.

  RBCD Auto Mode had four more behind it, layered so that fixing the outer one exposes the
  next. The machine account was created without `-PassThru`, so the result was always null
  and every run threw before a computer was ever created; the result object was then read
  for a property it does not carry; the RBCD security descriptor was built by hand against
  a raw attribute parameter that has not existed since `-AddRBCD` replaced it in the
  v2.0.0 rewrite; and the cleanup path called a function that exists nowhere in this
  codebase, so every orphaned computer account from a failed configuration was silently
  left behind. Neither object's failure reason was ever read, so a real failure came back
  blank. Separately, resolving a Domain Controller without an active session passed a
  parameter `Resolve-adPEASName` does not have, which threw before the TGT was ever
  requested. All eight trace to the same rewrite, and were never caught because nothing
  had run this module since.

- **The `Set-Domain*` write helpers silently no-oped on writes that should have worked.**
  Five defects sat in `Set-DomainGPO` alone. Every `Add*` operation - scheduled task,
  local group member, logon and startup script, service, deployed file, firewall rule -
  builds its SMB scriptblock with `.GetNewClosure()`, which on real Windows PowerShell 5.1
  (and not under PowerShell 7, where this was tested) re-validates every captured variable
  against its attributes. An unbound `ValidateSet` parameter from an inactive parameter
  set holds `""`, which is not a member of its own set, so the closure itself threw and
  **every `Add*` operation was non-functional on the actual deployment target**. A local
  group member given by name was resolved through a `SecurityIdentifier` overload that
  does not exist, so that call threw too. A local variable silently clobbered the
  `-ItemName` parameter - PowerShell variable names being case-insensitive - so every
  name-matched removal searched for the wrong name. The GPO version bump passed a value
  outside `Invoke-SMBAccess`'s own `ValidateSet`, throwing after the AD write had already
  succeeded and discarding it. And SYSVOL permission mirroring shared one ACL object and
  one `Set-Acl` call between the owner change and the ACE mirroring, so a rejected owner -
  the near-universal case, since the account running this rarely holds
  `SeRestorePrivilege` for an arbitrary owner SID - discarded every mirrored ACE with it.
  `New-DomainGPO` had the same owner-poisons-ACEs bug and is fixed the same way.

  `Set-DomainObject`, the shared foundation the others delegate to, accepted
  `-ExtendedRight SelfMembership` as a `ValidateSet` value with no alias behind it: every
  such call failed at runtime with "Unknown ExtendedRight alias", a promise the
  `ValidateSet` made and the code never kept. It is implemented now, and deliberately
  distinct from the existing `AddMember`/`WriteMembers` aliases - Self-Membership lets a
  principal add only itself, not anyone. Four early-return paths also ignored `-PassThru`
  entirely, unlike every other failure path in that function, so a caller scripting
  against the result got a bare boolean with no message on exactly those failures.

  `Set-DomainComputer -ClearConstrainedDelegation` did not declare `-Principal`, although
  its own documented example removes a single SPN with it - every such call died in
  parameter-set resolution before the function ran. `Set-DomainUser`'s password parameters
  had no `[AllowEmptyString()]`, so `-PasswordNotRequired`, the switch whose entire
  purpose is the empty AD password, was unreachable. `Set-DomainGroup`'s security and
  distribution conversions read `groupType` without `-Raw` and then cast the resulting
  display string to an integer, so every conversion threw and reported a bogus failure
  before the bit math ever ran.

- **AD CS enrollment over RPC and HTTP lost errors and rejected valid input.** A
  connection failure while submitting a certificate request over HTTP - CA unreachable,
  refused, DNS failure - surfaced from the request-body write, which sat outside the
  `WebException` handler around the response. .NET does not connect for a POST until the
  request stream is opened, so the one place a connection error can appear was the one
  place not guarded: the caller crashed instead of receiving the `Status='Error'` result
  every other failure path here produces. Separately, an empty Base64 certificate string
  was rejected at the parameter-binding layer before the function's own "Empty Base64
  input" handling could ever run.

- **`Invoke-DCSync -Identity <GUID>` never reached the RPC call.** The GUID branch computed
  the target GUID and then passed a hardcoded `$null` for that parameter. The account name
  is null on this path too - a bare GUID never resolves to a sAMAccountName here - so the
  replication call received neither and always failed with "No user or GUID specified".
  Replicating a single account by objectGUID could never have worked. The log line and the
  error result also carried nothing identifying, for the same reason; both now fall back
  through account name, GUID and the raw `-Identity` value.

- **`Import-KerberosTicket` could not import a raw ticket.** Following the function's own
  example - raw ticket bytes plus a session key, mirroring what `Invoke-KerberosAuth`
  returns - hit a bare parameter-binding exception several calls deep inside the KRB-CRED
  builder instead of a message saying what to actually pass; the required realm and client
  name were never validated up front. Worse, the server name was splatted
  unconditionally, and splatting an unset parameter passes an explicit empty string, which
  overrides the `krbtgt` default rather than leaving it unset - and an empty ASN.1 general
  string is rejected outright. Importing a TGT without spelling out `-ServerName krbtgt`,
  the overwhelmingly common case, crashed. Both are fixed and the documented example
  corrected.

- **`-ForceKerberos` was silently ignored for a cross-domain NetBIOS credential.** When a
  username or credential carries a NetBIOS domain prefix that resolves to a different
  realm, `Connect-adPEAS` cannot discover a KDC for the NetBIOS name and falls through to
  NTLM or SimpleBind - and it did so regardless of `-ForceKerberos`, unlike every other
  Kerberos-failure path in that function. That broke the switch's documented contract
  ("fails completely, no SimpleBind/NTLM fallback") for exactly the credential shape most
  likely in a cross-domain assessment. `-ForceKerberos` combined with `-ForcePassTheCert`,
  which always uses Schannel and never Kerberos by design, also produced no warning at
  all, unlike the equivalent combinations with `-UseWindowsAuth`; it now warns the same
  way.

- **`-IgnoreSSLErrors` demanded an explicit argument despite its name.** It was declared as
  a `[bool]` with a `$true` default in `Connect-adPEAS`, `Connect-LDAP` and
  `Invoke-HTTPRequest`, and a `[bool]` parameter requires an argument no matter what it
  defaults to - so `Connect-adPEAS -IgnoreSSLErrors -UseLDAPS` failed with a missing
  argument error. All three are `[switch]` now, which behaves correctly across every call
  shape: the bare flag, no flag at all, `-IgnoreSSLErrors:$false` and
  `-IgnoreSSLErrors:$true`.

- Smaller corrections: the SMB failure message in `Get-CredentialExposure` was printed
  twice; pattern hits in custom-path mode were tagged with the wrong object type; two
  tier-2 credential patterns were unreachable behind a more generic one; a scheduled task
  without a name attribute was reported as `Properties`; the membership path in
  `Get-PrivilegedGroupMembers` used a stray `?` as its separator; broad SIDs were compared
  with a substring regex instead of equality; and `Get-DangerousOUPermissions` claimed
  "no dangerous OU permissions detected" when the domain had returned no OUs at all.

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
