<#
.SYNOPSIS
    Central definition of security-relevant registry values deployed via Group Policy.

.DESCRIPTION
    Single source of truth for the Get-GPORegistrySettings check. Each entry describes
    a registry value that, WHEN ACTIVELY SET to a specific value, enables or facilitates
    an attack (credential theft, lateral movement, privilege escalation, defense evasion).

    Design principle: only POSITIVELY SET values are flagged.
    Absence of a hardening value is NOT a finding here, because GPO/SYSVOL parsing cannot
    reliably distinguish "not configured in this GPO" from "secure" - flagging absence
    would produce false negatives presented as secure.

    Both GPO registry delivery mechanisms are matched against this table:
      - Administrative Templates  -> Registry.pol  (PReg binary format)
      - Group Policy Preferences  -> Registry.xml  (XML format)

    Match types:
      Equals        - DWORD value equals MatchValue
      LessOrEqual   - DWORD value <= MatchValue
      GreaterThan   - DWORD value > MatchValue
      Present       - value exists at all (used for REG_SD allow-lists)
      UrlNotHttps   - REG_SZ value starts with http:// (cleartext, not https)

    StoredAsString = $true marks a setting that Windows keeps as a REG_SZ holding a number
    (AutoAdminLogon "1"). Equals then also reads the number out of the string. Every other
    entry is a DWORD setting, and there a string is not the setting: a REG_SZ "0" written
    to NoLmHash is not the dangerous DWORD 0, so the flag stays off for them.

    Hive/Key matching: the Key field holds the path WITHOUT the hive prefix. The hive is
    derived from the source (Machine\Registry.pol -> HKLM, User\Registry.pol -> HKCU) or
    read explicitly from Registry.xml. Key comparison is case-insensitive with leading
    backslashes stripped.

.NOTES
    Author: Alexander Sturz (@_61106960_)
    Part of adPEAS v2 - Active Directory Privilege Escalation Awesome Scripts

    References:
      - OneLogon / Zerologon allow-list:  https://github.com/rub-softsec/onelogon
      - AlwaysInstallElevated:            https://docs.specterops.io/ghostpack-docs/SharpUp-mdx/checks/alwaysinstallelevated
      - LocalAccountTokenFilterPolicy:    https://blog.harmj0y.net/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/
      - RDP Restricted Admin (PtH):       https://www.levelblue.com/blogs/spiderlabs-blog/restricted-admin-mode-circumventing-mfa-on-rdp-logons/
      - Point and Print / PrintNightmare:  see Get-GPOPointAndPrint (dedicated check)
      - WSUS over HTTP (MITM -> SYSTEM):  https://trustedsec.com/blog/wsus-is-sus-ntlm-relay-attacks-in-plain-sight
      - RDP SecurityLayer / UserAuthentication / MinEncryptionLevel policy keys:
                                           https://admx.newyard.nl/gpo/require-use-of-specific-security-layer-for-remote-rdp-connections/
      - Windows Firewall EnableFirewall policy keys per profile:
                                           https://learn.microsoft.com/en-us/previous-versions/windows/embedded/jj963363(v=winembedded.81)
      - AllowInsecureGuestAuth policy key: https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-lanmanworkstation
      - SMB server/client signing:         see Get-SMBSigningStatus (dedicated check, not duplicated here)
      - SMBv1 / SMBv2 server and client:   https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3
      - RejectUnencryptedAccess:           https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security
      - DsrmAdminLogonBehavior:            https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc732714(v=ws.10)
      - RpcAuthnLevelPrivacyEnabled:       https://support.microsoft.com/help/4599464 (KB4599464, CVE-2021-1678)
      - SetProxyBehaviorForUpdateDetection: https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-update
                                           (value name and 0/1 read from WindowsUpdate.admx, policy CorpWuURL)
      - Maximum machine account password age:
                                           https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/domain-member-maximum-machine-account-password-age
      - RestrictNullSessAccess:            https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-access-restrict-anonymous-access-to-named-pipes-and-shares
      - ConsentPromptBehaviorAdmin:        https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/settings-and-configuration
      - EnableScriptBlockLogging:          https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1
                                           (class Both and Disabled = 0 read from PowerShellExecutionPolicy.admx)
      - Schannel protocol Enabled values:  https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings
#>

# =============================================================================
# CENTRAL DANGEROUS REGISTRY KEY TABLE
# =============================================================================
# ConsoleClass: 'Finding' (red) for Critical/High, 'Hint' (yellow) for Medium.
# FindingId links each entry to its tooltip in adPEAS-FindingDefinitions.ps1.
# VulnerabilityName is the displayed (and trigger-matched) label - keep it stable.
$Script:DangerousRegistryKeys = @(

    # =========================================================================
    # TIER 1 - directly exploitable, "set = vulnerability"
    # =========================================================================

    @{
        Id                = 'WDIGEST'
        Hive              = 'HKLM'
        Key               = 'System\CurrentControlSet\Control\SecurityProviders\WDigest'
        ValueName         = 'UseLogonCredential'
        Match             = 'Equals'
        MatchValue        = 1
        Severity          = 'High'
        ConsoleClass      = 'Finding'
        FindingId         = 'REGISTRY_WDIGEST'
        VulnerabilityName = 'WDigest cleartext credential caching enabled'
        RiskReason        = 'LSASS caches plaintext credentials, recoverable with Mimikatz sekurlsa::wdigest'
    }
    @{
        Id                = 'ONELOGON'
        Hive              = 'HKLM'
        Key               = 'System\CurrentControlSet\Services\Netlogon\Parameters'
        ValueName         = 'VulnerableChannelAllowList'
        Match             = 'Present'
        MatchValue        = $null
        Severity          = 'Critical'
        ConsoleClass      = 'Finding'
        FindingId         = 'REGISTRY_ONELOGON'
        VulnerabilityName = 'Vulnerable Netlogon secure channel allow-list (Zerologon/OneLogon)'
        RiskReason        = 'Listed accounts may use insecure Netlogon - exploitable via OneLogon/Zerologon'
    }
    @{
        Id                = 'AUTOLOGON'
        Hive              = 'HKLM'
        Key               = 'Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
        ValueName         = 'AutoAdminLogon'
        Match             = 'Equals'
        MatchValue        = 1
        # Microsoft documents the value as a String value with the data 1, and all three
        # parsers put a REG_SZ into ValueString - so the rule compared only ValueInt and
        # never fired on the value as Windows stores it.
        StoredAsString    = $true
        Severity          = 'High'
        ConsoleClass      = 'Finding'
        FindingId         = 'REGISTRY_AUTOLOGON'
        VulnerabilityName = 'AutoAdminLogon enabled (automatic logon)'
        RiskReason        = 'Automatic logon active - credentials often stored in DefaultPassword (see Credential Exposure)'
    }
    @{
        Id                = 'LMCOMPAT'
        Hive              = 'HKLM'
        Key               = 'System\CurrentControlSet\Control\Lsa'
        ValueName         = 'LmCompatibilityLevel'
        Match             = 'LessOrEqual'
        MatchValue        = 2
        Severity          = 'High'
        ConsoleClass      = 'Finding'
        FindingId         = 'REGISTRY_LMCOMPAT'
        VulnerabilityName = 'Weak LM/NTLMv1 authentication allowed'
        RiskReason        = 'LM/NTLMv1 responses use DES - crackable and enables NTLM relay / hash capture'
    }
    @{
        Id                = 'NOLMHASH'
        Hive              = 'HKLM'
        Key               = 'System\CurrentControlSet\Control\Lsa'
        ValueName         = 'NoLmHash'
        Match             = 'Equals'
        MatchValue        = 0
        Severity          = 'High'
        ConsoleClass      = 'Finding'
        FindingId         = 'REGISTRY_NOLMHASH'
        VulnerabilityName = 'LM hash storage enabled'
        RiskReason        = 'Weak LM hashes stored in the SAM - trivially cracked offline'
    }
    @{
        Id                = 'REMOTEUAC'
        Hive              = 'HKLM'
        Key               = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
        ValueName         = 'LocalAccountTokenFilterPolicy'
        Match             = 'Equals'
        MatchValue        = 1
        Severity          = 'High'
        ConsoleClass      = 'Finding'
        FindingId         = 'REGISTRY_REMOTEUAC'
        VulnerabilityName = 'Remote UAC token filtering disabled (LocalAccountTokenFilterPolicy)'
        RiskReason        = 'Any local admin can pass-the-hash remotely to admin shares / WMI'
    }
    @{
        Id                = 'AIE_HKLM'
        Hive              = 'HKLM'
        Key               = 'Software\Policies\Microsoft\Windows\Installer'
        ValueName         = 'AlwaysInstallElevated'
        Match             = 'Equals'
        MatchValue        = 1
        Severity          = 'Critical'
        ConsoleClass      = 'Finding'
        FindingId         = 'REGISTRY_ALWAYSINSTALLELEVATED'
        VulnerabilityName = 'AlwaysInstallElevated enabled (MSI install as SYSTEM)'
        RiskReason        = 'Any user installs MSI as SYSTEM - requires both HKLM and HKCU set'
    }
    @{
        Id                = 'AIE_HKCU'
        Hive              = 'HKCU'
        Key               = 'Software\Policies\Microsoft\Windows\Installer'
        ValueName         = 'AlwaysInstallElevated'
        Match             = 'Equals'
        MatchValue        = 1
        Severity          = 'Critical'
        ConsoleClass      = 'Finding'
        FindingId         = 'REGISTRY_ALWAYSINSTALLELEVATED'
        VulnerabilityName = 'AlwaysInstallElevated enabled (MSI install as SYSTEM)'
        RiskReason        = 'Any user installs MSI as SYSTEM - requires both HKLM and HKCU set'
    }
    @{
        Id                = 'ENABLELUA'
        Hive              = 'HKLM'
        Key               = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
        ValueName         = 'EnableLUA'
        Match             = 'Equals'
        MatchValue        = 0
        Severity          = 'High'
        ConsoleClass      = 'Finding'
        FindingId         = 'REGISTRY_ENABLELUA'
        VulnerabilityName = 'User Account Control (UAC) disabled'
        RiskReason        = 'UAC off - no token filtering, all local admins usable for remote pass-the-hash'
    }
    @{
        Id                = 'RESTRICTEDADMIN'
        Hive              = 'HKLM'
        Key               = 'System\CurrentControlSet\Control\Lsa'
        ValueName         = 'DisableRestrictedAdmin'
        Match             = 'Equals'
        MatchValue        = 0
        # Medium, not High. The value is the KB2871997 retrofit switch for Windows 7 and
        # Server 2008 R2: from Windows 8.1 and Server 2012 R2 on, Restricted Admin mode is
        # there without it, so setting it to 0 establishes nothing that is not already the
        # case - while a domain without this GPO has the same path open and this check says
        # nothing at all. Administrators also set it to 0 deliberately, because Restricted
        # Admin is how they keep their credentials off the target host.
        Severity          = 'Medium'
        ConsoleClass      = 'Hint'
        FindingId         = 'REGISTRY_RESTRICTEDADMIN'
        VulnerabilityName = 'RDP Restricted Admin mode enabled (Pass-the-Hash over RDP)'
        RiskReason        = 'RDP accepts hash-based auth - enables PtH over RDP and MFA bypass'
    }
    @{
        Id                = 'WSUS_HTTP'
        Hive              = 'HKLM'
        Key               = 'Software\Policies\Microsoft\Windows\WindowsUpdate'
        ValueName         = 'WUServer'
        Match             = 'UrlNotHttps'
        MatchValue        = $null
        Severity          = 'High'
        ConsoleClass      = 'Finding'
        FindingId         = 'REGISTRY_WSUS_HTTP'
        VulnerabilityName = 'WSUS update server configured over cleartext HTTP'
        RiskReason        = 'Update traffic over HTTP - MITM injects updates for SYSTEM-level RCE'
    }

    # ESC10, both halves. The SID extension a CA writes into a certificate is what binds it
    # to one account; these two values decide whether a domain controller still honours that
    # binding. They live on the DC rather than on a template or a CA, which is why they turn
    # up here and not in the AD CS checks - and why this check only sees them when they are
    # deployed by Group Policy. A value set locally on a domain controller is invisible from
    # the directory, and the finding text says so.
    @{
        Id                = 'ESC10_KDC_BINDING'
        Hive              = 'HKLM'
        Key               = 'System\CurrentControlSet\Services\Kdc'
        ValueName         = 'StrongCertificateBindingEnforcement'
        Match             = 'Equals'
        MatchValue        = 0
        Severity          = 'High'
        ConsoleClass      = 'Finding'
        FindingId         = 'REGISTRY_ESC10_KDC_BINDING'
        VulnerabilityName = 'Kerberos ignores the certificate SID extension (ESC10)'
        RiskReason        = 'Value 0 makes the KDC skip the SID extension even when it is present, so every certificate maps by UPN alone - a UPN an attacker who can write that attribute chooses. Value 2 is full enforcement; 1 only validates the extension when a certificate carries one'
    }
    # Value 1 is the other half of the same setting, and it has to come after the entry
    # above: the matcher takes the first entry whose condition holds, and 0 is the worse
    # case. Compatibility mode validates the SID extension only when the certificate
    # carries one - and a certificate without that extension is precisely what a template
    # with CT_FLAG_NO_SECURITY_EXTENSION issues. So this value is the second precondition
    # for ESC9, which adPEAS reports on the template side and could not confirm here.
    @{
        Id                = 'ESC10_KDC_BINDING_COMPAT'
        Hive              = 'HKLM'
        Key               = 'System\CurrentControlSet\Services\Kdc'
        ValueName         = 'StrongCertificateBindingEnforcement'
        Match             = 'Equals'
        MatchValue        = 1
        Severity          = 'Medium'
        ConsoleClass      = 'Finding'
        FindingId         = 'REGISTRY_ESC10_KDC_BINDING_COMPAT'
        VulnerabilityName = 'Kerberos accepts a certificate without a SID extension (ESC10 / ESC9 precondition)'
        RiskReason        = 'Compatibility mode validates the SID extension only when the certificate has one. A template carrying CT_FLAG_NO_SECURITY_EXTENSION issues certificates without it, and those map by UPN alone - which is the ESC9 attack and needs this value to be 1 or 0. Full enforcement is 2, and has been the default since February 2025'
    }

    @{
        Id                = 'ESC10_SCHANNEL_UPN'
        Hive              = 'HKLM'
        Key               = 'System\CurrentControlSet\Control\SecurityProviders\Schannel'
        ValueName         = 'CertificateMappingMethods'
        Match             = 'BitSet'
        MatchValue        = 0x4
        Severity          = 'High'
        ConsoleClass      = 'Finding'
        FindingId         = 'REGISTRY_ESC10_SCHANNEL_UPN'
        VulnerabilityName = 'Schannel maps certificates by UPN (ESC10)'
        RiskReason        = 'Bit 0x4 re-enables UPN-based mapping for Schannel, so a certificate authenticates over LDAPS or any TLS client-auth endpoint as whichever account carries the UPN in its SAN'
    }

    # =========================================================================
    # TIER 2 - defenses explicitly disabled / weakened (only flagged when set)
    # =========================================================================

    @{
        Id                = 'DEFENDER_OFF'
        Hive              = 'HKLM'
        Key               = 'Software\Policies\Microsoft\Windows Defender'
        ValueName         = 'DisableAntiSpyware'
        Match             = 'Equals'
        MatchValue        = 1
        Severity          = 'Medium'
        ConsoleClass      = 'Hint'
        FindingId         = 'REGISTRY_DEFENDER_DISABLED'
        VulnerabilityName = 'Microsoft Defender Antivirus disabled via GPO'
        RiskReason        = 'Endpoint AV disabled centrally - removes a key detection layer'
    }
    @{
        Id                = 'DEFENDER_RTP'
        Hive              = 'HKLM'
        Key               = 'Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
        ValueName         = 'DisableRealtimeMonitoring'
        Match             = 'Equals'
        MatchValue        = 1
        Severity          = 'Medium'
        ConsoleClass      = 'Hint'
        FindingId         = 'REGISTRY_DEFENDER_DISABLED'
        VulnerabilityName = 'Microsoft Defender Antivirus disabled via GPO'
        RiskReason        = 'Real-time protection disabled centrally - removes a key detection layer'
    }
    @{
        Id                = 'RUNASPPL_OFF'
        Hive              = 'HKLM'
        Key               = 'System\CurrentControlSet\Control\Lsa'
        ValueName         = 'RunAsPPL'
        Match             = 'Equals'
        MatchValue        = 0
        Severity          = 'Medium'
        ConsoleClass      = 'Hint'
        FindingId         = 'REGISTRY_RUNASPPL'
        VulnerabilityName = 'LSA Protection (RunAsPPL) explicitly disabled'
        RiskReason        = 'LSASS not protected - eases credential dumping from memory'
    }
    # Credential Guard is configured through Device Guard policy, and that is the path a
    # GPO writes: "Turn On Virtualization Based Security" sets LsaCfgFlags under
    # Software\Policies\Microsoft\Windows\DeviceGuard. The entry below looked for the value
    # under System\CurrentControlSet\Control\Lsa, which is where Windows keeps the state at
    # runtime - a location no Group Policy template writes, so this check could not match
    # it and said nothing about a domain that turns Credential Guard off everywhere.
    @{
        Id                = 'CREDGUARD_OFF'
        Hive              = 'HKLM'
        Key               = 'Software\Policies\Microsoft\Windows\DeviceGuard'
        ValueName         = 'LsaCfgFlags'
        Match             = 'Equals'
        MatchValue        = 0
        Severity          = 'Medium'
        ConsoleClass      = 'Hint'
        FindingId         = 'REGISTRY_CREDGUARD'
        VulnerabilityName = 'Credential Guard explicitly disabled'
        RiskReason        = 'Credential Guard off - derived credentials exposed in LSASS'
    }
    # The runtime path as well, because a Group Policy Preference item can write any key it
    # likes and setting the runtime value directly is a known way to turn the feature off
    # without touching the policy.
    @{
        Id                = 'CREDGUARD_OFF_RUNTIME'
        Hive              = 'HKLM'
        Key               = 'System\CurrentControlSet\Control\Lsa'
        ValueName         = 'LsaCfgFlags'
        Match             = 'Equals'
        MatchValue        = 0
        Severity          = 'Medium'
        ConsoleClass      = 'Hint'
        FindingId         = 'REGISTRY_CREDGUARD'
        VulnerabilityName = 'Credential Guard disabled on the runtime key'
        RiskReason        = 'Credential Guard off - derived credentials exposed in LSASS'
    }
    @{
        Id                = 'FILTERADMINTOKEN'
        Hive              = 'HKLM'
        Key               = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
        ValueName         = 'FilterAdministratorToken'
        Match             = 'Equals'
        MatchValue        = 0
        Severity          = 'Medium'
        ConsoleClass      = 'Hint'
        FindingId         = 'REGISTRY_FILTERADMINTOKEN'
        VulnerabilityName = 'Built-in Administrator (RID-500) UAC token filtering disabled'
        RiskReason        = 'RID-500 admin usable for remote pass-the-hash'
    }
    @{
        Id                = 'CREDSSP_ORACLE'
        Hive              = 'HKLM'
        Key               = 'Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters'
        ValueName         = 'AllowEncryptionOracle'
        Match             = 'Equals'
        MatchValue        = 2
        Severity          = 'Medium'
        ConsoleClass      = 'Hint'
        FindingId         = 'REGISTRY_CREDSSP_ORACLE'
        VulnerabilityName = 'CredSSP encryption oracle set to Vulnerable (CVE-2018-0886)'
        RiskReason        = 'CredSSP accepts unpatched clients - MITM remote code execution'
    }
    @{
        Id                = 'MACHINE_PW_NOCHANGE'
        Hive              = 'HKLM'
        Key               = 'System\CurrentControlSet\Services\Netlogon\Parameters'
        ValueName         = 'DisablePasswordChange'
        Match             = 'Equals'
        MatchValue        = 1
        Severity          = 'Medium'
        ConsoleClass      = 'Hint'
        FindingId         = 'REGISTRY_MACHINE_PASSWORD_STATIC'
        VulnerabilityName = 'Machine account password rotation disabled'
        RiskReason        = 'Static machine password - enables long-lived silver ticket persistence'
    }
    @{
        Id                = 'MACHINE_PW_REFUSE'
        Hive              = 'HKLM'
        Key               = 'System\CurrentControlSet\Services\Netlogon\Parameters'
        ValueName         = 'RefusePasswordChange'
        Match             = 'Equals'
        MatchValue        = 1
        Severity          = 'Medium'
        ConsoleClass      = 'Hint'
        FindingId         = 'REGISTRY_MACHINE_PASSWORD_STATIC'
        VulnerabilityName = 'Machine account password rotation disabled'
        RiskReason        = 'Static machine password - enables long-lived silver ticket persistence'
    }
    @{
        Id                = 'NULL_RESTRICTANON'
        Hive              = 'HKLM'
        Key               = 'System\CurrentControlSet\Control\Lsa'
        ValueName         = 'RestrictAnonymous'
        Match             = 'Equals'
        MatchValue        = 0
        Severity          = 'Medium'
        ConsoleClass      = 'Hint'
        FindingId         = 'REGISTRY_NULL_SESSION'
        VulnerabilityName = 'Anonymous (null session) enumeration enabled'
        RiskReason        = 'Null sessions can enumerate shares/accounts - reconnaissance aid'
    }
    @{
        Id                = 'NULL_RESTRICTANONSAM'
        Hive              = 'HKLM'
        Key               = 'System\CurrentControlSet\Control\Lsa'
        ValueName         = 'RestrictAnonymousSAM'
        Match             = 'Equals'
        MatchValue        = 0
        Severity          = 'Medium'
        ConsoleClass      = 'Hint'
        FindingId         = 'REGISTRY_NULL_SESSION'
        VulnerabilityName = 'Anonymous (null session) enumeration enabled'
        RiskReason        = 'Null sessions can enumerate SAM accounts - reconnaissance aid'
    }
    @{
        Id                = 'NULL_EVERYONE_ANON'
        Hive              = 'HKLM'
        Key               = 'System\CurrentControlSet\Control\Lsa'
        ValueName         = 'EveryoneIncludesAnonymous'
        Match             = 'Equals'
        MatchValue        = 1
        Severity          = 'Medium'
        ConsoleClass      = 'Hint'
        FindingId         = 'REGISTRY_NULL_SESSION'
        VulnerabilityName = 'Anonymous (null session) enumeration enabled'
        RiskReason        = 'Anonymous users gain Everyone rights - broadens null session access'
    }
    # SMB server signing is deliberately not in this table: Get-SMBSigningStatus covers it
    # already, in more detail - server AND client, with the full Required/Optional/Disabled/
    # Not configured matrix rather than one Equals-0 rule. A second, coarser entry here would
    # have reported the same GPO twice under two different checks.

    # =========================================================================
    # TIER 1/2 - RDP hardening, Windows Firewall, SMB client guest auth
    # =========================================================================
    # RDP Restricted Admin above answers "can a hash authenticate this session"; these three
    # answer the question in front of it: is the session negotiated safely at all. Values
    # live under the Terminal Services *policy* key, not the live
    # \CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\ path a logged-on session
    # reads at connect time - GPO Administrative Templates for RDS write to the Policies
    # branch, same as every other entry in this table.

    @{
        Id                = 'RDP_NLA_OFF'
        Hive              = 'HKLM'
        Key               = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
        ValueName         = 'UserAuthentication'
        Match             = 'Equals'
        MatchValue        = 0
        Severity          = 'High'
        ConsoleClass      = 'Finding'
        FindingId         = 'REGISTRY_RDP_NLA'
        VulnerabilityName = 'RDP Network Level Authentication disabled'
        RiskReason        = 'A session reaches the logon screen before any credential is checked - unauthenticated exposure to RDP protocol vulnerabilities (the BlueKeep class) and to unthrottled credential guessing'
    }
    @{
        Id                = 'RDP_SECLAYER_LOW'
        Hive              = 'HKLM'
        Key               = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
        ValueName         = 'SecurityLayer'
        Match             = 'Equals'
        MatchValue        = 0
        Severity          = 'High'
        ConsoleClass      = 'Finding'
        FindingId         = 'REGISTRY_RDP_SECURITYLAYER'
        VulnerabilityName = 'RDP Security Layer downgraded (no TLS enforcement)'
        RiskReason        = 'Value 0 forces the original RDP Security Layer instead of TLS - a self-signed, unverifiable server certificate and weak native encryption, both open to MITM credential capture. 1 (Negotiate) and 2 (TLS) are not flagged'
    }
    @{
        Id                = 'RDP_MINENCRYPTION_LOW'
        Hive              = 'HKLM'
        Key               = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
        ValueName         = 'MinEncryptionLevel'
        Match             = 'LessOrEqual'
        MatchValue        = 1
        Severity          = 'Medium'
        ConsoleClass      = 'Hint'
        FindingId         = 'REGISTRY_RDP_ENCRYPTION'
        VulnerabilityName = 'RDP encryption level set to Low'
        RiskReason        = 'Level 1 encrypts client-to-server traffic only, with weak 40/56-bit RC4 - server-to-client stays in the clear. Only the native RDP encryption path is affected; TLS (SecurityLayer 2) supersedes it'
    }

    # Windows Firewall, one profile per link scope. Three entries, one VulnerabilityName -
    # the same convention the two Defender entries above use, because it is the same finding
    # regardless of which profile the GPO turned off, and RiskReason says which one.
    @{
        Id                = 'FIREWALL_DOMAIN_OFF'
        Hive              = 'HKLM'
        Key               = 'Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
        ValueName         = 'EnableFirewall'
        Match             = 'Equals'
        MatchValue        = 0
        Severity          = 'Medium'
        ConsoleClass      = 'Hint'
        FindingId         = 'REGISTRY_FIREWALL_DISABLED'
        VulnerabilityName = 'Windows Firewall disabled via GPO'
        RiskReason        = 'Domain profile firewall disabled centrally - every host lateral-movement-reachable while on the domain network'
    }
    @{
        Id                = 'FIREWALL_STANDARD_OFF'
        Hive              = 'HKLM'
        Key               = 'Software\Policies\Microsoft\WindowsFirewall\StandardProfile'
        ValueName         = 'EnableFirewall'
        Match             = 'Equals'
        MatchValue        = 0
        Severity          = 'Medium'
        ConsoleClass      = 'Hint'
        FindingId         = 'REGISTRY_FIREWALL_DISABLED'
        VulnerabilityName = 'Windows Firewall disabled via GPO'
        RiskReason        = 'Private profile firewall disabled centrally - every host lateral-movement-reachable while on a private network'
    }
    @{
        Id                = 'FIREWALL_PUBLIC_OFF'
        Hive              = 'HKLM'
        Key               = 'Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
        ValueName         = 'EnableFirewall'
        Match             = 'Equals'
        MatchValue        = 0
        Severity          = 'Medium'
        ConsoleClass      = 'Hint'
        FindingId         = 'REGISTRY_FIREWALL_DISABLED'
        VulnerabilityName = 'Windows Firewall disabled via GPO'
        RiskReason        = 'Public profile firewall disabled centrally - every host directly reachable on an untrusted network (VPN split-tunnel, hotel/coffee-shop Wi-Fi)'
    }

    @{
        Id                = 'GUEST_AUTH_INSECURE'
        Hive              = 'HKLM'
        Key               = 'Software\Policies\Microsoft\Windows\LanmanWorkstation'
        ValueName         = 'AllowInsecureGuestAuth'
        Match             = 'Equals'
        MatchValue        = 1
        Severity          = 'Medium'
        ConsoleClass      = 'Hint'
        FindingId         = 'REGISTRY_INSECURE_GUEST_AUTH'
        VulnerabilityName = 'Insecure guest logon (SMB) allowed via GPO'
        RiskReason        = 'The SMB client accepts an unauthenticated guest session when the server refuses its credentials - a rogue or coerced server captures whatever the client sends, with no signing and no encryption enforced'
    }

    # SMB protocol versions and encryption, as Microsoft documents the values for Group
    # Policy ("Detect, enable, and disable SMBv1, SMBv2, and SMBv3 in Windows"; "SMB
    # Security Enhancements"). Signing has its own check, Get-SMBSigningStatus. Only a GPO
    # that turns a protection off is reported - one that turns SMBv1 off is the
    # recommendation, and the absence of either says nothing.
    @{
        Id                = 'SMB1_SERVER'
        Hive              = 'HKLM'
        Key               = 'System\CurrentControlSet\Services\LanmanServer\Parameters'
        ValueName         = 'SMB1'
        Match             = 'Equals'
        MatchValue        = 1
        Severity          = 'Medium'
        ConsoleClass      = 'Hint'
        FindingId         = 'REGISTRY_SMB1_SERVER'
        VulnerabilityName = 'SMBv1 server enabled via GPO'
        RiskReason        = 'The machines accept SMBv1, which has no pre-authentication integrity - an attacker in the path can downgrade a connection to it - and which Microsoft asks not to use at all'
    }
    @{
        Id                = 'SMB1_CLIENT'
        Hive              = 'HKLM'
        Key               = 'System\CurrentControlSet\Services\mrxsmb10'
        ValueName         = 'Start'
        # 4 disables the SMBv1 client driver; 2 (automatic) and 3 (manual) leave it loadable.
        Match             = 'LessOrEqual'
        MatchValue        = 3
        Severity          = 'Medium'
        ConsoleClass      = 'Hint'
        FindingId         = 'REGISTRY_SMB1_CLIENT'
        VulnerabilityName = 'SMBv1 client enabled via GPO'
        RiskReason        = 'The machines can still speak SMBv1 to a server, so an attacker in the path can offer them the protocol without pre-authentication integrity, signing improvements or encryption'
    }
    @{
        Id                = 'SMB2_SERVER_DISABLED'
        Hive              = 'HKLM'
        Key               = 'System\CurrentControlSet\Services\LanmanServer\Parameters'
        ValueName         = 'SMB2'
        Match             = 'Equals'
        MatchValue        = 0
        Severity          = 'Medium'
        ConsoleClass      = 'Hint'
        FindingId         = 'REGISTRY_SMB2_SERVER_DISABLED'
        VulnerabilityName = 'SMBv2/v3 server disabled via GPO'
        RiskReason        = 'Disabling SMBv2 disables SMBv3 with it: the server loses encryption, pre-authentication integrity and the stronger signing, and is left with SMBv1 or no file sharing at all'
    }
    @{
        Id                = 'SMB_UNENCRYPTED_ACCESS'
        Hive              = 'HKLM'
        Key               = 'System\CurrentControlSet\Services\LanmanServer\Parameters'
        ValueName         = 'RejectUnencryptedAccess'
        Match             = 'Equals'
        MatchValue        = 0
        Severity          = 'Medium'
        ConsoleClass      = 'Hint'
        FindingId         = 'REGISTRY_SMB_UNENCRYPTED_ACCESS'
        VulnerabilityName = 'Unencrypted access to encrypted SMB shares allowed via GPO'
        RiskReason        = 'A share or server that requires encryption also serves clients that cannot encrypt - an attacker in the path claims to be such a client, or downgrades one, and reads the data the encryption was set up to protect'
    }
    # Only 2 is flagged. 0 (the default) admits the DSRM account only to a domain
    # controller started in restore mode, and 1 also while AD DS is stopped - Microsoft's
    # own suggestion for a single domain controller or an isolated one.
    @{
        Id                = 'DSRM_ADMIN_LOGON'
        Hive              = 'HKLM'
        Key               = 'System\CurrentControlSet\Control\Lsa'
        ValueName         = 'DsrmAdminLogonBehavior'
        Match             = 'Equals'
        MatchValue        = 2
        Severity          = 'High'
        ConsoleClass      = 'Finding'
        FindingId         = 'REGISTRY_DSRM_ADMIN_LOGON'
        VulnerabilityName = 'DSRM Administrator logon allowed at any time'
        RiskReason        = 'On a domain controller the DSRM account - its local administrator, whose password no password policy checks - logs on while the directory runs, over the network with its hash alone'
    }

    # =========================================================================
    # Coverage item B21 - settings that take back a hardening Windows ships with
    # =========================================================================

    # KB4599464 (CVE-2021-1678): since the September 14, 2021 updates a missing value means
    # 1, so only an explicit 0 turns the hardening off - "Not recommended", "not protected".
    @{
        Id                = 'PRINT_RPC_PRIVACY_OFF'
        Hive              = 'HKLM'
        Key               = 'System\CurrentControlSet\Control\Print'
        ValueName         = 'RpcAuthnLevelPrivacyEnabled'
        Match             = 'Equals'
        MatchValue        = 0
        Severity          = 'Medium'
        ConsoleClass      = 'Hint'
        FindingId         = 'REGISTRY_PRINT_RPC_PRIVACY'
        VulnerabilityName = 'Print spooler RPC privacy hardening switched off'
        RiskReason        = 'The spooler accepts IRemoteWinspool calls without packet privacy again - the hardening against relaying them (CVE-2021-1678) is undone'
    }
    # "Specify intranet Microsoft update service location", the proxy element. 0 (default):
    # system proxy only; 1: the user proxy as a fallback. It matters for an http:// update
    # server only - which WSUS_HTTP reports - and Microsoft says 1 "makes scans unsecure".
    @{
        Id                = 'WSUS_USER_PROXY'
        Hive              = 'HKLM'
        Key               = 'Software\Policies\Microsoft\Windows\WindowsUpdate'
        ValueName         = 'SetProxyBehaviorForUpdateDetection'
        Match             = 'Equals'
        MatchValue        = 1
        Severity          = 'Medium'
        ConsoleClass      = 'Hint'
        FindingId         = 'REGISTRY_WSUS_USER_PROXY'
        VulnerabilityName = 'Update scan may fall back to the user proxy'
        RiskReason        = 'With an http:// update server, the scan of the update service, which runs as SYSTEM, can go through a proxy the logged-on user chooses'
    }
    # Domain member: Maximum machine account password age - 1 to 999 days, 30 by default and
    # by Microsoft's recommendation. MACHINE_PW_NOCHANGE above is the extreme of it.
    @{
        Id                = 'MACHINE_PW_AGE'
        Hive              = 'HKLM'
        Key               = 'System\CurrentControlSet\Services\Netlogon\Parameters'
        ValueName         = 'MaximumPasswordAge'
        Match             = 'GreaterThan'
        MatchValue        = 30
        Severity          = 'Medium'
        ConsoleClass      = 'Hint'
        FindingId         = 'REGISTRY_MACHINE_PASSWORD_AGE'
        VulnerabilityName = 'Machine account password changed less often than every 30 days'
        RiskReason        = 'A captured machine account password or hash stays valid for longer - for silver tickets, and as the computer account itself'
    }
    # Network access: Restrict anonymous access to Named Pipes and Shares - 1 (Enabled) is
    # the default. 0 lets null sessions reach every pipe and share whose permissions admit
    # them, not only those named in NullSessionPipes and NullSessionShares.
    @{
        Id                = 'NULL_SHARES_PIPES'
        Hive              = 'HKLM'
        Key               = 'System\CurrentControlSet\Services\LanManServer\Parameters'
        ValueName         = 'RestrictNullSessAccess'
        Match             = 'Equals'
        MatchValue        = 0
        Severity          = 'Medium'
        ConsoleClass      = 'Hint'
        FindingId         = 'REGISTRY_NULL_SESSION'
        VulnerabilityName = 'Anonymous (null session) access to shares and named pipes unrestricted'
        RiskReason        = 'Null sessions reach every share and named pipe whose permissions admit anonymous users, not only the ones listed in NullSessionShares and NullSessionPipes'
    }
    # "Turn on PowerShell Script Block Logging" set to Disabled writes 0. The policy exists in
    # both halves (ADMX class Both), the engine reads the machine value and then the user's,
    # and PowerShell 7 has a key of its own. An explicit 0 also suppresses the script blocks
    # PowerShell logs by itself as suspicious - CompiledScriptBlock.LogScriptBlockCreation
    # skips even a forced entry when the setting is false.
    @{
        Id                = 'SCRIPTBLOCK_OFF_HKLM'
        Hive              = 'HKLM'
        Key               = 'Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
        ValueName         = 'EnableScriptBlockLogging'
        Match             = 'Equals'
        MatchValue        = 0
        Severity          = 'Medium'
        ConsoleClass      = 'Hint'
        FindingId         = 'REGISTRY_SCRIPTBLOCK_LOGGING_OFF'
        VulnerabilityName = 'PowerShell script block logging switched off'
        RiskReason        = 'No event 4104 for the script blocks PowerShell runs - not even for the ones it would log by itself as suspicious'
    }
    @{
        Id                = 'SCRIPTBLOCK_OFF_HKCU'
        Hive              = 'HKCU'
        Key               = 'Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
        ValueName         = 'EnableScriptBlockLogging'
        Match             = 'Equals'
        MatchValue        = 0
        Severity          = 'Medium'
        ConsoleClass      = 'Hint'
        FindingId         = 'REGISTRY_SCRIPTBLOCK_LOGGING_OFF'
        VulnerabilityName = 'PowerShell script block logging switched off'
        RiskReason        = 'No event 4104 for the script blocks PowerShell runs - not even for the ones it would log by itself as suspicious'
    }
    @{
        Id                = 'SCRIPTBLOCK_OFF_CORE_HKLM'
        Hive              = 'HKLM'
        Key               = 'Software\Policies\Microsoft\PowerShellCore\ScriptBlockLogging'
        ValueName         = 'EnableScriptBlockLogging'
        Match             = 'Equals'
        MatchValue        = 0
        Severity          = 'Medium'
        ConsoleClass      = 'Hint'
        FindingId         = 'REGISTRY_SCRIPTBLOCK_LOGGING_OFF'
        VulnerabilityName = 'PowerShell script block logging switched off'
        RiskReason        = 'No event 4104 for the script blocks PowerShell 7 runs - not even for the ones it would log by itself as suspicious'
    }
    @{
        Id                = 'SCRIPTBLOCK_OFF_CORE_HKCU'
        Hive              = 'HKCU'
        Key               = 'Software\Policies\Microsoft\PowerShellCore\ScriptBlockLogging'
        ValueName         = 'EnableScriptBlockLogging'
        Match             = 'Equals'
        MatchValue        = 0
        Severity          = 'Medium'
        ConsoleClass      = 'Hint'
        FindingId         = 'REGISTRY_SCRIPTBLOCK_LOGGING_OFF'
        VulnerabilityName = 'PowerShell script block logging switched off'
        RiskReason        = 'No event 4104 for the script blocks PowerShell 7 runs - not even for the ones it would log by itself as suspicious'
    }
    # User Account Control: Behavior of the elevation prompt for administrators in Admin
    # Approval Mode - 5 is the default, 0 is "Elevate without prompting", which Microsoft
    # reserves for "the most constrained environments". ENABLELUA above switches UAC off.
    @{
        Id                = 'UAC_ADMIN_NO_PROMPT'
        Hive              = 'HKLM'
        Key               = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
        ValueName         = 'ConsentPromptBehaviorAdmin'
        Match             = 'Equals'
        MatchValue        = 0
        Severity          = 'Medium'
        ConsoleClass      = 'Hint'
        FindingId         = 'REGISTRY_UAC_NO_PROMPT'
        VulnerabilityName = 'Administrators elevate without a UAC prompt'
        RiskReason        = 'Any program an administrator runs can take the full administrative token without a prompt'
    }
    # Schannel: an Enabled value under Protocols\<version>\Server or \Client overrides the
    # system default - 1 switches the version on, 0 off (TLS registry settings). Read as
    # anything but 0, because the value is a BOOL and 0xffffffff is written as well.
    @{
        Id                = 'SSL30_SERVER'
        Hive              = 'HKLM'
        Key               = 'System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server'
        ValueName         = 'Enabled'
        Match             = 'GreaterThan'
        MatchValue        = 0
        Severity          = 'Medium'
        ConsoleClass      = 'Hint'
        FindingId         = 'REGISTRY_LEGACY_TLS'
        VulnerabilityName = 'SSL 3.0 switched on for the server role'
        RiskReason        = 'Clients can negotiate SSL 3.0 with these servers, which the POODLE attack breaks'
    }
    @{
        Id                = 'SSL30_CLIENT'
        Hive              = 'HKLM'
        Key               = 'System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client'
        ValueName         = 'Enabled'
        Match             = 'GreaterThan'
        MatchValue        = 0
        Severity          = 'Medium'
        ConsoleClass      = 'Hint'
        FindingId         = 'REGISTRY_LEGACY_TLS'
        VulnerabilityName = 'SSL 3.0 switched on for the client role'
        RiskReason        = 'These computers offer SSL 3.0 to the servers they connect to, which the POODLE attack breaks'
    }
    @{
        Id                = 'TLS10_SERVER'
        Hive              = 'HKLM'
        Key               = 'System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server'
        ValueName         = 'Enabled'
        Match             = 'GreaterThan'
        MatchValue        = 0
        Severity          = 'Medium'
        ConsoleClass      = 'Hint'
        FindingId         = 'REGISTRY_LEGACY_TLS'
        VulnerabilityName = 'TLS 1.0 switched on for the server role'
        RiskReason        = 'Clients can negotiate TLS 1.0 with these servers, which RFC 8996 deprecates'
    }
    @{
        Id                = 'TLS10_CLIENT'
        Hive              = 'HKLM'
        Key               = 'System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client'
        ValueName         = 'Enabled'
        Match             = 'GreaterThan'
        MatchValue        = 0
        Severity          = 'Medium'
        ConsoleClass      = 'Hint'
        FindingId         = 'REGISTRY_LEGACY_TLS'
        VulnerabilityName = 'TLS 1.0 switched on for the client role'
        RiskReason        = 'These computers offer TLS 1.0 to the servers they connect to, which RFC 8996 deprecates'
    }
)
