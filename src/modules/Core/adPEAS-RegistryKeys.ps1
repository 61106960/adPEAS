<#
.SYNOPSIS
    Central definition of security-relevant registry values deployed via Group Policy.

.DESCRIPTION
    Single source of truth for the Get-GPORegistrySettings check. Each entry describes
    a registry value that, WHEN ACTIVELY SET to a specific value, enables or facilitates
    an attack (credential theft, lateral movement, privilege escalation, defense evasion).

    Design principle (matches CLAUDE.md focus): only POSITIVELY SET values are flagged.
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
        Severity          = 'High'
        ConsoleClass      = 'Finding'
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
    @{
        Id                = 'CREDGUARD_OFF'
        Hive              = 'HKLM'
        Key               = 'System\CurrentControlSet\Control\Lsa'
        ValueName         = 'LsaCfgFlags'
        Match             = 'Equals'
        MatchValue        = 0
        Severity          = 'Medium'
        ConsoleClass      = 'Hint'
        FindingId         = 'REGISTRY_CREDGUARD'
        VulnerabilityName = 'Credential Guard explicitly disabled'
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
)
