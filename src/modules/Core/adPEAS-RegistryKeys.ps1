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
      - PrintNightmare / Point and Print: https://itm4n.github.io/printnightmare-exploitation/
      - WSUS over HTTP (MITM -> SYSTEM):  https://trustedsec.com/blog/wsus-is-sus-ntlm-relay-attacks-in-plain-sight
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
        Id                = 'PNP_NOWARN'
        Hive              = 'HKLM'
        Key               = 'Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
        ValueName         = 'NoWarningNoElevationOnInstall'
        Match             = 'Equals'
        MatchValue        = 1
        Severity          = 'High'
        ConsoleClass      = 'Finding'
        FindingId         = 'REGISTRY_POINT_AND_PRINT'
        VulnerabilityName = 'Point and Print allows non-admin printer driver installation (PrintNightmare)'
        RiskReason        = 'No elevation prompt on driver install - PrintNightmare-style code execution'
    }
    @{
        Id                = 'PNP_DRVADMIN'
        Hive              = 'HKLM'
        Key               = 'Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
        ValueName         = 'RestrictDriverInstallationToAdministrators'
        Match             = 'Equals'
        MatchValue        = 0
        Severity          = 'High'
        ConsoleClass      = 'Finding'
        FindingId         = 'REGISTRY_POINT_AND_PRINT'
        VulnerabilityName = 'Point and Print allows non-admin printer driver installation (PrintNightmare)'
        RiskReason        = 'Driver install not restricted to admins - PrintNightmare-style code execution'
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
    @{
        Id                = 'SMB_SIGN_OFF'
        Hive              = 'HKLM'
        Key               = 'System\CurrentControlSet\Services\LanManServer\Parameters'
        ValueName         = 'RequireSecuritySignature'
        Match             = 'Equals'
        MatchValue        = 0
        Severity          = 'Medium'
        ConsoleClass      = 'Hint'
        FindingId         = 'REGISTRY_SMB_SIGNING'
        VulnerabilityName = 'SMB server signing not required'
        RiskReason        = 'SMB signing not enforced - enables SMB/NTLM relay attacks'
    }
)
